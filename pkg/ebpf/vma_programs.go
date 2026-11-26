package ebpf

import (
	"fmt"
	"os"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
)

const (
	legacySyscallCheckerProgram = "syscall_checker"
	helperSyscallCheckerProgram = "syscall_checker_vma"
	legacyForkProgram           = "tracepoint__sched__sched_process_fork"
	helperForkProgram           = "tracepoint__sched__sched_process_fork_vma"
	helperStackRecoveryProgram  = "trace_schedule_tail_vma"
	vmaStackRecoveryGroupName   = "vma_stack_recovery"
)

const vmaStackRecoveryProbeHandle probes.Handle = 0 // Local to its probe group.

type vmaLookupBackend uint8

const (
	vmaLookupLegacy vmaLookupBackend = iota
	vmaLookupHelper
)

func (b vmaLookupBackend) String() string {
	if b == vmaLookupHelper {
		return "bpf_find_vma"
	}
	return "legacy"
}

func (b vmaLookupBackend) syscallCheckerProgram() string {
	if b == vmaLookupHelper {
		return helperSyscallCheckerProgram
	}
	return legacySyscallCheckerProgram
}

func (b vmaLookupBackend) forkProgram() string {
	if b == vmaLookupHelper {
		return helperForkProgram
	}
	return legacyForkProgram
}

// Callback-based programs require the BPF JIT, which helper-ID probes do not
// check. An always-on kernel config establishes support even when the sysctl is
// hidden from the current namespace. Otherwise, require a readable enabled value.
func vmaJITEnabled(alwaysOn bool, readFile func(string) ([]byte, error)) (bool, error) {
	if alwaysOn {
		return true, nil
	}

	const path = "/proc/sys/net/core/bpf_jit_enable"
	value, err := readFile(path)
	if err != nil {
		return false, fmt.Errorf("read BPF JIT status from %s: %w", path, err)
	}
	switch strings.TrimSpace(string(value)) {
	case "0":
		return false, nil
	case "1", "2":
		return true, nil
	default:
		return false, fmt.Errorf("invalid BPF JIT status in %s: %q", path, strings.TrimSpace(string(value)))
	}
}

func vmaKernelVersionCompatible(info probes.EnvironmentProvider) (bool, error) {
	return probes.NewKernelVersionRequirement("", "6.1.0", "").IsCompatible(info)
}

// selectVMALookupBackend keeps callback-based programs out of older kernels.
// Helper availability alone does not establish that the full programs pass the
// verifier; the selected programs still have to pass BPFLoadObject.
func selectVMALookupBackend(
	needed bool,
	kernelCompatible func() (bool, error),
	helperSupported probes.HelperSupportChecker,
) (vmaLookupBackend, error) {
	if !needed {
		return vmaLookupLegacy, nil
	}

	compatible, err := kernelCompatible()
	if err != nil {
		return vmaLookupLegacy, fmt.Errorf("check VMA helper kernel compatibility: %w", err)
	}
	if !compatible {
		return vmaLookupLegacy, nil
	}

	// The syscall checker uses a raw tracepoint for its two VMA lookups.
	// Stack recovery makes one lookup at schedule_tail entry, where the child
	// has not run userspace yet. Check the helpers for both program types.
	for _, programType := range []bpf.BPFProgType{bpf.BPFProgTypeRawTracepoint, bpf.BPFProgTypeKprobe} {
		for _, helper := range []bpf.BPFFunc{bpf.BPFFuncFindVma, bpf.BPFFuncGetCurrentTaskBtf} {
			supported, err := helperSupported(programType, helper)
			if err != nil {
				return vmaLookupLegacy, fmt.Errorf("check VMA helper %d for %s: %w", helper, programType, err)
			}
			if !supported {
				return vmaLookupLegacy, nil
			}
		}
	}

	return vmaLookupHelper, nil
}

// setVMAProgramsAutoload excludes unselected variants before the object is
// loaded. The fork program is enabled later by the regular event dependencies;
// stack recovery and syscall checker probes are attached after the object loads.
// Keep the legacy checker loaded when no VMA event is initially selected, as it
// was before backend selection was introduced.
func setVMAProgramsAutoload(backend vmaLookupBackend, setAutoload func(string, bool) error) error {
	for _, name := range []string{
		legacySyscallCheckerProgram,
		helperSyscallCheckerProgram,
		legacyForkProgram,
		helperForkProgram,
		helperStackRecoveryProgram,
	} {
		if err := setAutoload(name, false); err != nil {
			return fmt.Errorf("disable VMA program %s: %w", name, err)
		}
	}

	programs := []string{backend.syscallCheckerProgram()}
	if backend == vmaLookupHelper {
		programs = append(programs, helperStackRecoveryProgram)
	}
	for _, name := range programs {
		if err := setAutoload(name, true); err != nil {
			return fmt.Errorf("enable VMA program %s: %w", name, err)
		}
	}
	return nil
}

// attachVMAStackRecovery runs before the fork probe is attached, so a child
// cannot acquire pending recovery state before the recovery hook is ready.
// extraProbes owns the link and detaches it during Close, including init failures.
func (t *Tracee) attachVMAStackRecovery() error {
	if t.vmaLookupBackend != vmaLookupHelper {
		return nil
	}

	group, ok := t.extraProbes[vmaStackRecoveryGroupName]
	if !ok {
		group = probes.NewProbeGroup(t.bpfModule, map[probes.Handle]probes.Probe{
			vmaStackRecoveryProbeHandle: probes.NewTraceProbe(probes.KProbe, "schedule_tail", helperStackRecoveryProgram),
		})
		t.extraProbes[vmaStackRecoveryGroupName] = group
	}
	if err := group.Attach(vmaStackRecoveryProbeHandle, t.getKernelSymbols()); err != nil {
		return fmt.Errorf("attach VMA stack recovery at schedule_tail: %w", err)
	}
	return nil
}

// configureVMAPrograms runs after detector registration, so their event
// dependencies participate in selection, but before BPFLoadObject.
func (t *Tracee) configureVMAPrograms() error {
	needed := false
	for _, eventID := range []events.ID{events.SuspiciousSyscallSource, events.StackPivot} {
		if _, err := t.eventsDependencies.GetEvent(eventID); err == nil {
			needed = true
			break
		}
	}

	backend, err := selectVMALookupBackend(needed, func() (bool, error) {
		compatible, err := vmaKernelVersionCompatible(t.config.OSInfo)
		if err != nil || !compatible {
			return compatible, err
		}
		alwaysOn := t.config.KernelConfig != nil &&
			t.config.KernelConfig.GetValue(environment.CONFIG_BPF_JIT_ALWAYS_ON) == environment.BUILTIN
		return vmaJITEnabled(alwaysOn, os.ReadFile)
	}, probes.CheckBPFHelperSupportLibbpfgo)
	if err != nil {
		logger.Warnw("Using legacy VMA lookup after compatibility check failed", "error", err)
	}

	if err := t.defaultProbes.SelectProgram(probes.SchedProcessFork, backend.forkProgram()); err != nil {
		return err
	}
	if err := setVMAProgramsAutoload(backend, func(name string, autoload bool) error {
		prog, err := t.bpfModule.GetProgram(name)
		if err != nil {
			return err
		}
		return prog.SetAutoload(autoload)
	}); err != nil {
		return err
	}

	t.vmaLookupBackend = backend
	logger.Debugw("Selected VMA lookup backend", "backend", backend.String())
	return nil
}
