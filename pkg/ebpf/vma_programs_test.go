package ebpf

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
)

func TestVMAJITEnabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		alwaysOn bool
		value    string
		readErr  error
		enabled  bool
		wantErr  bool
	}{
		{name: "always-on config does not require visible sysctl", alwaysOn: true, readErr: os.ErrNotExist, enabled: true},
		{name: "disabled JIT", value: "0\n"},
		{name: "enabled JIT", value: "1\n", enabled: true},
		{name: "enabled JIT with debug output", value: "2\n", enabled: true},
		{name: "surrounding whitespace", value: " \t1\r\n", enabled: true},
		{name: "empty setting", value: "\n", wantErr: true},
		{name: "malformed setting", value: "enabled\n", wantErr: true},
		{name: "multiple settings", value: "1 0\n", wantErr: true},
		{name: "unsupported numeric setting", value: "3\n", wantErr: true},
		{name: "negative setting", value: "-1\n", wantErr: true},
		{name: "missing sysctl", readErr: os.ErrNotExist, wantErr: true},
		{name: "permission denied", readErr: os.ErrPermission, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabled, err := vmaJITEnabled(tc.alwaysOn, func(path string) ([]byte, error) {
				if path != "/proc/sys/net/core/bpf_jit_enable" {
					return nil, os.ErrNotExist
				}
				return []byte(tc.value), tc.readErr
			})
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "BPF JIT status")
				if tc.readErr != nil {
					assert.ErrorIs(t, err, tc.readErr)
				}
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.enabled, enabled)
		})
	}
}

func TestSelectVMALookupBackend(t *testing.T) {
	type helperRequirement struct {
		program bpf.BPFProgType
		helper  bpf.BPFFunc
	}
	requirements := []helperRequirement{
		{bpf.BPFProgTypeRawTracepoint, bpf.BPFFuncFindVma},
		{bpf.BPFProgTypeRawTracepoint, bpf.BPFFuncGetCurrentTaskBtf},
		{bpf.BPFProgTypeKprobe, bpf.BPFFuncFindVma},
		{bpf.BPFProgTypeKprobe, bpf.BPFFuncGetCurrentTaskBtf},
	}

	t.Run("no VMA events do not probe optional kernel features", func(t *testing.T) {
		backend, err := selectVMALookupBackend(false, func() (bool, error) {
			t.Fatal("kernel check must not run without a VMA event")
			return false, nil
		}, func(bpf.BPFProgType, bpf.BPFFunc) (bool, error) {
			t.Fatal("helper check must not run without a VMA event")
			return false, nil
		})
		require.NoError(t, err)
		assert.Equal(t, vmaLookupLegacy, backend)
	})

	t.Run("older kernel keeps legacy even when helpers might exist", func(t *testing.T) {
		backend, err := selectVMALookupBackend(true, func() (bool, error) {
			return false, nil
		}, func(bpf.BPFProgType, bpf.BPFFunc) (bool, error) {
			t.Fatal("older kernels must not select callback-based programs")
			return true, nil
		})
		require.NoError(t, err)
		assert.Equal(t, vmaLookupLegacy, backend)
	})

	t.Run("compatible kernel supports lookup and stack recovery helpers", func(t *testing.T) {
		available := map[helperRequirement]bool{
			{bpf.BPFProgTypeRawTracepoint, bpf.BPFFuncFindVma}:           true,
			{bpf.BPFProgTypeRawTracepoint, bpf.BPFFuncGetCurrentTaskBtf}: true,
			{bpf.BPFProgTypeKprobe, bpf.BPFFuncFindVma}:                  true,
			{bpf.BPFProgTypeKprobe, bpf.BPFFuncGetCurrentTaskBtf}:        true,
		}
		backend, err := selectVMALookupBackend(true, func() (bool, error) {
			return true, nil
		}, func(program bpf.BPFProgType, helper bpf.BPFFunc) (bool, error) {
			return available[helperRequirement{program, helper}], nil
		})
		require.NoError(t, err)
		assert.Equal(t, vmaLookupHelper, backend)
	})

	t.Run("disabled JIT retains legacy without probing helpers", func(t *testing.T) {
		backend, err := selectVMALookupBackend(true, func() (bool, error) {
			return vmaJITEnabled(false, func(string) ([]byte, error) {
				return []byte("0\n"), nil
			})
		}, func(bpf.BPFProgType, bpf.BPFFunc) (bool, error) {
			t.Fatal("helper availability does not make callbacks usable without JIT")
			return true, nil
		})
		require.NoError(t, err)
		assert.Equal(t, vmaLookupLegacy, backend)
	})

	t.Run("unknown JIT state retains legacy and explains the failure", func(t *testing.T) {
		backend, err := selectVMALookupBackend(true, func() (bool, error) {
			return vmaJITEnabled(false, func(string) ([]byte, error) {
				return nil, os.ErrPermission
			})
		}, func(bpf.BPFProgType, bpf.BPFFunc) (bool, error) {
			t.Fatal("helper checks must not run when JIT support is unknown")
			return true, nil
		})
		require.ErrorIs(t, err, os.ErrPermission)
		assert.Contains(t, err.Error(), "BPF JIT status")
		assert.Equal(t, vmaLookupLegacy, backend)
	})

	for _, unavailable := range requirements {
		t.Run("unavailable "+unavailable.program.String()+"/"+unavailable.helper.String(), func(t *testing.T) {
			backend, err := selectVMALookupBackend(true, func() (bool, error) {
				return true, nil
			}, func(program bpf.BPFProgType, helper bpf.BPFFunc) (bool, error) {
				return (helperRequirement{program, helper}) != unavailable, nil
			})
			require.NoError(t, err)
			assert.Equal(t, vmaLookupLegacy, backend)
		})
	}

	t.Run("kernel detection failure retains legacy", func(t *testing.T) {
		checkErr := errors.New("kernel release unavailable")
		backend, err := selectVMALookupBackend(true, func() (bool, error) {
			return false, checkErr
		}, nil)
		require.ErrorIs(t, err, checkErr)
		assert.Equal(t, vmaLookupLegacy, backend)
	})

	for _, failed := range requirements {
		t.Run("helper detection failure "+failed.program.String()+"/"+failed.helper.String(), func(t *testing.T) {
			checkErr := errors.New("helper probe failed")
			backend, err := selectVMALookupBackend(true, func() (bool, error) {
				return true, nil
			}, func(program bpf.BPFProgType, helper bpf.BPFFunc) (bool, error) {
				if (helperRequirement{program, helper}) == failed {
					return false, checkErr
				}
				return true, nil
			})
			require.ErrorIs(t, err, checkErr)
			assert.Equal(t, vmaLookupLegacy, backend)
		})
	}
}

type vmaTestOSInfo struct {
	release string
}

func (v vmaTestOSInfo) GetOSReleaseID() environment.OSReleaseID {
	return 0
}

func (v vmaTestOSInfo) CompareOSBaseKernelRelease(version string) (environment.KernelVersionComparison, error) {
	return environment.CompareKernelRelease(v.release, version)
}

func TestVMABackendKernelReleases(t *testing.T) {
	for _, tc := range []struct {
		release string
		backend vmaLookupBackend
	}{
		{"4.18.0-test.1.x86_64", vmaLookupLegacy},
		{"5.4.0", vmaLookupLegacy},
		{"5.10.0", vmaLookupLegacy},
		{"5.15.0", vmaLookupLegacy},
		{"6.0.19", vmaLookupLegacy},
		{"6.1.0", vmaLookupHelper},
		{"6.6.0-test.1.x86_64", vmaLookupHelper},
		{"6.12.0", vmaLookupHelper},
		{"7.0.0", vmaLookupHelper},
	} {
		t.Run(tc.release, func(t *testing.T) {
			backend, err := selectVMALookupBackend(true, func() (bool, error) {
				return vmaKernelVersionCompatible(vmaTestOSInfo{tc.release})
			}, func(program bpf.BPFProgType, helper bpf.BPFFunc) (bool, error) {
				return (program == bpf.BPFProgTypeRawTracepoint || program == bpf.BPFProgTypeKprobe) &&
					(helper == bpf.BPFFuncFindVma || helper == bpf.BPFFuncGetCurrentTaskBtf), nil
			})
			require.NoError(t, err)
			assert.Equal(t, tc.backend, backend)
		})
	}
}

func TestVMASyscallCheckerProbePlan(t *testing.T) {
	syscalls := []syscallInfo{
		{id: events.Read, name: "read"},
		{id: events.Write, name: "write"},
	}

	t.Run("modern events and selected syscalls share one raw tracepoint", func(t *testing.T) {
		plans := make(map[probes.Handle]syscallCheckerProbePlan)
		for range 2 { // Both events can request the same or different syscalls.
			for _, syscall := range syscalls {
				plan := planSyscallCheckerProbe(vmaLookupHelper, syscall)
				plans[plan.handle] = plan
				assert.Equal(t, probes.ProbeType(probes.RawTracepoint), plan.probeType)
				assert.Equal(t, "raw_syscalls:sys_enter", plan.eventName)
				assert.Equal(t, helperSyscallCheckerProgram, plan.programName)
				assert.Less(t, int32(plan.handle), int32(0), "shared handle must not collide with syscall IDs")
			}
		}
		assert.Len(t, plans, 1, "both events must produce the same shared hook plan")
	})

	t.Run("legacy keeps a kprobe for each selected syscall", func(t *testing.T) {
		plans := make(map[probes.Handle]syscallCheckerProbePlan)
		for _, syscall := range syscalls {
			plan := planSyscallCheckerProbe(vmaLookupLegacy, syscall)
			plans[plan.handle] = plan
			assert.Equal(t, probes.Handle(syscall.id), plan.handle)
			assert.Equal(t, probes.ProbeType(probes.SyscallEnter), plan.probeType)
			assert.Equal(t, syscall.name, plan.eventName)
			assert.Equal(t, legacySyscallCheckerProgram, plan.programName)
		}
		assert.Len(t, plans, len(syscalls))
	})
}

func TestVMAProgramAutoloadIsolation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend vmaLookupBackend
		enabled string
	}{
		{"legacy checker remains available for later policies", vmaLookupLegacy, legacySyscallCheckerProgram},
		{"helper lookup", vmaLookupHelper, helperSyscallCheckerProgram},
	} {
		t.Run(tc.name, func(t *testing.T) {
			states := map[string]bool{
				legacySyscallCheckerProgram: true,
				helperSyscallCheckerProgram: true,
				legacyForkProgram:           true,
				helperForkProgram:           true,
				helperStackRecoveryProgram:  true,
			}
			err := setVMAProgramsAutoload(tc.backend, func(name string, enabled bool) error {
				states[name] = enabled
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, tc.enabled == legacySyscallCheckerProgram, states[legacySyscallCheckerProgram])
			assert.Equal(t, tc.enabled == helperSyscallCheckerProgram, states[helperSyscallCheckerProgram])
			assert.Equal(t, tc.backend == vmaLookupHelper, states[helperStackRecoveryProgram])
			assert.False(t, states[legacyForkProgram], "fork autoload belongs to the event dependency manager")
			assert.False(t, states[helperForkProgram], "fork autoload belongs to the event dependency manager")
		})
	}
}

func TestVMALegacyDoesNotAttachStackRecovery(t *testing.T) {
	tracee := &Tracee{vmaLookupBackend: vmaLookupLegacy}
	require.NoError(t, tracee.attachVMAStackRecovery())
	assert.Empty(t, tracee.extraProbes)
}

type selfLoadedProbeFixture struct {
	program  string
	event    string
	typeID   probes.ProbeType
	attached bool
}

func (p selfLoadedProbeFixture) GetProgramName() string         { return p.program }
func (p selfLoadedProbeFixture) GetEventName() string           { return p.event }
func (p selfLoadedProbeFixture) GetProbeType() probes.ProbeType { return p.typeID }
func (p selfLoadedProbeFixture) IsAttached() bool               { return p.attached }

func TestVMASelfLoadedHookCounts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		kprobesOnly bool
		want        map[string]int
	}{
		{"ftrace excludes only attached kprobes", true, map[string]int{"schedule_tail": 2, "other_target": 1}},
		{"complete tracing inventory includes raw tracepoints", false, map[string]int{"schedule_tail": 2, "other_target": 1, "raw_syscalls:sys_enter": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counts := make(map[string]int)
			seen := make(map[selfLoadedProbeKey]struct{})
			for _, probe := range []selfLoadedProbeFixture{
				{helperStackRecoveryProgram, "schedule_tail", probes.KProbe, true},
				{helperStackRecoveryProgram, "schedule_tail", probes.KProbe, true}, // Shared dependency.
				{helperStackRecoveryProgram, "schedule_tail", probes.KretProbe, true},
				{helperStackRecoveryProgram, "other_target", probes.KProbe, true},
				{"failed_attach", "schedule_tail", probes.KProbe, false},
				{"failed_attach", "unattached_target", probes.KProbe, false},
				{helperSyscallCheckerProgram, "raw_syscalls:sys_enter", probes.RawTracepoint, true},
			} {
				recordSelfLoadedProbe(counts, seen, probe, tc.kprobesOnly)
			}
			assert.Equal(t, tc.want, counts)
		})
	}
}

// Only public metadata is used. Embedding the probe interface lets this value
// live in a real group without attaching a program or changing private fields.
type registeredSelfLoadedProbeFixture struct {
	probes.Probe
	selfLoadedProbeFixture
}

func TestVMARecoveryHookInSelfLoadedPrograms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		probe    probes.Probe
		addGroup bool
		want     map[string]int
	}{
		{
			name: "attached recovery is excluded from external hooks",
			probe: registeredSelfLoadedProbeFixture{selfLoadedProbeFixture: selfLoadedProbeFixture{
				program: helperStackRecoveryProgram, event: "schedule_tail", typeID: probes.KProbe, attached: true,
			}},
			addGroup: true,
			want:     map[string]int{"schedule_tail": 1},
		},
		{
			name: "failed recovery attachment does not hide external hooks",
			probe: registeredSelfLoadedProbeFixture{selfLoadedProbeFixture: selfLoadedProbeFixture{
				program: helperStackRecoveryProgram, event: "schedule_tail", typeID: probes.KProbe,
			}},
			addGroup: true,
			want:     map[string]int{},
		},
		{name: "absent recovery group", want: map[string]int{}},
		{name: "absent recovery probe", addGroup: true, want: map[string]int{}},
		{name: "typed nil recovery probe", probe: (*probes.TraceProbe)(nil), addGroup: true, want: map[string]int{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracee := &Tracee{
				eventsDependencies: dependencies.NewDependenciesManager(nil),
				extraProbes:        make(map[string]*probes.ProbeGroup),
			}
			if tc.addGroup {
				tracee.extraProbes[vmaStackRecoveryGroupName] = probes.NewProbeGroup(nil, map[probes.Handle]probes.Probe{
					vmaStackRecoveryProbeHandle: tc.probe,
				})
			}
			assert.Equal(t, tc.want, tracee.getSelfLoadedPrograms(true))
			assert.Equal(t, tc.want, tracee.getSelfLoadedPrograms(false))
		})
	}
}

func TestVMAProgramAutoloadFailure(t *testing.T) {
	t.Run("failure to exclude a variant is returned", func(t *testing.T) {
		loadErr := errors.New("autoload cannot be changed")
		err := setVMAProgramsAutoload(vmaLookupHelper, func(name string, enabled bool) error {
			if name == helperForkProgram && !enabled {
				return loadErr
			}
			return nil
		})
		require.ErrorIs(t, err, loadErr)
	})

	t.Run("failure to enable selected checker is returned", func(t *testing.T) {
		loadErr := errors.New("selected program unavailable")
		err := setVMAProgramsAutoload(vmaLookupHelper, func(_ string, enabled bool) error {
			if enabled {
				return loadErr
			}
			return nil
		})
		require.ErrorIs(t, err, loadErr)
	})

	t.Run("failure to enable stack recovery is returned", func(t *testing.T) {
		loadErr := errors.New("stack recovery program unavailable")
		err := setVMAProgramsAutoload(vmaLookupHelper, func(name string, enabled bool) error {
			if name == helperStackRecoveryProgram && enabled {
				return loadErr
			}
			return nil
		})
		require.ErrorIs(t, err, loadErr)
	})
}
