package ebpf

import (
	"fmt"
	"math"
	"strconv"
	"unsafe"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
)

type eventParameterHandler func(t *Tracee, eventParams []map[string]filters.Filter[*filters.StringFilter]) error

var eventParameterHandlers = map[events.ID]eventParameterHandler{
	events.SuspiciousSyscallSource: prepareSuspiciousSyscallSource,
	events.StackPivot:              prepareStackPivot,
}

// handleEventParameters performs initialization actions according to event parameters,
// specified using policies or the command line as event arguments.
// For example, an event can use one of its parameters to populate eBPF maps,
// or perhaps attach eBPF programs according to the parameters.
func (t *Tracee) handleEventParameters() error {
	// Iterate through registerd event parameter handlers
	for eventID, handler := range eventParameterHandlers {
		// Make sure this event is selected
		if _, err := t.eventsDependencies.GetEvent(eventID); err != nil {
			continue
		}
		// Get the event parameters for all policies.
		// Event parameters are simply event data filters, interpreted according to the
		// specific event and filter in question.
		// While this method of specifying event parameters is convenient, it may cause
		// confusion as it abuses the filter system.
		// TODO: in the future, a dedicated event parameter system should be added.
		eventParams := make([]map[string]filters.Filter[*filters.StringFilter], 0)
		for iterator := t.policyManager.CreateAllIterator(); iterator.HasNext(); {
			policy := iterator.Next()
			if rule, ok := policy.Rules[eventID]; ok {
				policyParams := rule.DataFilter.GetFieldFilters()
				if len(policyParams) == 0 {
					continue
				}
				eventParams = append(eventParams, policyParams)
			}
		}
		if len(eventParams) == 0 {
			// No parameters for this event
			continue
		}
		// Call handler
		if err := handler(t, eventParams); err != nil {
			if err := t.eventsDependencies.RemoveEvent(eventID); err != nil {
				logger.Warnw("Failed to remove event from dependencies manager", "remove reason", "failed handling event parameters", "error", err)
			}
			return fmt.Errorf("failed to handle parameters for event %s: %v", events.Core.GetDefinitionByID(eventID).GetName(), err)
		}
	}
	return nil
}

type syscallInfo struct {
	id   events.ID
	name string
}

// This handle is local to the syscall_checkers group. Legacy syscall handles
// are nonnegative; the modern backend attaches one raw tracepoint for all
// selected syscalls and both checker events.
const syscallCheckerRawTracepointHandle probes.Handle = -1

type syscallCheckerProbePlan struct {
	handle      probes.Handle
	probeType   probes.ProbeType
	eventName   string
	programName string
}

func planSyscallCheckerProbe(backend vmaLookupBackend, syscall syscallInfo) syscallCheckerProbePlan {
	if backend == vmaLookupHelper {
		return syscallCheckerProbePlan{
			handle:      syscallCheckerRawTracepointHandle,
			probeType:   probes.RawTracepoint,
			eventName:   "raw_syscalls:sys_enter",
			programName: backend.syscallCheckerProgram(),
		}
	}
	return syscallCheckerProbePlan{
		handle:      probes.Handle(syscall.id),
		probeType:   probes.SyscallEnter,
		eventName:   syscall.name,
		programName: backend.syscallCheckerProgram(),
	}
}

func getSyscallsFromParams(eventParams []map[string]filters.Filter[*filters.StringFilter], syscallArgName string) ([]syscallInfo, error) {
	syscalls := []syscallInfo{}

	for _, policyParams := range eventParams {
		syscallsParam, ok := policyParams[syscallArgName].(*filters.StringFilter)
		if !ok {
			return syscalls, errfmt.Errorf("invalid argument name '%s'", syscallArgName)
		}

		for _, entry := range syscallsParam.Equal() {
			syscallIDInt, err := strconv.Atoi(entry)
			if err != nil {
				return syscalls, errfmt.WrapError(err)
			}
			if syscallIDInt > math.MaxInt32 {
				return syscalls, errfmt.Errorf("invalid syscall ID %d", syscallIDInt)
			}
			syscallID := events.ID(syscallIDInt)

			syscallDef := events.Core.GetDefinitionByID(events.ID(syscallID))
			if syscallDef.NotValid() {
				return syscalls, errfmt.Errorf("syscall id %d is not valid", syscallID)
			}

			syscalls = append(syscalls, syscallInfo{
				id:   syscallID,
				name: syscallDef.GetName(),
			})
		}
	}

	return syscalls, nil
}

func registerSyscallChecker(t *Tracee, eventParams []map[string]filters.Filter[*filters.StringFilter],
	syscallArgName string, selectedSyscallsMapName string) error {
	// Create probe group if needed
	probeGroupName := "syscall_checkers"
	probeGroup, ok := t.extraProbes[probeGroupName]
	if !ok {
		probeGroup = probes.NewProbeGroup(t.bpfModule, map[probes.Handle]probes.Probe{})
		t.extraProbes[probeGroupName] = probeGroup
	}

	// Get list of syscalls to be checked
	syscalls, err := getSyscallsFromParams(eventParams, syscallArgName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Get map of syscalls to be checked
	syscallsMap, err := t.bpfModule.GetMap(selectedSyscallsMapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	for _, syscall := range syscalls {
		// Modern checks share one raw syscall entry tracepoint. Legacy checks
		// retain individual syscall kprobes.
		plan := planSyscallCheckerProbe(t.vmaLookupBackend, syscall)
		if !probeGroup.HandleExists(plan.handle) {
			probe := probes.NewTraceProbe(plan.probeType, plan.eventName, plan.programName)
			if err := probeGroup.AddProbe(plan.handle, probe); err != nil {
				return errfmt.WrapError(err)
			}
			if err := probeGroup.Attach(plan.handle, t.getKernelSymbols()); err != nil {
				if t.vmaLookupBackend == vmaLookupHelper {
					return fmt.Errorf("attach VMA syscall entry tracepoint: %w", err)
				}
				// Report attachment errors but don't fail, because it may be a syscall that doesn't exist on this system
				logger.Warnw("Failed to attach syscall checker kprobe", "syscall", syscall.name, "error", err)
				continue
			}
		}

		// Update syscalls to check map with this syscall
		id := uint32(syscall.id)
		val := uint32(1)
		if err := syscallsMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&val)); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

func prepareSuspiciousSyscallSource(t *Tracee, eventParams []map[string]filters.Filter[*filters.StringFilter]) error {
	return registerSyscallChecker(t, eventParams, "syscall", "suspicious_syscall_source_syscalls")
}

func prepareStackPivot(t *Tracee, eventParams []map[string]filters.Filter[*filters.StringFilter]) error {
	return registerSyscallChecker(t, eventParams, "syscall", "stack_pivot_syscalls")
}
