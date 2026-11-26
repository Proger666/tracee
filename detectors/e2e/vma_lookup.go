//go:build e2e

package e2e

import (
	"context"
	"math"
	"os"
	"strconv"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eVMALookup{}) }

// E2eVMALookup checks actual VMA event behavior, including two lookups from one
// syscall. The fixture executes exactly one getpid with both an anonymous IP
// and a heap SP, so matching thread IDs must describe that same invocation.
type E2eVMALookup struct {
	logger       detection.Logger
	failed       bool
	emitted      bool
	normalMain   bool
	normalThread bool
	foundStart   bool
	foundEnd     bool
	sourceThread uint32
	pivotThread  uint32
}

func (d *E2eVMALookup) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "VMA_LOOKUP",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "getpid", Dependency: detection.DependencyRequired},
				{Name: "suspicious_syscall_source", Dependency: detection.DependencyRequired},
				{Name: "stack_pivot", Dependency: detection.DependencyRequired},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "VMA_LOOKUP",
			Description: "Instrumentation events E2E Tests: VMA lookup regression",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *E2eVMALookup) Init(params detection.DetectorParams) error {
	*d = E2eVMALookup{logger: params.Logger}
	return nil
}

func (d *E2eVMALookup) reject(event *v1beta1.Event, reason string) {
	d.failed = true
	// The shell checker also checks this message after Tracee stops, so a false
	// positive received after a success event cannot accidentally pass the test.
	d.logger.Errorw("VMA_LOOKUP validation failed", "event", event.Name, "reason", reason)
}

func (d *E2eVMALookup) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	process := event.GetWorkload().GetProcess()
	thread := process.GetThread()
	name := thread.GetName()
	if name != "vma_normal" && name != "vma_start" && name != "vma_end" && name != "vma_both" {
		return nil, nil
	}
	tid := thread.GetHostTid().GetValue()
	pid := process.GetHostPid().GetValue()
	if tid == 0 || pid == 0 {
		d.reject(event, "fixture event has no process/thread identity")
		return nil, nil
	}

	if name == "vma_normal" {
		if event.Name != "getpid" {
			d.reject(event, "ordinary main or pthread stack produced a VMA alert")
			return nil, nil
		}
		if tid == pid {
			d.normalMain = true
		} else {
			d.normalThread = true
		}
	} else if event.Name != "getpid" {
		syscall, ok := vmaEventString(event, "syscall")
		if !ok || syscall == "" {
			d.reject(event, "missing or invalid syscall")
			return nil, nil
		}
		if syscall != "getpid" {
			return nil, nil
		}
		vmaType, ok := vmaEventString(event, "vma_type")
		if !ok {
			d.reject(event, "missing or invalid VMA type")
			return nil, nil
		}

		addressName := "ip"
		if event.Name == "stack_pivot" {
			addressName = "sp"
		}
		address, okAddress := vmaEventAddress(event, addressName)
		start, okStart := vmaEventAddress(event, "vma_start")
		size, okSize := vmaEventUint64(event, "vma_size")
		if !okAddress || !okStart || !okSize || size == 0 || size > math.MaxUint64-start ||
			address < start || address-start >= size {
			d.reject(event, "reported address is outside the half-open VMA interval")
			return nil, nil
		}

		switch event.Name {
		case "suspicious_syscall_source":
			if vmaType != "anonymous" || size != uint64(os.Getpagesize()) {
				d.reject(event, "guarded code mapping must be one anonymous page")
				return nil, nil
			}
			switch name {
			case "vma_start":
				if address-start >= 16 {
					d.reject(event, "syscall near mapping start has incorrect metadata")
					return nil, nil
				}
				d.foundStart = true
			case "vma_end":
				// Only the return instruction remains: 1 byte on x86, 4 on ARM.
				if size-(address-start) > 4 {
					d.reject(event, "syscall near mapping end has incorrect metadata")
					return nil, nil
				}
				d.foundEnd = true
			case "vma_both":
				d.sourceThread = tid
			}
		case "stack_pivot":
			if name != "vma_both" || vmaType != "heap" {
				d.reject(event, "unexpected stack pivot outside the combined scenario")
				return nil, nil
			}
			d.pivotThread = tid
		}
	}

	if d.failed || d.emitted || !d.normalMain || !d.normalThread || !d.foundStart || !d.foundEnd ||
		d.sourceThread == 0 || d.sourceThread != d.pivotThread {
		return nil, nil
	}
	d.emitted = true
	return detection.Detected(), nil
}

// Pointers are numeric before decoded-data enrichment and hexadecimal strings
// afterwards. Accept both representations, while rejecting missing metadata.
func vmaEventAddress(event *v1beta1.Event, name string) (uint64, bool) {
	switch value := vmaEventField(event, name).GetValue().(type) {
	case *v1beta1.EventValue_Pointer:
		if value != nil {
			return value.Pointer, true
		}
	case *v1beta1.EventValue_Str:
		if value != nil {
			address, err := strconv.ParseUint(value.Str, 0, 64)
			return address, err == nil
		}
	}
	return 0, false
}

func vmaEventString(event *v1beta1.Event, name string) (string, bool) {
	value, ok := vmaEventField(event, name).GetValue().(*v1beta1.EventValue_Str)
	if !ok || value == nil {
		return "", false
	}
	return value.Str, true
}

func vmaEventUint64(event *v1beta1.Event, name string) (uint64, bool) {
	value, ok := vmaEventField(event, name).GetValue().(*v1beta1.EventValue_UInt64)
	if !ok || value == nil {
		return 0, false
	}
	return value.UInt64, true
}

// Validation must reject malformed input rather than panic or accept ambiguous
// metadata. Keep this local to the E2E detector's stricter result contract.
func vmaEventField(event *v1beta1.Event, name string) *v1beta1.EventValue {
	var found *v1beta1.EventValue
	for _, field := range event.GetData() {
		if field == nil {
			return nil
		}
		if field.Name == name {
			if found != nil {
				return nil
			}
			found = field
		}
	}
	return found
}

func (d *E2eVMALookup) Close() error { return nil }
