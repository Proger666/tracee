//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func vmaTestEvent(name, comm string, tid uint32, address uint64) *v1beta1.Event {
	event := &v1beta1.Event{
		Name: name,
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				HostPid: wrapperspb.UInt32(100),
				Thread:  &v1beta1.Thread{Name: comm, HostTid: wrapperspb.UInt32(tid)},
			},
		},
	}
	if name == "getpid" {
		return event
	}
	addressName, vmaType := "ip", "anonymous"
	if name == "stack_pivot" {
		addressName, vmaType = "sp", "heap"
	}
	event.Data = []*v1beta1.EventValue{
		v1beta1.NewStringValue("syscall", "getpid"),
		v1beta1.NewStringValue("vma_type", vmaType),
		v1beta1.NewStringValue(addressName, fmt.Sprintf("0x%x", address)),
		v1beta1.NewStringValue("vma_start", "0x10000"),
		v1beta1.NewUInt64Value("vma_size", uint64(os.Getpagesize())),
	}
	return event
}

func vmaTestPrerequisites() []*v1beta1.Event {
	return []*v1beta1.Event{
		vmaTestEvent("getpid", "vma_normal", 100, 0),
		vmaTestEvent("getpid", "vma_normal", 101, 0),
		vmaTestEvent("suspicious_syscall_source", "vma_start", 102, 0x10007),
		vmaTestEvent("suspicious_syscall_source", "vma_end", 103, 0x10000+uint64(os.Getpagesize())-1),
	}
}

func vmaTestCompleteEvents() []*v1beta1.Event {
	return append(vmaTestPrerequisites(),
		vmaTestEvent("suspicious_syscall_source", "vma_both", 104, 0x10007),
		vmaTestEvent("stack_pivot", "vma_both", 104, 0x10800))
}

func newVMATestDetector(t *testing.T) (*E2eVMALookup, *vmaRecordingLogger) {
	t.Helper()
	logger := &vmaRecordingLogger{}
	detector := &E2eVMALookup{}
	require.NoError(t, detector.Init(detection.DetectorParams{Logger: logger}))
	return detector, logger
}

func runVMATestEvents(t *testing.T, detector *E2eVMALookup, events ...*v1beta1.Event) int {
	t.Helper()
	count := 0
	for _, event := range events {
		outputs, err := detector.OnEvent(context.Background(), event)
		require.NoError(t, err)
		count += len(outputs)
	}
	return count
}

func TestVMALookupRequiresBothEventsFromOneThread(t *testing.T) {
	for _, pivotFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("pivot_first_%v", pivotFirst), func(t *testing.T) {
			detector := &E2eVMALookup{}
			require.NoError(t, detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))
			require.Zero(t, runVMATestEvents(t, detector, vmaTestPrerequisites()...))

			source := vmaTestEvent("suspicious_syscall_source", "vma_both", 104, 0x10007)
			pivot := vmaTestEvent("stack_pivot", "vma_both", 104, 0x10800)
			first, second := source, pivot
			if pivotFirst {
				first, second = second, first
			}
			// A single event cannot hide the helper refusing the other lookup.
			require.Zero(t, runVMATestEvents(t, detector, first))
			require.Equal(t, 1, runVMATestEvents(t, detector, second))
		})
	}

	t.Run("different_threads_do_not_satisfy_combined_case", func(t *testing.T) {
		detector := &E2eVMALookup{}
		require.NoError(t, detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))
		events := append(vmaTestPrerequisites(),
			vmaTestEvent("suspicious_syscall_source", "vma_both", 104, 0x10007),
			vmaTestEvent("stack_pivot", "vma_both", 105, 0x10800))
		require.Zero(t, runVMATestEvents(t, detector, events...))
	})
}

func TestVMALookupRequiresNormalMainAndThread(t *testing.T) {
	for _, missing := range []int{0, 1} {
		t.Run(fmt.Sprintf("missing_normal_case_%d", missing), func(t *testing.T) {
			detector := &E2eVMALookup{}
			require.NoError(t, detector.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))
			events := vmaTestPrerequisites()
			events = append(events[:missing], events[missing+1:]...)
			events = append(events,
				vmaTestEvent("suspicious_syscall_source", "vma_both", 104, 0x10007),
				vmaTestEvent("stack_pivot", "vma_both", 104, 0x10800))
			require.Zero(t, runVMATestEvents(t, detector, events...))
		})
	}
}

func TestVMALookupRejectsNormalThreadFalsePositive(t *testing.T) {
	for _, name := range []string{"suspicious_syscall_source", "stack_pivot"} {
		t.Run(name, func(t *testing.T) {
			detector, logger := newVMATestDetector(t)
			events := append(vmaTestPrerequisites(),
				vmaTestEvent(name, "vma_normal", 101, 0x10800),
				vmaTestEvent("suspicious_syscall_source", "vma_both", 104, 0x10007),
				vmaTestEvent("stack_pivot", "vma_both", 104, 0x10800))
			require.Zero(t, runVMATestEvents(t, detector, events...))
			require.Contains(t, logger.errors, "VMA_LOOKUP validation failed")
			require.Zero(t, runVMATestEvents(t, detector, vmaTestCompleteEvents()...))
		})
	}
}

type vmaRecordingLogger struct {
	testutil.MockLogger
	errors []string
}

func (l *vmaRecordingLogger) Errorw(message string, keysAndValues ...interface{}) {
	l.errors = append(l.errors, message)
}

func TestVMALookupRecordsLateFalsePositive(t *testing.T) {
	for _, name := range []string{"suspicious_syscall_source", "stack_pivot"} {
		t.Run(name, func(t *testing.T) {
			detector, logger := newVMATestDetector(t)
			require.Equal(t, 1, runVMATestEvents(t, detector, vmaTestCompleteEvents()...))
			require.Empty(t, logger.errors)

			// A success event cannot be retracted. Preserve this error for the
			// runner's post-stop check instead of ignoring events after success.
			late := vmaTestEvent(name, "vma_normal", 101, 0x10800)
			require.Zero(t, runVMATestEvents(t, detector, late))
			require.Contains(t, logger.errors, "VMA_LOOKUP validation failed")
			require.Zero(t, runVMATestEvents(t, detector, vmaTestCompleteEvents()...))
		})
	}
}

func replaceVMATestField(event *v1beta1.Event, replacement *v1beta1.EventValue) {
	for i, field := range event.Data {
		if field.GetName() == replacement.Name {
			event.Data[i] = replacement
			return
		}
	}
	event.Data = append(event.Data, replacement)
}

func requireVMATestRejection(t *testing.T, event *v1beta1.Event) {
	t.Helper()
	detector, logger := newVMATestDetector(t)
	require.Zero(t, runVMATestEvents(t, detector, event))
	require.Contains(t, logger.errors, "VMA_LOOKUP validation failed")
	// A later complete valid sequence must not erase the malformed result.
	require.Zero(t, runVMATestEvents(t, detector, vmaTestCompleteEvents()...))
}

func TestVMALookupRejectsMalformedMetadata(t *testing.T) {
	for _, name := range []string{"syscall", "vma_type", "ip", "vma_start", "vma_size"} {
		t.Run("missing_"+name, func(t *testing.T) {
			event := vmaTestEvent("suspicious_syscall_source", "vma_start", 102, 0x10007)
			for i, field := range event.Data {
				if field.Name == name {
					event.Data = append(event.Data[:i], event.Data[i+1:]...)
					break
				}
			}
			requireVMATestRejection(t, event)
		})
		t.Run("wrong_type_"+name, func(t *testing.T) {
			event := vmaTestEvent("suspicious_syscall_source", "vma_start", 102, 0x10007)
			replaceVMATestField(event, &v1beta1.EventValue{Name: name, Value: &v1beta1.EventValue_Bool{Bool: true}})
			requireVMATestRejection(t, event)
		})
	}

	for _, field := range []*v1beta1.EventValue{
		{Name: "syscall", Value: (*v1beta1.EventValue_Str)(nil)},
		{Name: "vma_type", Value: (*v1beta1.EventValue_Str)(nil)},
		{Name: "ip", Value: (*v1beta1.EventValue_Str)(nil)},
		{Name: "ip", Value: (*v1beta1.EventValue_Pointer)(nil)},
		{Name: "vma_start", Value: (*v1beta1.EventValue_Pointer)(nil)},
		{Name: "vma_size", Value: (*v1beta1.EventValue_UInt64)(nil)},
		{Name: "vma_size"},
	} {
		t.Run(fmt.Sprintf("nil_%s_%T", field.Name, field.Value), func(t *testing.T) {
			event := vmaTestEvent("suspicious_syscall_source", "vma_start", 102, 0x10007)
			replaceVMATestField(event, field)
			requireVMATestRejection(t, event)
		})
	}

	for _, tc := range []struct {
		name   string
		mutate func(*v1beta1.Event)
	}{
		{"nil_data", func(event *v1beta1.Event) { event.Data = nil }},
		{"nil_first_field", func(event *v1beta1.Event) { event.Data = append([]*v1beta1.EventValue{nil}, event.Data...) }},
		{"nil_last_field", func(event *v1beta1.Event) { event.Data = append(event.Data, nil) }},
		{"duplicate_address", func(event *v1beta1.Event) {
			event.Data = append(event.Data, v1beta1.NewStringValue("ip", "0x10007"))
		}},
		{"empty_syscall", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewStringValue("syscall", ""))
		}},
		{"malformed_address", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewStringValue("ip", "not-an-address"))
		}},
		{"negative_address", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewStringValue("ip", "-1"))
		}},
		{"unrepresentable_address", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewStringValue("ip", "0x10000000000000000"))
		}},
		{"zero_size", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewUInt64Value("vma_size", 0))
		}},
		{"address_below_start", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewStringValue("ip", "0xffff"))
		}},
		{"address_at_exclusive_end", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewStringValue("ip", fmt.Sprintf("0x%x", 0x10000+os.Getpagesize())))
		}},
		{"overflowing_end", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewStringValue("vma_start", "0xfffffffffffffff8"))
			replaceVMATestField(event, v1beta1.NewStringValue("ip", "0xfffffffffffffffe"))
		}},
		{"incorrect_mapping_type", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewStringValue("vma_type", "heap"))
		}},
		{"wrong_mapping_size", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewUInt64Value("vma_size", uint64(os.Getpagesize()*2)))
		}},
		{"start_not_near_boundary", func(event *v1beta1.Event) {
			replaceVMATestField(event, v1beta1.NewStringValue("ip", "0x10010"))
		}},
		{"end_not_near_boundary", func(event *v1beta1.Event) {
			event.Workload.Process.Thread.Name = "vma_end"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := vmaTestEvent("suspicious_syscall_source", "vma_start", 102, 0x10007)
			tc.mutate(event)
			requireVMATestRejection(t, event)
		})
	}
}

func TestVMALookupRejectsMalformedStackMetadata(t *testing.T) {
	for _, field := range []*v1beta1.EventValue{
		{Name: "sp"},
		{Name: "sp", Value: (*v1beta1.EventValue_Pointer)(nil)},
		{Name: "sp", Value: (*v1beta1.EventValue_Str)(nil)},
		v1beta1.NewStringValue("sp", "0xffff"),
		v1beta1.NewStringValue("sp", fmt.Sprintf("0x%x", 0x10000+os.Getpagesize())),
		v1beta1.NewStringValue("sp", "invalid"),
		v1beta1.NewUInt64Value("sp", 0x10800),
		v1beta1.NewStringValue("vma_type", "anonymous"),
		v1beta1.NewUInt64Value("vma_size", 0),
	} {
		t.Run(fmt.Sprintf("%s_%v", field.Name, field.Value), func(t *testing.T) {
			event := vmaTestEvent("stack_pivot", "vma_both", 104, 0x10800)
			replaceVMATestField(event, field)
			requireVMATestRejection(t, event)
		})
	}
}

func TestVMALookupRequiresProcessAndThreadIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		comm string
	}{
		{"getpid", "vma_normal"},
		{"suspicious_syscall_source", "vma_both"},
		{"stack_pivot", "vma_both"},
	} {
		for _, missing := range []string{"pid", "tid"} {
			t.Run(tc.name+"_"+missing, func(t *testing.T) {
				event := vmaTestEvent(tc.name, tc.comm, 104, 0x10007)
				if missing == "pid" {
					event.Workload.Process.HostPid = nil
				} else {
					event.Workload.Process.Thread.HostTid = wrapperspb.UInt32(0)
				}
				requireVMATestRejection(t, event)
			})
		}
	}
}

func TestVMALookupAcceptsAddressRepresentations(t *testing.T) {
	for _, numeric := range []bool{false, true} {
		t.Run(fmt.Sprintf("numeric_%v", numeric), func(t *testing.T) {
			detector, logger := newVMATestDetector(t)
			events := vmaTestCompleteEvents()
			// The start address is included; the final byte is covered by vma_end.
			replaceVMATestField(events[2], v1beta1.NewStringValue("ip", "0x10000"))
			if numeric {
				for _, event := range events {
					if event.Name == "getpid" {
						continue
					}
					addressName, address := "ip", uint64(0x10007)
					switch event.Workload.Process.Thread.Name {
					case "vma_start":
						address = 0x10000
					case "vma_end":
						address = 0x10000 + uint64(os.Getpagesize()) - 1
					}
					if event.Name == "stack_pivot" {
						addressName, address = "sp", 0x10800
					}
					replaceVMATestField(event, &v1beta1.EventValue{Name: addressName, Value: &v1beta1.EventValue_Pointer{Pointer: address}})
					replaceVMATestField(event, &v1beta1.EventValue{Name: "vma_start", Value: &v1beta1.EventValue_Pointer{Pointer: 0x10000}})
				}
			}
			require.Equal(t, 1, runVMATestEvents(t, detector, events...))
			require.Empty(t, logger.errors)
		})
	}
}

func TestVMALookupAcceptsNonOverflowingHighInterval(t *testing.T) {
	detector, logger := newVMATestDetector(t)
	events := vmaTestCompleteEvents()
	start := uint64(math.MaxUint64) - uint64(os.Getpagesize())
	replaceVMATestField(events[2], v1beta1.NewStringValue("vma_start", fmt.Sprintf("0x%x", start)))
	replaceVMATestField(events[2], v1beta1.NewStringValue("ip", fmt.Sprintf("0x%x", start)))
	require.Equal(t, 1, runVMATestEvents(t, detector, events...))
	require.Empty(t, logger.errors)
}

func TestVMALookupEmitsSuccessOnlyOnce(t *testing.T) {
	detector, logger := newVMATestDetector(t)
	require.Equal(t, 1, runVMATestEvents(t, detector, vmaTestCompleteEvents()...))
	require.Zero(t, runVMATestEvents(t, detector, vmaTestCompleteEvents()...))
	require.Empty(t, logger.errors)
}

func TestVMALookupIgnoresUnrelatedEvents(t *testing.T) {
	detector, logger := newVMATestDetector(t)
	unrelated := vmaTestEvent("suspicious_syscall_source", "another_process", 105, 0)
	unrelated.Data = []*v1beta1.EventValue{nil}
	require.Zero(t, runVMATestEvents(t, detector, nil, &v1beta1.Event{}, unrelated))
	require.Equal(t, 1, runVMATestEvents(t, detector, vmaTestCompleteEvents()...))
	require.Empty(t, logger.errors)
}
