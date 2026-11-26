package ebpf

import (
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/events"
)

// These benchmarks exercise startup decisions with fake capabilities and
// sysctl contents. They never probe or load a BPF program.
var (
	vmaBenchBackend vmaLookupBackend
	vmaBenchPlan    syscallCheckerProbePlan
	vmaBenchEnabled bool
	vmaBenchError   error
)

func BenchmarkVMABackendSelection(b *testing.B) {
	for _, tc := range []struct {
		name                        string
		needed, compatible, helpers bool
		want                        vmaLookupBackend
	}{
		{"unused", false, true, true, vmaLookupLegacy},
		{"legacy", true, false, true, vmaLookupLegacy},
		{"helper", true, true, true, vmaLookupHelper},
		{"missing_helper", true, true, false, vmaLookupLegacy},
	} {
		b.Run(tc.name, func(b *testing.B) {
			compatible := func() (bool, error) { return tc.compatible, nil }
			helper := func(bpf.BPFProgType, bpf.BPFFunc) (bool, error) { return tc.helpers, nil }
			if got, err := selectVMALookupBackend(tc.needed, compatible, helper); err != nil || got != tc.want {
				b.Fatalf("unexpected backend: got %v, error %v, want %v", got, err, tc.want)
			}
			b.ReportAllocs()
			for b.Loop() {
				vmaBenchBackend, vmaBenchError = selectVMALookupBackend(tc.needed, compatible, helper)
			}
		})
	}
}

func BenchmarkVMAProbePlan(b *testing.B) {
	for _, backend := range []vmaLookupBackend{vmaLookupLegacy, vmaLookupHelper} {
		b.Run(backend.String(), func(b *testing.B) {
			syscall := syscallInfo{id: events.Getpid, name: "getpid"}
			plan := planSyscallCheckerProbe(backend, syscall)
			if plan.eventName == "" || plan.programName == "" {
				b.Fatal("probe plan does not identify an event and program")
			}
			b.ReportAllocs()
			for b.Loop() {
				vmaBenchPlan = planSyscallCheckerProbe(backend, syscall)
			}
		})
	}
}

func BenchmarkVMAJITSelection(b *testing.B) {
	value := []byte("1\n")
	read := func(string) ([]byte, error) { return value, nil }
	if enabled, err := vmaJITEnabled(false, read); err != nil || !enabled {
		b.Fatalf("enabled JIT fixture: enabled %v, error %v", enabled, err)
	}
	b.ReportAllocs()
	for b.Loop() {
		vmaBenchEnabled, vmaBenchError = vmaJITEnabled(false, read)
	}
}

// This measures startup mask merging with a userspace map fake, including the
// fixture reset and its byte-buffer copies. It does not measure BPF map syscalls
// or syscall-event runtime overhead.
func BenchmarkVMASyscallMaskMerge(b *testing.B) {
	for _, tc := range []struct {
		name     string
		existing []byte
	}{
		{name: "new_selection"},
		{name: "add_second_check", existing: vmaSelectionBytes(vmaCheckStack)},
		{name: "already_selected", existing: vmaSelectionBytes(vmaCheckSource | vmaCheckStack)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			m := &vmaSelectionTestMap{values: make(map[uint32][]byte)}
			b.ReportAllocs()
			for b.Loop() {
				if tc.existing == nil {
					delete(m.values, 0)
				} else {
					m.values[0] = tc.existing
				}
				vmaBenchError = enableVMASyscallCheck(m, 0, vmaCheckSource)
			}
			if vmaBenchError != nil {
				b.Fatal(vmaBenchError)
			}
		})
	}
}
