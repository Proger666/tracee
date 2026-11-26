package ebpf

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
)

// This fake implements the userspace map API. It does not create or load a BPF
// map, and it copies pointer arguments before returning, as libbpfgo does.
type vmaSelectionTestMap struct {
	values    map[uint32][]byte
	lookupErr error
	updateErr error
}

func (m *vmaSelectionTestMap) GetValue(key unsafe.Pointer) ([]byte, error) {
	if m.lookupErr != nil {
		return nil, m.lookupErr
	}
	value, ok := m.values[*(*uint32)(key)]
	if !ok {
		return nil, fmt.Errorf("lookup selection: %w", syscall.ENOENT)
	}
	return append([]byte(nil), value...), nil
}

func (m *vmaSelectionTestMap) Update(key, value unsafe.Pointer) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.values[*(*uint32)(key)] = vmaSelectionBytes(*(*uint32)(value))
	return nil
}

func vmaSelectionBytes(value uint32) []byte {
	encoded := make([]byte, 4)
	binary.NativeEndian.PutUint32(encoded, value)
	return encoded
}

type vmaSelectionTestProbeGroup struct {
	registered map[probes.Handle]probes.Probe
	attached   map[probes.Handle]bool
	attachErr  error
}

func newVMASelectionTestProbeGroup() *vmaSelectionTestProbeGroup {
	return &vmaSelectionTestProbeGroup{
		registered: make(map[probes.Handle]probes.Probe),
		attached:   make(map[probes.Handle]bool),
	}
}

func (g *vmaSelectionTestProbeGroup) HandleExists(handle probes.Handle) bool {
	_, ok := g.registered[handle]
	return ok
}

func (g *vmaSelectionTestProbeGroup) AddProbe(handle probes.Handle, probe probes.Probe) error {
	if g.HandleExists(handle) {
		return fmt.Errorf("probe %d is already registered", handle)
	}
	g.registered[handle] = probe
	return nil
}

func (g *vmaSelectionTestProbeGroup) Attach(handle probes.Handle, _ ...interface{}) error {
	if !g.HandleExists(handle) {
		return fmt.Errorf("probe %d is not registered", handle)
	}
	if g.attached[handle] {
		return nil
	}
	if g.attachErr != nil {
		return g.attachErr
	}
	g.attached[handle] = true
	return nil
}

func TestVMASyscallCheckSelection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing []byte
		check    uint32
		want     uint32
	}{
		{name: "new source selection", check: vmaCheckSource, want: 1},
		{name: "new stack selection", check: vmaCheckStack, want: 2},
		{name: "empty selection", existing: vmaSelectionBytes(0), check: vmaCheckSource, want: 1},
		{name: "source after stack", existing: vmaSelectionBytes(2), check: vmaCheckSource, want: 3},
		{name: "stack after source", existing: vmaSelectionBytes(1), check: vmaCheckStack, want: 3},
		{name: "repeated source", existing: vmaSelectionBytes(1), check: vmaCheckSource, want: 1},
		{name: "repeated stack", existing: vmaSelectionBytes(2), check: vmaCheckStack, want: 2},
		{name: "repeated combined selection", existing: vmaSelectionBytes(3), check: vmaCheckSource, want: 3},
		{name: "preserves other bits", existing: vmaSelectionBytes(0x80), check: vmaCheckSource, want: 0x81},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &vmaSelectionTestMap{values: map[uint32][]byte{
				7: vmaSelectionBytes(2),
			}}
			if tc.existing != nil {
				m.values[0] = tc.existing
			}

			require.NoError(t, enableVMASyscallCheck(m, 0, tc.check))
			assert.Equal(t, map[uint32][]byte{
				0: vmaSelectionBytes(tc.want),
				7: vmaSelectionBytes(2),
			}, m.values)
		})
	}
}

func TestVMASyscallCheckPolicyUnion(t *testing.T) {
	type registration struct {
		check    uint32
		policies [][]events.ID
	}
	source := registration{
		check: vmaCheckSource,
		policies: [][]events.ID{
			{events.Read, events.Write},
			{events.Read, events.Read, events.Getpid},
		},
	}
	stack := registration{
		check: vmaCheckStack,
		policies: [][]events.ID{
			{events.Write, events.Getpid},
			{events.Write, events.Close},
		},
	}
	for _, tc := range []struct {
		name          string
		registrations []registration
	}{
		{name: "source first", registrations: []registration{source, stack}},
		{name: "stack first", registrations: []registration{stack, source}},
		{name: "repeated registration", registrations: []registration{source, stack, source, stack}},
	} {
		for _, backend := range []vmaLookupBackend{vmaLookupLegacy, vmaLookupHelper} {
			t.Run(tc.name+"/"+backend.String(), func(t *testing.T) {
				m := &vmaSelectionTestMap{values: make(map[uint32][]byte)}
				group := newVMASelectionTestProbeGroup()
				for _, registration := range tc.registrations {
					params := make([]map[string]filters.Filter[*filters.StringFilter], 0, len(registration.policies))
					for _, syscalls := range registration.policies {
						values := make([]string, 0, len(syscalls))
						for _, id := range syscalls {
							values = append(values, strconv.Itoa(int(id)))
						}
						filter := filters.NewStringFilter(nil)
						require.NoError(t, filter.Parse("="+strings.Join(values, ",")))
						params = append(params, map[string]filters.Filter[*filters.StringFilter]{"syscall": filter})
					}
					syscalls, err := getSyscallsFromParams(params, "syscall")
					require.NoError(t, err)
					require.NoError(t, registerVMASyscallCheckers(group, m, backend, syscalls, registration.check, nil))
				}

				assert.Equal(t, map[uint32][]byte{
					uint32(events.Read):   vmaSelectionBytes(1),
					uint32(events.Write):  vmaSelectionBytes(3),
					uint32(events.Getpid): vmaSelectionBytes(3),
					uint32(events.Close):  vmaSelectionBytes(2),
				}, m.values)
				if backend == vmaLookupHelper {
					assert.Len(t, group.attached, 1)
				} else {
					assert.Len(t, group.attached, 4)
				}
			})
		}
	}
}

func TestVMASyscallCheckAttachFailure(t *testing.T) {
	for _, backend := range []vmaLookupBackend{vmaLookupLegacy, vmaLookupHelper} {
		t.Run(backend.String(), func(t *testing.T) {
			m := &vmaSelectionTestMap{values: make(map[uint32][]byte)}
			group := newVMASelectionTestProbeGroup()
			group.attachErr = fmt.Errorf("attach: %w", syscall.ENOENT)
			syscalls := []syscallInfo{{id: events.Read, name: "read"}}

			for _, check := range []uint32{vmaCheckSource, vmaCheckSource, vmaCheckStack} {
				err := registerVMASyscallCheckers(group, m, backend, syscalls, check, nil)
				if backend == vmaLookupHelper {
					require.ErrorIs(t, err, syscall.ENOENT)
				} else {
					require.NoError(t, err)
				}
				assert.Empty(t, m.values, "an unattached probe must not enable a check")
				assert.Empty(t, group.attached)
			}

			group.attachErr = nil
			require.NoError(t, registerVMASyscallCheckers(group, m, backend, syscalls, vmaCheckSource, nil))
			require.NoError(t, registerVMASyscallCheckers(group, m, backend, syscalls, vmaCheckStack, nil))
			assert.Equal(t, map[uint32][]byte{uint32(events.Read): vmaSelectionBytes(3)}, m.values)
			assert.Len(t, group.attached, 1)
		})
	}
}

func TestVMASyscallCheckUnloadedProbe(t *testing.T) {
	for _, backend := range []vmaLookupBackend{vmaLookupLegacy, vmaLookupHelper} {
		t.Run(backend.String(), func(t *testing.T) {
			// A nil module makes the real probe group reject attachment without
			// entering libbpf or invoking a kernel operation.
			group := probes.NewProbeGroup(nil, map[probes.Handle]probes.Probe{})
			m := &vmaSelectionTestMap{values: make(map[uint32][]byte)}
			syscalls := []syscallInfo{{id: events.Read, name: "read"}}
			for _, check := range []uint32{vmaCheckSource, vmaCheckStack} {
				err := registerVMASyscallCheckers(group, m, backend, syscalls, check, nil)
				if backend == vmaLookupHelper {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				assert.Empty(t, m.values)
			}
		})
	}
}

func TestVMASyscallCheckMapErrors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lookupErr error
		updateErr error
		wantErr   error
	}{
		{name: "lookup failure", lookupErr: fmt.Errorf("lookup: %w", syscall.EIO), wantErr: syscall.EIO},
		{name: "lookup denied", lookupErr: fmt.Errorf("lookup: %w", syscall.EPERM), wantErr: syscall.EPERM},
		{name: "update failure", updateErr: fmt.Errorf("update: %w", syscall.ENOSPC), wantErr: syscall.ENOSPC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &vmaSelectionTestMap{
				values:    map[uint32][]byte{5: vmaSelectionBytes(2)},
				lookupErr: tc.lookupErr,
				updateErr: tc.updateErr,
			}
			err := enableVMASyscallCheck(m, 5, vmaCheckSource)
			require.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, map[uint32][]byte{5: vmaSelectionBytes(2)}, m.values)

			m.lookupErr = nil
			m.updateErr = nil
			require.NoError(t, enableVMASyscallCheck(m, 5, vmaCheckSource))
			assert.Equal(t, map[uint32][]byte{5: vmaSelectionBytes(3)}, m.values)
		})
	}
}

func TestVMASyscallCheckMalformedValue(t *testing.T) {
	for _, size := range []int{0, 1, 3, 5, 8} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			value := make([]byte, size)
			m := &vmaSelectionTestMap{values: map[uint32][]byte{5: value}}
			require.Error(t, enableVMASyscallCheck(m, 5, vmaCheckSource))
			assert.Equal(t, map[uint32][]byte{5: value}, m.values)
		})
	}
}
