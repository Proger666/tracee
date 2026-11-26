package probes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeGroupSelectProgram(t *testing.T) {
	t.Run("select variant without replacing the probe handle or hook", func(t *testing.T) {
		probe := NewTraceProbe(RawTracepoint, "sched:sched_process_fork", "legacy_fork")
		group := NewProbeGroup(nil, map[Handle]Probe{SchedProcessFork: probe})

		require.NoError(t, group.SelectProgram(SchedProcessFork, "helper_fork"))
		registered, ok := group.GetProbeByHandle(SchedProcessFork).(interface {
			GetProgramName() string
			GetEventName() string
		})
		require.True(t, ok, "registered probe must expose its program and hook")
		assert.Equal(t, "helper_fork", registered.GetProgramName())
		assert.Equal(t, "sched:sched_process_fork", registered.GetEventName())
		assert.Equal(t, ProbeType(RawTracepoint), group.GetProbeType(SchedProcessFork))
	})

	t.Run("attached probe cannot be redirected", func(t *testing.T) {
		probe := NewTraceProbe(RawTracepoint, "sched:sched_process_fork", "legacy_fork")
		probe.attached = true
		group := NewProbeGroup(nil, map[Handle]Probe{SchedProcessFork: probe})

		require.Error(t, group.SelectProgram(SchedProcessFork, "helper_fork"))
		registered, ok := group.GetProbeByHandle(SchedProcessFork).(interface{ GetProgramName() string })
		require.True(t, ok, "registered probe must expose its program")
		assert.Equal(t, "legacy_fork", registered.GetProgramName())
	})

	t.Run("typed nil probe is rejected without changing the registration", func(t *testing.T) {
		var probe *TraceProbe
		group := NewProbeGroup(nil, map[Handle]Probe{SchedProcessFork: probe})

		require.Error(t, group.SelectProgram(SchedProcessFork, "helper_fork"))
		assert.True(t, group.HandleExists(SchedProcessFork))
		assert.Nil(t, group.GetProbeByHandle(SchedProcessFork))
	})

	t.Run("invalid selection leaves the registered probe intact", func(t *testing.T) {
		probe := NewTraceProbe(RawTracepoint, "sched:sched_process_fork", "legacy_fork")
		group := NewProbeGroup(nil, map[Handle]Probe{SchedProcessFork: probe})

		require.Error(t, group.SelectProgram(SchedProcessFork, ""))
		require.Error(t, group.SelectProgram(SchedProcessExec, "helper_fork"))
		registered, ok := group.GetProbeByHandle(SchedProcessFork).(interface{ GetProgramName() string })
		require.True(t, ok, "registered probe must expose its program")
		assert.Equal(t, "legacy_fork", registered.GetProgramName())
	})
}
