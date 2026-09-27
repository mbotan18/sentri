package monitor

// Pure-logic tests for the detector: feed a baseline + synthetic live events and
// assert on which are flagged. No ptrace/container/root involved.

import (
	"bytes"
	"strings"
	"testing"
)

func baselineWith(names ...string) *Baseline {
	b := NewBaseline("test")
	counts := map[string]int64{}
	for _, n := range names {
		counts[n] = 1
	}
	b.AddRun(counts)
	return b
}

func TestDetectorFlagsUnknownSyscalls(t *testing.T) {
	b := baselineWith("openat", "read", "close", "write")
	var out bytes.Buffer
	d := NewDetector(b, "abc123", &out)

	// A matching workload: every syscall is in the baseline -> no alerts.
	for _, s := range []string{"openat", "read", "read", "write", "close"} {
		d.Inspect(SyscallEvent{Syscall: s, PID: 1})
	}
	if d.AnomalyCount() != 0 {
		t.Fatalf("expected 0 anomalies on matching workload, got %d", d.AnomalyCount())
	}

	// Now a "compromise": syscalls the benign profile never held.
	d.Inspect(SyscallEvent{Syscall: "socket", PID: 2})
	d.Inspect(SyscallEvent{Syscall: "connect", PID: 2, Path: ""})
	d.Inspect(SyscallEvent{Syscall: "connect", PID: 2}) // repeat: counted, not re-alerted
	d.Inspect(SyscallEvent{Syscall: "ptrace", PID: 2})

	if d.AnomalyCount() != 4 { // socket + connect + connect + ptrace
		t.Errorf("AnomalyCount = %d, want 4", d.AnomalyCount())
	}
	if d.DistinctAnomalies() != 3 { // socket, connect, ptrace
		t.Errorf("DistinctAnomalies = %d, want 3", d.DistinctAnomalies())
	}
	got := d.AnomalousSyscalls()
	want := []string{"connect", "ptrace", "socket"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("AnomalousSyscalls = %v, want %v", got, want)
	}

	// Alert text should mention the syscalls once each (dedup).
	s := out.String()
	if strings.Count(s, "syscall=") != 3 {
		t.Errorf("expected 3 alert lines, got:\n%s", s)
	}
	if !strings.Contains(s, "connect") || !strings.Contains(s, "never-seen-in-baseline(test)") {
		t.Errorf("alert text missing expected content:\n%s", s)
	}
}

func TestDetectorSummaryClean(t *testing.T) {
	b := baselineWith("openat", "read")
	var out bytes.Buffer
	d := NewDetector(b, "id", &out)
	d.Inspect(SyscallEvent{Syscall: "openat", PID: 1})
	d.Summary()
	if !strings.Contains(out.String(), "no anomalies") {
		t.Errorf("clean summary missing 'no anomalies': %s", out.String())
	}
}

func TestDetectorSummaryFlagged(t *testing.T) {
	b := baselineWith("openat")
	var out bytes.Buffer
	d := NewDetector(b, "id", &out)
	d.Inspect(SyscallEvent{Syscall: "connect", PID: 1})
	d.Summary()
	if !strings.Contains(out.String(), "anomalous syscall") || !strings.Contains(out.String(), "connect") {
		t.Errorf("flagged summary wrong: %s", out.String())
	}
}
