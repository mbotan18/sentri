package monitor

// Unit tests for the baseline learner. These are PURE LOGIC — they feed
// synthetic trace lines / counts and assert on the aggregation, with no ptrace,
// container, or root involved. They run on any platform (see the note in the
// Milestone 5 verification steps: `go test ./monitor`).

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCountsFromReader(t *testing.T) {
	in := strings.Join([]string{
		`{"ts":"t","syscall":"openat","pid":1,"args":[]}`,
		`{"ts":"t","syscall":"read","pid":1,"args":[]}`,
		`{"ts":"t","syscall":"openat","pid":1,"args":[]}`,
		``,                     // blank line: skipped
		`not json at all`,      // malformed: skipped
		`{"ts":"t","pid":1}`,   // no syscall field: skipped
		`{"ts":"t","syscall":"close","pid":2,"args":[]}`,
	}, "\n")

	counts, total, err := CountsFromReader(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if counts["openat"] != 2 {
		t.Errorf("openat = %d, want 2", counts["openat"])
	}
	if counts["read"] != 1 || counts["close"] != 1 {
		t.Errorf("read=%d close=%d, want 1 and 1", counts["read"], counts["close"])
	}
}

func TestAddRunMerge(t *testing.T) {
	b := NewBaseline("alpine")
	b.AddRun(map[string]int64{"openat": 2, "read": 1})
	b.AddRun(map[string]int64{"openat": 3, "write": 5})

	if b.TrainingRuns != 2 {
		t.Errorf("TrainingRuns = %d, want 2", b.TrainingRuns)
	}
	if b.Syscalls["openat"] != 5 {
		t.Errorf("openat = %d, want 5 (2+3)", b.Syscalls["openat"])
	}
	if b.Syscalls["read"] != 1 || b.Syscalls["write"] != 5 {
		t.Errorf("read=%d write=%d, want 1 and 5", b.Syscalls["read"], b.Syscalls["write"])
	}
	if b.TotalSyscalls != 11 {
		t.Errorf("TotalSyscalls = %d, want 11", b.TotalSyscalls)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	b := NewBaseline("alpine:3.24")
	b.AddRun(map[string]int64{"openat": 2, "close": 1})
	if err := b.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := LoadBaseline(dir, "alpine:3.24")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.TrainingRuns != 1 {
		t.Errorf("TrainingRuns = %d, want 1", got.TrainingRuns)
	}
	if got.Syscalls["openat"] != 2 || got.Syscalls["close"] != 1 {
		t.Errorf("round-trip counts wrong: %+v", got.Syscalls)
	}
	if got.TotalSyscalls != 3 {
		t.Errorf("TotalSyscalls = %d, want 3", got.TotalSyscalls)
	}
}

func TestBaselinePathSanitised(t *testing.T) {
	p := baselinePath("baselines", "alpine:3.24")
	base := filepath.Base(p)
	if strings.ContainsAny(base, `:/\`) {
		t.Fatalf("unsafe baseline filename: %q", base)
	}
	if base != "alpine_3.24.json" {
		t.Errorf("filename = %q, want alpine_3.24.json", base)
	}
}

func TestLoadMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	b, err := LoadBaseline(dir, "never-trained")
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if b.TrainingRuns != 0 || len(b.Syscalls) != 0 {
		t.Errorf("expected empty baseline, got %+v", b)
	}
}
