package monitor

// detector.go implements Milestone 6: comparing live syscalls against a learned
// baseline and raising real-time alerts. PORTABLE (no ptrace) so it's unit-tested
// with synthetic events.
//
// ===========================================================================
// ANOMALY RULE — stated exactly (the spec forbids an unexplained magic number)
// ===========================================================================
// A syscall is flagged as anomalous when its NAME was NEVER observed in the
// baseline for this image. That's the whole rule — the "unknown-syscall" rule.
//
// Why this rule:
//   - HIGH PRECISION: if the monitored workload matches what was trained, every
//     syscall it makes already exists in the baseline, so a matching run yields
//     ZERO alerts (acceptance criterion #1). A compromise that performs a new
//     KIND of action — opening a network socket, calling ptrace, changing file
//     permissions — necessarily issues syscalls the benign profile never held,
//     so it is caught in real time (acceptance criterion #2).
//   - EXPLAINABLE: there is no threshold to tune or justify; "was this syscall
//     ever normal for this image?" is a yes/no question.
//
// To keep the output READABLE (this is the demo artifact), we alert ONCE per
// distinct anomalous syscall name; repeats are counted, not reprinted.
//
// A FREQUENCY-based rule (flag a syscall whose observed rate deviates from the
// baseline rate by more than some X) is a documented alternative we deliberately
// leave OFF: rate thresholds trade false positives for recall and would add
// noise to the demo. The unknown-syscall rule is deterministic; the frequency
// knob is noted here as future work.

import (
	"fmt"
	"io"
	"sort"
)

// ANSI styles — they make the alert POP on screen for the demo recording.
const (
	colReset  = "\033[0m"
	colRedB   = "\033[1;31m" // bold red
	colGreenB = "\033[1;32m" // bold green
	colBold   = "\033[1m"
	colDim    = "\033[2m"
)

// Detector compares live syscalls against a baseline and reports anomalies.
type Detector struct {
	baseline    *Baseline
	containerID string
	out         io.Writer
	alerted     map[string]int // anomalous syscall name -> times observed
	total       int            // total anomalous syscalls observed
}

// NewDetector builds a detector for one monitored run.
func NewDetector(b *Baseline, containerID string, out io.Writer) *Detector {
	return &Detector{
		baseline:    b,
		containerID: containerID,
		out:         out,
		alerted:     map[string]int{},
	}
}

// Inspect checks one live syscall against the baseline, printing an alert the
// FIRST time each anomalous syscall name is seen. Wire this as the tracer's emit.
func (d *Detector) Inspect(ev SyscallEvent) {
	if _, known := d.baseline.Syscalls[ev.Syscall]; known {
		return // present in the baseline -> normal, nothing to do
	}
	d.total++
	seen := d.alerted[ev.Syscall]
	d.alerted[ev.Syscall]++
	if seen > 0 {
		return // already alerted for this syscall name; just keep the count
	}

	pathPart := ""
	if ev.Path != "" {
		pathPart = fmt.Sprintf("  path=%q", ev.Path)
	}
	fmt.Fprintf(d.out,
		"%s🚨 ANOMALY%s  syscall=%s%s%s  pid=%d  container=%s  %sreason=never-seen-in-baseline(%s)%s%s\n",
		colRedB, colReset, colBold, ev.Syscall, colReset, ev.PID, d.containerID,
		colDim, d.baseline.Image, colReset, pathPart)
}

// AnomalyCount / DistinctAnomalies expose results (used by tests and callers).
func (d *Detector) AnomalyCount() int      { return d.total }
func (d *Detector) DistinctAnomalies() int { return len(d.alerted) }

// AnomalousSyscalls returns the distinct anomalous syscall names, sorted.
func (d *Detector) AnomalousSyscalls() []string {
	names := make([]string, 0, len(d.alerted))
	for k := range d.alerted {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Summary prints a one-line verdict at the end of the monitored run.
func (d *Detector) Summary() {
	if d.total == 0 {
		fmt.Fprintf(d.out, "%s✓ no anomalies — behaviour matched baseline %q%s\n",
			colGreenB, d.baseline.Image, colReset)
		return
	}
	fmt.Fprintf(d.out, "%s✗ %d anomalous syscall(s) across %d type(s): %v%s\n",
		colRedB, d.total, len(d.alerted), d.AnomalousSyscalls(), colReset)
}
