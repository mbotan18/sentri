package monitor

// baseline.go implements Milestone 5: turning raw syscall traces (the JSON-lines
// from Milestone 4) into a persisted "normal" profile per image.
//
// This file is deliberately PORTABLE (no ptrace, no build tag) — it's pure data
// aggregation — so it can be unit-tested on any platform with synthetic logs.
//
// ===========================================================================
// BASELINE STRUCTURE — DESIGN DECISION (the spec asks us to state this clearly)
// ===========================================================================
// The baseline is a per-syscall FREQUENCY profile: a map of syscall name -> how
// many times it was seen across all training runs, plus a few totals. Why this
// shape:
//   - It directly answers the two questions the Milestone 6 detector will ask:
//       (a) "was this syscall EVER seen as normal for this image?"  -> key exists
//       (b) "is its RATE wildly out of line with normal?"           -> count/total
//   - It is order-INDEPENDENT and tiny, so additional training runs simply
//     accumulate into the same counts.
//
// The richer alternative is a SEQUENCE / BIGRAM model (counts of ordered syscall
// PAIRS), which can catch anomalous *ordering* even when every individual call
// is itself "normal" — a deliberate nod to n-gram intrusion detection. We keep
// the MVP to frequencies so it stays small and can't block Milestone 6; the
// bigram model is documented here as a clean future extension, not built.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultBaselineDir is where baseline files live, relative to where sentri runs.
const DefaultBaselineDir = "baselines"

// Baseline is the learned "normal" syscall profile for one image.
type Baseline struct {
	Image         string           `json:"image"`
	CreatedAt     string           `json:"created_at"`
	UpdatedAt     string           `json:"updated_at"`
	TrainingRuns  int              `json:"training_runs"`
	TotalSyscalls int64            `json:"total_syscalls"`
	Syscalls      map[string]int64 `json:"syscalls"` // syscall name -> observed count
}

// NewBaseline returns an empty baseline for image.
func NewBaseline(image string) *Baseline {
	now := time.Now().UTC().Format(time.RFC3339)
	return &Baseline{
		Image:     image,
		CreatedAt: now,
		UpdatedAt: now,
		Syscalls:  map[string]int64{},
	}
}

// CountsFromReader reads JSON-lines trace data and tallies syscall-name counts,
// returning the per-name counts and the grand total. Lines that don't parse or
// carry no syscall name are skipped defensively (e.g. a truncated final line).
func CountsFromReader(r io.Reader) (map[string]int64, int64, error) {
	counts := map[string]int64{}
	var total int64

	sc := bufio.NewScanner(r)
	// Trace lines can be long (they may include a decoded path), so allow up to
	// 1 MiB per line instead of bufio's small default.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		// We only need the syscall name here, so decode into a minimal struct.
		var tl struct {
			Syscall string `json:"syscall"`
		}
		if err := json.Unmarshal(line, &tl); err != nil || tl.Syscall == "" {
			continue // skip malformed / non-syscall lines rather than failing
		}
		counts[tl.Syscall]++
		total++
	}
	if err := sc.Err(); err != nil {
		return nil, 0, fmt.Errorf("read trace: %w", err)
	}
	return counts, total, nil
}

// CountsFromTrace is CountsFromReader for a file path.
func CountsFromTrace(path string) (map[string]int64, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open trace %s: %w", path, err)
	}
	defer f.Close()
	return CountsFromReader(f)
}

// AddRun merges one training run's counts into the baseline: it sums counts,
// increments the training-run counter, and refreshes totals + timestamp. This is
// what makes "one or more training runs" accumulate into a single profile.
func (b *Baseline) AddRun(counts map[string]int64) {
	if b.Syscalls == nil {
		b.Syscalls = map[string]int64{}
	}
	for name, c := range counts {
		b.Syscalls[name] += c
		b.TotalSyscalls += c
	}
	b.TrainingRuns++
	b.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
}

// Names returns the baseline's syscall names, sorted (handy for stable output).
func (b *Baseline) Names() []string {
	names := make([]string, 0, len(b.Syscalls))
	for n := range b.Syscalls {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// FilePath is the on-disk path this baseline saves to under dir.
func (b *Baseline) FilePath(dir string) string { return baselinePath(dir, b.Image) }

// baselinePath builds the on-disk path for an image's baseline JSON, sanitising
// the image name so tags like "alpine:3.24" or "repo/img" are filesystem-safe.
func baselinePath(dir, image string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			return r
		default:
			return '_' // ':' '/' etc. -> '_'
		}
	}, image)
	if safe == "" {
		safe = "default"
	}
	return filepath.Join(dir, safe+".json")
}

// LoadBaseline loads the baseline for image from dir, or returns a fresh empty
// one if none exists yet (so a first `sentri train` starts from scratch).
func LoadBaseline(dir, image string) (*Baseline, error) {
	path := baselinePath(dir, image)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewBaseline(image), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Syscalls == nil {
		b.Syscalls = map[string]int64{}
	}
	return &b, nil
}

// Save writes the baseline to dir as pretty-printed JSON (dir created if needed).
func (b *Baseline) Save(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create baseline dir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	path := baselinePath(dir, b.Image)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write baseline %s: %w", path, err)
	}
	return nil
}
