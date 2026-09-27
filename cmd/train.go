package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"sentri/isolation"
	"sentri/monitor"
)

// defaultTrainWorkload is a representative "normal" workload used when the user
// doesn't supply their own. It exercises a spread of ordinary syscalls — listing
// directories, reading a file, walking the filesystem, spawning child processes —
// so the learned baseline reflects benign behaviour. Output goes to /tmp inside
// the container (Alpine has /tmp; note it has NO /dev/null) to keep the console
// clean. For a meaningful Milestone 6 demo, the "normal" run there should use a
// comparable workload so the baseline actually covers it.
var defaultTrainWorkload = []string{
	"/bin/sh", "-c",
	"ls -la / >/tmp/o 2>&1; cat /etc/os-release >/tmp/o 2>&1; " +
		"find /usr -type f >/tmp/o 2>&1; ls /bin >/tmp/o 2>&1; echo trained",
}

// Train implements `sentri train <image> [command...]`.
//
// It runs a workload inside a TRACED container (reusing the Milestone 4 tracer),
// then aggregates the observed syscalls into the image's baseline (Milestone 5),
// creating it or merging into an existing one. Requires root (it launches a
// traced, namespaced container).
func Train(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sentri train <image> [command...]")
	}
	image := args[0]
	command := args[1:]
	if len(command) == 0 {
		command = defaultTrainWorkload
	}

	// Trace this training run to a temporary log on the HOST filesystem.
	traceFile := filepath.Join(os.TempDir(), fmt.Sprintf("sentri-train-%d.jsonl", os.Getpid()))
	defer os.Remove(traceFile)

	fmt.Fprintf(os.Stderr, "sentri: training baseline for %q ...\n", image)
	if err := isolation.Run(isolation.Config{
		Command:  command,
		Trace:    true,
		TraceLog: traceFile,
	}); err != nil {
		return fmt.Errorf("training run: %w", err)
	}

	// Aggregate the trace into per-syscall counts.
	counts, total, err := monitor.CountsFromTrace(traceFile)
	if err != nil {
		return err
	}
	if total == 0 {
		return fmt.Errorf("no syscalls captured — did the workload run? (trace: %s)", traceFile)
	}

	// Merge into the (possibly pre-existing) baseline and persist it.
	b, err := monitor.LoadBaseline(monitor.DefaultBaselineDir, image)
	if err != nil {
		return err
	}
	b.AddRun(counts)
	if err := b.Save(monitor.DefaultBaselineDir); err != nil {
		return err
	}

	fmt.Printf("trained %q: this run observed %d syscalls (%d distinct)\n", image, total, len(counts))
	fmt.Printf("baseline now: %d distinct syscalls across %d run(s) -> %s\n",
		len(b.Syscalls), b.TrainingRuns, b.FilePath(monitor.DefaultBaselineDir))
	return nil
}
