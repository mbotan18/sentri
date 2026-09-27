// Package cmd holds the user-facing CLI subcommands. For now that is just
// `run`. Later milestones add ps, exec, train, etc.
//
// This file is deliberately thin: its only job is to parse what the USER typed
// and hand off to the isolation package, which owns the actual kernel-level
// mechanics. Keeping "CLI parsing" and "namespace/cgroup mechanics" in separate
// packages makes each one easy to explain and test on its own.
package cmd

import (
	"flag"
	"fmt"
	"os"

	"sentri/isolation"
)

// Run implements `sentri run [--memory <size>] [--cpus <n>] [command...]`.
//
// args is everything the user typed after "run". Examples:
//
//	sentri run /bin/sh                          -> shell, no limits
//	sentri run --memory 50m /bin/sh             -> shell capped at 50 MiB RAM
//	sentri run --cpus 0.5 /bin/sh               -> shell capped at half a core
//	sentri run --memory 100m --cpus 0.5 /bin/sh -> both
func Run(args []string) error {
	// A FlagSet parses just this subcommand's flags (kept separate from any
	// global flags). ContinueOnError lets us return the error instead of the
	// flag package calling os.Exit itself.
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	memory := fs.String("memory", "", "memory limit, e.g. 100m or 1g (default: unlimited)")
	cpus := fs.Float64("cpus", 0, "CPU limit in cores, e.g. 0.5 for half a core (default: unlimited)")
	trace := fs.Bool("trace", false, "trace the container's syscalls to a JSON-lines log")
	traceLog := fs.String("trace-log", "trace.jsonl", "path for the syscall trace log (with --trace)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sentri run [--memory <size>] [--cpus <n>] [--trace] [--trace-log <path>] [command...]\n\n")
		fs.PrintDefaults()
	}

	// flag.Parse stops at the FIRST non-flag argument, so flags must come before
	// the command: `sentri run --memory 50m /bin/sh`. Everything from the
	// command onward is returned by fs.Args() untouched (so the command can have
	// its own flags without us mis-parsing them).
	if err := fs.Parse(args); err != nil {
		return err
	}

	command := fs.Args()
	if len(command) == 0 {
		// No command given: default to an interactive shell.
		command = []string{"/bin/sh"}
	}

	// Hand off to the isolation layer with everything it needs.
	return isolation.Run(isolation.Config{
		Command:     command,
		MemoryLimit: *memory,
		CPULimit:    *cpus,
		Trace:       *trace,
		TraceLog:    *traceLog,
	})
}
