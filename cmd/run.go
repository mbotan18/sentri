// Package cmd holds the user-facing CLI subcommands. For Milestone 1 that is
// just `run`. Later milestones add ps, exec, train, etc.
//
// This file is deliberately thin: its only job is to parse what the USER typed
// and hand off to the isolation package, which owns the actual kernel-level
// mechanics. Keeping "CLI parsing" and "namespace mechanics" in separate
// packages makes each one easy to explain and test on its own.
package cmd

import "sentri/isolation"

// Run implements `sentri run [command...]`.
//
// args is everything the user typed after "run". For example:
//
//	sentri run /bin/sh            -> args = ["/bin/sh"]
//	sentri run /bin/echo hello    -> args = ["/bin/echo", "hello"]
//
// Milestone 1 has no flags yet (--memory, --cpus arrive in Milestone 3 with
// cgroups), so we treat every argument as part of the command to run.
func Run(args []string) error {
	// If the user gave no command, default to an interactive shell. This makes
	// `sudo ./sentri run` on its own drop you straight into the container,
	// which is the quickest way to poke around and verify isolation.
	if len(args) == 0 {
		args = []string{"/bin/sh"}
	}

	// Hand off to the isolation layer. isolation.Run is the "parent" side of
	// the re-exec pattern described in main.go: it clones a copy of ourselves
	// into new namespaces and waits for it to finish.
	return isolation.Run(args)
}
