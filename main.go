// Package main is the CLI entrypoint for sentri.
//
// sentri uses a well-known trick for container runtimes written in Go called
// the "re-exec" pattern. You cannot safely enter new Linux namespaces from
// inside a running Go program, because the Go runtime is multi-threaded from
// the start and namespace transitions (especially the mount namespace) are
// per-thread / must happen in a single-threaded context before other setup.
//
// The standard solution, used by Docker's own libcontainer, is:
//
//   1. The PARENT process (this program, invoked as `sentri run ...`) launches
//      a fresh COPY of its own executable, telling the kernel via clone flags
//      to place that copy in brand-new namespaces.
//   2. That fresh copy re-enters main() and sees a hidden first argument
//      ("child"). It is now already inside the new namespaces, running as a
//      clean single-threaded process, so it can safely finish container setup
//      (set the hostname, mount /proc, ...) and then replace itself with the
//      real target program (e.g. /bin/sh).
//
// So the SAME binary runs in two roles, chosen by os.Args[1]:
//   - "run"   -> parent role  (cmd.Run)
//   - "child" -> in-namespace role (isolation.Child)   [internal, not for users]
package main

import (
	"fmt"
	"os"

	"sentri/cmd"
	"sentri/isolation"
)

func main() {
	// os.Args[0] is the program name; we need at least one subcommand after it.
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	// Dispatch on the subcommand. We keep this a plain switch rather than
	// pulling in a CLI framework (cobra) for Milestone 1 — the spec allows
	// either, and fewer dependencies keeps the isolation mechanics front and
	// centre while there are only a couple of commands.
	switch os.Args[1] {
	case "run":
		// User-facing: `sentri run [command...]`. Everything after "run" is the
		// command to execute inside the container (defaults to /bin/sh).
		if err := cmd.Run(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "sentri: run failed: %v\n", err)
			os.Exit(1)
		}

	case "train":
		// `sentri train <image> [command...]`: run a workload under tracing and
		// learn/update the "normal" syscall baseline for that image.
		if err := cmd.Train(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "sentri: train failed: %v\n", err)
			os.Exit(1)
		}

	case "child":
		// INTERNAL ONLY. This is the re-exec target from cmd.Run — it is already
		// running inside the new namespaces. A user should never type this.
		// Everything after "child" is the command to exec inside the container.
		if err := isolation.Child(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "sentri: child setup failed: %v\n", err)
			os.Exit(1)
		}

	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `sentri - a minimal container runtime (learning project)

usage:
  sentri run [--memory <size>] [--cpus <n>] [--trace] [command...]
                             run a command in an isolated container
                             (defaults to /bin/sh if no command is given)
  sentri train <image> [command...]
                             run a workload under tracing and learn/update the
                             "normal" syscall baseline for <image>

note: must be run as root / with sudo, because creating namespaces
      requires the CAP_SYS_ADMIN capability.
`)
}
