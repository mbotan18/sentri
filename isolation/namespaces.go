// Package isolation contains the kernel-level mechanics that make a process
// "contained": namespaces (this file), filesystem isolation via pivot_root
// (Milestone 2), and cgroups (Milestone 3).
//
// This file implements the namespace side of the runtime (Milestone 1) and
// wires in the filesystem side (Milestone 2, implemented in filesystem.go):
// the child enters new namespaces here, then hands off to pivotRoot() for the
// rootfs switch before exec'ing the container command.
//
// ---------------------------------------------------------------------------
// WHAT EACH CLONE_NEW* FLAG ISOLATES  (the spec explicitly asks for this)
// ---------------------------------------------------------------------------
// A "namespace" is a kernel feature that gives a process its own private view
// of one particular global system resource. Two processes in different
// namespaces of the same type simply cannot see each other's version of that
// resource. We request three in Milestone 1:
//
//   CLONE_NEWPID  -> new PID namespace.
//                    The first process in it becomes PID 1, and it can only
//                    see processes created inside this namespace. It CANNOT
//                    see (or signal, or ptrace) host processes. This is why,
//                    inside the container, our shell believes it is PID 1.
//
//   CLONE_NEWUTS  -> new UTS namespace.
//                    UTS = "UNIX Time-sharing System" — historically the
//                    struct that holds the hostname and domain name. A new UTS
//                    namespace gives the container its own hostname that we can
//                    change without touching the host's hostname. This is the
//                    easiest namespace to *prove* is working (set a hostname
//                    inside, check the host's is unchanged).
//
//   CLONE_NEWNS   -> new MOUNT namespace.
//                    ("NS" is historical — it was the first namespace Linux
//                    ever got.) It gives the container its own private list of
//                    mount points. We need this in Milestone 1 so that when we
//                    mount a fresh /proc (see Child below) it does NOT appear
//                    on the host. It becomes far more important in Milestone 2,
//                    where pivot_root swaps the container onto a completely
//                    different root filesystem.
//
// WHY PID-NAMESPACE ALONE IS NOT ENOUGH (sets up later milestones):
//   - A PID namespace only virtualises *process IDs*. The contained process
//     still shares the HOST's filesystem — `ls /` would show the host's root,
//     and it could read host files. Filesystem isolation is a SEPARATE concern
//     handled by the mount namespace + pivot_root in Milestone 2.
//   - It also shares the host's NETWORK (same interfaces/IPs — a network
//     namespace, CLONE_NEWNET, would be needed for that; out of scope here).
//   - And it imposes NO resource limits: the contained process can still use
//     all the host's CPU and RAM. Limiting that is what cgroups v2 does in
//     Milestone 3. Namespaces isolate *visibility*; cgroups limit *consumption*
//     — two orthogonal mechanisms, which is a key thing to be able to explain.
package isolation

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"sentri/monitor"
)

// containerHostname is the hostname we set inside the container's UTS
// namespace. Any distinct value works — the point is that it differs from the
// host's hostname, which proves UTS isolation.
const containerHostname = "sentri"

// defaultRootfs is the directory (relative to where sentri is run) holding the
// extracted Alpine root filesystem the container will pivot_root into.
// See the README section "Obtaining a root filesystem" for how to populate it.
const defaultRootfs = "rootfs"

// rootfsEnv is the environment variable the PARENT uses to hand the resolved,
// absolute rootfs path to the re-exec'd CHILD. We use an env var (rather than a
// CLI argument) so it stays out of the user-facing command line, and because
// the parent has already resolved and validated the path by the time the child
// needs it.
const rootfsEnv = "SENTRI_ROOTFS"

// Config holds everything the parent needs to launch a container.
type Config struct {
	Command     []string // program + args to run inside the container (e.g. ["/bin/sh"])
	MemoryLimit string   // human string like "100m" or "1g"; "" = no memory limit
	CPULimit    float64  // CPU cores, e.g. 0.5 = half a core; 0 = no CPU limit
	Trace       bool     // if true, ptrace the container and log its syscalls
	TraceLog    string   // path for the JSON-lines syscall log (when Trace is set)
}

// Run is the PARENT side of the re-exec pattern.
//
// It launches a fresh copy of THIS binary (/proc/self/exe) as a child process,
// re-invoking it with the hidden "child" subcommand, and asks the kernel to
// place that child in new namespaces via the Cloneflags below (and, if resource
// limits were requested, directly into a cgroup). The parent then waits for the
// child to exit and cleans up.
func Run(cfg Config) error {
	// Resolve the rootfs directory to an ABSOLUTE path. pivot_root (used in the
	// child) requires absolute paths, and resolving here — in the parent, before
	// we enter any namespace — means we can validate it and give the user a
	// friendly error rather than a cryptic failure deep inside the child.
	rootfs, err := filepath.Abs(defaultRootfs)
	if err != nil {
		return fmt.Errorf("resolve rootfs path: %w", err)
	}
	// Cheap sanity check that the rootfs is actually populated: a real Linux root
	// filesystem has a /bin directory. If it's missing, the user hasn't extracted
	// Alpine yet — tell them exactly what to do instead of failing obscurely.
	if fi, err := os.Stat(filepath.Join(rootfs, "bin")); err != nil || !fi.IsDir() {
		return fmt.Errorf("no root filesystem found at %s\n"+
			"       extract an Alpine minirootfs there first "+
			"(see README: \"Obtaining a root filesystem\")", rootfs)
	}

	// /proc/self/exe is a kernel-provided symlink to the currently running
	// executable. Executing it starts a brand-new copy of sentri. We prepend
	// "child" so that copy's main() dispatches into Child() below.
	//
	// exec.Command does NOT start anything yet; it just builds the description
	// of the process we want.
	cmd := exec.Command("/proc/self/exe", append([]string{"child"}, cfg.Command...)...)

	// Wire the child's standard streams to ours so the interactive shell's
	// input/output flows through to the user's terminal.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Hand the resolved rootfs path to the child via the environment. We start
	// from the parent's full environment and append our variable.
	cmd.Env = append(os.Environ(), rootfsEnv+"="+rootfs)

	// This is the crucial part. SysProcAttr lets us pass Linux-specific options
	// to the underlying clone()/fork() the Go runtime performs when starting
	// the child. Cloneflags is a bitmask: OR-ing the CLONE_NEW* flags together
	// tells the kernel "create the child in a NEW instance of each of these
	// namespaces" instead of sharing ours.
	attr := &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | // own hostname
			syscall.CLONE_NEWPID | // own PID space (child becomes PID 1)
			syscall.CLONE_NEWNS, // own mount table (so our /proc mount is private)
	}

	// Terminal / job-control fix for interactive shells.
	//
	// PROBLEM: an interactive shell (dash, i.e. /bin/sh on Ubuntu) running as
	// PID 1 in a NEW pid namespace enables job control, which manages the
	// terminal's "foreground process group". But the terminal it inherited is
	// owned by a process group that lives in the HOST pid namespace — invisible
	// from inside the container. On exit the shell tries to restore that
	// process group as the terminal's foreground, fails, and prints
	// "Cannot set tty process group (No such process)", exiting non-zero.
	//
	// FIX: put the child in its OWN session (Setsid) and make the terminal the
	// controlling terminal of THAT session (Setctty on Ctty=0, i.e. stdin).
	// Now job control operates entirely within the container's own session, so
	// entry and exit are clean.
	//
	// We only do this when stdin is an actual terminal (character device). If
	// input is piped/redirected (e.g. `sentri run /bin/echo hi < file`), there
	// is no controlling terminal to claim and Setctty would fail — so we skip
	// it and let the command run non-interactively.
	if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		attr.Setsid = true  // child becomes leader of a brand-new session
		attr.Setctty = true // make the terminal our controlling terminal...
		attr.Ctty = 0       // ...using file descriptor 0 (stdin)
	}

	// RESOURCE LIMITS (Milestone 3).
	// If the user requested a memory and/or CPU limit, create a cgroup v2 cgroup
	// carrying those limits and have the kernel place the child DIRECTLY into it
	// at clone time via CLONE_INTO_CGROUP (the UseCgroupFD/CgroupFD fields below).
	// Being born INTO the cgroup is race-free: the process is constrained from
	// its very first instruction. The classic alternative — start the process,
	// then echo its PID into the cgroup's cgroup.procs — leaves a brief window
	// where it runs unconstrained; we avoid that. (Full detail in cgroups.go.)
	var cgDir *os.File
	cleanupCgroup := func() {}
	if cfg.MemoryLimit != "" || cfg.CPULimit > 0 {
		memBytes, err := parseMemory(cfg.MemoryLimit)
		if err != nil {
			return err
		}
		f, cleanup, err := setupCgroup(containerID(), memBytes, cfg.CPULimit)
		if err != nil {
			return fmt.Errorf("cgroup setup: %w", err)
		}
		cgDir = f
		cleanupCgroup = cleanup
		attr.UseCgroupFD = true     // tell Go to clone the child into a cgroup...
		attr.CgroupFD = int(f.Fd()) // ...this one: the fd of the leaf cgroup dir
	}
	// When the container exits (or if we fail to launch it), close the cgroup fd
	// and remove the cgroup directory. We close BEFORE removing to avoid EBUSY on
	// the rmdir. This is the explicit cleanup cgroups need — unlike namespaces,
	// a cgroup lives in the host's cgroup filesystem and does NOT disappear on
	// its own when the process exits.
	defer func() {
		if cgDir != nil {
			cgDir.Close()
		}
		cleanupCgroup()
	}()

	// If syscall tracing was requested (Milestone 4), take the ptrace path: the
	// tracer must be the parent and must drive the child on a single, locked OS
	// thread. Otherwise, run normally.
	if cfg.Trace {
		attr.Ptrace = true // child does PTRACE_TRACEME and stops at its first exec
		cmd.SysProcAttr = attr
		return traceRun(cmd, cfg.TraceLog)
	}

	cmd.SysProcAttr = attr

	// cmd.Run() = Start() + Wait(): it starts the child (in its new namespaces)
	// and blocks until the child — i.e. the interactive shell — exits. When the
	// user types `exit`, control returns here and the function returns cleanly,
	// which tears everything down. Because the namespaces AND every mount we make
	// inside them (the rootfs bind mount, the pivoted root, /proc) live in the
	// child's own mount namespace, they all vanish automatically once the child
	// exits — nothing leaks onto the host and there is nothing to clean up by
	// hand. (Cgroups in Milestone 3 WILL need explicit cleanup, because those
	// live in the host's cgroup filesystem, not in a namespace.)
	return cmd.Run()
}

// traceRun launches the container under ptrace and runs the tracer loop.
//
// Unlike the normal path (cmd.Run), ptrace requires that the process is STARTED
// and then driven from the SAME OS thread — the Go scheduler must not move us to
// a different thread mid-trace, or the ptrace calls fail with ESRCH. So we lock
// the goroutine to its thread for the whole trace, use cmd.Start() (not Run),
// and let monitor.Trace do the wait/ptrace loop and reap the child itself. We
// deliberately do NOT call cmd.Wait() — that would race the tracer's own wait4.
func traceRun(cmd *exec.Cmd, logPath string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// The trace log is written on the HOST filesystem (the parent is never
	// pivot_root'ed), so it survives after the container exits.
	f, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create trace log %s: %w", logPath, err)
	}
	defer f.Close()

	// With SysProcAttr.Ptrace set, Start() forks the child, which calls
	// PTRACE_TRACEME and stops at its first execve, waiting for us.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start traced child: %w", err)
	}

	if err := monitor.Trace(cmd.Process.Pid, f); err != nil {
		return fmt.Errorf("tracer: %w", err)
	}

	fmt.Fprintf(os.Stderr, "sentri: syscall trace written to %s\n", logPath)
	return nil
}

// Child is the IN-NAMESPACE side of the re-exec pattern. By the time this runs,
// the kernel has already placed us inside the new PID/UTS/mount namespaces, and
// we are a clean single-threaded process — the safe place to finish setup.
//
// command is the program (and args) to ultimately run inside the container.
func Child(command []string) error {
	// (1) UTS namespace demo: give the container its own hostname.
	// Sethostname changes the hostname in OUR uts namespace only; because we
	// are in a fresh CLONE_NEWUTS namespace, the host's hostname is untouched.
	if err := syscall.Sethostname([]byte(containerHostname)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}

	// (2) FILESYSTEM ISOLATION (Milestone 2).
	// The parent handed us the absolute rootfs path in an env var. pivotRoot
	// (in filesystem.go) makes the mount namespace private, pivot_root()s onto
	// the Alpine rootfs, mounts a fresh /proc INSIDE it, and detaches the old
	// host root entirely. After this call, our view of "/" IS the Alpine
	// filesystem and the host filesystem is no longer mounted in our namespace.
	rootfs := os.Getenv(rootfsEnv)
	if rootfs == "" {
		// Should never happen: the parent always sets this. Guard anyway.
		return fmt.Errorf("%s not set (internal error: parent did not pass rootfs)", rootfsEnv)
	}
	if err := pivotRoot(rootfs); err != nil {
		return fmt.Errorf("filesystem setup: %w", err)
	}

	// (3) Replace this process with the target command via execve.
	//
	// We use syscall.Exec (not exec.Command) on purpose: execve REPLACES the
	// current process image in place rather than spawning a child. That means
	// the target program (e.g. /bin/sh) INHERITS our PID — so it becomes PID 1
	// in the new namespace, exactly as a container's init process should be.
	// If we spawned it as a child instead, the shell would be PID 2 and this
	// Go stub would be the real PID 1. Because we've already pivot_root'ed, the
	// "/bin/sh" we exec is Alpine's shell, resolved inside the new root.
	return execCommand(command)
}

// execCommand resolves the target program's path and execve's into it.
func execCommand(command []string) error {
	// LookPath finds the executable: it returns absolute paths (like /bin/sh)
	// unchanged, and resolves bare names (like "sh") against $PATH. Because
	// Child() has already pivot_root'ed by the time we get here, an absolute
	// path like /bin/sh resolves inside the Alpine rootfs (that's Alpine's
	// busybox shell), and any $PATH lookup searches the container's filesystem.
	path, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("lookup %q: %w", command[0], err)
	}

	// syscall.Exec(argv0, argv, envv). On success it NEVER returns — the
	// process has become the new program. It only returns if execve failed
	// (e.g. the binary doesn't exist inside the container). We pass the host's
	// current environment through for now.
	if err := syscall.Exec(path, command, os.Environ()); err != nil {
		return fmt.Errorf("exec %q: %w", path, err)
	}

	// Unreachable on success; present so the function has a return on all paths.
	return nil
}
