//go:build linux && amd64

// Package monitor implements the security half of sentri: syscall tracing
// (this file, Milestone 4), baseline learning (Milestone 5), and anomaly
// detection (Milestone 6).
//
// ===========================================================================
// WHY ptrace (and the trade-off vs seccomp)  — the spec asks us to justify this
// ===========================================================================
// We trace with ptrace(PTRACE_SYSCALL). The kernel stops the tracee twice per
// syscall (once on entry, once on exit) and hands control to us, the tracer, so
// we can read the syscall number and arguments from its registers.
//
// The alternative is a seccomp-BPF filter. The two make a classic trade-off:
//
//   ptrace:
//     + sees EVERY syscall with full arguments, and can read tracee memory
//       (so we can resolve the path passed to openat, etc.)
//     + simple mental model, no BPF program to write
//     - high overhead: two context switches to the tracer PER syscall
//     - known bypasses; not a security boundary on its own
//
//   seccomp-BPF (SECCOMP_RET_TRACE / SECCOMP_RET_ERRNO):
//     + runs IN-KERNEL, so it can filter/allow the common calls with almost no
//       overhead and only trap the interesting ones
//     + can actively BLOCK syscalls (real enforcement), not just observe
//     - the BPF program can't dereference pointers, so it can't see paths/args
//       by itself; you still need ptrace (SECCOMP_RET_TRACE) for that
//
// For sentri's goal — LEARN a full syscall profile and DETECT deviations — we
// want to see everything with arguments, and detection (not blocking) is the
// point. So ptrace is the right MVP. The production-grade design is the hybrid:
// a seccomp-BPF filter that fast-paths the boring calls and SECCOMP_RET_TRACEs
// only the security-relevant ones into ptrace. That's noted as a future step and
// in the README's Limitations.
package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"syscall"
	"time"
)

// ptrace option bits. Defined locally so we don't depend on which of these the
// standard syscall package happens to export on a given Go version.
const (
	optTraceSysGood = 0x00000001 // mark syscall-stops with SIGTRAP|0x80
	optTraceFork    = 0x00000002 // report fork() children (auto-trace them)
	optTraceVFork   = 0x00000004 // report vfork() children
	optTraceClone   = 0x00000008 // report clone() children/threads
	optTraceExec    = 0x00000010 // report a distinct event on execve
	optExitKill     = 0x00100000 // if the tracer dies, SIGKILL the tracees
)

// ptrace event codes, as returned by syscall.WaitStatus.TrapCause().
const (
	evFork  = 1
	evVFork = 2
	evClone = 3
	evExec  = 4
)

// __WALL: wait for all children, including clone()-created ones (threads).
const wall = 0x40000000

// syscallStop is the signal value a syscall-stop carries when TRACESYSGOOD is
// set: SIGTRAP with bit 7 set. It lets us distinguish syscall-stops from other
// SIGTRAPs (like breakpoints or the initial exec trap).
const syscallStop = syscall.SIGTRAP | 0x80

// event is one line of the JSON-lines trace log. Keeping it small and flat makes
// it trivial for the Milestone 5 baseline learner to parse back.
type event struct {
	Time    string   `json:"ts"`             // RFC3339 nanosecond timestamp
	Syscall string   `json:"syscall"`        // resolved name, e.g. "openat"
	PID     int      `json:"pid"`            // host-visible pid of the tracee
	Args    []uint64 `json:"args"`           // raw syscall args (registers)
	Path    string   `json:"path,omitempty"` // decoded path arg, when applicable
}

// Trace drives a ptrace loop over the process tree rooted at rootPID and writes
// one JSON line per syscall to out. rootPID was started by the caller with
// SysProcAttr.Ptrace = true, so it is already stopped at its initial exec. Trace
// returns once the entire tree has exited.
//
// THREADING: every wait and every PTRACE_* call must run on the SAME OS thread
// that started rootPID. The caller (isolation.traceRun) has already done
// runtime.LockOSThread() and calls us synchronously, so we run on that thread —
// we must NOT hand any ptrace work to another goroutine.
func Trace(rootPID int, out io.Writer) error {
	enc := json.NewEncoder(out)

	// (1) Reap the tracee's initial stop (it stopped at the execve of
	// /proc/self/exe, i.e. our own re-exec, before any container setup).
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(rootPID, &ws, 0, nil); err != nil {
		return fmt.Errorf("initial wait: %w", err)
	}

	// (2) Configure what the kernel reports to us.
	opts := optTraceSysGood | optTraceExec | optTraceFork | optTraceVFork | optTraceClone | optExitKill
	if err := syscall.PtraceSetOptions(rootPID, opts); err != nil {
		return fmt.Errorf("ptrace setoptions: %w", err)
	}

	// We only want the CONTAINER WORKLOAD's syscalls, not the ones our Go child
	// stub makes while doing pivot_root / mounts. So until the target program's
	// execve, we run the tracee freely with PTRACE_CONT (which does NOT stop on
	// syscalls). The moment we see that execve (evExec), we flip `logging` on and
	// switch to PTRACE_SYSCALL, recording everything from there.
	logging := false

	known := map[int]bool{rootPID: true} // pids we've initialised
	atEntry := map[int]bool{}            // per-pid: is the next syscall-stop an ENTRY?

	// resume continues a stopped tracee — stepping to the next syscall boundary
	// once we're logging, or running freely until then. `sig` injects a pending
	// signal (0 = none).
	resume := func(pid, sig int) {
		if logging {
			_ = syscall.PtraceSyscall(pid, sig)
		} else {
			_ = syscall.PtraceCont(pid, sig)
		}
	}

	// Kick the root tracee off (it's still stopped from step 1).
	_ = syscall.PtraceCont(rootPID, 0)

	for {
		pid, err := syscall.Wait4(-1, &ws, wall, nil)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.ECHILD {
				return nil // no tracees left: the whole tree has exited
			}
			return fmt.Errorf("wait4: %w", err)
		}

		// A tracee exited or was killed by a signal: forget it.
		if ws.Exited() || ws.Signaled() {
			delete(known, pid)
			delete(atEntry, pid)
			continue
		}
		if !ws.Stopped() {
			continue
		}

		// First time we see a pid: it's a newly-forked child's initial stop
		// (auto-attached via TRACE{FORK,VFORK,CLONE}). Its next syscall-stop will
		// be an ENTRY. Don't inject its initial SIGSTOP.
		if !known[pid] {
			known[pid] = true
			atEntry[pid] = true
			resume(pid, 0)
			continue
		}

		// Event stops (execve / new child) are reported via TrapCause().
		switch ws.TrapCause() {
		case evExec:
			// The target program's execve completed — begin logging this pid.
			if pid == rootPID {
				logging = true
			}
			atEntry[pid] = true
			resume(pid, 0)
			continue
		case evFork, evVFork, evClone:
			// Parent spawned a child; the child appears as its own "unknown pid"
			// stop above. Just keep the parent moving.
			resume(pid, 0)
			continue
		}

		// Syscall-entry / syscall-exit stop?
		if ws.StopSignal() == syscallStop {
			if logging {
				if atEntry[pid] {
					// ENTRY: registers hold the syscall number + arguments.
					var regs syscall.PtraceRegs
					if err := syscall.PtraceGetRegs(pid, &regs); err == nil {
						logSyscall(enc, pid, &regs)
					}
				}
				atEntry[pid] = !atEntry[pid] // entry -> exit -> entry -> ...
			}
			resume(pid, 0)
			continue
		}

		// Otherwise it's a genuine signal being delivered to the tracee. Forward
		// it so the program still receives its SIGINT/SIGTERM/etc., except the
		// housekeeping signals we must not re-inject.
		sig := int(ws.StopSignal())
		if ws.StopSignal() == syscall.SIGSTOP || ws.StopSignal() == syscall.SIGTRAP {
			sig = 0
		}
		resume(pid, sig)
	}
}

// logSyscall writes one JSON line describing a syscall ENTRY.
func logSyscall(enc *json.Encoder, pid int, regs *syscall.PtraceRegs) {
	// On x86-64: the syscall number is in orig_rax at entry (rax gets clobbered
	// by the return value on exit, which is why we log on entry). The six
	// arguments are, in order, rdi, rsi, rdx, r10, r8, r9.
	num := int(regs.Orig_rax)
	args := []uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9}

	ev := event{
		Time:    time.Now().UTC().Format(time.RFC3339Nano),
		Syscall: syscallName(num),
		PID:     pid,
		Args:    args,
	}
	// For syscalls whose interesting argument is a pathname pointer, read the
	// string out of the tracee's memory so the log is human-readable (e.g. shows
	// WHICH file openat opened). Best-effort — omit on any error.
	if idx, ok := pathArgIndex[num]; ok {
		ev.Path = readString(pid, uintptr(args[idx]))
	}

	_ = enc.Encode(&ev) // Encoder.Encode appends '\n' → one JSON object per line
}

// pathArgIndex maps a syscall number to which arg (index into args) is a
// pathname pointer, for the common path-taking syscalls.
var pathArgIndex = map[int]int{
	2:   0, // open(path, ...)
	257: 1, // openat(dirfd, path, ...)
	59:  0, // execve(path, ...)
	322: 1, // execveat(dirfd, path, ...)
	4:   0, // stat(path, ...)
	6:   0, // lstat(path, ...)
	262: 1, // newfstatat(dirfd, path, ...)
	332: 1, // statx(dirfd, path, ...)
	21:  0, // access(path, ...)
	89:  0, // readlink(path, ...)
	83:  0, // mkdir(path, ...)
	87:  0, // unlink(path)
	263: 1, // unlinkat(dirfd, path, ...)
}

// readString reads a NUL-terminated string from the tracee's memory at addr via
// ptrace PEEKDATA (8 bytes per call). Capped at `max` bytes so a bad/garbage
// pointer can't make us loop forever.
func readString(pid int, addr uintptr) string {
	if addr == 0 {
		return ""
	}
	const max = 4096
	out := make([]byte, 0, 64)
	word := make([]byte, 8)
	for len(out) < max {
		n, err := syscall.PtracePeekData(pid, addr, word)
		if err != nil || n == 0 {
			break
		}
		for i := 0; i < n; i++ {
			if word[i] == 0 {
				return string(out)
			}
			out = append(out, word[i])
		}
		addr += uintptr(n)
	}
	return string(out)
}
