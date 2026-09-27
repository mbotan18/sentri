//go:build linux && amd64

package monitor

import "fmt"

// syscallName maps an x86-64 syscall NUMBER to its human name.
//
// WHY a hand-maintained table (a documented design choice): the standard library
// has no public "syscall number -> name" map, and syscall numbers are
// ARCHITECTURE-SPECIFIC (openat is 257 on x86-64 but a different number on
// arm64). Rather than pull in a big generated dependency, we keep a curated set
// covering the common startup calls (so a trace of `cat` reads clearly) plus the
// security-relevant ones the anomaly detector cares about (execve, connect,
// socket, ptrace, chmod, setuid, mount, ...). Anything not in the table is
// logged as "syscall_<n>" so nothing is silently dropped.
//
// This file is built only for linux/amd64 (see the build tag) because the
// numbers below are the x86-64 ABI. Porting to another arch = a new table.
func syscallName(n int) string {
	if s, ok := syscallNames[n]; ok {
		return s
	}
	return fmt.Sprintf("syscall_%d", n)
}

var syscallNames = map[int]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	16:  "ioctl",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	22:  "pipe",
	23:  "select",
	24:  "sched_yield",
	25:  "mremap",
	28:  "madvise",
	35:  "nanosleep",
	40:  "sendfile", // busybox cat/cp use this to copy a file to stdout
	32:  "dup",
	33:  "dup2",
	39:  "getpid",
	41:  "socket",  // security-relevant: network
	42:  "connect", // security-relevant: network (reverse shells)
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	48:  "shutdown",
	49:  "bind",   // security-relevant: network
	50:  "listen", // security-relevant: network
	51:  "getsockname",
	52:  "getpeername",
	54:  "setsockopt",
	55:  "getsockopt",
	56:  "clone",  // security-relevant: process creation
	57:  "fork",   // security-relevant: process creation
	58:  "vfork",  // security-relevant: process creation
	59:  "execve", // security-relevant: running new programs
	60:  "exit",
	61:  "wait4",
	62:  "kill", // security-relevant: signalling other processes
	63:  "uname",
	72:  "fcntl",
	78:  "getdents",
	79:  "getcwd",
	80:  "chdir",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	85:  "creat",
	86:  "link",
	87:  "unlink", // security-relevant: deleting files
	88:  "symlink",
	89:  "readlink",
	90:  "chmod", // security-relevant: permission changes
	92:  "chown", // security-relevant: ownership changes
	95:  "umask",
	96:  "gettimeofday",
	97:  "getrlimit",
	99:  "sysinfo",
	100: "times",
	101: "ptrace", // security-relevant: debugging/injection/anti-debug
	102: "getuid",
	104: "getgid",
	105: "setuid", // security-relevant: privilege changes
	106: "setgid", // security-relevant: privilege changes
	107: "geteuid",
	108: "getegid",
	110: "getppid",
	113: "setreuid",
	137: "statfs",
	138: "fstatfs",
	157: "prctl",
	158: "arch_prctl",
	186: "gettid",
	202: "futex",
	217: "getdents64",
	218: "set_tid_address",
	228: "clock_gettime",
	230: "clock_nanosleep",
	231: "exit_group",
	234: "tgkill",
	257: "openat", // the modern open; very common in any file access
	258: "mkdirat",
	260: "fchownat",
	262: "newfstatat",
	263: "unlinkat",
	268: "fchmodat",
	272: "unshare", // security-relevant: namespace creation
	273: "set_robust_list",
	280: "utimensat",
	281: "epoll_pwait",
	288: "accept4",
	290: "eventfd2",
	291: "epoll_create1",
	292: "dup3",
	293: "pipe2",
	302: "prlimit64",
	317: "seccomp", // security-relevant: syscall filtering
	318: "getrandom",
	319: "memfd_create", // security-relevant: fileless execution
	322: "execveat",     // security-relevant: running new programs
	332: "statx",
	334: "rseq", // per-thread restartable sequences; common in modern libc/musl startup
	435: "clone3", // modern process creation
	439: "faccessat2",
}
