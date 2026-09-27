package isolation

// cgroups.go implements Milestone 3: limiting the container's CPU and memory
// with cgroups v2, and cleaning the cgroup up on exit.
//
// ===========================================================================
// NAMESPACES vs CGROUPS  (a distinction worth being crisp about)
// ===========================================================================
// Namespaces (Milestones 1-2) control what a process can SEE. Cgroups control
// what a process can USE. They are completely separate kernel mechanisms:
//   - a namespace gives a private view of a resource (PIDs, mounts, hostname);
//   - a cgroup ("control group") accounts for and CAPS consumption of a
//     resource (CPU time, memory, IO) for a group of processes.
// You can have one without the other. sentri uses both.
//
// ===========================================================================
// HOW cgroups v2 ENFORCES LIMITS  (the mechanism, for interviews)
// ===========================================================================
// cgroups v2 is a single unified hierarchy mounted at /sys/fs/cgroup. Each
// directory IS a cgroup; creating a directory creates a cgroup, and the kernel
// fills it with control files. You:
//   1. create a cgroup directory,
//   2. write limits into its interface files (memory.max, cpu.max),
//   3. put a process in it (by writing to cgroup.procs, or — as we do — by
//      cloning the process directly into it),
// and the kernel enforces the limits in the scheduler / memory subsystem:
//   - memory.max: if the cgroup's memory usage would exceed this and memory
//     can't be reclaimed, the kernel OOM-kills a process INSIDE this cgroup
//     (not the host, not other containers).
//   - cpu.max = "QUOTA PERIOD": the cgroup may consume QUOTA microseconds of CPU
//     per PERIOD microseconds; the scheduler throttles it once the quota for the
//     current window is spent.
//
// Two cgroups v2 RULES this code respects:
//   - A controller (cpu, memory) is only usable in a cgroup if its PARENT has
//     enabled it for children via "+<ctrl>" in the parent's
//     cgroup.subtree_control. So we enable controllers on our `sentri` parent
//     BEFORE creating the leaf, else the leaf has no memory.max / cpu.max files.
//   - "No internal processes": a (non-root) cgroup can't both hold processes and
//     enable controllers for children. Fine here: `sentri` holds only
//     sub-cgroups; the leaf holds the process but enables nothing further.
//
// Layout we build:
//
//   /sys/fs/cgroup/                 (root, managed by systemd)
//     └── sentri/                   (our parent; delegates cpu/memory downward)
//           └── <container-id>/     (leaf; the container runs here, limits set)

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	cgroupRoot       = "/sys/fs/cgroup" // the cgroup v2 unified mount point
	cgroupParentName = "sentri"         // our parent cgroup under the root
	cpuPeriod        = 100000           // 100 ms scheduling window, in microseconds
)

// containerID returns a short random hex id used to name this container's
// cgroup directory (and, later, other per-container state).
func containerID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Extremely unlikely; fall back to the PID for a still-unique-ish name.
		return fmt.Sprintf("c%d", os.Getpid())
	}
	return hex.EncodeToString(b) // 8 hex characters, e.g. "1a2b3c4d"
}

// setupCgroup creates a cgroup v2 cgroup for one container, applies the memory
// and CPU limits, and returns:
//   - an OPEN *os.File for the leaf cgroup directory (the caller passes its fd
//     to the kernel via CLONE_INTO_CGROUP so the child is born inside it), and
//   - a cleanup func that removes the cgroup once the container has exited.
//
// memoryBytes <= 0 means "no memory limit"; cpus <= 0 means "no CPU limit".
func setupCgroup(id string, memoryBytes int64, cpus float64) (*os.File, func(), error) {
	// Which controllers do we actually need to enable?
	var needed []string
	if memoryBytes > 0 {
		needed = append(needed, "memory")
	}
	if cpus > 0 {
		needed = append(needed, "cpu")
	}

	parentPath := filepath.Join(cgroupRoot, cgroupParentName)
	leafPath := filepath.Join(parentPath, id)

	// (1) Ensure the ROOT delegates our controllers down to its children. On
	// systemd distros cpu+memory are already delegated at the root, and writing
	// "+cpu +memory" again is an idempotent no-op. We treat any error here as
	// non-fatal — the real requirement is that our `sentri` parent (below) ends
	// up able to enable them; if it can't, that's where we surface the error.
	_ = delegateControllers(cgroupRoot, needed)

	// (2) Create our parent cgroup. Creating a directory under the cgroup2 mount
	// IS creating a cgroup; the kernel populates it with the interface files.
	if err := os.MkdirAll(parentPath, 0755); err != nil {
		return nil, nil, fmt.Errorf("create %s: %w", parentPath, err)
	}

	// (3) Enable the needed controllers for `sentri`'s children (the leaf).
	if err := delegateControllers(parentPath, needed); err != nil {
		return nil, nil, fmt.Errorf("enable %v on %s: %w\n"+
			"       (need cgroups v2 with cpu+memory delegated; check "+
			"`cat /sys/fs/cgroup/cgroup.controllers`)", needed, parentPath, err)
	}

	// (4) Create the leaf cgroup for THIS container.
	if err := os.Mkdir(leafPath, 0755); err != nil {
		return nil, nil, fmt.Errorf("create %s: %w", leafPath, err)
	}
	// From here on, on any error, remove what we made.
	cleanup := func() { removeCgroup(leafPath, parentPath) }

	// (5) Write the limits INTO the leaf, BEFORE any process is placed there, so
	// the process is constrained from birth.
	if memoryBytes > 0 {
		// Hard memory limit in bytes. Exceeding it (when memory can't be
		// reclaimed) triggers an OOM-kill of a process in THIS cgroup only.
		if err := writeCgroupFile(leafPath, "memory.max", strconv.FormatInt(memoryBytes, 10)); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	if cpus > 0 {
		// cpu.max is "QUOTA PERIOD" in microseconds. quota = cpus * period, so
		// 0.5 cpus -> "50000 100000" = at most 50 ms of CPU per 100 ms = half a
		// core. int64() truncates fractional microseconds, which is fine.
		quota := int64(cpus * float64(cpuPeriod))
		if err := writeCgroupFile(leafPath, "cpu.max", fmt.Sprintf("%d %d", quota, cpuPeriod)); err != nil {
			cleanup()
			return nil, nil, err
		}
	}

	// (6) Open the leaf DIRECTORY so the caller can hand its fd to the kernel via
	// SysProcAttr.CgroupFD/UseCgroupFD (CLONE_INTO_CGROUP). Opening a directory
	// read-only is valid on Linux and gives us the fd we need.
	f, err := os.Open(leafPath)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("open cgroup dir %s: %w", leafPath, err)
	}

	return f, cleanup, nil
}

// delegateControllers enables the given controllers for a cgroup's children by
// writing e.g. "+cpu +memory" to <dir>/cgroup.subtree_control.
func delegateControllers(dir string, ctrls []string) error {
	if len(ctrls) == 0 {
		return nil
	}
	var b strings.Builder
	for i, c := range ctrls {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("+")
		b.WriteString(c)
	}
	return writeCgroupFile(dir, "cgroup.subtree_control", b.String())
}

// writeCgroupFile writes a single value to a cgroup interface file. cgroupfs
// files expect the whole value in ONE write() call; os.WriteFile does exactly
// one write, which is why it's the right tool here (a buffered writer that split
// the value across writes could be rejected).
func writeCgroupFile(dir, name, value string) error {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(value), 0644); err != nil {
		return fmt.Errorf("write %q to %s: %w", value, p, err)
	}
	return nil
}

// removeCgroup deletes the leaf cgroup (and the parent if it is now empty).
//
// A cgroup directory can only be rmdir'd once it has no member processes and no
// child cgroups. Two things can leave it briefly non-empty right after the
// container exits, both of which a naive single rmdir trips over:
//   - a straggler process (a grandchild that briefly outlives PID 1), and
//   - the kernel releasing the cgroup ASYNCHRONOUSLY, so an rmdir issued in the
//     microseconds after the process is reaped can still fail with EBUSY.
// So we (1) tell the kernel to kill anything left in the cgroup, then (2) retry
// the rmdir a few times with a short backoff. This is the standard way real
// runtimes make cgroup teardown reliable.
func removeCgroup(leafPath, parentPath string) {
	// (1) cgroup.kill: writing "1" SIGKILLs every process still in the cgroup
	// (a cgroups v2 feature, kernel >= 5.14). Best-effort — a no-op if empty.
	_ = os.WriteFile(filepath.Join(leafPath, "cgroup.kill"), []byte("1"), 0644)

	// (2) Retry rmdir until it succeeds or we give up (~1s total). os.Remove on
	// a directory issues rmdir(2), which the kernel handles specially for
	// cgroupfs (it tears the cgroup down).
	for i := 0; i < 20; i++ {
		if err := os.Remove(leafPath); err == nil {
			break // gone
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Best-effort: also remove our shared `sentri` parent, but this only
	// succeeds (and only should) if no other container is still using it —
	// rmdir fails harmlessly on a non-empty directory.
	_ = os.Remove(parentPath)
}

// parseMemory converts a human memory string ("50m", "1g", "512k", "1048576")
// into a byte count. Suffixes are binary: k = 1024, m = 1024^2, g = 1024^3; no
// suffix means bytes. Deliberately simple (single-letter suffixes only).
func parseMemory(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil // no limit
	}
	var mult int64 = 1
	switch s[len(s)-1] {
	case 'k', 'K':
		mult = 1 << 10
		s = s[:len(s)-1]
	case 'm', 'M':
		mult = 1 << 20
		s = s[:len(s)-1]
	case 'g', 'G':
		mult = 1 << 30
		s = s[:len(s)-1]
	case 'b', 'B':
		mult = 1
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid --memory value %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid --memory value: must not be negative")
	}
	return n * mult, nil
}
