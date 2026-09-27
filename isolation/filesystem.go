package isolation

// filesystem.go implements Milestone 2: switching the container onto a real,
// isolated root filesystem (an extracted Alpine rootfs) using pivot_root, and
// mounting a fresh /proc inside it.
//
// ===========================================================================
// WHY pivot_root INSTEAD OF plain chroot  (the spec asks us to justify this)
// ===========================================================================
// chroot(2) only changes which directory the calling process treats as "/" for
// resolving absolute pathnames. It does NOT move any mounts, and it does NOT
// remove the process's access to the rest of the host. That makes a chroot
// "jail" escapable by a process that still has root/CAP_SYS_CHROOT. The classic
// escape:
//
//   1. The process is (or becomes) root and can call chroot() again.
//   2. It opens a file descriptor to a directory OUTSIDE the intended jail
//      (or simply never chdir()s into the new root — chroot leaves the current
//      working directory where it was), e.g.  fd = open(".", O_RDONLY).
//   3. It calls chroot("somesubdir") to move the root "down".
//   4. Because its CWD/fd is now *above* the new root, it does
//      fchdir(fd) then chdir("../../../../..") repeatedly, climbing past the
//      jail to the real filesystem root, and finally chroot(".") there —
//      escaping into the host filesystem.
//
// The root cause is that chroot never severs the process from the host mount
// tree; it just changes a pointer used for path lookups.
//
// pivot_root(2), used together with the mount namespace (CLONE_NEWNS), is
// fundamentally stronger. It swaps the actual ROOT MOUNT of our (private) mount
// namespace to the new rootfs and lets us then UNMOUNT the old root entirely.
// After that there is no mount in our namespace that refers to the host
// filesystem at all — it isn't merely hidden from path resolution, it is
// detached. The "chdir upward" trick has nothing to climb into, because the old
// root is gone from this namespace.
//
// HONEST CAVEAT (worth stating in an interview, not hiding): pivot_root is not,
// by itself, a security sandbox. Our container process still runs as REAL root
// with CAP_SYS_ADMIN and the full syscall surface, so a determined process
// could still do damage (e.g. mknod a block device for the host disk and read
// it, load kernel modules, etc.). Production runtimes additionally: run the
// container as an unprivileged user via a USER namespace (so container-root is
// not host-root), DROP capabilities, and filter syscalls with seccomp. sentri
// deliberately does none of those yet — it demonstrates the isolation
// mechanism, and the README documents this as a known limitation.

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// pivotRoot switches the process's root filesystem to newRoot and mounts a
// fresh /proc inside it. It MUST run inside a mount namespace (CLONE_NEWNS),
// which the parent set up — otherwise every mount below would leak onto the
// host. It is called from Child() in namespaces.go before exec'ing the command.
func pivotRoot(newRoot string) error {
	// (1) Make our entire mount tree PRIVATE (recursively).
	//
	// On systemd distros like Ubuntu, "/" is a SHARED mount by default. In a
	// shared mount, mount/unmount events PROPAGATE to peer mounts — including
	// back to the host. Two reasons this matters here:
	//   - correctness: pivot_root refuses to operate if the new root has shared
	//     propagation (it would return EINVAL);
	//   - isolation: without this, our bind mount / pivot could affect the host.
	// The empty source + MS_PRIVATE is the canonical "change the propagation
	// type of this mount subtree" call; MS_REC applies it to everything under /.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / rprivate: %w", err)
	}

	// (2) pivot_root requires new_root to be a MOUNT POINT, not just a plain
	// directory. Bind-mounting the rootfs directory onto itself is the standard
	// trick to turn a directory into a mount point. MS_BIND makes the same files
	// appear at the target; MS_REC carries along any submounts.
	if err := syscall.Mount(newRoot, newRoot, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind-mount rootfs onto itself: %w", err)
	}

	// (3) pivot_root needs a directory INSIDE the new root in which to park the
	// OLD root. We create newRoot/.pivot_old for that. (0700 = owner-only.)
	putOld := filepath.Join(newRoot, ".pivot_old")
	if err := os.MkdirAll(putOld, 0700); err != nil {
		return fmt.Errorf("create put_old dir: %w", err)
	}

	// (4) THE SWITCH. pivot_root(new_root, put_old):
	//   - makes new_root the new "/" for our mount namespace, and
	//   - moves what used to be "/" (the host root) to put_old.
	// After the call, from our point of view the old root lives at
	// "/.pivot_old" (because put_old was newRoot/.pivot_old, and newRoot is now
	// "/").
	if err := syscall.PivotRoot(newRoot, putOld); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}

	// (5) Our current working directory may still be a reference into the OLD
	// root. Move it to the new "/" so we don't hold the old root busy and so
	// relative paths behave.
	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("chdir to new /: %w", err)
	}

	// (6) Mount a fresh /proc INSIDE the new root. As in Milestone 1, tools like
	// `ps` read /proc rather than calling the kernel directly, and the proc
	// filesystem is populated according to the mounting process's PID namespace
	// — so this gives correct, container-only process listings. The mount point
	// "/proc" is a directory that already exists inside the Alpine rootfs.
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("mount /proc in new root: %w", err)
	}

	// (7) Detach the OLD root. MNT_DETACH is a LAZY unmount: it removes the old
	// root from our namespace immediately, and frees it fully once nothing is
	// using it. This is the step that actually closes the chroot-style escape
	// route — afterwards the host filesystem simply isn't mounted here.
	if err := syscall.Unmount("/.pivot_old", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}

	// (8) Remove the now-empty stash directory so the container's "/" is clean
	// (no leftover /.pivot_old visible to the user).
	if err := os.Remove("/.pivot_old"); err != nil {
		return fmt.Errorf("remove put_old dir: %w", err)
	}

	return nil
}
