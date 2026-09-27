# sentri

A minimal container runtime built from scratch in Go — Linux namespaces,
cgroups v2, and filesystem isolation — with an integrated **syscall-level
anomaly detector** that learns a "normal" syscall profile per image and flags
deviations at runtime.

This is a learning / portfolio project. It is **not** a production sandbox; see
"Limitations" (added in a later milestone) for an honest account of what it does
and does not guarantee.

> ⚠️ **Linux + root required.** sentri uses `clone()` namespace flags, cgroups
> v2, `pivot_root`, and `ptrace` — Linux-only kernel features. It does not run
> on macOS or Windows. Run it on a real Linux machine, VM, or cloud instance,
> as **root / with `sudo`** (creating namespaces needs `CAP_SYS_ADMIN`).

## Build status

Built milestone by milestone against `docs/spec.md`.

- [x] **Milestone 1 — Process isolation via namespaces** (PID, UTS, mount)
- [x] **Milestone 2 — Filesystem isolation** (`pivot_root` onto an Alpine rootfs)
- [ ] Milestone 3 — Resource limiting via cgroups v2
- [ ] Milestone 4 — Syscall tracing
- [ ] Milestone 5 — Baseline learner
- [ ] Milestone 6 — Real-time anomaly detection
- [ ] Milestone 7 — Documentation and polish

## Quick start

```bash
# 1. Build the binary (on the Linux box):
go build -o sentri .

# 2. Obtain a root filesystem into ./rootfs  (see next section)

# 3. Run an isolated shell (root required for namespaces + pivot_root):
sudo ./sentri run /bin/sh
```

Inside the shell you should see it running as PID 1, with its own hostname, its
own process tree, **and** the Alpine root filesystem instead of the host's.

## Obtaining a root filesystem

`sentri` does **not** implement an image registry client (out of scope — see the
spec's Non-Goals). Instead you populate `./rootfs` with a minimal Alpine root
filesystem once, and every `sentri run` pivots into it.

**Recommended — download the official Alpine minirootfs** (no Docker needed).
Run this from the project root on the Linux box:

```bash
# Grab the current stable Alpine minirootfs and extract it into ./rootfs.
# 'latest-stable' always points at the current Alpine release, so we scrape the
# exact filename from the release directory rather than hard-coding a version.
BASE=https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64
FILE=$(curl -s "$BASE/" | grep -o 'alpine-minirootfs-[0-9.]*-x86_64.tar.gz' | sort -u | head -1)
curl -LO "$BASE/$FILE"
sudo tar -xzf "$FILE" -C rootfs        # sudo so file ownership (root) is preserved
```

**Alternative — export it from Docker** (if you already have Docker):

```bash
docker export "$(docker create alpine)" | sudo tar -C rootfs -xf -
```

Either way, verify it worked:

```bash
cat rootfs/etc/os-release   # should say Alpine Linux
ls rootfs/bin               # should list busybox and friends
```

`rootfs/` is git-ignored (it's large and easy to re-fetch), so it is never
committed.

## Why `pivot_root`, not plain `chroot`

`chroot(2)` only changes which directory the process treats as `/` for path
lookups. It does **not** move mounts or sever the process from the host, so a
process still running as root can escape a `chroot` jail: because `chroot`
leaves your working directory untouched, you can hold a directory file
descriptor (or CWD) *outside* the new root, `chroot` into a subdirectory, then
`chdir("..")` repeatedly to climb back above the jail and `chroot(".")` on the
real root — landing back in the host filesystem.

`pivot_root(2)`, combined with the mount namespace (`CLONE_NEWNS`), is stronger:
it swaps the actual **root mount** of our private mount namespace to the Alpine
rootfs and then **unmounts the old host root entirely** (`MNT_DETACH`). After
that, the host filesystem is not merely hidden from path resolution — it is not
mounted in our namespace at all, so the "climb upward" escape has nowhere to go.

**Honest caveat:** `pivot_root` alone is *not* a security sandbox. The container
still runs as real root with full capabilities and the entire syscall surface.
True hardening also requires a **user namespace** (so container-root ≠
host-root), **dropping capabilities**, and **seccomp** syscall filtering — none
of which `sentri` does yet. This is documented, not hidden; see Limitations.

## Milestone 1 — what's isolated (and what isn't yet)

`sentri run` places the process in three new Linux namespaces:

| Flag | Namespace | What it gives the container |
|------|-----------|-----------------------------|
| `CLONE_NEWPID` | PID | Its own process-ID space; the shell is PID 1 and cannot see host processes. |
| `CLONE_NEWUTS` | UTS | Its own hostname, changeable without affecting the host. |
| `CLONE_NEWNS`  | Mount | Its own mount table, so mounting a fresh `/proc` stays private to the container. |

Namespaces isolate **visibility**, not consumption:

- ~~The container still shares the host filesystem.~~ **Done in Milestone 2** —
  `pivot_root` switches the container onto the Alpine rootfs; `ls /` and
  `cat /etc/os-release` now show Alpine, not the host.
- It still shares the **host network**.
- It has **no resource limits** — fixed in Milestone 3 with cgroups v2.

## Milestone 2 — filesystem isolation

Once the container is in its own mount namespace (from Milestone 1), the child:

1. Marks its mount tree **private** so nothing propagates to the host.
2. **Bind-mounts** `./rootfs` onto itself (pivot_root needs the new root to be a
   real mount point).
3. Calls **`pivot_root`** to make the Alpine rootfs its `/` and park the old root
   at `/.pivot_old`.
4. Mounts a fresh **`/proc`** inside the new root (so `ps` works).
5. **Detaches** the old root (`MNT_DETACH`) and removes the stash directory —
   after this the host filesystem is gone from the container's view.

See [`isolation/filesystem.go`](isolation/filesystem.go) for the fully commented
implementation and the chroot-escape explanation.
