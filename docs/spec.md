# `sentri` — Project Specification

**Purpose of this document:** this is a build spec for an AI coding agent (Claude Code / Codex) to work from, milestone by milestone. Feed it one milestone at a time — do not ask the agent to implement the whole thing in one pass. Each milestone has explicit acceptance criteria; do not move to the next milestone until the current one's criteria are verifiably met.

**Environment note — read before starting:** this project requires Linux kernel features (`clone()` with namespace flags, cgroups v2, `ptrace`/`seccomp`) that do not work natively on macOS or Windows. Development must happen on a real Linux machine, a Linux VM, or a cloud Linux instance (e.g. a small EC2 box — this doubles as legitimate AWS experience). Confirm the dev environment before Milestone 1, and confirm root/sudo access is available, since namespace and cgroup operations require elevated privileges.

---

## 1. Project Overview

**Name:** `sentri`

**One-line description:** A minimal container runtime built from scratch in Go (namespaces, cgroups, filesystem isolation) with an integrated syscall-level anomaly detector that flags containers behaving outside their learned-normal syscall profile.

**Core novelty (the USP):** Standard "build your own Docker" projects stop at isolation. `sentri` adds a security layer *inside* the runtime itself: it traces every syscall a container process makes, learns a baseline "normal" syscall profile per container image during a training run, and flags real-time deviations from that baseline during subsequent runs — effectively a purpose-built, lightweight intrusion detection system (comparable in spirit to Falco) rather than isolation-only tooling with security bolted on separately.

**Primary goal:** produce a working, demoable systems project showing OS/kernel-level competence (namespaces, cgroups, syscalls) combined with a security-engineering angle (anomaly detection, baseline profiling) — directly relevant to cloud infrastructure and security-conscious engineering roles.

---

## 2. Goals and Non-Goals

### Goals
- Working process isolation via Linux namespaces (PID, UTS, mount at minimum)
- Resource limiting via cgroups v2 (CPU, memory)
- Filesystem isolation via `chroot`/`pivot_root`, running a real minimal root filesystem (e.g. Alpine)
- A CLI (`sentri run`, `sentri ps`, `sentri exec`, `sentri logs`) usable end-to-end
- A syscall tracer (via `ptrace` or `seccomp`) capturing every syscall a container makes
- A baseline learner that profiles normal syscall behaviour per image
- An anomaly detector flagging deviations from that baseline in real time, with a working demo showing it catch a simulated compromise
- Clean, well-commented code the author can explain and defend, including its limitations, in an interview

### Non-Goals (explicitly out of scope — do not implement unless asked)
- Full OCI image format compatibility — a simplified image-pulling mechanism (e.g. manually extracting a pre-downloaded Alpine rootfs tarball) is sufficient; do not build a full registry client unless time allows as a stretch goal
- Full networking (bridge + veth + NAT) — out of scope for this spec's core milestones; note as a stretch goal only, do not let it block finishing the security-detection milestones, which are the actual USP
- Multi-host orchestration / scheduling
- Production-grade sandboxing robustness — this is a demonstration of understanding, not a hardened production sandbox, and the README should say so explicitly (overclaiming security guarantees here would be a credibility risk in an interview, not a strength)

---

## 3. Architecture

```
sentri/
├── go.mod
├── main.go                     # CLI entrypoint (cobra or plain flag-based subcommands)
├── cmd/
│   ├── run.go                    # `sentri run <image>`
│   ├── ps.go                       # `sentri ps`
│   └── exec.go                    # `sentri exec`
├── isolation/
│   ├── namespaces.go        # clone() with namespace flags
│   ├── filesystem.go           # chroot/pivot_root, rootfs setup
│   └── cgroups.go              # cgroups v2 setup, CPU/memory limits
├── rootfs/
│   └── (fetched/extracted minimal Alpine rootfs, gitignored — document how to obtain it)
├── monitor/
│   ├── tracer.go                  # ptrace/seccomp syscall tracing
│   ├── baseline.go             # baseline profile learner + persistence (JSON on disk is fine)
│   └── detector.go             # real-time anomaly detection against baseline
├── demo/
│   └── compromised_payload/  # a benign "simulated attacker" script for the demo scenario
└── README.md
```

### Key design decisions to make explicit in code comments
- Why `ptrace` vs `seccomp` was chosen (or both — `seccomp-bpf` with `SECCOMP_RET_TRACE` combines filtering efficiency with `ptrace`'s ability to inspect args) — this is a real engineering trade-off (performance overhead vs inspection depth) worth being explicit about
- How the baseline profile is structured — per-syscall frequency counts? Sequence-based (n-gram of syscalls, another nice callback to the dissertation if you want to extend the theme)? State clearly which was chosen and why
- What counts as "anomalous" — a fixed threshold, a statistical outlier measure, or simply "never seen in baseline"? Document the exact rule

---

## 4. Milestones

### Milestone 1 — Process isolation via namespaces
**Goal:** Run a shell inside an isolated process using PID and UTS namespaces, proving isolation works.

**Tasks:**
1. Initialise `go.mod`, project structure as above.
2. Implement `isolation/namespaces.go`: use `syscall.SysProcAttr` with `Cloneflags` (`CLONE_NEWPID`, `CLONE_NEWUTS`, `CLONE_NEWNS` at minimum) to launch a child process (e.g. `/bin/sh`) in new namespaces.
3. Implement `sentri run` (`cmd/run.go`) to invoke this and drop the user into an interactive shell inside the new namespace.

**Acceptance criteria:**
- Running `sentri run /bin/sh` drops into a shell.
- Inside that shell, `ps aux` (or `ps` if busybox) shows only the container's own processes — the isolated process should see itself as PID 1, not its real host PID.
- `hostname` inside the container can be changed independently of the host (proves UTS namespace isolation) — set a distinct hostname on entry and confirm the host's own hostname is unaffected.
- Exiting the shell cleanly tears down the process.

**Explicitly ask the agent to comment:** what each `CLONE_NEW*` flag actually isolates, and why PID namespace alone doesn't give filesystem or network isolation (sets up the following milestones correctly).

---

### Milestone 2 — Filesystem isolation with a real rootfs
**Goal:** The container runs inside a real minimal Linux root filesystem (Alpine), isolated from the host filesystem via `chroot`/`pivot_root`.

**Tasks:**
1. Document (in README, not code) how to obtain a minimal rootfs — e.g. `docker export $(docker create alpine) | tar -C rootfs -xvf -`, or downloading an official Alpine minirootfs tarball directly. Do not implement a registry client for this.
2. Implement `isolation/filesystem.go`: use `pivot_root` (preferred over plain `chroot` — explain why in comments: `pivot_root` fully detaches the old root, `chroot` alone is escapable) to switch the container process's root to the extracted Alpine rootfs before `exec`ing the shell.
3. Mount `/proc` inside the new root so `ps` and friends work correctly (this requires the `CLONE_NEWNS` mount namespace from Milestone 1 plus an explicit `mount -t proc proc /proc` inside the container).

**Acceptance criteria:**
- Inside `sentri run /bin/sh`, `ls /` shows the Alpine filesystem, not the host's.
- `cat /etc/os-release` inside the container shows Alpine, confirming true filesystem isolation.
- `ps aux` continues to work correctly (proves `/proc` was mounted correctly inside the new root).
- Deliberately test the escape case commented in code: explain (in comments/README, not necessarily as working exploit code) why plain `chroot` without `pivot_root` and without dropping capabilities is escapable — this is a well-known point and shows security awareness.

---

### Milestone 3 — Resource limiting via cgroups v2
**Goal:** Limit CPU and memory available to the container process, and prove the limit is enforced.

**Tasks:**
1. Implement `isolation/cgroups.go`: create a new cgroup under `/sys/fs/cgroup/sentri/<container-id>/`, write CPU (`cpu.max`) and memory (`memory.max`) limits, and add the container's PID to `cgroup.procs`.
2. Wire this into `sentri run` with flags, e.g. `--memory 100m --cpus 0.5`.
3. Clean up the cgroup on container exit.

**Acceptance criteria:**
- With `--memory 50m`, running a deliberate memory-hog process inside the container (e.g. a small script that allocates memory in a loop) gets OOM-killed once it exceeds the limit — verify by checking the process's exit status/dmesg, not just assuming.
- With `--cpus 0.5`, a CPU-bound busy-loop inside the container measurably uses no more than ~50% of one core on the host (verify with `top`/`htop` on the host during the test, or a more precise measurement if the agent suggests one).
- Cgroup directory is cleaned up after the container process exits (verify it no longer exists under `/sys/fs/cgroup/sentri/`).

---

### Milestone 4 — Syscall tracing
**Goal:** Capture every syscall the container process makes, logged with enough detail (syscall name, key arguments, timestamp) to build a baseline from later.

**Tasks:**
1. Implement `monitor/tracer.go`: attach to the container's process using `ptrace(PTRACE_SYSCALL)` (or set up a `seccomp-bpf` filter with `SECCOMP_RET_TRACE` if the agent recommends this combined approach — document whichever is chosen and why in code comments).
2. Resolve syscall numbers to human-readable names (a lookup table exists in `golang.org/x/sys/unix` or can be hand-maintained for the common set — connect, execve, fork, open, socket, ptrace itself, etc. — don't need every syscall, focus on security-relevant ones).
3. Output a structured log (JSON lines are ideal — easy to parse later for the baseline learner) of `{timestamp, syscall_name, pid, args}` for each traced syscall.

**Acceptance criteria:**
- Running a known workload inside the container (e.g. `cat /etc/hostname`) produces a log clearly showing the expected syscalls (`openat`, `read`, `close`, etc.) in order.
- Tracing overhead is acknowledged and roughly measured (compare execution time of a benchmark command with and without tracing attached) — this is a real trade-off worth being able to quote a number for.

---

### Milestone 5 — Baseline learner
**Goal:** From one or more "known good" training runs of a given container image, build and persist a normal syscall profile.

**Tasks:**
1. Implement `monitor/baseline.go`: aggregate syscall logs from Milestone 4 into a profile per image — decide and document the exact structure (recommended: frequency count per syscall name, plus optionally a simple sequence/bigram model of syscall order — the bigram approach is a nice deliberate callback to the dissertation's n-gram work if time allows, but a frequency-count baseline is a perfectly acceptable MVP; do not let this become scope creep that blocks Milestone 6).
2. Persist the profile to disk as JSON, keyed by image name/tag.
3. Add a `sentri train <image>` command that runs a workload and saves its resulting profile as the baseline for that image.

**Acceptance criteria:**
- `sentri train alpine` (running some representative workload) produces a saved baseline JSON file.
- The baseline correctly reflects the syscalls actually observed (spot-check against the raw trace log from Milestone 4).

---

### Milestone 6 — Real-time anomaly detection
**Goal:** On subsequent container runs, compare live syscall activity against the saved baseline and flag deviations as they happen.

**Tasks:**
1. Implement `monitor/detector.go`: for each syscall observed live, check against the baseline — flag if the syscall was never seen in the baseline for this image, or (if using frequency-based scoring) if its rate is a significant outlier from the baseline rate. State the exact threshold/rule used, in comments and README — do not leave this as an unexplained magic number.
2. On flag, emit a structured alert (stdout is fine for the demo; a stubbed webhook call is a nice polish touch but not required) including syscall name, container ID, and why it was flagged.
3. Add a `--monitor` flag to `sentri run` to enable live detection against a previously trained baseline for that image.

**Acceptance criteria:**
- Running the container normally (same workload as training) produces no false-positive alerts.
- **Demo scenario (the headline artifact for this project):** place a small "simulated compromise" script in `demo/compromised_payload/` that does something a normal workload wouldn't — e.g. opens a reverse-shell-style socket connection, or spawns an unexpected child process, or calls `ptrace` on itself (a classic anti-debugging/injection technique). Running this inside `sentri run --monitor` must produce a clear, real-time alert flagging the anomalous syscall(s).
- Record a short screen capture of this demo running — this is the single most valuable artifact from the whole project for a CV/portfolio link, more valuable than any code snippet.

---

### Milestone 7 — Documentation and polish
**Goal:** A README that stands on its own for a recruiter or interviewer skimming the repo, and an honest account of the project's real security limitations.

**Tasks:**
1. Architecture diagram showing the flow: CLI → namespace/cgroup/filesystem isolation → running container → syscall tracer → baseline/detector.
2. Plain-language explanation of the anomaly detection approach and its link to prior SIEM/IPS home-lab work.
3. The demo scenario, embedded (link to the screen recording, plus the raw alert output as text/log excerpt).
4. Instructions to run locally, including the Linux/root requirement called out prominently at the top.
5. An explicit **"Limitations and what this is not"** section: this is not a production-grade sandbox, `ptrace`-based tracing has known bypasses and performance overhead, baseline-based anomaly detection has false-positive/false-negative trade-offs inherent to the approach, and this doesn't implement full seccomp-profile enforcement (only detection, not blocking) unless that was added as a stretch goal. Being upfront about this is a strength, not a weakness — it shows mature security thinking rather than overclaiming.

**Acceptance criteria:**
- A person who has never seen the code can read the README, watch the demo, and understand what the project proves and what it explicitly does not claim to solve, in under 5 minutes.

---

## 5. Testing Standards (apply throughout, not just at the end)
- Where kernel interaction makes traditional unit testing impractical (e.g. `clone()` with namespace flags), favour integration-style tests that actually spin up a container and assert on observable outcomes (process count inside, hostname, cgroup limits enforced) rather than skipping tests entirely.
- Pure logic components (baseline aggregation, anomaly scoring) should have proper unit tests independent of any real container/kernel interaction — feed them synthetic syscall logs.

## 6. Interview-Readiness Checklist (self-check before calling this project "done")
- [ ] Can explain what each `CLONE_NEW*` flag isolates and what namespaces alone do *not* provide (no resource limits, no filesystem isolation without additional steps)
- [ ] Can explain why `pivot_root` is preferred over plain `chroot` for container filesystem isolation
- [ ] Can explain how cgroups v2 enforce the CPU/memory limits at the kernel level
- [ ] Can explain the `ptrace`/`seccomp` trade-off made and its performance overhead
- [ ] Can explain exactly how the baseline is built and what counts as an anomaly, including the threshold/rule used
- [ ] Can talk through the demo scenario end to end and what real-world attack pattern it's modelling
- [ ] Can name at least two concrete limitations of this system's security guarantees, unprompted
