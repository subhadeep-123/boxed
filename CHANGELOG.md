# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and commit subjects
follow [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

Adds a layered overlayfs root filesystem as an alternative to a flat `--rootfs`,
extends cgroup resource limits beyond CPU and memory, runs the container command
under a minimal PID 1 init that reaps zombies and forwards signals, and stops a
container process from leaking when setup fails after it has been cloned.

### Features

- Four more cgroup v2 controllers: `--pids-limit` caps the number of tasks,
  `--cpuset-cpus` and `--cpuset-mems` pin a container to specific CPUs and
  NUMA nodes, and a repeatable `--io-max` caps block IO throughput per
  device. `--pids-limit` is the one that protects the host rather than the
  container: a fork bomb exhausts the system-wide PID table, and nothing
  else in the set prevents that.
- Controllers are now enabled by probing the parent cgroup's own
  `cgroup.controllers` — the set actually delegated to it — instead of
  writing a hardcoded `+cpu +memory`. Requesting a controller the kernel
  has not delegated fails with a message naming the flag and listing what
  is available, rather than a bare `ENOENT` from the write.
- `--io-max` takes a device path (`/dev/sda:wbps=1048576`) rather than a
  raw `MAJ:MIN` pair, resolving it through `stat(2)` and rejecting anything
  that is not a block device. Note only direct IO is throttled: buffered
  writes return from page cache and are flushed later by writeback, outside
  the cgroup's accounting.
- Malformed limits are rejected immediately after argument parsing, before
  the container is cloned, so a typo no longer costs a spawned and killed
  child process.
- Limit flags are grouped under a "Resource limits" heading in `--help`.

- `--image <DIR>` stacks ordered layer subdirectories with overlayfs
  (read-only lowers, an ephemeral per-run upper/work scratch) into one
  merged directory, which then pivot_roots through the existing
  `setup_rootfs` unchanged. This is what makes container image layers and
  copy-on-write isolation possible, instead of mutating a single flat
  rootfs directly. `--image` and `--rootfs` are mutually exclusive.
- Ephemeral scratch directories are torn down on the host after the
  container exits. They are keyed by the PID of `boxed` itself, chosen
  before the clone: inside its new PID namespace the child sees itself as
  PID 1, so its own PID cannot name a per-run directory. Teardown first
  restores the read bit on overlayfs's private `work/work` directory,
  which the kernel creates with mode 000 and which a rootless user could
  not otherwise remove.
- The container command now runs under a minimal init shim instead of being
  PID 1 itself. The shim is a fork of `boxed` taken after capabilities are
  dropped and seccomp is applied, so it stays inside the same boundary as the
  command. It reaps every process reparented to it, forwards `SIGINT`,
  `SIGTERM` and `SIGHUP` to the command, and exits with the command's status
  (`128 + N` when the command was killed by signal N). Those signals are
  blocked across the fork, so one that arrives before forwarding is ready is
  delivered late rather than lost. Visible changes: the command is PID 2
  (`echo $$` prints `2`, and `/proc/1/comm` reads `boxed`); a command that
  cannot be executed exits `127` instead of `1`; `--pids-limit` counts the
  shim, so a limit below 2 cannot start anything; and a custom
  `--seccomp-profile` allowlist must permit `clone`, `wait4`, `kill`,
  `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn` and `exit_group`.

### Bug Fixes

- `--rootless` no longer fails with `EACCES` on a root-owned rootfs.
  `pivot_root` now uses the `pivot_root(".", ".")` sequence from
  `pivot_root(2)` instead of creating an `old_root` directory inside the
  rootfs, which an unmapped owner makes unwritable even to namespace root.
  `/proc` is now mounted before the pivot, since a user namespace may only
  mount a new proc while the host's is still visible, which it no longer is
  once the old root is detached. `tmp_setup.sh` also extracts `/tmp/minirootfs` as the invoking user so the
  rootless container can write to it.
- A failure in parent-side setup after the clone (uid/gid mapping, cgroup
  creation) no longer leaves the container process blocked forever. The
  child inherited its own copy of the sync pipe's write end, so its read
  could never see EOF. It now closes that copy first, and the parent closes
  its end and reaps the child before returning the error, so the cgroup is
  removed only after the child has left it.
- The container command no longer inherits both ends of the parent/child
  sync pipe: the pipe is created with `O_CLOEXEC`.
- Ctrl-C and `SIGTERM` now stop a running container. The command used to be
  PID 1 of its namespace, and the kernel discards a signal sent to a
  namespace init that has no handler for it, even when it comes from the
  host, so the signal `boxed` forwarded was silently ignored.
- Processes orphaned inside a container are reaped instead of piling up as
  zombies, each of which kept a slot counted against `--pids-limit`.

## [0.3.1] - 2026-07-25

Replaces chroot with pivot_root for real root filesystem isolation.

### Features

- Container root isolation now uses `pivot_root` instead of `chroot`. `chroot`
  only redirects path resolution for `/`; it never removed the host's mount
  table, which is copied into the container's mount namespace at `clone()`
  time. `pivot_root` swaps which mount is root and detaches the old one via
  `umount2(MNT_DETACH)`, so the host filesystem is genuinely unreachable from
  inside the container rather than merely hidden from view.

## [0.3.0] - 2026-07-24

Adds seccomp-bpf syscall filtering.

### Features

- Seccomp filtering: OCI seccomp profiles are parsed and validated, then
  compiled into BPF filters and installed before `exec`. The default policy
  is now deny-by-default rather than an allowlist, and `no_new_privs` is set
  unconditionally so a contained process can't regain privileges it dropped.

### Bug Fixes

- The seccomp test fixture profile is now portable across environments
  instead of assuming a specific host architecture.

## [0.2.0] - 2026-07-19

Adds rootless mode: containers can now run inside a user namespace without
requiring root on the host.

### Features

- Rootless containers via an optional `CLONE_NEWUSER`, with configurable
  UID/GID mapping between host and namespace through `--host-uid`/`--host-gid`.
  `--uid`/`--gid` now consistently mean the in-namespace identity.
- Parent and child now synchronize namespace setup over a pipe instead of
  racing, closing a window where the child could run before its namespace
  was fully configured.
- `make nonroot` runs the runtime end-to-end without `sudo`.

### Bug Fixes

- `--host-uid`/`--host-gid` are validated before the child is spawned, and a
  sync-pipe EOF is no longer mistaken for a valid go-ahead signal.
- Fallible calls across the rootless/namespace/process code paths now carry
  error context instead of failing silently.

### Refactoring

- The child spawn and cgroup lifecycle were restructured into
  `ChildContext`/`RuntimeConfig`, and `run_in_namespace`'s flat parameter list
  was replaced with a config struct, ahead of adding rootless support.

## [0.1.0] - 2026-06-29

Initial release: a CLI that spawns a process into PID/UTS/mount/net
namespaces, chroots it into a supplied root filesystem, applies cgroups v2
CPU/memory limits, and drops capabilities before handing off control.

### Features

- CLI with subcommands for running a containerized process.
- Process spawning via `fork()`/`execvp()`/`waitpid()`, with signal
  forwarding to the contained process.
- Namespace isolation (PID, UTS, mount, net) via `clone()`.
- Chroot-based rootfs setup, with `/proc` mounted inside and the root made
  private to prevent mount events leaking to the host.
- cgroups v2 integration for CPU and memory limits.
- Capability dropping via `prctl()`.

[Unreleased]: https://github.com/subhadeep-123/boxed/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/subhadeep-123/boxed/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/subhadeep-123/boxed/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/subhadeep-123/boxed/releases/tag/v0.1.0
