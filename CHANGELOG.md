# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and commit subjects
follow [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

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
