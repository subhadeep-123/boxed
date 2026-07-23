# boxed

[![CI](https://github.com/subhadeep-123/boxed/actions/workflows/ci.yml/badge.svg)](https://github.com/subhadeep-123/boxed/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

A container runtime built from scratch in Rust. Implements the same Linux primitives Docker uses under the hood — namespaces, cgroups v2, chroot, capability dropping, and seccomp-bpf syscall filtering — with no abstraction layers hiding what's happening.

It started as an exercise in understanding, at the syscall level, what a container actually is. It's grown into a real rootless runtime since — see [CHANGELOG.md](CHANGELOG.md) for what's shipped, and [open issues](https://github.com/subhadeep-123/boxed/issues) for where it's headed (OCI compliance, a microVM backend).

---

## Architecture

```text
boxed run --rootfs /tmp/minirootfs --cpu 50000 --memory 268435456 --rootless /bin/sh
      │
      ├── process.rs      fork() + execvp() + waitpid(), signal forwarding
      ├── namespace.rs    clone() with CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWNET
      ├── rootless.rs     optional CLONE_NEWUSER, host<->container uid/gid mapping
      ├── rootfs.rs       chroot() into Alpine rootfs, mount /proc
      ├── cgroups.rs      write to /sys/fs/cgroup/ to cap CPU and memory
      ├── capabilities.rs drop dangerous capabilities via prctl()
      └── seccomp.rs      compile an OCI seccomp profile (or default deny) into a BPF filter
```

---

## Prerequisites

- Linux with cgroups v2 (Ubuntu 22.04+ has this by default)
- Rust toolchain: `curl https://sh.rustup.rs | sh`
- Run commands with `sudo` (namespaces and cgroups require `CAP_SYS_ADMIN`)

**Optional — Alpine rootfs for filesystem isolation:**

```bash
wget https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.0-x86_64.tar.gz
mkdir -p /tmp/minirootfs
sudo tar -xzf alpine-minirootfs-3.19.0-x86_64.tar.gz -C /tmp/minirootfs
```

---

## Quick Start

```bash
git clone https://github.com/subhadeep-123/boxed.git
cd boxed
cargo build --release

# Run a command (no rootfs — just isolated namespaces)
sudo ./target/release/boxed run /bin/echo hello world

# Run a shell inside an isolated Alpine container
sudo ./target/release/boxed run \
  --rootfs /tmp/minirootfs \
  --cpu 50000 \
  --memory 268435456 \
  /bin/sh

# Same, but rootless — no sudo, via a user namespace (make nonroot wraps this)
./target/release/boxed run --rootfs /tmp/minirootfs --rootless /bin/sh

# Apply an OCI-style seccomp profile (see tests/fixtures for examples of
# the format); omitting this flag still applies boxed's own default-deny filter
sudo ./target/release/boxed run --seccomp-profile ./tests/fixtures/seccomp-profile-valid.json /bin/sh
```

Inside the container:

```text
/ $ hostname        # → boxed
/ $ ps -ef          # → only your shell (PID 1) and ps
/ $ cat /etc/os-release  # → Alpine Linux
/ $ exit
```

---

## Modules

| Module | What it does |
| --- | --- |
| `main.rs` | CLI entry point (`clap` derive). Parses `run` subcommand with `--rootfs`, `--cpu`, `--memory`, `--rootless`, `--seccomp-profile`. |
| `process.rs` | `fork()` + `execvp()` + `waitpid()`. Propagates exit codes. Signal forwarding. |
| `namespace.rs` | `clone()` with PID, UTS, MNT, NET (and optionally USER) namespace flags. Sets hostname to `boxed`. Parent/child sync over a pipe. |
| `rootless.rs` | Optional `CLONE_NEWUSER`. Maps a chosen in-namespace UID/GID to the invoking host user, so `--rootless` needs no `sudo`. |
| `rootfs.rs` | Bind-mounts rootfs, `chroot()`s into it, mounts `/proc` inside the container. |
| `cgroups.rs` | Creates a cgroup under `/sys/fs/cgroup/boxed/<pid>`, writes `cpu.max` and `memory.max`. |
| `capabilities.rs` | Drops all capabilities except a minimal safe set via `prctl()`. |
| `seccomp.rs` | Parses an OCI seccomp profile into syscall rules, compiles them into a BPF program, and installs it via `prctl(PR_SET_SECCOMP)`. Defaults to deny-by-default with `no_new_privs` set. |

---

## Linux Concepts Demonstrated

- **`fork()` / `exec()` / `waitpid()`** — how every process in Linux is created
- **Namespaces** (`clone` flags) — how containers get an isolated PID tree, hostname, filesystem, and network stack
- **chroot** — how a process is confined to a subtree of the filesystem
- **procfs** — why `/proc` has to be mounted inside the container separately
- **cgroups v2** — filesystem-based resource limits enforced by the kernel
- **Linux capabilities** — how root privilege is split into discrete units and dropped

---

## Testing

```bash
# Unit and integration tests (no root required)
make test

# Also run root-only tests (namespace/cgroup/capability)
make test-root
```

### What's tested

| Layer | Tests | Needs root |
| --- | --- | --- |
| **`cgroups`** | Config construction, path formatting, CPU quota string format | No |
| **`cgroups`** | Create/destroy cgroup, per-pid isolation | Yes (`#[ignore]`) |
| **`capabilities`** | No duplicates in retained set, dangerous caps excluded, subset of all caps | No |
| **`capabilities`** | `drop_capabilities()` succeeds | Yes (`#[ignore]`) |
| **`process`** | Atomic PID round-trip, signal forwarding stores PID | No |
| **`process`** | `wait_for_child` with zero/nonzero/signal exit codes (uses `fork`) | No |
| **CLI** | `--version`, `--help`, `run --help`, missing-command error | No |
| **CLI** | `run /bin/echo`, hostname=boxed, PID 1, exit code propagation, OOM kill | Yes (`#[ignore]`) |

Tests that require root are annotated with `#[ignore]`. Run them with:

```bash
sudo cargo test -- --include-ignored
```

---

## Development

```bash
make build          # debug build
make release        # release build
make test           # run all non-root tests
make test-root      # run all tests including root-only ones
make lint           # cargo clippy -D warnings
make fmt            # cargo fmt
make fmt-check      # check formatting (used in CI)
make ci             # full local CI gate (fmt + lint + test + release)

RUST_LOG=info sudo ./target/debug/boxed run /bin/sh   # verbose logging
```
