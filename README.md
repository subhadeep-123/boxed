# boxed

A container runtime built from scratch in Rust. Implements the same Linux primitives Docker uses under the hood — namespaces, cgroups v2, chroot, and capability dropping — with no abstraction layers hiding what's happening.

The goal is not to ship a product. The goal is to understand, at the kernel level, what a container actually is.

---

## Architecture

```
boxed run --rootfs /tmp/minirootfs --cpu 50000 --mem 268435456 /bin/sh
      │
      ├── process.rs      fork() + execvp() + waitpid(), signal forwarding
      ├── namespaces.rs   clone() with CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWNET
      ├── rootfs.rs       chroot() into Alpine rootfs, mount /proc
      ├── cgroups.rs      write to /sys/fs/cgroup/ to cap CPU and memory
      └── capabilities.rs drop dangerous capabilities via prctl()
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
git clone <repo-url>
cd boxed
cargo build --release

# Run a command (no isolation yet — just fork/exec)
sudo ./target/release/boxed run /bin/echo hello world

# Run a shell inside an isolated Alpine container
sudo ./target/release/boxed run \
  --rootfs /tmp/minirootfs \
  --cpu 50000 \
  --mem 268435456 \
  /bin/sh
```

Inside the container:
```
/ $ hostname        # → boxed
/ $ ps -ef          # → only your shell (PID 1) and ps
/ $ cat /etc/os-release  # → Alpine Linux
/ $ exit
```

---

## Modules

| Module | What it does |
|---|---|
| `main.rs` | CLI entry point (`clap` derive). Parses `run` subcommand with `--rootfs`, `--cpu`, `--mem`. |
| `process.rs` | `fork()` + `execvp()` + `waitpid()`. Propagates exit codes. Signal forwarding. |
| `namespaces.rs` | `clone()` with PID, UTS, MNT, NET namespace flags. Sets hostname to `boxed`. |
| `rootfs.rs` | Bind-mounts rootfs, `chroot()`s into it, mounts `/proc` inside the container. |
| `cgroups.rs` | Creates a cgroup under `/sys/fs/cgroup/boxed/<pid>`, writes `cpu.max` and `memory.max`. |
| `capabilities.rs` | Drops all capabilities except a minimal safe set via `prctl()`. |

---

## Linux Concepts Demonstrated

- **`fork()` / `exec()` / `waitpid()`** — how every process in Linux is created
- **Namespaces** (`clone` flags) — how containers get an isolated PID tree, hostname, filesystem, and network stack
- **chroot** — how a process is confined to a subtree of the filesystem
- **procfs** — why `/proc` has to be mounted inside the container separately
- **cgroups v2** — filesystem-based resource limits enforced by the kernel
- **Linux capabilities** — how root privilege is split into discrete units and dropped

---

## Development

```bash
cargo build          # debug build
cargo clippy         # lint
cargo fmt            # format
RUST_LOG=info sudo ./target/debug/boxed run /bin/sh   # verbose logging
```
