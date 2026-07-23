# Contributing to boxed

Thanks for considering a contribution. `boxed` is a container runtime built
from scratch in Rust to understand, at the syscall level, what a container
actually is — namespaces, cgroups, chroot, capabilities, and now seccomp-bpf.
Contributions that keep that spirit (no abstraction layers hiding what's
happening) are especially welcome.

By participating, you're expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- Pick up an open [issue](https://github.com/subhadeep-123/boxed/issues) —
  issues labeled `good first issue` are a reasonable starting point.
- Report a bug: include your kernel version, distro, and the exact `boxed`
  command that misbehaved.
- Propose a feature by opening an issue before writing code, so the design
  can be discussed first — this project touches raw syscalls and namespaces,
  where the "obvious" approach is often wrong in a subtle way.

## Getting set up

```sh
git clone https://github.com/subhadeep-123/boxed.git
cd boxed
cargo build
```

Common workflows are wrapped in the `Makefile`:

```sh
make build        # cargo build
make test         # cargo test (non-root tests only)
make test-root    # cargo test -- --include-ignored (needs sudo; exercises
                   # namespace/cgroup/capability code paths)
make lint         # cargo clippy -- -D warnings
make fmt          # cargo fmt
make fmt-check    # cargo fmt --check
make ci           # fmt-check + lint + test + release build — run this
                   # before opening a PR, it mirrors what CI checks
```

Some tests require root because they create real namespaces and cgroups.
`cargo test` alone only runs the tests that don't need it; run `make test-root`
if you're touching `namespace.rs`, `cgroups.rs`, `rootless.rs`, or `capabilities.rs`.

## Commit conventions

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

feat(seccomp): translate resolved profiles into BPF filters
fix(rootless): validate --host-uid/--host-gid before spawning the child
refactor(namespace): replace run_in_namespace's flat params with a config struct
test(rootless): add unit and integration coverage for issue #1
```

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`. The scope is
usually the module (`namespace`, `rootless`, `cgroups`, `seccomp`, `process`,
`capabilities`). This is what makes the changelog groupable and `git log`
useful as project history, not just noise.

Commits must be signed off (Developer Certificate of Origin) to certify you
wrote the patch or otherwise have the right to submit it:

```sh
git commit -s -m "feat(seccomp): ..."
```

## Pull requests

1. Fork the repo and branch off `main`.
2. Keep PRs scoped to one logical change — kernel-style, not a grab bag.
   Split unrelated fixes into separate PRs.
3. Run `make ci` locally before pushing.
4. `main` is protected: PRs need one approving review and a green `Format` /
   `Lint` / `Test` check before merging.
5. If your change is user-facing (a new flag, a behavior change, a fix), add
   an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md), in the
   same `### Features` / `### Bug Fixes` / `### Refactoring` grouping already
   used there. If your PR also bumps the version in `Cargo.toml`, merging it
   automatically tags and publishes a GitHub Release (see
   [release.yml](.github/workflows/release.yml) and
   [tag-release.yml](.github/workflows/tag-release.yml)) — most PRs should
   *not* bump the version; that's a maintainer decision made when cutting
   a release.

## Code style

- `cargo fmt` and `cargo clippy -- -D warnings` must both pass clean.
- Prefer explicit error handling (`anyhow::Context`) over `.unwrap()` outside
  of tests.
- Comment the *why*, not the *what* — especially for anything working around
  kernel/syscall quirks. A comment explaining a subtle `clone()` flag
  interaction is worth it; a comment restating the function name is not.
