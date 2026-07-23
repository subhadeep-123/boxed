use std::process::Command;

fn boxed() -> Command {
    Command::new(env!("CARGO_BIN_EXE_boxed"))
}

// ── CLI argument parsing (no root required) ───────────────────────────────────

#[test]
fn version_flag() {
    let out = boxed().arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("0.1"), "unexpected version: {stdout}");
}

#[test]
fn help_flag() {
    let out = boxed().arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("container runtime"),
        "missing description in --help"
    );
}

#[test]
fn run_subcommand_help() {
    let out = boxed().args(["run", "--help"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--rootfs"), "missing --rootfs flag");
    assert!(stdout.contains("--cpu"), "missing --cpu flag");
    assert!(stdout.contains("--memory"), "missing --memory flag");
    assert!(stdout.contains("--rootless"), "missing --rootless flag");
    assert!(stdout.contains("--uid"), "missing --uid flag");
    assert!(stdout.contains("--gid"), "missing --gid flag");
}

// ── rootless flag wiring (no root required) ──────────────────────────────────

#[test]
fn uid_without_rootless_fails() {
    let out = boxed()
        .args(["run", "--uid", "1000", "/bin/true"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "--uid without --rootless should be rejected by clap's `requires`"
    );
}

#[test]
fn gid_without_rootless_fails() {
    let out = boxed()
        .args(["run", "--gid", "1000", "/bin/true"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "--gid without --rootless should be rejected by clap's `requires`"
    );
}

#[test]
fn rootless_uid_sentinel_max_is_rejected() {
    // Fails inside RootlessConfig::new()'s validation, before any namespace
    // or privileged operation runs -- doesn't need root.
    let out = boxed()
        .args(["run", "--rootless", "--uid", "4294967295", "/bin/true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sentinel"),
        "expected sentinel-rejection message, got: {stderr}"
    );
}

#[test]
fn rootless_gid_sentinel_max_is_rejected() {
    let out = boxed()
        .args(["run", "--rootless", "--gid", "4294967295", "/bin/true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sentinel"),
        "expected sentinel-rejection message, got: {stderr}"
    );
}

#[test]
fn rootless_default_uid_is_root_inside() {
    // Unprivileged user namespaces are the whole point of --rootless: this
    // needs no root and no sudo, unlike the CLONE_NEWUSER-less tests below.
    let out = boxed()
        .args(["run", "--rootless", "/usr/bin/id", "-u"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0");
}

#[test]
fn rootless_custom_uid_is_applied() {
    let out = boxed()
        .args(["run", "--rootless", "--uid", "1000", "/usr/bin/id", "-u"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1000");
}

// ── seccomp filtering (no root required, uses --rootless) ────────────────────

#[test]
fn seccomp_missing_profile_file_fails() {
    let out = boxed()
        .args([
            "run",
            "--rootless",
            "--seccomp-profile",
            "/nonexistent/profile.json",
            "/bin/echo",
            "hello",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("failed to read seccomp profile"),
        "expected a read-failure message, got: {stderr}"
    );
}

#[test]
fn seccomp_malformed_profile_fails() {
    let path = std::env::temp_dir().join(format!("boxed-malformed-{}.json", std::process::id()));
    std::fs::write(&path, "{ this is not valid json").unwrap();

    let out = boxed()
        .args([
            "run",
            "--rootless",
            "--seccomp-profile",
            path.to_str().unwrap(),
            "/bin/echo",
            "hello",
        ])
        .output()
        .unwrap();

    std::fs::remove_file(&path).ok();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("failed to parse seccomp profile"),
        "expected a parse-failure message, got: {stderr}"
    );
}

#[test]
fn seccomp_profile_with_args_condition_rejected() {
    // tests/fixtures/seccomp-profile.json deliberately includes a `personality`
    // rule with an `args` condition -- arg-conditional matching isn't
    // supported, and a profile containing one must be rejected outright
    // rather than silently applied without the condition.
    let out = boxed()
        .args([
            "run",
            "--rootless",
            "--seccomp-profile",
            "tests/fixtures/seccomp-profile.json",
            "/bin/echo",
            "hello",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("arg-conditional matching"),
        "expected an arg-conditional rejection message, got: {stderr}"
    );
}

#[test]
fn seccomp_valid_profile_allows_execution() {
    let out = boxed()
        .args([
            "run",
            "--rootless",
            "--seccomp-profile",
            "tests/fixtures/seccomp-profile-valid.json",
            "/bin/echo",
            "hello",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
}

#[test]
fn seccomp_valid_profile_kills_disallowed_syscall() {
    // tests/fixtures/seccomp-profile-valid.json explicitly maps `mount` to
    // SCMP_ACT_KILL -- a real mount attempt (not the argument-less `mount`,
    // which only lists /proc/mounts and never calls the mount(2) syscall)
    // must die by SIGSYS under this custom profile, not just the default one.
    //
    // The grandchild that actually runs `mount` is killed by a real SIGSYS,
    // but process::wait_for_child() converts that into a normal exit code
    // (128 + signal) for boxed's own top-level process -- so what we observe
    // here via Command::output() is a plain exit code, not a raw signal.
    let out = boxed()
        .args([
            "run",
            "--rootless",
            "--seccomp-profile",
            "tests/fixtures/seccomp-profile-valid.json",
            "/bin/mount",
            "--bind",
            "/tmp",
            "/tmp",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        out.status.code(),
        Some(128 + libc::SIGSYS),
        "expected exit code 128+SIGSYS (killed by SIGSYS)"
    );
}

#[test]
fn seccomp_default_filter_kills_mount() {
    // No --seccomp-profile: the default denylist (DANGEROUS_SYSCALLS) applies,
    // and mount is in it. See the comment above for why this is a plain exit
    // code (128 + SIGSYS), not a raw signal, from Command::output()'s view.
    let out = boxed()
        .args(["run", "--rootless", "/bin/mount", "--bind", "/tmp", "/tmp"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        out.status.code(),
        Some(128 + libc::SIGSYS),
        "expected exit code 128+SIGSYS (killed by SIGSYS)"
    );
}

#[test]
fn run_without_command_fails() {
    let out = boxed().arg("run").output().unwrap();
    assert!(
        !out.status.success(),
        "expected failure when no command given"
    );
}

#[test]
fn unknown_subcommand_fails() {
    let out = boxed().arg("foobar").output().unwrap();
    assert!(!out.status.success());
}

// ── Container execution (requires root + Linux namespaces) ───────────────────
//
// Run with: sudo cargo test -- --include-ignored

#[test]
#[ignore = "requires root (CAP_SYS_ADMIN) and Linux namespaces"]
fn run_echo_no_rootfs() {
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "/bin/echo",
            "hello",
            "boxed",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello boxed");
}

#[test]
#[ignore = "requires root, Linux namespaces, and Alpine rootfs at /tmp/minirootfs"]
fn run_hostname_is_boxed() {
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--rootfs",
            "/tmp/minirootfs",
            "/bin/hostname",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "boxed",
        "hostname inside container should be 'boxed'"
    );
}

#[test]
#[ignore = "requires root, Linux namespaces, and Alpine rootfs at /tmp/minirootfs"]
fn run_init_process_is_pid_1() {
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--rootfs",
            "/tmp/minirootfs",
            "/bin/sh",
            "-c",
            "echo $$",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "1",
        "init process inside container should have PID 1"
    );
}

#[test]
#[ignore = "requires root, Linux namespaces, and Alpine rootfs at /tmp/minirootfs"]
fn run_exit_code_propagates() {
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--rootfs",
            "/tmp/minirootfs",
            "/bin/sh",
            "-c",
            "exit 42",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(42),
        "exit code should propagate from container"
    );
}

#[test]
#[ignore = "environment-dependent: relies on cgroups v2 NOT being delegated \
            to the invoking (non-root) user, so cgroup setup fails after the \
            child is already spawned -- exercises the orphan-leak fix"]
fn cgroup_setup_failure_does_not_leak_child() {
    // Forces a failure between spawn_child() and the final sync-pipe write:
    // --memory triggers setup_cgroup(), which fails with Permission denied
    // creating /sys/fs/cgroup/boxed unless this user has cgroup delegation.
    // `sleep 5` (not a fast-exiting command) makes a leaked child observable
    // via pgrep instead of racing an instant exit.
    let out = Command::new(env!("CARGO_BIN_EXE_boxed"))
        .args(["run", "--rootless", "--memory", "104857600", "sleep", "5"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "expected cgroup setup to fail without delegation"
    );

    std::thread::sleep(std::time::Duration::from_millis(300));

    let leaked = Command::new("pgrep")
        .args(["-f", "sleep 5"])
        .output()
        .unwrap();
    assert!(
        !leaked.status.success(),
        "found leaked child process(es): {}",
        String::from_utf8_lossy(&leaked.stdout)
    );
}

#[test]
#[ignore = "requires root, cgroups v2, and Alpine rootfs at /tmp/minirootfs"]
fn run_memory_limit_applied() {
    // With a 64 MB limit, trying to allocate 256 MB should be killed by OOM.
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--rootfs",
            "/tmp/minirootfs",
            "--memory",
            "67108864", // 64 MB
            "/bin/sh",
            "-c",
            "dd if=/dev/zero bs=1M count=256 | wc -c",
        ])
        .output()
        .unwrap();
    // Process should be OOM-killed (non-zero exit).
    assert!(!out.status.success(), "process should have been OOM-killed");
}
