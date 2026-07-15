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
