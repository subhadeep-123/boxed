use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

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

// ── --image / --rootfs mutual exclusivity (no root required) ─────────────────

#[test]
fn image_and_rootfs_together_rejected() {
    let out = boxed()
        .args([
            "run",
            "--image",
            "/tmp/boxed-layers",
            "--rootfs",
            "/tmp/minirootfs",
            "/bin/true",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "--image and --rootfs together should be rejected by clap's conflicts_with"
    );
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

// ── sync pipe lifecycle (no root required, uses --rootless) ──────────────────

#[test]
fn cgroup_setup_failure_does_not_leak_child() {
    // Forces a failure between spawn_child() and the sync-pipe write: --memory
    // makes setup_cgroup() create /sys/fs/cgroup/boxed, which only root can do.
    if nix::unistd::Uid::effective().is_root() {
        eprintln!("skipping: cgroup setup succeeds as root, so nothing fails after clone");
        return;
    }

    // Not output(): a leaked child keeps inherited stdout/stderr pipes open,
    // and output() would wait on them forever instead of failing the test.
    let status = boxed()
        .args(["run", "--rootless", "--memory", "104857600", "sleep", "5"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "expected cgroup setup to fail as non-root"
    );

    // No delay before checking: boxed reaps the child before it returns. A
    // leaked child never reaches exec, so it still carries boxed's command
    // line; match that rather than a bare "sleep 5" any process could run.
    let leaked = Command::new("pgrep")
        .args(["-f", "boxed run --rootless --memory 104857600 sleep 5"])
        .output()
        .unwrap();
    assert!(
        !leaked.status.success(),
        "found leaked child process(es): {}",
        String::from_utf8_lossy(&leaked.stdout)
    );
}

#[test]
fn sync_pipe_not_inherited_by_command() {
    // Pipes this test process already holds may legitimately pass through
    // boxed (from the terminal or cargo); only a pipe boxed created itself is
    // a leak. fds 0-2 are the command's stdio, which output() makes pipes.
    let inherited: Vec<String> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .map(|target| target.display().to_string())
        .collect();

    let out = boxed()
        .args(["run", "--rootless", "/bin/ls", "-l", "/proc/self/fd"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let leaked: Vec<&str> = stdout
        .lines()
        .filter(|line| {
            let Some((lhs, target)) = line.split_once(" -> ") else {
                return false;
            };
            let fd: u32 = lhs
                .rsplit(' ')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            fd > 2 && target.starts_with("pipe:") && !inherited.iter().any(|t| t == target)
        })
        .collect();
    assert!(
        leaked.is_empty(),
        "container command inherited pipe(s) created by boxed: {leaked:?}"
    );
}

// ── init shim (no root required, uses --rootless) ────────────────────────────

// Host pids of `pid`'s children, zombies included.
fn children_of(pid: u32) -> Vec<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect()
}

fn comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

// State letter from /proc/<pid>/stat, 'Z' for a zombie. It follows comm, which
// is in parentheses and may contain spaces, so split after the last ") ".
fn state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?.1.chars().next()
}

fn wait_until<T>(timeout: Duration, what: &str, mut poll: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = poll() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        sleep(Duration::from_millis(20));
    }
}

// A spawned `boxed run --rootless` that is killed on drop, so a failed assertion
// cannot leave a container behind. Killing boxed alone is not enough: the
// container init is its child in another PID namespace and would carry on
// orphaned, while SIGKILL to the init takes the whole namespace down with it.
struct Container(Child);

impl Container {
    fn spawn(args: &[&str]) -> Self {
        let child = boxed()
            .args(["run", "--rootless"])
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self(child)
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }

    // Host pid of the container process running `name`: the init or a child of it.
    fn find(&self, name: &str) -> Option<u32> {
        children_of(self.pid())
            .into_iter()
            .flat_map(|init| std::iter::once(init).chain(children_of(init)))
            .find(|&pid| comm(pid) == name)
    }

    fn wait_exit(&mut self, timeout: Duration) -> ExitStatus {
        wait_until(timeout, "boxed to exit", || self.0.try_wait().unwrap())
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        for init in children_of(self.pid()) {
            let _ = kill(Pid::from_raw(init as i32), Signal::SIGKILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn assert_signal_terminates_container(sig: Signal) {
    let mut container = Container::spawn(&["/bin/sleep", "100"]);
    // Signal only once `sleep` runs. boxed installs its handlers before letting
    // the container start, and the shim holds signals pending from before its
    // fork, so nothing sent from this point on can be dropped.
    wait_until(Duration::from_secs(5), "sleep to start", || {
        container.find("sleep")
    });

    kill(Pid::from_raw(container.pid() as i32), sig).unwrap();
    let status = container.wait_exit(Duration::from_secs(5));
    assert_eq!(
        status.code(),
        Some(128 + sig as i32),
        "expected the command to die by {sig:?}"
    );
}

#[test]
fn run_sigint_terminates_container() {
    assert_signal_terminates_container(Signal::SIGINT);
}

#[test]
fn run_sigterm_terminates_container() {
    assert_signal_terminates_container(Signal::SIGTERM);
}

#[test]
fn run_reaps_orphaned_processes() {
    // The subshell exits at once, orphaning `sleep 1` onto the container init,
    // and `exec` turns the command itself into a `sleep 4` that never waits.
    // Without an init that reaps orphans, `sleep 1` stays a zombie to the end.
    let mut container = Container::spawn(&["/bin/sh", "-c", "(sleep 1 &); exec sleep 4"]);
    let init = wait_until(Duration::from_secs(5), "the container init", || {
        children_of(container.pid()).first().copied()
    });

    // By now `sleep 1` has exited and `sleep 4` has not.
    sleep(Duration::from_secs(2));
    assert!(
        container.find("sleep").is_some(),
        "the container exited before the check"
    );
    let zombies: Vec<u32> = children_of(init)
        .into_iter()
        .filter(|&pid| state(pid) == Some('Z'))
        .collect();
    assert!(
        zombies.is_empty(),
        "zombies left under the container init: {zombies:?}"
    );

    assert!(container.wait_exit(Duration::from_secs(10)).success());
}

#[test]
fn run_missing_command_exits_127() {
    let out = boxed()
        .args(["run", "--rootless", "/nonexistent-command"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(127),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
            "echo $$; cat /proc/1/comm",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        ["2", "boxed"],
        "the command should be PID 2, under boxed's init shim as PID 1"
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

// ── rootfs isolation (pivot_root, requires root + Linux namespaces) ──────────

#[test]
#[ignore = "requires root, Linux namespaces, and Alpine rootfs at /tmp/minirootfs"]
fn run_proc_mounts_shows_only_container_mounts() {
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--rootfs",
            "/tmp/minirootfs",
            "/bin/cat",
            "/proc/mounts",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mount_count = stdout.lines().count();
    assert!(
        mount_count <= 2,
        "expected only the container's own mounts (/ and /proc), got {mount_count}:\n{stdout}"
    );
    assert!(
        stdout.contains(" /proc "),
        "expected a /proc mount inside the container:\n{stdout}"
    );
}

#[test]
#[ignore = "requires root, Linux namespaces, and Alpine rootfs at /tmp/minirootfs"]
fn run_old_root_is_unreachable() {
    let marker_path = format!("/tmp/boxed_test_marker_{}", std::process::id());
    std::fs::write(&marker_path, "host-only content").expect("failed to write host marker file");

    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--rootfs",
            "/tmp/minirootfs",
            "/bin/sh",
            "-c",
            &format!("test -f {marker_path} && echo FOUND || echo NOTFOUND"),
        ])
        .output()
        .unwrap();

    std::fs::remove_file(&marker_path).ok();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "NOTFOUND",
        "a file that only exists on the host filesystem should be unreachable \
         from inside the container after pivot_root"
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

// ── overlayfs layered root filesystem (requires root, Linux namespaces, and
//    the layered fixture at /tmp/boxed-layers created by tmp_setup.sh) ───────

#[test]
#[ignore = "requires root, Linux namespaces, and layered fixture at /tmp/boxed-layers"]
fn run_image_boots() {
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--image",
            "/tmp/boxed-layers",
            "/bin/echo",
            "hello",
            "overlay",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello overlay");
}

#[test]
#[ignore = "requires root, Linux namespaces, and layered fixture at /tmp/boxed-layers"]
fn run_image_merges_multiple_layers() {
    // /tmp/boxed-layers/01-app contributes app-marker.txt on top of the
    // 00-base Alpine layer -- confirms multiple lowerdirs actually stack
    // into one merged view instead of only the base layer being used.
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--image",
            "/tmp/boxed-layers",
            "/bin/cat",
            "/app-marker.txt",
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
        "app-layer-marker"
    );
}

#[test]
#[ignore = "requires root, Linux namespaces, and layered fixture at /tmp/boxed-layers"]
fn run_image_cow_does_not_affect_base_layer() {
    // A file written inside the container must land only in the ephemeral
    // upper layer -- the read-only 00-base layer on the host must remain
    // untouched after the container exits.
    let marker = format!("cow-test-{}.txt", std::process::id());
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--image",
            "/tmp/boxed-layers",
            "/bin/sh",
            "-c",
            &format!("echo written-in-container > /{marker}"),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let leaked_to_base = std::path::Path::new("/tmp/boxed-layers/00-base").join(&marker);
    assert!(
        !leaked_to_base.exists(),
        "file written inside the container leaked into the read-only base layer: {}",
        leaked_to_base.display()
    );
}

// ── Resource limits: argument rejection (no root required) ───────────────────
//
// These run unprivileged because CgroupConfig::validate() is called straight
// after argument parsing, before any container work.

#[test]
fn io_max_unknown_key_rejected() {
    let out = boxed()
        .args([
            "run",
            "--io-max",
            "/dev/sda:wpbs=1048576",
            "/bin/echo",
            "hi",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("wpbs"),
        "should quote the bad key: {stderr}"
    );
}

#[test]
fn io_max_non_block_device_rejected() {
    let out = boxed()
        .args([
            "run",
            "--io-max",
            "/dev/null:wbps=1048576",
            "/bin/echo",
            "hi",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a block device"), "stderr: {stderr}");
}

#[test]
fn io_max_missing_colon_rejected() {
    let out = boxed()
        .args(["run", "--io-max", "/dev/sda", "/bin/echo", "hi"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("DEVICE:KEY=VALUE"), "stderr: {stderr}");
}

#[test]
fn run_help_lists_every_resource_limit() {
    let out = boxed().args(["run", "--help"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--cpu",
        "--memory",
        "--pids-limit",
        "--cpuset-cpus",
        "--cpuset-mems",
        "--io-max",
    ] {
        assert!(stdout.contains(flag), "missing {flag} in --help");
    }
    assert!(
        stdout.contains("Resource limits"),
        "limits should be grouped under their own heading"
    );
}

// ── Resource limits: enforcement (requires root) ─────────────────────────────

#[test]
#[ignore = "requires root (CAP_SYS_ADMIN) and cgroups v2"]
fn pids_limit_contains_fork_bomb() {
    // A bounded fork loop rather than `:(){ :|:& };:` — with a working limit
    // both are contained, but only this one is survivable if the limit is
    // broken. 200 attempts against a limit of 10 will always hit EAGAIN.
    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--pids-limit",
            "10",
            "/bin/sh",
            "-c",
            "i=0; while [ $i -lt 200 ]; do /bin/sleep 5 & i=$((i+1)); done; echo survived",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    // The shell reports each refused fork; the exact wording varies by shell,
    // so accept either the errno text or the generic "fork" complaint.
    assert!(
        stderr.contains("Resource temporarily unavailable") || stderr.contains("fork"),
        "expected the kernel to refuse forks past the limit; stderr: {stderr}"
    );
}

#[test]
#[ignore = "requires root, cgroups v2, and BOXED_TEST_BLOCK_DEV=/dev/sdX"]
fn io_max_throttles_direct_writes() {
    // The backing device differs per machine, so it is supplied explicitly
    // rather than guessed from a mount point.
    let Ok(device) = std::env::var("BOXED_TEST_BLOCK_DEV") else {
        eprintln!("skipping: set BOXED_TEST_BLOCK_DEV to a block device, e.g. /dev/sda");
        return;
    };

    let target = "/var/tmp/boxed-io-max-test.bin";
    // 20MB at 2MB/s cannot complete faster than ~10s.
    let limit = 2 * 1024 * 1024;
    let started = std::time::Instant::now();

    let out = Command::new("sudo")
        .args([
            env!("CARGO_BIN_EXE_boxed"),
            "run",
            "--io-max",
            &format!("{device}:wbps={limit}"),
            "/bin/dd",
            "if=/dev/zero",
            &format!("of={target}"),
            "bs=1M",
            "count=20",
            // Buffered writes return from page cache and are flushed later by
            // writeback, outside this cgroup's accounting — they would show no
            // throttling at all and make a correct implementation look broken.
            "oflag=direct",
        ])
        .output()
        .unwrap();

    let elapsed = started.elapsed();
    let _ = std::fs::remove_file(target);

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        elapsed.as_secs() >= 5,
        "20MB at {limit}B/s should have taken ~10s, took {elapsed:?} — was the write throttled?"
    );
}
