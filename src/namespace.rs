use anyhow::{Context, Result};
use log::{error, info};
use nix::sched::{CloneFlags, clone};
use nix::sys::prctl::set_no_new_privs;
use nix::sys::signal::Signal;
use nix::unistd::{Pid, pipe, read, sethostname, write};
use std::ffi::CString;
use std::os::fd::OwnedFd;

use crate::cgroups::Cgroup;
use crate::rootless::RootlessConfig;
use crate::seccomp::{self, apply_default_filter};

const STACK_SIZE: usize = 1024 * 1024; // 1MB

pub struct RunOptions {
    pub command: Vec<String>,
    pub rootfs: Option<String>,
    pub hostname: Option<String>,
    pub cpu: Option<u64>,
    pub memory: Option<u64>,
    pub seccomp_profile: Option<seccomp::ResolvedProfile>,
}

struct ChildContext {
    command: Vec<String>,
    rootfs: Option<String>,
    hostname: Option<String>,
    sync_fd: OwnedFd,
    seccomp_profile: Option<seccomp::ResolvedProfile>,
}

impl ChildContext {
    fn new(
        cmd: Vec<String>,
        rootfs: Option<String>,
        hostname: Option<String>,
        sync_fd: OwnedFd,
        seccomp_profile: Option<seccomp::ResolvedProfile>,
    ) -> Self {
        Self {
            command: cmd,
            rootfs,
            hostname,
            sync_fd,
            seccomp_profile,
        }
    }

    fn enter(&self) -> Result<()> {
        // Check if parent is done writing
        let mut buf = [0u8; 1];
        let res = read(&self.sync_fd, &mut buf).context("failed to read sync signal from parent");
        match res {
            Ok(0) => anyhow::bail!("received 0 byte from parent process, indicating closed pipe"),
            Ok(n) => info!("Received {n} byte from parent process, synchronization complete"),
            Err(e) => {
                error!("{e}");
                return Err(e);
            }
        };

        sethostname(self.hostname.as_deref().unwrap_or("boxed"))
            .context("failed to set hostname")?;

        if let Some(path) = &self.rootfs {
            crate::rootfs::setup_rootfs(path).context("rootfs setup failed")?;
        }

        // Drop extra capabilities for the container
        crate::capabilities::drop_capabilities().context("failed to drop capabilities")?;

        // Set the calling thread's `no_new_privs` attribute.
        // Once set this option can not be unset
        set_no_new_privs().context("failed to set no_new_privs for child process")?;
        apply_default_filter(self.seccomp_profile.as_ref())
            .context("failed to apply default seccomp filters")?;

        let cmd_cstr = CString::new(self.command[0].as_str())
            .context("command name contains an embedded null byte")?;
        let args: Vec<CString> = self
            .command
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();

        nix::unistd::execvp(&cmd_cstr, &args)
            .with_context(|| format!("execvp failed for command '{}'", self.command[0]))?;
        unreachable!();
    }
}

struct RuntimeConfig {
    cpu: Option<u64>,
    memory: Option<u64>,
    flags: CloneFlags,

    rootless: RootlessConfig,
}

impl RuntimeConfig {
    fn new(cpu: Option<u64>, memory: Option<u64>, rootless: RootlessConfig) -> Self {
        Self {
            cpu,
            memory,
            flags: Self::build_clone_flags(rootless.enabled),
            rootless,
        }
    }

    fn build_clone_flags(is_rootless: bool) -> CloneFlags {
        let mut default_flags = CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWNET;

        if is_rootless {
            default_flags |= CloneFlags::CLONE_NEWUSER;
        }

        default_flags
    }

    fn setup_cgroup(&self, pid: Pid) -> Result<Option<Cgroup>> {
        if self.cpu.is_none() && self.memory.is_none() {
            return Ok(None);
        }

        let config = crate::cgroups::CgroupConfig {
            cpu_quota: self.cpu,
            memory_max: self.memory,
        };

        let cg = Cgroup::create(pid.as_raw() as u32, &config)?;
        cg.add_process(pid.as_raw() as u32)?;

        Ok(Some(cg))
    }

    fn setup_signals(&self, pid: Pid) -> Result<()> {
        crate::process::setup_signal_forwarding(pid)
    }

    fn spawn_child(&self, ctx: ChildContext) -> Result<Pid> {
        let mut stack = vec![0u8; STACK_SIZE];

        let child_fn = Box::new(move || -> isize {
            match ctx.enter() {
                Ok(_) => 0,
                Err(e) => {
                    log::error!("child error: {:?}", e);
                    1
                }
            }
        });

        let child_pid = unsafe {
            clone(
                child_fn,
                &mut stack,
                self.flags,
                Some(Signal::SIGCHLD as i32),
            )
        }
        .context("clone failed")?;

        info!("Created Child with PID - {child_pid}");
        Ok(child_pid)
    }

    fn wait_for_child(&self, pid: Pid) -> Result<i32> {
        crate::process::wait_for_child(pid)
    }
}

pub fn run_in_namespace(opts: RunOptions, rootless: RootlessConfig) -> Result<i32> {
    let runtime = RuntimeConfig::new(opts.cpu, opts.memory, rootless);

    // Read and write file descriptor for parent-child-synchronization
    let (read_fd, write_fd) = pipe().context("failed to create parent-child sync pipe")?;

    let child_ctx = ChildContext::new(
        opts.command.to_vec(),
        opts.rootfs,
        opts.hostname,
        read_fd,
        opts.seccomp_profile,
    );

    let child = runtime.spawn_child(child_ctx)?;

    // Setup Uid and Gid Mapping for between Parent and Child
    runtime.rootless.setup_mappings(child)?;

    let _cgroup = runtime.setup_cgroup(child)?;

    runtime
        .setup_signals(child)
        .context("failed to setup up signal forwarding")?;

    // Unblock the child now that parent-side setup is done.
    write(&write_fd, &[1]).context("failed to signal child to proceed")?;
    drop(write_fd);

    runtime.wait_for_child(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_flags_baseline_always_present() {
        let flags = RuntimeConfig::build_clone_flags(false);
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWUTS));
        assert!(flags.contains(CloneFlags::CLONE_NEWNS));
        assert!(flags.contains(CloneFlags::CLONE_NEWNET));
    }

    #[test]
    fn clone_flags_excludes_newuser_when_not_rootless() {
        let flags = RuntimeConfig::build_clone_flags(false);
        assert!(!flags.contains(CloneFlags::CLONE_NEWUSER));
    }

    #[test]
    fn clone_flags_includes_newuser_when_rootless() {
        let flags = RuntimeConfig::build_clone_flags(true);
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
    }
}
