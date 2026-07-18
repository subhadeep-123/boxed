use anyhow::{Context, Result};
use log::info;
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::unistd::{Pid, pipe, read, sethostname, write};
use std::ffi::CString;
use std::os::fd::OwnedFd;

use crate::cgroups::Cgroup;
use crate::rootless::RootlessConfig;

const STACK_SIZE: usize = 1024 * 1024; // 1MB

struct ChildContext {
    command: Vec<String>,
    rootfs: Option<String>,
    hostname: Option<String>,
    sync_fd: OwnedFd,
}

impl ChildContext {
    fn new(
        cmd: Vec<String>,
        rootfs: Option<String>,
        hostname: Option<String>,
        sync_fd: OwnedFd,
    ) -> Self {
        Self {
            command: cmd,
            rootfs,
            hostname,
            sync_fd,
        }
    }

    fn enter(&self) -> Result<()> {
        // Check if parent is done writing
        let mut buf = [0u8; 1];
        read(&self.sync_fd, &mut buf)?;

        sethostname(self.hostname.as_deref().unwrap_or("boxed"))
            .context("failed to set hostname")?;

        if let Some(path) = &self.rootfs {
            crate::rootfs::setup_rootfs(path).context("rootfs setup failed")?;
        }

        crate::capabilities::drop_capabilities().context("failed to drop capabilities")?;

        let cmd_cstr = CString::new(self.command[0].as_str())?;
        let args: Vec<CString> = self
            .command
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();

        nix::unistd::execvp(&cmd_cstr, &args).context("execvp failed")?;
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
    fn new(cpu: Option<u64>, memory: Option<u64>, rootless: bool) -> Self {
        let rootless_config = RootlessConfig::new(rootless);

        Self {
            cpu,
            memory,
            flags: Self::build_clone_flags(&rootless_config),
            rootless: rootless_config,
        }
    }

    fn build_clone_flags(rootless_config: &RootlessConfig) -> CloneFlags {
        let mut default_flags = CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWNET;

        if rootless_config.enabled {
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

pub fn run_in_namespace(
    command: &[String],
    rootfs: Option<String>,
    hostname: Option<String>,
    cpu: Option<u64>,
    memory: Option<u64>,
    rootless: bool,
) -> Result<i32> {
    let runtime = RuntimeConfig::new(cpu, memory, rootless);

    // Read and write file descriptor for parent-child-synchronization
    let (read_fd, write_fd) = pipe()?;

    let child_ctx = ChildContext::new(command.to_vec(), rootfs, hostname, read_fd);

    let child = runtime.spawn_child(child_ctx)?;

    // Setup Uid and Gid Mapping for between Parent and Child
    runtime.rootless.setup_mappings(child)?;

    let _cgroup = runtime.setup_cgroup(child)?;

    runtime
        .setup_signals(child)
        .context("failed to setup up signal forwarding")?;

    // Unblock the child now that parent-side setup is done.
    write(&write_fd, &[1])?;
    drop(write_fd);
    
    runtime.wait_for_child(child)
}
