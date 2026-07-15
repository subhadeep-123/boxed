use anyhow::{Context, Result};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::unistd::{Pid, sethostname};
use std::ffi::CString;

use crate::cgroups::Cgroup;

const STACK_SIZE: usize = 1024 * 1024; // 1MB

struct ChildContext {
    command: Vec<String>,
    rootfs: Option<String>,
    hostname: Option<String>,
}

impl ChildContext {
    fn new(cmd: Vec<String>, rootfs: Option<String>, hostname: Option<String>) -> Self {
        Self {
            command: cmd,
            rootfs,
            hostname,
        }
    }

    fn enter(&self) -> Result<()> {
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
}

impl RuntimeConfig {
    fn new(cpu: Option<u64>, memory: Option<u64>) -> Self {
        Self {
            cpu,
            memory,
            flags: Self::build_clone_flags(),
        }
    }

    fn build_clone_flags() -> CloneFlags {
        CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWNET
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
) -> Result<i32> {
    let runtime = RuntimeConfig::new(cpu, memory);

    let child_ctx = ChildContext::new(command.to_vec(), rootfs, hostname);

    let child = runtime.spawn_child(child_ctx)?;

    let _cgroup = runtime.setup_cgroup(child)?;

    runtime
        .setup_signals(child)
        .context("failed to setup up signal forwarding")?;

    runtime.wait_for_child(child)
}
