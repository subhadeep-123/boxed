use anyhow::{Context, Result};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::sethostname;
use std::ffi::CString;

const STACK_SIZE: usize = 1024 * 1024; // 1MB

pub fn run_in_namespace(
    command: &[String],
    rootfs: Option<String>,
    cpu: Option<u64>,
    mem: Option<u64>,
) -> Result<i32> {
    let mut stack = vec![0u8; STACK_SIZE];
    let cmd = command.to_vec();
    let rootfs_path = rootfs.clone();

    let flags = CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWNET;

    let child_fn = Box::new(move || -> isize {
        match child_main(&cmd, &rootfs_path) {
            Ok(_) => 0,
            Err(e) => {
                log::error!("child error: {:?}", e);
                1
            }
        }
    });

    let child_pid = unsafe { clone(child_fn, &mut stack, flags, Some(Signal::SIGCHLD as i32)) }
        .context("clone failed")?;

    let cgroup = if cpu.is_some() || mem.is_some() {
        let config = crate::cgroups::CgroupConfig {
            cpu_quota: cpu,
            memory_max: mem,
        };
        let cg = crate::cgroups::Cgroup::create(child_pid.as_raw() as u32, &config)?;
        cg.add_process(child_pid.as_raw() as u32)?;
        Some(cg)
    } else {
        None
    };

    let result = match waitpid(child_pid, None).context("waitpid failed")? {
        WaitStatus::Exited(_, code) => Ok(code),
        WaitStatus::Signaled(_, sig, _) => {
            log::info!("child killed by signal: {:?}", sig);
            Ok(128 + sig as i32)
        }
        other => {
            log::warn!("unexpected wait status: {:?}", other);
            Ok(1)
        }
    };

    if let Some(cg) = cgroup {
        let _ = cg.destroy(); // best-effort cleanup
    }

    result
}

fn child_main(command: &[String], rootfs: &Option<String>) -> Result<()> {
    sethostname("boxed").context("failed to set hostname")?;

    if let Some(path) = rootfs {
        crate::rootfs::setup_rootfs(path).context("rootfs setup failed")?;
    }

    crate::capabilities::drop_capabilities().context("failed to drop capabilities")?;

    let cmd_cstr = CString::new(command[0].as_str())?;
    let args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    nix::unistd::execvp(&cmd_cstr, &args).context("execvp failed")?;
    unreachable!();
}
