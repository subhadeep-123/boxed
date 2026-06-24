use anyhow::{Context, Result};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::sethostname;
use std::ffi::CString;

const STACK_SIZE: usize = 1024 * 1024; // 1MB

pub fn run_in_namespace(command: &[String]) -> Result<i32> {
    let mut stack = vec![0u8; STACK_SIZE];

    let cmd = command.to_vec();

    let flags = CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWNET;

    let child_fn = Box::new(move || -> isize {
        match child_main(&cmd) {
            Ok(_) => 0,
            Err(e) => {
                log::error!("child error: {:?}", e);
                1
            }
        }
    });

    let child_pid = unsafe { clone(child_fn, &mut stack, flags, Some(Signal::SIGCHLD as i32)) }
        .context("clone failed")?;

    match waitpid(child_pid, None).context("waitpid failed")? {
        WaitStatus::Exited(_, code) => Ok(code),
        WaitStatus::Signaled(_, sig, _) => {
            log::info!("child killed by signal: {:?}", sig);
            Ok(128 + sig as i32)
        }
        other => {
            log::warn!("unexpected wait status: {:?}", other);
            Ok(1)
        }
    }
}

fn child_main(command: &[String]) -> Result<()> {
    sethostname("boxed").context("failed to set hostname")?;

    let cmd_cstr = CString::new(command[0].as_str())?;
    let args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    nix::unistd::execvp(&cmd_cstr, &args).context("execvp failed")?;
    unreachable!();
}
