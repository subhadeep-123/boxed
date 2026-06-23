use anyhow::{Context, Result};
use log::info;
use nix::{
    sys::wait::{WaitStatus, waitpid},
    unistd::{ForkResult, execvp, fork},
};
use std::ffi::CString;

pub fn spawn_process(command: &[String]) -> Result<i32> {
    let cmd_cstr = CString::new(command[0].as_str())?;
    let args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Child => {
            let err = execvp(&cmd_cstr, &args).unwrap_err();
            std::process::exit(err as i32);
        }
        ForkResult::Parent { child } => match waitpid(child, None).context("waitpid failed")? {
            WaitStatus::Exited(_, code) => Ok(code),
            WaitStatus::Signaled(_, sig, _) => {
                info!("child killed by signal: {:?}", sig);
                Ok(128 + sig as i32)
            }
            other => {
                info!("unexpected wait status: {:?}", other);
                Ok(1)
            }
        },
    }
}
