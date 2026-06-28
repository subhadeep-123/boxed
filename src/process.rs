use anyhow::{Context, Result};
use log::info;
use nix::{
    sys::{
        signal::{Signal, kill},
        wait::{WaitStatus, waitpid},
    },
    unistd::Pid,
};
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_signal(sig: i32) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        let _ = kill(Pid::from_raw(pid), Signal::try_from(sig).unwrap());
    }
}

pub fn setup_signal_forwarding(child_pid: Pid) -> Result<()> {
    CHILD_PID.store(child_pid.as_raw(), Ordering::SeqCst);

    unsafe {
        let handler = nix::sys::signal::SigHandler::Handler(forward_signal);
        nix::sys::signal::signal(Signal::SIGINT, handler)?;
        nix::sys::signal::signal(Signal::SIGTERM, handler)?;
        nix::sys::signal::signal(Signal::SIGHUP, handler)?;
    }

    Ok(())
}

pub fn wait_for_child(child_pid: Pid) -> Result<i32> {
    loop {
        match waitpid(child_pid, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                info!("child killed by signal: {:?}", sig);
                return Ok(128 + sig as i32);
            }
            Ok(other) => {
                info!("unexpected wait status: {:?}", other);
                return Ok(1);
            }
            // interrupted, retry
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e).context("waitpid failed"),
        }
    }
}
