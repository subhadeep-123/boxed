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
        nix::sys::signal::signal(Signal::SIGINT, handler)
            .with_context(|| format!("failed to install handler for {:?}", Signal::SIGINT))?;
        nix::sys::signal::signal(Signal::SIGTERM, handler)
            .with_context(|| format!("failed to install handler for {:?}", Signal::SIGTERM))?;
        nix::sys::signal::signal(Signal::SIGHUP, handler)
            .with_context(|| format!("failed to install handler for {:?}", Signal::SIGHUP))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{ForkResult, fork};
    use std::sync::Mutex;

    // Serialize tests that touch the global CHILD_PID or install signal handlers.
    static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn child_pid_atomic_roundtrip() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        let prev = CHILD_PID.swap(12345, Ordering::SeqCst);
        assert_eq!(CHILD_PID.load(Ordering::SeqCst), 12345);
        CHILD_PID.store(prev, Ordering::SeqCst);
    }

    #[test]
    fn setup_signal_forwarding_stores_pid() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        setup_signal_forwarding(Pid::from_raw(9999)).expect("signal setup failed");
        assert_eq!(CHILD_PID.load(Ordering::SeqCst), 9999);
        CHILD_PID.store(0, Ordering::SeqCst);
    }

    #[test]
    fn wait_for_child_zero_exit() {
        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => {
                assert_eq!(wait_for_child(child).expect("wait failed"), 0);
            }
            ForkResult::Child => std::process::exit(0),
        }
    }

    #[test]
    fn wait_for_child_nonzero_exit() {
        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => {
                assert_eq!(wait_for_child(child).expect("wait failed"), 42);
            }
            ForkResult::Child => std::process::exit(42),
        }
    }

    #[test]
    fn wait_for_child_max_exit_code() {
        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => {
                assert_eq!(wait_for_child(child).expect("wait failed"), 127);
            }
            ForkResult::Child => std::process::exit(127),
        }
    }

    #[test]
    fn wait_for_child_signal_exit_code() {
        use nix::sys::signal::{Signal, kill};
        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => {
                kill(child, Signal::SIGKILL).expect("kill failed");
                let code = wait_for_child(child).expect("wait failed");
                // SIGKILL is 9, so expect 128 + 9 = 137
                assert_eq!(code, 128 + Signal::SIGKILL as i32);
            }
            ForkResult::Child => {
                // pause indefinitely — parent will kill us
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                }
            }
        }
    }
}
