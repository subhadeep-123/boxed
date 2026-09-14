use anyhow::{Context, Result};
use log::{debug, info};
use nix::{
    sys::{
        signal::{SigSet, SigmaskHow, Signal, kill, sigprocmask},
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

fn forwarded_signal_set() -> SigSet {
    let mut set = SigSet::empty();
    for sig in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
        set.add(sig);
    }
    set
}

pub fn block_forwarded_signals() -> Result<()> {
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&forwarded_signal_set()), None)
        .context("failed to block forwarded signals")
}

pub fn unblock_forwarded_signals() -> Result<()> {
    sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&forwarded_signal_set()), None)
        .context("failed to unblock forwarded signals")
}

fn exit_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, sig, _) => {
            info!("child killed by signal: {:?}", sig);
            128 + sig as i32
        }
        other => {
            info!("unexpected wait status: {:?}", other);
            1
        }
    }
}

pub fn wait_for_child(child_pid: Pid) -> Result<i32> {
    loop {
        match waitpid(child_pid, None) {
            Ok(status) => return Ok(exit_code(status)),
            // interrupted, retry
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e).context("waitpid failed"),
        }
    }
}

pub fn reap_until_exit(child_pid: Pid) -> Result<i32> {
    loop {
        match waitpid(None, None) {
            Ok(status) if status.pid() == Some(child_pid) => return Ok(exit_code(status)),
            Ok(status) => debug!("reaped untracked child: {:?}", status),
            // interrupted, retry
            Err(nix::errno::Errno::EINTR) => continue,
            // no children left at all: the tracked child was never seen exiting
            Err(nix::errno::Errno::ECHILD) => {
                anyhow::bail!("no children left while waiting for pid {child_pid}")
            }
            Err(e) => return Err(e).context("waitpid failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::{SigHandler, raise};
    use nix::sys::wait::{Id, WaitPidFlag, waitid};
    use nix::unistd::{ForkResult, fork};
    use std::sync::Mutex;
    use std::time::Duration;

    // Serialize tests that touch the global CHILD_PID, install signal handlers,
    // or fork: reap_until_exit waits on any child, so running beside another
    // forking test it would reap that test's child out from under it.
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
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => {
                assert_eq!(wait_for_child(child).expect("wait failed"), 0);
            }
            ForkResult::Child => std::process::exit(0),
        }
    }

    #[test]
    fn wait_for_child_nonzero_exit() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => {
                assert_eq!(wait_for_child(child).expect("wait failed"), 42);
            }
            ForkResult::Child => std::process::exit(42),
        }
    }

    #[test]
    fn wait_for_child_max_exit_code() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
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
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
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

    #[test]
    fn reap_until_exit_reaps_others_and_returns_tracked_code() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        let other = match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => child,
            ForkResult::Child => unsafe { libc::_exit(7) },
        };
        // WNOWAIT reports the exit without reaping it, so `other` is already a
        // zombie when the loop starts, ahead of the tracked child.
        waitid(Id::Pid(other), WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT).expect("waitid failed");

        let tracked = match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                std::thread::sleep(Duration::from_millis(100));
                unsafe { libc::_exit(3) }
            }
        };

        assert_eq!(reap_until_exit(tracked).expect("reap failed"), 3);
        // The loop reaped `other` on the way, so it is no longer ours to wait on.
        assert_eq!(
            waitpid(other, Some(WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD)
        );
    }

    #[test]
    fn reap_until_exit_signal_exit_code() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => {
                // SIGKILL for the same reason as wait_for_child_signal_exit_code:
                // the child inherits any handler another test installed, and a
                // caught signal would leave it running.
                kill(child, Signal::SIGKILL).expect("kill failed");
                let code = reap_until_exit(child).expect("reap failed");
                assert_eq!(code, 128 + Signal::SIGKILL as i32);
            }
            ForkResult::Child => loop {
                std::thread::sleep(Duration::from_secs(60));
            },
        }
    }

    #[test]
    fn reap_until_exit_without_children_fails() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        // ECHILD must end the loop; retrying it would spin forever.
        assert!(reap_until_exit(Pid::from_raw(i32::MAX)).is_err());
    }

    #[test]
    fn blocked_signal_is_forwarded_on_unblock() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        // Forked before blocking, because the mask is inherited. The child also
        // resets SIGTERM, since a forward_signal handler inherited from another
        // test would catch the forwarded signal instead of dying.
        let child = match unsafe { fork() }.expect("fork failed") {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                let _ = unsafe { nix::sys::signal::signal(Signal::SIGTERM, SigHandler::SigDfl) };
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
        };

        block_forwarded_signals().expect("block failed");
        setup_signal_forwarding(child).expect("signal setup failed");
        // raise() targets this thread, whose mask now holds SIGTERM pending.
        raise(Signal::SIGTERM).expect("raise failed");
        std::thread::sleep(Duration::from_millis(100));
        let before_unblock = waitpid(child, Some(WaitPidFlag::WNOHANG));

        unblock_forwarded_signals().expect("unblock failed");
        let code = wait_for_child(child);
        CHILD_PID.store(0, Ordering::SeqCst);

        assert_eq!(
            before_unblock,
            Ok(WaitStatus::StillAlive),
            "a blocked signal was forwarded before unblock"
        );
        assert_eq!(code.expect("wait failed"), 128 + Signal::SIGTERM as i32);
    }
}
