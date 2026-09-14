use anyhow::{Context, Result};
use log::{error, info};
use nix::fcntl::OFlag;
use nix::sched::{CloneFlags, clone};
use nix::sys::prctl::set_no_new_privs;
use nix::sys::signal::Signal;
use nix::unistd::{ForkResult, Pid, fork, pipe2, read, sethostname, write};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use crate::cgroups::{Cgroup, CgroupConfig};
use crate::overlay;
use crate::rootless::RootlessConfig;
use crate::seccomp::{self, apply_default_filter};

const STACK_SIZE: usize = 1024 * 1024; // 1MB

pub struct RunOptions {
    pub command: Vec<String>,
    pub rootfs: Option<String>,
    pub image: Option<String>,
    pub hostname: Option<String>,
    pub limits: CgroupConfig,
    pub seccomp_profile: Option<seccomp::ResolvedProfile>,
}

struct ChildContext {
    command: Vec<String>,
    rootfs: Option<String>,
    image: Option<String>,
    hostname: Option<String>,
    sync_fd: OwnedFd,
    // The parent's end of the sync pipe, as numbered in the parent's fd table.
    // clone() copies that table, so the child holds this fd too and must close it.
    parent_write_fd: RawFd,
    seccomp_profile: Option<seccomp::ResolvedProfile>,
    run_id: u32,
}

impl ChildContext {
    fn config_fs(&self) -> Result<()> {
        match (&self.image, &self.rootfs) {
            (Some(image), None) => {
                let merged_path: PathBuf = crate::overlay::setup(image, self.run_id)
                    .with_context(|| format!("Failed to setup overlay on {}", image))?;

                let merged_path: &str = merged_path
                    .to_str()
                    .context("merged path is not valid UTF-8")?;

                crate::rootfs::setup(merged_path).with_context(|| {
                    format!(
                        "Failed to setup rootfs on overlay merged path {}",
                        merged_path
                    )
                })?;
            }
            (None, Some(rootfs)) => {
                crate::rootfs::setup(rootfs)
                    .with_context(|| format!("Failed to setup rootfs on {}", rootfs))?;
            }
            (None, None) => {}
            (Some(_), Some(_)) => {
                unreachable!("clap guarantees --image and --rootfs are mutually exclusive");
            }
        }

        Ok(())
    }

    fn enter(&self) -> Result<i32> {
        // A pipe read returns 0 only once every write end is closed. Drop our
        // inherited copy so that, if the parent gives up, the read below sees
        // EOF instead of blocking forever on a write end we hold ourselves.
        //
        // SAFETY: nothing else in the child owns this fd. The parent's OwnedFd
        // lives in run_in_namespace, which the child never returns to, so it
        // is never dropped here and the fd cannot be closed twice.
        drop(unsafe { OwnedFd::from_raw_fd(self.parent_write_fd) });

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

        // Do Filesystem configuration based on --rootfs/--image
        self.config_fs()?;

        // Drop extra capabilities for the container
        crate::capabilities::drop_capabilities().context("failed to drop capabilities")?;

        // Set the calling thread's `no_new_privs` attribute.
        // Once set this option can not be unset
        set_no_new_privs().context("failed to set no_new_privs for child process")?;
        apply_default_filter(self.seccomp_profile.as_ref())
            .context("failed to apply default seccomp filters")?;

        // Built before the fork, so a bad argument is an ordinary error here
        // rather than something the forked child has to handle.
        let args: Vec<CString> = self
            .command
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<Result<_, _>>()
            .context("command contains an embedded null byte")?;

        // Until the parent unblocks, SIGINT/SIGTERM/SIGHUP are held pending
        // instead of being dropped while forwarding has no target yet.
        crate::process::block_forwarded_signals()?;

        // SAFETY: this process came from clone() and is single-threaded, so the
        // forked child can run ordinary code before it execs.
        match unsafe { fork() }.context("failed to fork container command")? {
            ForkResult::Child => exec_command(&args),
            ForkResult::Parent { child } => {
                crate::process::setup_signal_forwarding(child)?;
                crate::process::unblock_forwarded_signals()?;
                crate::process::reap_until_exit(child)
            }
        }
    }
}

// Runs in the forked child and never returns. Failure must leave through
// _exit: returning an error would unwind through a copy of the shim's stack
// and run its exit path a second time, in the wrong process.
fn exec_command(args: &[CString]) -> ! {
    // The signal mask survives execve, so skipping this would start the
    // command with Ctrl-C blocked for its whole life.
    if let Err(e) = crate::process::unblock_forwarded_signals() {
        error!("{e:?}");
        // SAFETY: _exit only ends this process, skipping atexit handlers and
        // stdio buffers inherited from the shim.
        unsafe { libc::_exit(127) }
    }

    let Err(e) = nix::unistd::execvp(&args[0], args);
    error!(
        "execvp failed for command '{}': {e}",
        args[0].to_string_lossy()
    );
    // SAFETY: as above.
    unsafe { libc::_exit(127) }
}

struct RuntimeConfig {
    limits: CgroupConfig,
    flags: CloneFlags,

    rootless: RootlessConfig,
}

impl RuntimeConfig {
    fn new(limits: CgroupConfig, rootless: RootlessConfig) -> Self {
        Self {
            limits,
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
        if self.limits.is_noop() {
            return Ok(None);
        }

        let cg = Cgroup::create(pid.as_raw() as u32, &self.limits)?;
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
                Ok(code) => code as isize,
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
    let runtime = RuntimeConfig::new(opts.limits, rootless);

    // Read and write file descriptor for parent-child-synchronization
    let (read_fd, write_fd) =
        pipe2(OFlag::O_CLOEXEC).context("failed to create parent-child sync pipe")?;

    let overlay_used = opts.image.is_some();

    let run_id = std::process::id();
    let child_ctx = ChildContext {
        command: opts.command,
        rootfs: opts.rootfs,
        image: opts.image,
        hostname: opts.hostname,
        sync_fd: read_fd,
        parent_write_fd: write_fd.as_raw_fd(),
        seccomp_profile: opts.seccomp_profile,
        run_id,
    };

    let child = runtime.spawn_child(child_ctx)?;

    // Declared before the setup block, so on failure it is dropped only after
    // the child has been reaped: rmdir on a cgroup fails while a task is in it.
    let mut _cgroup = None;

    // Every step that can fail while the child waits on the sync pipe, run as
    // one block so failure is handled in exactly one place below.
    let setup = (|| -> Result<()> {
        // Setup Uid and Gid Mapping for between Parent and Child
        runtime.rootless.setup_mappings(child)?;

        _cgroup = runtime.setup_cgroup(child)?;

        runtime
            .setup_signals(child)
            .context("failed to setup up signal forwarding")?;

        // Unblock the child now that parent-side setup is done.
        write(&write_fd, &[1]).context("failed to signal child to proceed")?;
        Ok(())
    })();

    // After the go-ahead byte this is just cleanup. On failure it is the abort:
    // the child's read returns 0 and it exits without running the command.
    drop(write_fd);

    if let Err(e) = setup {
        if let Err(reap_err) = runtime.wait_for_child(child) {
            error!("failed to reap child after setup failure: {:?}", reap_err);
        }
        return Err(e);
    }

    let exit_code = runtime.wait_for_child(child);

    // Overlay teardown
    if overlay_used && let Err(e) = overlay::teardown(run_id) {
        error!("overlay teardown failed: {:?}", e);
    }

    exit_code
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
