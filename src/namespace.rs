use anyhow::{Context, Result};
use log::{error, info};
use nix::sched::{CloneFlags, clone};
use nix::sys::prctl::set_no_new_privs;
use nix::sys::signal::Signal;
use nix::unistd::{Pid, pipe, read, sethostname, write};
use std::ffi::CString;
use std::os::fd::OwnedFd;
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
    seccomp_profile: Option<seccomp::ResolvedProfile>,
    run_id: u32,
}

impl ChildContext {
    fn new(
        cmd: Vec<String>,
        rootfs: Option<String>,
        image: Option<String>,
        hostname: Option<String>,
        sync_fd: OwnedFd,
        seccomp_profile: Option<seccomp::ResolvedProfile>,
        run_id: u32,
    ) -> Self {
        Self {
            command: cmd,
            rootfs,
            image,
            hostname,
            sync_fd,
            seccomp_profile,
            run_id,
        }
    }

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

        // Do Filesystem configuration based on --rootfs/--image
        self.config_fs()?;

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
    let runtime = RuntimeConfig::new(opts.limits, rootless);

    // Read and write file descriptor for parent-child-synchronization
    let (read_fd, write_fd) = pipe().context("failed to create parent-child sync pipe")?;

    let overlay_used = opts.image.is_some();

    let run_id = std::process::id();
    let child_ctx = ChildContext::new(
        opts.command.to_vec(),
        opts.rootfs,
        opts.image,
        opts.hostname,
        read_fd,
        opts.seccomp_profile,
        run_id,
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
