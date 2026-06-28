use anyhow::{Context, Result};
use nix::mount::{MsFlags, mount};
use nix::unistd::{chdir, chroot};

pub fn setup_rootfs(rootfs_path: &str) -> Result<()> {
    // Break shared propagation inherited from the parent namespace so that
    // mounts inside the container do not leak back to the host.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("failed to make / private")?;

    chroot(rootfs_path).with_context(|| format!("chroot to {} failed", rootfs_path))?;

    chdir("/").context("chdir to / after chroot failed")?;

    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .context("failed to mount /proc inside container")?;

    Ok(())
}
