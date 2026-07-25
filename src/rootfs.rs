use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::{chdir, pivot_root};

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

    // Mount rootfs_path onto itself, to create a mount card
    mount(
        Some(rootfs_path),
        rootfs_path,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("failed to mount {} onto itself", rootfs_path))?;

    // Prepare a subdirectory under rootfs_path for swap with the root
    let put_old = PathBuf::from(rootfs_path).join("old_root");
    fs::create_dir_all(&put_old)
        .with_context(|| format!("failed to create subdirectory - {}", put_old.display()))?;

    // Change directory to rootfs
    chdir(rootfs_path).with_context(|| format!("failed to change directory to {}", rootfs_path))?;

    // Swap the new_root with old_root
    pivot_root(".", &put_old).with_context(|| {
        format!(
            "Pivot Root from {} to {} failed",
            rootfs_path,
            put_old.display()
        )
    })?;

    let put_old = PathBuf::from("/old_root");
    // Detach and clean up the old root:
    umount2(&put_old, MntFlags::MNT_DETACH)
        .with_context(|| format!("failed to unmount {}", put_old.display()))?;

    // Remove the now-empty put_old
    fs::remove_dir(put_old).context("failed to remove put_old mount directory")?;

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
