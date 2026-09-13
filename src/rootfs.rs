use anyhow::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::{chdir, pivot_root};

pub fn setup(rootfs_path: &str) -> Result<()> {
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

    // Mount /proc before pivoting: inside a user namespace the kernel only
    // allows a new proc mount while an existing one is still fully visible
    // in this mount namespace, and the host's /proc goes away with old root.
    let proc_path = format!("{}/proc", rootfs_path);
    mount(
        Some("proc"),
        proc_path.as_str(),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .with_context(|| format!("failed to mount proc on {}", proc_path))?;

    // Change directory to rootfs
    chdir(rootfs_path).with_context(|| format!("failed to change directory to {}", rootfs_path))?;

    // Pivot with new_root and put_old both ".": the old root is stacked on
    // top of the new root at /, so no put_old directory has to be created
    // inside the rootfs, which may not be writable (e.g. rootless, where the
    // rootfs owner is not mapped into the user namespace). See pivot_root(2).
    pivot_root(".", ".").with_context(|| format!("failed to pivot_root into {}", rootfs_path))?;

    // "." resolves to the topmost mount stacked at /, which is the old root
    umount2(".", MntFlags::MNT_DETACH).context("failed to detach old root")?;

    // pivot_root does not move the cwd, so anchor it at the new root
    chdir("/").context("failed to change directory to new root")?;

    Ok(())
}
