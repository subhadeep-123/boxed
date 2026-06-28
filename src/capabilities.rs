use anyhow::{Context, Result};
use caps::{CapSet, Capability};

const RETAINED_CAPS: &[Capability] = &[
    Capability::CAP_CHOWN,
    Capability::CAP_DAC_OVERRIDE,
    Capability::CAP_FSETID,
    Capability::CAP_FOWNER,
    Capability::CAP_MKNOD,
    Capability::CAP_NET_RAW,
    Capability::CAP_SETGID,
    Capability::CAP_SETUID,
    Capability::CAP_SETFCAP,
    Capability::CAP_SETFCAP,
    Capability::CAP_NET_BIND_SERVICE,
    Capability::CAP_SYS_CHROOT,
    Capability::CAP_SETPCAP,
    Capability::CAP_AUDIT_WRITE,
];

pub fn drop_capabilities() -> Result<()> {
    let all = caps::all();

    for cap in all {
        if !RETAINED_CAPS.contains(&cap) {
            // Bounding set must be dropped first — it's the ceiling on what exec can grant.
            // Without this, root (UID 0) gets F(permitted)=all-ones on exec, and
            // P'(permitted) = P(inheritable) | P(bounding), restoring every cap we dropped.
            caps::drop(None, CapSet::Bounding, cap)
                .with_context(|| format!("failed to drop {:?} from bounding set", cap))?;
            caps::drop(None, CapSet::Effective, cap)
                .with_context(|| format!("failed to drop {:?} from effective set", cap))?;
            caps::drop(None, CapSet::Permitted, cap)
                .with_context(|| format!("failed to drop {:?} from permitted set", cap))?;
            caps::drop(None, CapSet::Inheritable, cap)
                .with_context(|| format!("failed to drop {:?} from inheritable set", cap))?;
        }
    }
    Ok(())
}
