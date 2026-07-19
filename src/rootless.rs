use std::{fs::OpenOptions, io::Write};

use anyhow::{Context, Result};
use log::info;
use nix::unistd::{Gid, Pid, Uid};
use nix::unistd::{getgid, getuid};

pub struct RootlessConfig {
    pub enabled: bool,

    // Inside-container Uid and Gid
    pub uid: Uid,
    pub gid: Gid,
}

impl RootlessConfig {
    pub fn new(enabled: bool, uid: Option<u32>, gid: Option<u32>) -> Result<Self> {
        Ok(Self {
            enabled,
            uid: Self::validate_uid(uid)?,
            gid: Self::validate_gid(gid)?,
        })
    }
    fn validate_uid(uid: Option<u32>) -> Result<Uid> {
        match uid {
            None => Ok(Uid::from_raw(0)),
            Some(want) if want != u32::MAX => Ok(Uid::from_raw(want)),
            Some(want) => anyhow::bail!(
                "cannot map inside uid {want}: collides with the POSIX (uid_t)-1 sentinel for \"unchanged/invalid\""
            ),
        }
    }

    fn validate_gid(gid: Option<u32>) -> Result<Gid> {
        match gid {
            None => Ok(Gid::from_raw(0)),
            Some(want) if want != u32::MAX => Ok(Gid::from_raw(want)),
            Some(want) => anyhow::bail!(
                "cannot map inside gid {want}: collides with the POSIX (gid_t)-1 sentinel for \"unchanged/invalid\""
            ),
        }
    }

    fn write_setgroups(pid: Pid) -> Result<()> {
        // Open the procfs file for setgroups configuration
        let mut setgroups_file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/setgroups"))
            .context(format!("failed to open setgroups file for pid {pid}"))?;

        // Write "deny" to disable setgroups system call permanently
        setgroups_file.write_all(b"deny").context(format!(
            "failed to disable setgroups for pid {pid} (required before gid_map can be written)"
        ))?;

        Ok(())
    }

    fn write_uid_map(pid: Pid, uid: Uid) -> Result<()> {
        let mut uid_map_file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/uid_map"))
            .context(format!("failed to open uid_map for pid {pid}"))?;

        let host_uid = getuid();
        let mapping = format!("{} {} 1\n", uid.as_raw(), host_uid);
        uid_map_file.write_all(mapping.as_bytes()).context(format!(
            "failed to write uid mapping '{mapping}' for pid {pid}"
        ))?;

        info!("Initialized UID mapping for process {pid}: inside uid {uid} -> host uid {host_uid}");
        Ok(())
    }

    fn write_gid_map(pid: Pid, gid: Gid) -> Result<()> {
        let mut gid_map_file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/gid_map"))
            .context(format!("failed to open gid_map for pid {pid}"))?;

        let host_gid = getgid();
        let mapping = format!("{} {} 1\n", gid.as_raw(), host_gid);
        gid_map_file.write_all(mapping.as_bytes()).context(format!(
            "failed to write gid mapping '{mapping}' for pid {pid}"
        ))?;

        info!("Initialized GID mapping for process {pid}: inside gid {gid} -> host gid {host_gid}");
        Ok(())
    }

    pub fn setup_mappings(&self, pid: Pid) -> Result<()> {
        // check if rootless is enabled
        if !self.enabled {
            info!("Skipping Host-Child Pid-Uid mapping as rootless is disabled");
            return Ok(());
        }

        // Write "deny" to process setgroups file
        Self::write_setgroups(pid)?;

        // Maps Parents Pid/Gid with Child, now that setgroups is disabled
        Self::write_uid_map(pid, self.uid)?;
        Self::write_gid_map(pid, self.gid)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_uid_none_defaults_to_root() {
        assert_eq!(
            RootlessConfig::validate_uid(None).unwrap(),
            Uid::from_raw(0)
        );
    }

    #[test]
    fn validate_uid_explicit_zero_is_allowed() {
        // Regression test: `want > 0` previously rejected this by accident.
        assert_eq!(
            RootlessConfig::validate_uid(Some(0)).unwrap(),
            Uid::from_raw(0)
        );
    }

    #[test]
    fn validate_uid_arbitrary_value_is_allowed() {
        assert_eq!(
            RootlessConfig::validate_uid(Some(1000)).unwrap(),
            Uid::from_raw(1000)
        );
    }

    #[test]
    fn validate_uid_rejects_sentinel_max() {
        assert!(RootlessConfig::validate_uid(Some(u32::MAX)).is_err());
    }

    #[test]
    fn validate_gid_none_defaults_to_root() {
        assert_eq!(
            RootlessConfig::validate_gid(None).unwrap(),
            Gid::from_raw(0)
        );
    }

    #[test]
    fn validate_gid_explicit_zero_is_allowed() {
        assert_eq!(
            RootlessConfig::validate_gid(Some(0)).unwrap(),
            Gid::from_raw(0)
        );
    }

    #[test]
    fn validate_gid_arbitrary_value_is_allowed() {
        assert_eq!(
            RootlessConfig::validate_gid(Some(1000)).unwrap(),
            Gid::from_raw(1000)
        );
    }

    #[test]
    fn validate_gid_rejects_sentinel_max() {
        assert!(RootlessConfig::validate_gid(Some(u32::MAX)).is_err());
    }

    #[test]
    fn new_disabled_defaults_uid_gid_to_root() {
        let config = RootlessConfig::new(false, None, None).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.uid, Uid::from_raw(0));
        assert_eq!(config.gid, Gid::from_raw(0));
    }

    #[test]
    fn new_enabled_with_custom_ids() {
        let config = RootlessConfig::new(true, Some(1000), Some(2000)).unwrap();
        assert!(config.enabled);
        assert_eq!(config.uid, Uid::from_raw(1000));
        assert_eq!(config.gid, Gid::from_raw(2000));
    }

    #[test]
    fn new_rejects_sentinel_uid_even_when_disabled() {
        // Documents current behavior: validation runs unconditionally in
        // `new()`, regardless of `enabled`. In practice the CLI's
        // `requires = "rootless"` constraint keeps this from being reachable
        // through normal use, but the Rust API itself doesn't guard it.
        assert!(RootlessConfig::new(false, Some(u32::MAX), None).is_err());
    }

    #[test]
    fn setup_mappings_disabled_is_noop() {
        let config = RootlessConfig::new(false, None, None).unwrap();
        // Must never touch /proc/1/* when rootless is disabled.
        assert!(config.setup_mappings(Pid::from_raw(1)).is_ok());
    }
}
