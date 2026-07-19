use std::{fs::OpenOptions, io::Write};

use anyhow::{Context, Ok, Result};
use log::info;
use nix::unistd::{Gid, Pid, Uid};
use nix::unistd::{getgid, getuid};

pub struct RootlessConfig {
    pub enabled: bool,
    pub host_uid: Uid,
    pub host_gid: Gid,
}

impl RootlessConfig {
    pub fn new(enabled: bool, uid: Option<u32>, gid: Option<u32>) -> Result<Self> {
        let privileged = getuid().is_root();

        let host_uid = Self::validate_uid(uid, privileged)?;
        let host_gid = Self::validate_gid(gid, privileged)?;

        Ok(Self {
            enabled,
            host_uid,
            host_gid,
        })
    }

    fn validate_uid(uid: Option<u32>, privileged: bool) -> Result<Uid> {
        let real_uid = getuid();

        let uid = match uid {
            None => Ok(real_uid), // no --host-uid given, just use ours
            Some(want) if privileged => Ok(Uid::from_raw(want)), // privileged: kernel allows anything
            Some(want) if want == real_uid.as_raw() => Ok(Uid::from_raw(want)), // unprivileged but matches own uid: legal
            Some(want) => anyhow::bail!(
                "cannot map host uid {want}: unprivileged process can only map its own real uid ({real_uid})"
            ),
        };

        uid
    }

    fn validate_gid(gid: Option<u32>, privileged: bool) -> Result<Gid> {
        let real_gid = getgid();

        let gid = match gid {
            None => Ok(real_gid), // no --host-gid given, just use ours
            Some(want) if privileged => Ok(Gid::from_raw(want)), // privileged: kernel allows anything
            Some(want) if want == real_gid.as_raw() => Ok(Gid::from_raw(want)), // unprivileged but matches own gid: legal
            Some(want) => anyhow::bail!(
                "cannot map host gid {want}: unprivileged process can only map its own real gid ({real_gid})"
            ),
        };

        gid
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

    fn write_uid_map(pid: Pid, host_uid: Uid) -> Result<()> {
        let mut uid_map_file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/uid_map"))
            .context(format!("failed to open uid_map for pid {pid}"))?;

        let mapping = format!("0 {} 1\n", host_uid.as_raw());
        uid_map_file
        .write_all(mapping.as_bytes())
        .context(format!("failed to write uid mapping '{mapping}' for pid {pid} (unprivileged processes may only map their own real uid)"))?;

        info!(
            "Initialized UID mapping for process {} to host UID {}",
            pid, host_uid
        );
        Ok(())
    }

    fn write_gid_map(pid: Pid, host_gid: Gid) -> Result<()> {
        let mut gid_map_file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/gid_map"))
            .context(format!("failed to open gid_map for pid {pid}"))?;

        let mapping = format!("0 {} 1\n", host_gid.as_raw());
        gid_map_file
        .write_all(mapping.as_bytes())
        .context(format!("failed to write gid mapping '{mapping}' for pid {pid} (unprivileged processes may only map their own real gid)"))?;

        info!(
            "Initialized GID mapping for process {} to host GID {}",
            pid, host_gid
        );
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
        Self::write_uid_map(pid, self.host_uid)?;
        Self::write_gid_map(pid, self.host_gid)?;

        Ok(())
    }
}
