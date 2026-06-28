use anyhow::Context;
use anyhow::Result;
use std::{fs, path::PathBuf};

pub struct CgroupConfig {
    pub cpu_quota: Option<u64>,
    pub memory_max: Option<u64>,
}

pub struct Cgroup {
    pub path: PathBuf,
}

impl Cgroup {
    pub fn create(pid: u32, config: &CgroupConfig) -> Result<Self> {
        let parent = PathBuf::from("/sys/fs/cgroup/boxed");
        fs::create_dir_all(&parent).context("failed to create boxed cgroup dir")?;
        // cgroups v2: controllers must be enabled in the parent before child cgroups can use them
        fs::write(parent.join("cgroup.subtree_control"), "+cpu +memory")
            .context("failed to enable cgroup controllers — are cpu/memory available in /sys/fs/cgroup/cgroup.subtree_control?")?;

        let path = PathBuf::from(format!("/sys/fs/cgroup/boxed/{}", pid));
        fs::create_dir_all(&path)
            .with_context(|| format!("failed to create cgroup dir at {:?}", path))?;

        if let Some(quota) = config.cpu_quota {
            let value = format!("{} 100000", quota);
            fs::write(path.join("cpu.max"), value).context("failed to write cpu.max")?;
        }

        if let Some(mem) = config.memory_max {
            fs::write(path.join("memory.max"), mem.to_string())
                .context("failed to write memory.max")?;
        }

        Ok(Self { path })
    }

    pub fn add_process(&self, pid: u32) -> Result<()> {
        fs::write(self.path.join("cgroup.procs"), pid.to_string())
            .context("failed to add process to cgroup")?;
        Ok(())
    }

    pub fn destroy(&self) -> Result<()> {
        fs::remove_dir(&self.path)
            .with_context(|| format!("failed to remove cgroup at {:?}", self.path))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_all_none() {
        let config = CgroupConfig { cpu_quota: None, memory_max: None };
        assert!(config.cpu_quota.is_none());
        assert!(config.memory_max.is_none());
    }

    #[test]
    fn config_with_values() {
        let config = CgroupConfig { cpu_quota: Some(50_000), memory_max: Some(256 * 1024 * 1024) };
        assert_eq!(config.cpu_quota, Some(50_000));
        assert_eq!(config.memory_max, Some(268_435_456));
    }

    #[test]
    fn cpu_quota_string_format() {
        assert_eq!(format!("{} 100000", 50_000u64), "50000 100000");
        assert_eq!(format!("{} 100000", 10_000u64), "10000 100000");
        assert_eq!(format!("{} 100000", 100_000u64), "100000 100000");
    }

    #[test]
    fn cgroup_path_contains_pid() {
        let pid: u32 = 1234;
        let path = PathBuf::from(format!("/sys/fs/cgroup/boxed/{}", pid));
        assert_eq!(path.to_str().unwrap(), "/sys/fs/cgroup/boxed/1234");
    }

    #[test]
    fn cgroup_path_unique_per_pid() {
        let p1 = PathBuf::from(format!("/sys/fs/cgroup/boxed/{}", 100u32));
        let p2 = PathBuf::from(format!("/sys/fs/cgroup/boxed/{}", 200u32));
        assert_ne!(p1, p2);
    }

    #[test]
    #[ignore = "requires root and cgroups v2"]
    fn create_and_destroy() {
        let config = CgroupConfig { cpu_quota: Some(50_000), memory_max: Some(64 * 1024 * 1024) };
        let cg = Cgroup::create(99997, &config).expect("create failed");
        assert!(cg.path.exists());
        cg.destroy().expect("destroy failed");
        assert!(!cg.path.exists());
    }

    #[test]
    #[ignore = "requires root and cgroups v2"]
    fn create_cpu_only() {
        let config = CgroupConfig { cpu_quota: Some(25_000), memory_max: None };
        let cg = Cgroup::create(99998, &config).expect("create failed");
        assert!(cg.path.exists());
        cg.destroy().expect("destroy failed");
    }

    #[test]
    #[ignore = "requires root and cgroups v2"]
    fn create_mem_only() {
        let config = CgroupConfig { cpu_quota: None, memory_max: Some(32 * 1024 * 1024) };
        let cg = Cgroup::create(99999, &config).expect("create failed");
        assert!(cg.path.exists());
        cg.destroy().expect("destroy failed");
    }
}
