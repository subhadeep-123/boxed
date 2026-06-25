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
