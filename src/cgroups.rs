use anyhow::{Context, Result, bail};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Parent cgroup holding one child cgroup per container.
const CGROUP_ROOT: &str = "/sys/fs/cgroup/boxed";

/// A cgroup v2 controller paired with the CLI flag that requests it. Kept
/// together so the flag named in an error can't drift from the controller.
struct RequiredController {
    name: &'static str,
    flag: &'static str,
}

pub struct CgroupConfig {
    pub cpu_quota: Option<u64>,
    pub memory_max: Option<u64>,
}

impl CgroupConfig {
    pub fn is_noop(&self) -> bool {
        self.cpu_quota.is_none() && self.memory_max.is_none()
    }

    pub fn new(cpu_quota: Option<u64>, memory_max: Option<u64>) -> Self {
        CgroupConfig {
            cpu_quota,
            memory_max,
        }
    }

    fn required_controllers(&self) -> Vec<RequiredController> {
        let mut required = Vec::new();

        if self.cpu_quota.is_some() {
            required.push(RequiredController {
                name: "cpu",
                flag: "--cpu",
            });
        }
        if self.memory_max.is_some() {
            required.push(RequiredController {
                name: "memory",
                flag: "--memory",
            });
        }

        required
    }
}

pub struct Cgroup {
    pub path: PathBuf,
}

fn write_controller(cgroup_dir: &Path, filename: &str, value: impl AsRef<[u8]>) -> Result<()> {
    fs::write(cgroup_dir.join(filename), value)
        .with_context(|| format!("failed to write {}", filename))
}

/// Reads a `cgroup.controllers` file into the controller names it lists.
fn read_controllers(path: &Path) -> Result<Vec<String>> {
    Ok(fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?
        .split_whitespace()
        .map(str::to_owned)
        .collect())
}

/// Checks every required controller was delegated to us, and builds the
/// `cgroup.subtree_control` line that enables them.
fn validate_controllers(required: &[RequiredController], available: &[String]) -> Result<String> {
    for controller in required {
        if !available.iter().any(|a| a.as_str() == controller.name) {
            bail!(
                "{} requested, but the `{}` controller is not available to {} — it lists only: {}",
                controller.flag,
                controller.name,
                CGROUP_ROOT,
                available.join(" ")
            );
        }
    }

    Ok(required
        .iter()
        .map(|c| format!("+{}", c.name))
        .collect::<Vec<_>>()
        .join(" "))
}

impl Cgroup {
    pub fn create(pid: u32, config: &CgroupConfig) -> Result<Self> {
        let parent = PathBuf::from(CGROUP_ROOT);
        fs::create_dir_all(&parent).context("failed to create boxed cgroup dir")?;

        // A cgroup's own cgroup.controllers lists what its parent delegated to
        // it, which is what we can actually enable — not the full set the
        // kernel supports.
        let available = read_controllers(&parent.join("cgroup.controllers"))?;
        let required = config.required_controllers();

        // cgroups v2: controllers must be enabled in the parent before child cgroups can use them
        let subtree_control = validate_controllers(&required, &available)?;
        let subtree_control_path = parent.join("cgroup.subtree_control");
        fs::write(&subtree_control_path, &subtree_control).with_context(|| {
            format!(
                "failed to write {:?} to {}",
                subtree_control,
                subtree_control_path.display()
            )
        })?;

        let path = parent.join(pid.to_string());
        fs::create_dir_all(&path)
            .with_context(|| format!("failed to create cgroup dir at {:?}", path))?;

        if let Some(quota) = config.cpu_quota {
            write_controller(&path, "cpu.max", format!("{} 100000", quota))?;
        }

        if let Some(memory) = config.memory_max {
            write_controller(&path, "memory.max", memory.to_string())?;
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

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_all_none() {
        let config = CgroupConfig {
            cpu_quota: None,
            memory_max: None,
        };
        assert!(config.cpu_quota.is_none());
        assert!(config.memory_max.is_none());
    }

    #[test]
    fn config_with_values() {
        let config = CgroupConfig {
            cpu_quota: Some(50_000),
            memory_max: Some(256 * 1024 * 1024),
        };
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
        let config = CgroupConfig {
            cpu_quota: Some(50_000),
            memory_max: Some(64 * 1024 * 1024),
        };
        let cg = Cgroup::create(99997, &config).expect("create failed");
        assert!(cg.path.exists());
        cg.destroy().expect("destroy failed");
        assert!(!cg.path.exists());
    }

    #[test]
    #[ignore = "requires root and cgroups v2"]
    fn create_cpu_only() {
        let config = CgroupConfig {
            cpu_quota: Some(25_000),
            memory_max: None,
        };
        let cg = Cgroup::create(99998, &config).expect("create failed");
        assert!(cg.path.exists());
        cg.destroy().expect("destroy failed");
    }

    #[test]
    #[ignore = "requires root and cgroups v2"]
    fn create_mem_only() {
        let config = CgroupConfig {
            cpu_quota: None,
            memory_max: Some(32 * 1024 * 1024),
        };
        let cg = Cgroup::create(99999, &config).expect("create failed");
        assert!(cg.path.exists());
        cg.destroy().expect("destroy failed");
    }
}
