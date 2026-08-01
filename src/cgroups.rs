use anyhow::{Context, Result, bail};
use nix::sys::stat::{SFlag, major, minor, stat};
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
    pub pids_limit: Option<u64>,
    pub cpuset_cpus: Option<String>,
    pub cpuset_mems: Option<String>,
    pub io_max: Vec<String>,
}

impl CgroupConfig {
    pub fn is_noop(&self) -> bool {
        self.cpu_quota.is_none()
            && self.memory_max.is_none()
            && self.pids_limit.is_none()
            && self.cpuset_cpus.is_none()
            && self.cpuset_mems.is_none()
            && self.io_max.is_empty()
    }

    /// Rejects malformed `--io-max` values up front. `create` parses these
    /// again, but only after the container has been cloned — calling this
    /// straight after argument parsing turns a typo into an immediate error
    /// instead of one reported after a process has been spawned and killed.
    pub fn validate(&self) -> Result<()> {
        for spec in &self.io_max {
            let parsed = parse_io_max(spec)?;
            resolve_device(&parsed.device)?;
        }
        Ok(())
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

        if self.pids_limit.is_some() {
            required.push(RequiredController {
                name: "pids",
                flag: "--pids-limit",
            });
        }

        // Both cpuset flags are served by the single `cpuset` controller, so
        // it is requested once rather than once per flag — two entries would
        // emit "+cpuset +cpuset" into cgroup.subtree_control.
        if self.cpuset_cpus.is_some() || self.cpuset_mems.is_some() {
            required.push(RequiredController {
                name: "cpuset",
                flag: "--cpuset-cpus/--cpuset-mems",
            });
        }

        if !self.io_max.is_empty() {
            required.push(RequiredController {
                name: "io",
                flag: "--io-max",
            });
        }

        required
    }
}

/// One `--io-max` value: the device it names, and the limits asked for it.
#[derive(Debug, PartialEq)]
struct IoMax {
    device: String,
    limits: Vec<(String, u64)>,
}

/// The only keys `io.max` accepts. Anything else is a typo and silently
/// dropping it would leave the user believing a limit was applied
const IO_MAX_KEYS: [&str; 4] = ["rbps", "wbps", "riops", "wiops"];

fn parse_io_max(spec: &str) -> Result<IoMax> {
    let (device, limits) = spec.split_once(':').with_context(|| {
        format!("invalid --io-max {spec:?}: expected DEVICE:KEY=VALUE, e.g. /dev/sda:wbps=1048576")
    })?;

    if device.is_empty() {
        bail!("invalid --io-max {spec:?}: device path is empty");
    }
    if limits.is_empty() {
        bail!("invalid --io-max {spec:?}: no limits given after ':'");
    }

    let limits = limits
        .split(',')
        .map(|pair| {
            let (key, value) = pair
                .split_once('=')
                .with_context(|| format!("invalid --io-max entry {pair:?}: expected KEY=VALUE"))?;

            if !IO_MAX_KEYS.contains(&key) {
                bail!(
                    "invalid --io-max key {key:?}: expected one of {}",
                    IO_MAX_KEYS.join(", ")
                );
            }

            let value: u64 = value
                .parse()
                .with_context(|| format!("invalid --io-max value {value:?} for {key}"))?;

            Ok((key.to_string(), value))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(IoMax {
        device: device.to_string(),
        limits,
    })
}

///  /dev/sda -> "8:0". The only part that touches the kernel.
fn resolve_device(path: &str) -> Result<String> {
    let info = stat(path).with_context(|| format!("failed to stat {path}"))?;

    // /dev/null is a "character" device with a perfectly valid st_rdev
    // Writing its number to io.max would throttle nothing, silently.
    if SFlag::from_bits_truncate(info.st_mode) & SFlag::S_IFMT != SFlag::S_IFBLK {
        bail!("{path} is not a block device");
    }

    // st_rdev is the device this node "refers to. st_dev would be devtmpfs,
    // the filesystem the node itself lives on, which cannot be throttled.
    Ok(format!("{}:{}", major(info.st_rdev), minor(info.st_rdev)))
}

fn render_io_max(device_number: &str, limits: &[(String, u64)]) -> String {
    let mut line = String::from(device_number);
    for (key, value) in limits {
        line.push_str(&format!(" {key}={value}"));
    }
    line
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
/// Turns a rejected `cpuset.*` write into something diagnosable by quoting the
/// matching `.effective` file — the only place that knows what the hierarchy
/// actually permits, since it accounts for parent restrictions and offline
/// CPUs. `cpuset_type` is the infix: `"cpus"` or `"mems"`.
fn handle_cpuset_write_error(
    ret: Result<()>,
    cgroup_dir: &Path,
    cpuset_type: &str,
    cpuset_value: &str,
) -> Result<()> {
    let Err(err) = ret else {
        return Ok(());
    };

    // The write failed for some reason — invalid range, but equally EACCES or
    // ENOENT. `.effective` is added as context; it never replaces the original
    // error, which carries the actual cause.
    let effective_file = format!("cpuset.{}.effective", cpuset_type);
    match fs::read_to_string(cgroup_dir.join(&effective_file)) {
        Ok(effective) => Err(err.context(format!(
            "--cpuset-{} {:?} was rejected; {} allows {}",
            cpuset_type,
            cpuset_value,
            cgroup_dir.display(),
            effective.trim()
        ))),
        // A failure to read .effective must not mask the write error.
        Err(_) => Err(err.context(format!(
            "--cpuset-{} {:?} was rejected, and {} could not be read",
            cpuset_type, cpuset_value, effective_file
        ))),
    }
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

        if let Some(pids_limit) = config.pids_limit {
            write_controller(&path, "pids.max", pids_limit.to_string())?;
        }

        if let Some(cpuset_cpus) = &config.cpuset_cpus {
            let ret = write_controller(&path, "cpuset.cpus", cpuset_cpus);
            handle_cpuset_write_error(ret, &path, "cpus", cpuset_cpus)?;
        }

        if let Some(cpuset_mems) = &config.cpuset_mems {
            let ret = write_controller(&path, "cpuset.mems", cpuset_mems);
            handle_cpuset_write_error(ret, &path, "mems", cpuset_mems)?;
        }

        for spec in &config.io_max {
            let parsed = parse_io_max(spec)?;
            let device = resolve_device(&parsed.device)?;
            write_controller(&path, "io.max", render_io_max(&device, &parsed.limits))?;
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
            pids_limit: None,
            cpuset_cpus: None,
            cpuset_mems: None,
            io_max: Vec::new(),
        };
        assert!(config.is_noop());
    }

    #[test]
    fn config_with_values() {
        let config = CgroupConfig {
            cpu_quota: Some(50_000),
            memory_max: Some(256 * 1024 * 1024),
            pids_limit: Some(100),
            cpuset_cpus: Some("0-1".to_string()),
            cpuset_mems: Some("0".to_string()),
            io_max: vec!["/dev/sda:wbps=1048576".to_string()],
        };
        assert_eq!(config.cpu_quota, Some(50_000));
        assert_eq!(config.memory_max, Some(268_435_456));
        assert_eq!(config.pids_limit, Some(100));
        assert_eq!(config.cpuset_cpus.as_deref(), Some("0-1"));
        assert_eq!(config.cpuset_mems.as_deref(), Some("0"));
        assert_eq!(config.io_max, vec!["/dev/sda:wbps=1048576"]);
        assert!(!config.is_noop());
    }

    #[test]
    fn config_with_only_io_max_is_not_noop() {
        // io_max is the one field held in a Vec, so emptiness rather than
        // None decides whether a cgroup is created at all.
        let config = CgroupConfig {
            cpu_quota: None,
            memory_max: None,
            pids_limit: None,
            cpuset_cpus: None,
            cpuset_mems: None,
            io_max: vec!["/dev/sda:wbps=1048576".to_string()],
        };
        assert!(!config.is_noop());
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
            pids_limit: Some(100),
            // CPU 0 and NUMA node 0 exist on every machine, so this stays
            // valid wherever the root-gated suite is run.
            cpuset_cpus: Some("0".to_string()),
            cpuset_mems: Some("0".to_string()),
            io_max: Vec::new(),
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
            pids_limit: None,
            cpuset_cpus: None,
            cpuset_mems: None,
            io_max: Vec::new(),
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
            pids_limit: None,
            cpuset_cpus: None,
            cpuset_mems: None,
            io_max: Vec::new(),
        };
        let cg = Cgroup::create(99999, &config).expect("create failed");
        assert!(cg.path.exists());
        cg.destroy().expect("destroy failed");
    }

    #[test]
    #[ignore = "requires root and cgroups v2"]
    fn create_cpuset_only() {
        let config = CgroupConfig {
            cpu_quota: None,
            memory_max: None,
            pids_limit: None,
            cpuset_cpus: Some("0".to_string()),
            cpuset_mems: None,
            io_max: Vec::new(),
        };
        let cg = Cgroup::create(99996, &config).expect("create failed");
        assert!(cg.path.exists());
        cg.destroy().expect("destroy failed");
    }
}
