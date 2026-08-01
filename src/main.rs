use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

mod capabilities;
mod cgroups;
mod config;
mod namespace;
mod overlay;
mod process;
mod rootfs;
mod rootless;
mod seccomp;

#[derive(Parser)]
#[command(name = "boxed")]
#[command(about = "A container runtime built from scratch", version="0.1", long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(trailing_var_arg = true)]
    Run {
        #[arg(long, help = "Path to root filesystem")]
        rootfs: Option<String>,

        #[arg(
            long,
            conflicts_with = "rootfs",
            help = "Path to a directory of stacked overlay layers"
        )]
        image: Option<String>,

        #[command(flatten)]
        limits: CgroupArgs,

        #[arg(required = true, help = "Command to run inside the container")]
        command: Vec<String>,

        #[arg(long, help = "Hostname for the container")]
        hostname: Option<String>,

        #[arg(long, help = "Run the container in a rootless (user) namespace")]
        rootless: bool,

        #[arg(
            long,
            requires = "rootless",
            help = "UID to appear as inside the container"
        )]
        uid: Option<u32>,

        #[arg(
            long,
            requires = "rootless",
            help = "GID to appear as inside the container"
        )]
        gid: Option<u32>,

        #[arg(long, help = "Parse JSON file for secure computing configuration")]
        seccomp_profile: Option<String>,
    },
}

// Cgroup limits. `help_heading` is set per-argument rather than with
// `next_help_heading` on the struct: the latter also applies to every
// argument declared after the `flatten` in the parent, which drags
// unrelated flags under this heading. Doc comments are avoided here too —
// clap turns them into the subcommand's `about` text.
#[derive(clap::Args, Debug)]
struct CgroupArgs {
    #[arg(
        long,
        help_heading = "Resource limits",
        help = "CPU quota in microseconds (per 100000us period)"
    )]
    cpu: Option<u64>,

    #[arg(long, help_heading = "Resource limits", help = "Memory limit in bytes")]
    memory: Option<u64>,

    #[arg(
        long,
        help_heading = "Resource limits",
        help = "Max tasks; threads count, and PID 1 is included"
    )]
    pids_limit: Option<u64>,

    #[arg(
        long,
        help_heading = "Resource limits",
        help = "CPUs the container may run on, e.g. 0-3 or 0,2,4"
    )]
    cpuset_cpus: Option<String>,

    #[arg(
        long,
        help_heading = "Resource limits",
        help = "NUMA memory nodes the container may allocate from, e.g. 0"
    )]
    cpuset_mems: Option<String>,

    #[arg(
        long,
        help_heading = "Resource limits",
        help = "Block IO cap, e.g. /dev/sda:wbps=1048576 — keys rbps/wbps (bytes/s), riops/wiops (ops/s); repeat per device",
        // Continuation lines start at column 0: a string literal keeps whatever
        // indentation is typed, and clap renders it verbatim.
        long_help = "Block IO cap, e.g. /dev/sda:wbps=1048576.
Keys: rbps, wbps (bytes/sec), riops, wiops (ops/sec). Repeat the flag per device.

Only direct I/O is throttled. Buffered writes land in page cache and are flushed \
later by writeback, so they will appear unthrottled — test with dd oflag=direct."
    )]
    io_max: Vec<String>,
}

impl From<CgroupArgs> for cgroups::CgroupConfig {
    fn from(value: CgroupArgs) -> Self {
        Self {
            cpu_quota: value.cpu,
            memory_max: value.memory,
            pids_limit: value.pids_limit,
            cpuset_cpus: value.cpuset_cpus,
            cpuset_mems: value.cpuset_mems,
            io_max: value.io_max,
        }
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();

    config::create_config_dir()?;

    info!("Starting Container");

    match cli.command {
        Commands::Run {
            rootfs,
            image,
            limits,
            command,
            hostname,
            rootless,
            uid,
            gid,
            seccomp_profile,
        } => {
            // TODO - Config Parser
            // Load Default Config
            // Render with ASCI
            // Initial Logs + Telemetry
            let mut setup_msg = format!(
                "container config: rootfs={rootfs:?} image={image:?} limits={limits:?} hostname={hostname:?}",
            );
            if rootless {
                setup_msg.push_str(" with rootless mode enabled");
            } else {
                setup_msg.push_str(" with rootless mode disabled");
            }

            info!("{setup_msg}");

            // parse seccomp profile flag
            let seccomp_profile = seccomp_profile
                .map(seccomp::SeccompProfile::from_file)
                .transpose()?;

            let opts = namespace::RunOptions {
                command,
                rootfs,
                image,
                hostname,
                limits: limits.into(),
                seccomp_profile,
            };

            let rootless = rootless::RootlessConfig::new(rootless, uid, gid)?;

            let exit_code = namespace::run_in_namespace(opts, rootless)?;
            if exit_code == 0 {
                info!("Goodbye!!",);
            } else {
                info!("Exited with code {}", exit_code);
            }

            std::process::exit(exit_code)
        }
    }
}
