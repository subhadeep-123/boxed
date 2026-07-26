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
}

impl From<CgroupArgs> for cgroups::CgroupConfig {
    fn from(value: CgroupArgs) -> Self {
        Self {
            cpu_quota: value.cpu,
            memory_max: value.memory,
            pids_limit: value.pids_limit,
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
