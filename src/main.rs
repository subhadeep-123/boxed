use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

mod capabilities;
mod cgroups;
mod namespace;
mod process;
mod rootfs;
mod rootless;

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

        #[arg(long, help = "CPU quota in microseconds (per 100000us period)")]
        cpu: Option<u64>,

        #[arg(long, help = "Memory limit in bytes")]
        memory: Option<u64>,

        #[arg(required = true, help = "Command to run inside the container")]
        command: Vec<String>,

        #[arg(long, help = "Hostname for the container")]
        hostname: Option<String>,

        #[arg(long, help = "Run the container in a rootless (user) namespace")]
        rootless: bool,

        #[arg(
            long,
            requires = "rootless",
            help = "Host UID to map into the container"
        )]
        host_uid: Option<u32>,

        #[arg(
            long,
            requires = "rootless",
            help = "Host GID to map into the container"
        )]
        host_gid: Option<u32>,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();

    let cli = Cli::parse();

    info!("Starting Container");

    match cli.command {
        Commands::Run {
            rootfs,
            cpu,
            memory,
            command,
            hostname,
            rootless,
            host_uid,
            host_gid,
        } => {
            // TODO - Config Parser
            // Load Default Config
            // Render with ASCI
            // Initial Logs + Telemetry
            let mut setup_msg = format!(
                "container config: rootfs={rootfs:?} cpu={cpu:?} memory={memory:?} hostname={hostname:?}",
            );
            if rootless {
                setup_msg.push_str(" with rootless mode enabled");
            } else {
                setup_msg.push_str(" with rootless mode disabled");
            }

            info!("{setup_msg}");

            let opts = namespace::RunOptions {
                command,
                rootfs,
                hostname,
                cpu,
                memory,
            };

            let rootless = rootless::RootlessConfig::new(rootless, host_uid, host_gid)?;

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
