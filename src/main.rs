use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

mod capabilities;
mod cgroups;
mod namespace;
mod process;
mod rootfs;

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
        } => {
            info!(
                "container config: rootfs={:?} cpu={:?} memory={:?} hostname={:?}",
                rootfs, cpu, memory, hostname
            );

            let exit_code = namespace::run_in_namespace(&command, rootfs, hostname, cpu, memory)?;
            if exit_code == 0 {
                info!("Goodbye!!",);
            } else {
                info!("Exited with code {}", exit_code);
            }

            std::process::exit(exit_code)
        }
    }
}
