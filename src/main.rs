use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

#[derive(Parser)]
#[command(name = "boxed")]
#[command(about = "A container runtime built from scratch", version="0.1", long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(long, help = "Path to root filesystem")]
        rootfs: Option<String>,

        #[arg(long, help = "CPU quota in microseconds (per 100000us period)")]
        cpu: Option<u64>,

        #[arg(long, help = "Memory limit in bytes")]
        mem: Option<u64>,

        #[arg(required = true, help = "Command to run inside the container")]
        command: Vec<String>,
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
            mem,
            command,
        } => {
            info!(
                "container config: rootfs={:?} cpu={:?} mem={:?}",
                rootfs, cpu, mem
            );
            info!("would run: {:?}", command);
        }
    }

    Ok(())
}
