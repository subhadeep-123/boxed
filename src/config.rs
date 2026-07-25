use anyhow::{Context, Result};
use log::info;
use std::{env, fs, path::PathBuf};

pub fn config_dir() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME environment variable is not set")?;

    Ok(std::path::Path::new(&home).join(format!(".{}", env!("CARGO_PKG_NAME"))))
}

pub fn create_config_dir() -> Result<()> {
    let dir = config_dir()?;

    fs::create_dir_all(&dir)?;

    info!("Created config directory at {}", dir.display());

    Ok(())
}
