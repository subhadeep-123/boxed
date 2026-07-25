use anyhow::{Context, Result, bail};
use log::info;
use nix::{
    mount::{MsFlags, mount},
    unistd::Pid,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn subdirectories(path: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs.push(entry.path());
        }
    }

    if dirs.is_empty() {
        bail!("no layers found under {}", path.display());
    }

    Ok(dirs)
}

fn discover_lower_layers(image_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut layers = subdirectories(image_dir)?;

    layers.sort_by(|a, b| a.file_name().unwrap().cmp(b.file_name().unwrap()));

    layers.reverse();

    Ok(layers)
}

struct OverlayPaths {
    upper: PathBuf,
    work: PathBuf,
    merged: PathBuf,
}

fn get_overlay_root(id: u32) -> PathBuf {
    std::env::temp_dir().join(format!("{}-overlay-{}", env!("CARGO_PKG_NAME"), id))
}

fn create_overlay_scratch() -> Result<OverlayPaths> {
    let root = get_overlay_root(std::process::id());

    let upper = root.join("upper");
    let work = root.join("work");
    let merged = root.join("merged");

    fs::create_dir_all(&upper)?;
    fs::create_dir_all(&work)?;
    fs::create_dir_all(&merged)?;

    info!("Created overlay scratch directory at {}", root.display());

    Ok(OverlayPaths {
        upper,
        work,
        merged,
    })
}

fn lowerdir_string(layers: &[PathBuf]) -> Result<String> {
    Ok(layers
        .iter()
        .map(|p| {
            p.to_str()
                .with_context(|| format!("path {} is not a valid UTF-8 path", p.display()))
        })
        .collect::<Result<Vec<_>>>()?
        .join(":"))
}

fn mount_overlay(layers: &[PathBuf], paths: &OverlayPaths) -> Result<()> {
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdir_string(layers)?,
        &paths
            .upper
            .to_str()
            .context("upper path is not valid UTF-8")?,
        &paths
            .work
            .to_str()
            .context("work path is not valid UTF-8")?
    );
    info!("OverlayFS mount data - {}", &data);

    mount(
        Some("overlay"),
        &paths.merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(data.as_str()),
    )?;

    info!("Overlay mounted at {}", paths.merged.display());

    Ok(())
}

pub fn setup(image: &str) -> Result<PathBuf> {
    let image_dir = Path::new(image);
    let layers = discover_lower_layers(image_dir)?;

    let overlay_paths = create_overlay_scratch()?;

    mount_overlay(&layers, &overlay_paths)?;

    Ok(overlay_paths.merged)
}

pub fn teardown(pid: Pid) -> Result<()> {
    let path = get_overlay_root(pid.as_raw() as u32);
    info!("Overlay teardown, dropping - {}", path.display());
    fs::remove_dir_all(path)?;
    Ok(())
}
