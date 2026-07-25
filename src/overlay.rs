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
        paths
            .upper
            .to_str()
            .context("upper path is not valid UTF-8")?,
        paths
            .work
            .to_str()
            .context("work path is not valid UTF-8")?
    );
    info!("OverlayFS mount data - {}", data);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("boxed-overlay-test-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discover_lower_layers_orders_topmost_layer_first() {
        let image_dir = unique_temp_dir("order");
        fs::create_dir_all(image_dir.join("00-base")).unwrap();
        fs::create_dir_all(image_dir.join("01-app")).unwrap();

        let layers = discover_lower_layers(&image_dir).unwrap();
        fs::remove_dir_all(&image_dir).ok();

        let names: Vec<_> = layers
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["01-app", "00-base"],
            "the most-recently-added layer must be leftmost/topmost in the returned order"
        );
    }

    #[test]
    fn discover_lower_layers_single_layer() {
        let image_dir = unique_temp_dir("single");
        fs::create_dir_all(image_dir.join("00-base")).unwrap();

        let layers = discover_lower_layers(&image_dir).unwrap();
        fs::remove_dir_all(&image_dir).ok();

        assert_eq!(layers.len(), 1);
    }

    #[test]
    fn discover_lower_layers_empty_dir_errors() {
        let image_dir = unique_temp_dir("empty");

        let result = discover_lower_layers(&image_dir);
        fs::remove_dir_all(&image_dir).ok();

        let err = result.expect_err("an image dir with zero layers must be rejected");
        assert!(
            err.to_string().contains("no layers found"),
            "expected a 'no layers found' error, got: {err}"
        );
    }

    #[test]
    fn discover_lower_layers_ignores_non_directory_entries() {
        let image_dir = unique_temp_dir("files-only");
        fs::write(image_dir.join("not-a-layer.txt"), b"hello").unwrap();

        let result = discover_lower_layers(&image_dir);
        fs::remove_dir_all(&image_dir).ok();

        assert!(
            result.is_err(),
            "a directory containing only files, no subdirectories, has zero real layers"
        );
    }

    #[test]
    fn discover_lower_layers_missing_dir_errors() {
        let missing =
            std::env::temp_dir().join(format!("boxed-overlay-test-missing-{}", std::process::id()));

        assert!(discover_lower_layers(&missing).is_err());
    }

    #[test]
    fn get_overlay_root_is_deterministic_per_pid() {
        assert_eq!(get_overlay_root(4821), get_overlay_root(4821));
        assert_ne!(get_overlay_root(4821), get_overlay_root(4822));
    }
}
