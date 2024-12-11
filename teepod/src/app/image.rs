use fs_err as fs;
use path_absolutize::Absolutize;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageInfo {
    pub cmdline: Option<String>,
    pub kernel: String,
    pub initrd: String,
    pub hda: Option<String>,
    pub rootfs: Option<String>,
    pub bios: Option<String>,
    pub rootfs_hash: Option<String>,
}

impl ImageInfo {
    pub fn load(filename: PathBuf) -> Result<Self> {
        let file = fs::File::open(filename).context("failed to open image info")?;
        let info: ImageInfo =
            serde_json::from_reader(file).context("failed to parse image info")?;
        Ok(info)
    }
}

#[derive(Debug)]
pub struct Image {
    pub info: ImageInfo,
    pub initrd: PathBuf,
    pub kernel: PathBuf,
    pub hda: Option<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub bios: Option<PathBuf>,
}

impl Image {
    pub fn load(base_path: impl AsRef<Path>) -> Result<Self> {
        let base_path = base_path.as_ref().absolutize()?;
        let info = ImageInfo::load(base_path.join("metadata.json"))?;
        let initrd = base_path.join(&info.initrd);
        let kernel = base_path.join(&info.kernel);
        let hda = info.hda.as_ref().map(|hda| base_path.join(hda));
        let rootfs = info.rootfs.as_ref().map(|rootfs| base_path.join(rootfs));
        let bios = info.bios.as_ref().map(|bios| base_path.join(bios));
        Self {
            info,
            hda,
            initrd,
            kernel,
            rootfs,
            bios,
        }
        .ensure_exists()
    }

    fn ensure_exists(self) -> Result<Self> {
        if !self.initrd.exists() {
            bail!("Initrd does not exist: {}", self.initrd.display());
        }
        if !self.kernel.exists() {
            bail!("Kernel does not exist: {}", self.kernel.display());
        }
        if let Some(hda) = &self.hda {
            if !hda.exists() {
                bail!("Hda does not exist: {}", hda.display());
            }
        }
        if let Some(rootfs) = &self.rootfs {
            if !rootfs.exists() {
                bail!("Rootfs does not exist: {}", rootfs.display());
            }
        }
        if let Some(bios) = &self.bios {
            if !bios.exists() {
                bail!("Bios does not exist: {}", bios.display());
            }
        }
        Ok(self)
    }
}
