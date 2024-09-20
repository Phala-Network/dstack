//! App related code
//!
//! Directory structure:
//! ```text
//! .teepod/
//! ├── image
//! │   └── ubuntu-24.04
//! │       ├── hda.img
//! │       ├── info.json
//! │       ├── initrd.img
//! │       ├── kernel
//! │       └── rootfs.iso
//! └── vm
//!     └── e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//!         └── shared
//!             └── docker-compose.yaml
//! ```
use crate::config::Config;
use crate::vm::run::{Image, VmConfig, VmMonitor};

use anyhow::{Context, Result};
use bon::Builder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use fs_err as fs;

#[derive(Deserialize, Serialize, Builder)]
pub struct Manifest {
    name: String,
    vcpu: u32,
    memory: u32,
    disk_size: u32,
    image: String,
    port_map: HashMap<u16, u16>,
}

#[derive(Clone)]
pub struct App {
    state: Arc<Mutex<AppState>>,
}

struct AppState {
    config: Config,
    monitor: VmMonitor,
}

impl App {
    pub(crate) fn vm_dir(&self) -> PathBuf {
        let base_path: PathBuf = self.state.lock().unwrap().config.run_path.clone().into();
        base_path.join("vm")
    }

    pub fn new(config: Config) -> Self {
        Self {
            state: Arc::new(Mutex::new(AppState {
                monitor: VmMonitor::new(config.qemu_path.clone()),
                config,
            })),
        }
    }

    pub fn load_vm(&self, work_dir: impl AsRef<Path>) -> Result<()> {
        let manifest_path = work_dir.as_ref().join("config.json");
        let manifest = fs::read_to_string(manifest_path).context("Failed to read manifest")?;
        let manifest: Manifest =
            serde_json::from_str(&manifest).context("Failed to parse manifest")?;
        let image = Image::load(&manifest.image)?;
        let id = uuid::Uuid::new_v4().to_string();
        let vm_config = VmConfig {
            id,
            process_name: manifest.name,
            vcpu: manifest.vcpu,
            memory: manifest.memory,
            image,
            // TODO: add tdx config
            tdx_config: None,
            port_map: manifest.port_map,
            disk_size: manifest.disk_size,
        };
        let result = self
            .state
            .lock()
            .unwrap()
            .monitor
            .run_vm(vm_config, work_dir.as_ref());
        if let Err(err) = result {
            println!("Failed to run VM: {err}");
        }
        Ok(())
    }

    pub fn stop_vm(&self, id: &str) -> Result<()> {
        self.state.lock().unwrap().monitor.stop_vm(id)?;
        Ok(())
    }

    pub fn reload_vms(&self) -> Result<()> {
        let vm_path = self.vm_dir();
        if vm_path.exists() {
            for entry in fs::read_dir(vm_path).context("Failed to read VM directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let vm_path = entry.path();
                if vm_path.is_dir() {
                    if let Err(err) = self.load_vm(vm_path) {
                        println!("Failed to load VM: {err}");
                    }
                }
            }
        }
        Ok(())
    }
}
