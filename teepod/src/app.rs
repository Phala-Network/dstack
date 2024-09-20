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
use crate::paths;
use crate::vm::run::{Image, VmConfig, VmMonitor};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use bon::builder;

#[builder]
#[derive(Deserialize, Serialize)]
pub struct Manifest {
    name: String,
    vcpu: u32,
    memory: u64,
    image: String,
    port_map: HashMap<u16, u16>,
}

pub struct App {
    state: Arc<Mutex<AppState>>,
}

struct AppState {
    monitor: VmMonitor,
}

impl App {
    pub fn new(qemu_bin: String) -> Self {
        Self {
            state: Arc::new(Mutex::new(AppState {
                monitor: VmMonitor::new(qemu_bin),
            })),
        }
    }

    pub fn load_vm(&self, work_dir: impl AsRef<Path>) -> Result<()> {
        let manifest_path = work_dir.as_ref().join("config.json");
        let manifest = fs::read_to_string(manifest_path).context("Failed to read manifest")?;
        let manifest: Manifest =
            serde_json::from_str(&manifest).context("Failed to parse manifest")?;
        let image = Image::load(&manifest.image)?;
        let vm_config = VmConfig {
            process_name: manifest.name,
            vcpu: manifest.vcpu,
            memory: manifest.memory,
            image,
            // TODO: add tdx config
            tdx_config: None,
            port_map: manifest.port_map,
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
        let vm_path = paths::vm_dir();
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
