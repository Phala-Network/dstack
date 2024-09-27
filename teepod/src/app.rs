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
use crate::vm::run::{Image, TdxConfig, VmConfig, VmMonitor};

use anyhow::{Context, Result};
use bon::Builder;
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use teepod_rpc::VmInfo;

#[derive(Deserialize, Serialize, Builder)]
pub struct Manifest {
    id: String,
    name: String,
    address: String,
    vcpu: u32,
    memory: u32,
    disk_size: u32,
    image: String,
    port_map: HashMap<u16, u16>,
}

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    state: Arc<Mutex<AppState>>,
}

pub(crate) struct AppState {
    monitor: VmMonitor,
}

impl App {
    pub(crate) fn vm_dir(&self) -> PathBuf {
        self.config.run_path.clone().into()
    }

    pub fn new(config: Config) -> Self {
        Self {
            state: Arc::new(Mutex::new(AppState {
                monitor: VmMonitor::new(config.qemu_path.clone()),
            })),
            config: Arc::new(config),
        }
    }

    pub fn load_vm(&self, work_dir: impl AsRef<Path>) -> Result<()> {
        let manifest_path = work_dir.as_ref().join("config.json");
        let manifest = fs::read_to_string(manifest_path).context("Failed to read manifest")?;
        let manifest: Manifest =
            serde_json::from_str(&manifest).context("Failed to parse manifest")?;
        let todo = "sanitize the image name";
        let image_path = self.config.image_path.join(&manifest.image);
        let image = Image::load(&image_path).context("Failed to load image")?;

        let todo = "CID management";

        static NEXT_CID: AtomicU32 = AtomicU32::new(10000);
        let cid = NEXT_CID.fetch_add(1, Ordering::Relaxed);

        let vm_config = VmConfig {
            id: manifest.id.clone(),
            process_name: manifest.name,
            vcpu: manifest.vcpu,
            memory: manifest.memory,
            image,
            tdx_config: Some(TdxConfig { cid }),
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

    pub fn list_vms(&self) -> Vec<VmInfo> {
        let mut infos = self
            .state
            .lock()
            .unwrap()
            .monitor
            .iter_vms()
            .map(|vm| vm.info())
            .collect::<Vec<_>>();

        infos.sort_by(|a, b| b.uptime_ms.cmp(&a.uptime_ms));

        infos
            .into_iter()
            .map(|info| VmInfo {
                id: info.id,
                status: if info.is_running {
                    "running".to_string()
                } else {
                    "stopped".to_string()
                },
                uptime: info.uptime,
            })
            .collect()
    }

    pub fn get_log(&self, id: &str) -> Result<String> {
        self.state.lock().unwrap().monitor.get_log(id)
    }
}
