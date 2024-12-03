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
//!             └── app-compose.json
//! ```
use crate::config::{Config, Protocol};
use crate::vm::run::{Image, TdxConfig, VmConfig, VmMonitor};

use anyhow::{bail, Context, Result};
use bon::Builder;
use fs_err as fs;
use id_pool::IdPool;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use teepod_rpc as pb;
use tracing::{error, Instrument};

mod id_pool;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PortMapping {
    pub address: IpAddr,
    pub protocol: Protocol,
    pub from: u16,
    pub to: u16,
}

#[derive(Deserialize, Serialize, Clone, Builder, Debug)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub app_id: String,
    pub vcpu: u32,
    pub memory: u32,
    pub disk_size: u32,
    pub image: String,
    pub port_map: Vec<PortMapping>,
    pub created_at_ms: u64,
}

#[derive(Deserialize, Serialize)]
pub struct State {
    started: bool,
}

pub struct VmWorkDir {
    workdir: PathBuf,
}
impl VmWorkDir {
    pub fn new(workdir: impl AsRef<Path>) -> Self {
        Self {
            workdir: workdir.as_ref().to_path_buf(),
        }
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.workdir.join("vm-manifest.json")
    }

    pub fn state_path(&self) -> PathBuf {
        self.workdir.join("vm-state.json")
    }

    pub fn manifest(&self) -> Result<Manifest> {
        let manifest_path = self.manifest_path();
        let manifest = fs::read_to_string(manifest_path).context("Failed to read manifest")?;
        let manifest: Manifest =
            serde_json::from_str(&manifest).context("Failed to parse manifest")?;
        Ok(manifest)
    }

    pub fn put_manifest(&self, manifest: &Manifest) -> Result<()> {
        let manifest_path = self.manifest_path();
        fs::write(manifest_path, serde_json::to_string(manifest)?)
            .context("Failed to write manifest")
    }

    pub fn started(&self) -> Result<bool> {
        let state_path = self.state_path();
        if !state_path.exists() {
            return Ok(false);
        }
        let state: State =
            serde_json::from_str(&fs::read_to_string(state_path).context("Failed to read state")?)
                .context("Failed to parse state")?;
        Ok(state.started)
    }

    pub fn set_started(&self, started: bool) -> Result<()> {
        let state_path = self.state_path();
        fs::write(state_path, serde_json::to_string(&State { started })?)
            .context("Failed to write state")
    }

    pub fn app_compose_path(&self) -> PathBuf {
        self.workdir.join("shared").join("app-compose.json")
    }

    pub fn encrypted_env_path(&self) -> PathBuf {
        self.workdir.join("shared").join("encrypted-env")
    }
}

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    state: Arc<Mutex<AppState>>,
}

pub(crate) struct AppState {
    monitor: VmMonitor,
    cid_pool: IdPool<u32>,
}

impl App {
    pub(crate) fn vm_dir(&self) -> PathBuf {
        self.config.run_path.clone().into()
    }

    pub fn new(config: Config) -> Self {
        let cid_start = config.cvm.cid_start;
        let cid_end = cid_start.saturating_add(config.cvm.cid_pool_size);
        let cid_pool = IdPool::new(cid_start, cid_end);
        Self {
            state: Arc::new(Mutex::new(AppState {
                cid_pool,
                monitor: VmMonitor::new(config.qemu_path.clone()),
            })),
            config: Arc::new(config),
        }
    }

    pub fn load_vm(&self, work_dir: impl AsRef<Path>) -> Result<()> {
        let vm_work_dir = VmWorkDir::new(work_dir.as_ref());
        let manifest = vm_work_dir.manifest().context("Failed to read manifest")?;
        let todo = "sanitize the image name";
        let image_path = self.config.image_path.join(&manifest.image);
        let image = Image::load(&image_path).context("Failed to load image")?;

        let cid = self
            .state
            .lock()
            .unwrap()
            .cid_pool
            .allocate()
            .context("CID pool exhausted")?;

        let vm_config = VmConfig {
            manifest,
            image,
            tdx_config: Some(TdxConfig { cid }),
            networking: self.config.networking.clone(),
        };
        if vm_config.manifest.disk_size > self.config.cvm.max_disk_size {
            bail!(
                "disk size too large, max size is {}",
                self.config.cvm.max_disk_size
            );
        }
        let started = vm_work_dir.started().context("Failed to read VM state")?;
        let result =
            self.state
                .lock()
                .unwrap()
                .monitor
                .load_vm(vm_config, work_dir.as_ref(), started);
        if let Err(err) = result {
            println!("Failed to run VM: {err}");
        }
        Ok(())
    }

    pub fn start_vm(&self, id: &str) -> Result<()> {
        self.state.lock().unwrap().monitor.start_vm(id)?;
        let work_dir = VmWorkDir::new(self.vm_dir().join(id));
        work_dir
            .set_started(true)
            .context("Failed to set started")?;
        Ok(())
    }

    pub fn stop_vm(&self, id: &str) -> Result<()> {
        let work_dir = VmWorkDir::new(self.vm_dir().join(id));
        work_dir
            .set_started(false)
            .context("Failed to set started")?;
        self.state.lock().unwrap().monitor.stop_vm(id)?;
        Ok(())
    }

    pub fn remove_vm(&self, id: &str) -> Result<()> {
        self.state.lock().unwrap().monitor.remove_vm(id)?;
        let vm_path = self.vm_dir().join(id);
        fs::remove_dir_all(vm_path).context("Failed to remove VM directory")?;
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
                        error!("Failed to load VM: {err}");
                    }
                }
            }
        }
        Ok(())
    }

    pub fn list_vms(&self) -> Vec<pb::VmInfo> {
        let mut infos = self
            .state
            .lock()
            .unwrap()
            .monitor
            .iter_vms()
            .map(|vm| vm.info())
            .collect::<Vec<_>>();

        infos.sort_by(|a, b| a.manifest.created_at_ms.cmp(&b.manifest.created_at_ms));
        let gw = &self.config.gateway;

        infos
            .into_iter()
            .map(|info| pb::VmInfo {
                id: info.manifest.id,
                name: info.manifest.name.clone(),
                status: info.status.to_string(),
                uptime: info.uptime,
                configuration: Some(pb::VmConfiguration {
                    name: info.manifest.name,
                    image: info.manifest.image,
                    compose_file: {
                        let workdir = VmWorkDir::new(&info.workdir);
                        fs::read_to_string(workdir.app_compose_path()).unwrap_or_default()
                    },
                    encrypted_env: {
                        let workdir = VmWorkDir::new(&info.workdir);
                        fs::read(workdir.encrypted_env_path()).unwrap_or_default()
                    },
                    vcpu: info.manifest.vcpu,
                    memory: info.manifest.memory,
                    disk_size: info.manifest.disk_size,
                    ports: info
                        .manifest
                        .port_map
                        .into_iter()
                        .map(|pm| pb::PortMapping {
                            protocol: pm.protocol.as_str().into(),
                            host_port: pm.from as u32,
                            vm_port: pm.to as u32,
                        })
                        .collect(),
                }),
                app_url: info.instance_id.as_ref().map(|id| {
                    format!(
                        "https://{id}-{}.{}:{}",
                        gw.tappd_port, gw.base_domain, gw.port
                    )
                }),
                app_id: info.manifest.app_id,
                instance_id: info.instance_id,
            })
            .collect()
    }

    pub fn get_log_file(&self, id: &str) -> Result<PathBuf> {
        self.state.lock().unwrap().monitor.get_log_file(id)
    }

    pub fn list_image_names(&self) -> Result<Vec<String>> {
        let image_path = self.config.image_path.clone();
        let images = fs::read_dir(image_path).context("Failed to read image directory")?;
        Ok(images
            .flat_map(|e| {
                Some(
                    e.ok()?
                        .path()
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                )
            })
            .collect())
    }

    pub fn get_vm(&self, id: &str) -> Option<pb::VmInfo> {
        let state = self.state.lock().unwrap();
        let vm = state.monitor.iter_vms().find(|vm| vm.info().manifest.id == id)?;
        let info = vm.info();
        let gw = &self.config.gateway;

        Some(pb::VmInfo {
            id: info.manifest.id,
            name: info.manifest.name.clone(),
            status: info.status.to_string(),
            uptime: info.uptime,
            configuration: Some(pb::VmConfiguration {
                name: info.manifest.name,
                image: info.manifest.image,
                compose_file: {
                    let workdir = VmWorkDir::new(&info.workdir);
                    fs::read_to_string(workdir.app_compose_path()).unwrap_or_default()
                },
                encrypted_env: {
                    let workdir = VmWorkDir::new(&info.workdir);
                    fs::read(workdir.encrypted_env_path()).unwrap_or_default()
                },
                vcpu: info.manifest.vcpu,
                memory: info.manifest.memory,
                disk_size: info.manifest.disk_size,
                ports: info
                    .manifest
                    .port_map
                    .into_iter()
                    .map(|pm| pb::PortMapping {
                        protocol: pm.protocol.as_str().into(),
                        host_port: pm.from as u32,
                        vm_port: pm.to as u32,
                    })
                    .collect(),
            }),
            app_url: info.instance_id.as_ref().map(|id| {
                format!(
                    "https://{id}-{}.{}:{}",
                    gw.tappd_port, gw.base_domain, gw.port
                )
            }),
            app_id: info.manifest.app_id,
            instance_id: info.instance_id,
        })
    }
}
