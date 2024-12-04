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

use anyhow::{bail, Context, Result};
use bon::Builder;
use fs_err as fs;
use id_pool::IdPool;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use supervisor_client::SupervisorClient;
use teepod_rpc as pb;
use tracing::error;

pub use image::{Image, ImageInfo};
pub use qemu::{TdxConfig, VmConfig, VmWorkDir};

mod id_pool;
mod image;
mod qemu;

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

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub supervisor: SupervisorClient,
    state: Arc<Mutex<AppState>>,
}

impl App {
    fn lock(&self) -> MutexGuard<AppState> {
        self.state.lock().unwrap()
    }

    pub(crate) fn vm_dir(&self) -> PathBuf {
        self.config.run_path.clone().into()
    }

    pub(crate) fn work_dir(&self, id: &str) -> VmWorkDir {
        VmWorkDir::new(self.config.run_path.join(id))
    }

    pub fn new(config: Config, supervisor: SupervisorClient) -> Self {
        let cid_start = config.cvm.cid_start;
        let cid_end = cid_start.saturating_add(config.cvm.cid_pool_size);
        let cid_pool = IdPool::new(cid_start, cid_end);
        Self {
            supervisor: supervisor.clone(),
            state: Arc::new(Mutex::new(AppState {
                cid_pool,
                vms: BTreeMap::new(),
            })),
            config: Arc::new(config),
        }
    }

    pub async fn load_vm(&self, work_dir: impl AsRef<Path>) -> Result<()> {
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
        let vm_id = vm_config.manifest.id.clone();
        self.lock().add(vm_config);
        let started = vm_work_dir.started().context("Failed to read VM state")?;
        if started {
            self.start_vm(&vm_id).await?;
        }
        Ok(())
    }

    pub async fn start_vm(&self, id: &str) -> Result<()> {
        let vm_config = self.lock().get(id).context("VM not found")?;
        let work_dir = self.work_dir(id);
        work_dir
            .set_started(true)
            .context("Failed to set started")?;
        let process_config = vm_config.config_qemu(&self.config.qemu_path, &work_dir)?;
        self.supervisor
            .deploy(process_config)
            .await
            .context("Failed to start VM")?;
        Ok(())
    }

    pub async fn stop_vm(&self, id: &str) -> Result<()> {
        let work_dir = self.work_dir(id);
        work_dir
            .set_started(false)
            .context("Failed to set started")?;
        self.supervisor.stop(id).await?;
        Ok(())
    }

    pub async fn remove_vm(&self, id: &str) -> Result<()> {
        let info = self.supervisor.info(id).await?;
        let is_running = info.map_or(false, |i| i.state.status.is_running());
        if is_running {
            bail!("VM is running, stop it first");
        }
        self.supervisor.remove(id).await?;
        self.lock().remove(id);
        let vm_path = self.work_dir(id);
        fs::remove_dir_all(&vm_path).context("Failed to remove VM directory")?;
        Ok(())
    }

    pub async fn reload_vms(&self) -> Result<()> {
        let vm_path = self.vm_dir();
        if vm_path.exists() {
            for entry in fs::read_dir(vm_path).context("Failed to read VM directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let vm_path = entry.path();
                if vm_path.is_dir() {
                    if let Err(err) = self.load_vm(vm_path).await {
                        error!("Failed to load VM: {err}");
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn list_vms(&self) -> Result<Vec<pb::VmInfo>> {
        let vms = self
            .supervisor
            .list()
            .await
            .context("Failed to list VMs")?
            .into_iter()
            .map(|p| (p.config.id.clone(), p))
            .collect::<HashMap<_, _>>();

        let mut infos = self
            .lock()
            .iter_vms()
            .map(|vm| vm.merge_info(&vms, &self.work_dir(&vm.manifest.id)))
            .collect::<Vec<_>>();

        infos.sort_by(|a, b| a.manifest.created_at_ms.cmp(&b.manifest.created_at_ms));
        let gw = &self.config.gateway;

        let lst = infos
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
            .collect();
        Ok(lst)
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
}

pub(crate) struct AppState {
    cid_pool: IdPool<u32>,
    vms: BTreeMap<String, Arc<VmConfig>>,
}

impl AppState {
    pub fn add(&mut self, vm: VmConfig) {
        self.vms.insert(vm.manifest.id.clone(), Arc::new(vm));
    }

    pub fn get(&self, id: &str) -> Option<Arc<VmConfig>> {
        self.vms.get(id).cloned()
    }

    pub fn remove(&mut self, id: &str) -> Option<Arc<VmConfig>> {
        self.vms.remove(id)
    }

    pub fn iter_vms(&self) -> impl Iterator<Item = &Arc<VmConfig>> {
        self.vms.values()
    }
}
