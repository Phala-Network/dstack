use std::path::PathBuf;

use anyhow::{Context, Result};
use fs_err as fs;
use ra_rpc::{Attestation, RpcCall};
use teepod_rpc::teepod_server::{TeepodRpc, TeepodServer};
use teepod_rpc::{CreateVmRequest, Id, VmInfo, VmListResponse};

use crate::app::{App, Manifest};
use crate::vm::image::ImageInfo;

fn hex_sha256(data: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub struct RpcHandler {
    app: App,
}

impl RpcHandler {
    fn prepare_work_dir(&self, id: &str, compose_file: &str, image_name: &str) -> Result<PathBuf> {
        let cfg = self.app.config.clone();
        let work_dir = cfg.run_path.join(&id);
        if work_dir.exists() {
            anyhow::bail!("VM already exists at {}", work_dir.display());
        }

        let shared_dir = work_dir.join("shared");
        fs::create_dir_all(&shared_dir).context("Failed to create shared directory")?;
        fs::write(shared_dir.join("docker-compose.yaml"), compose_file)
            .context("Failed to write compose file")?;
        let certs_dir = shared_dir.join("certs");
        fs::create_dir_all(&certs_dir).context("Failed to create certs directory")?;

        fs::copy(&cfg.cvm.ca_cert, certs_dir.join("ca.cert")).context("Failed to copy ca cert")?;
        fs::copy(&cfg.cvm.tmp_ca_cert, certs_dir.join("tmp-ca.cert"))
            .context("Failed to copy tmp ca cert")?;
        fs::copy(&cfg.cvm.tmp_ca_key, certs_dir.join("tmp-ca.key"))
            .context("Failed to copy tmp ca key")?;

        let image_path = cfg.image_path.join(image_name);
        let image_info = ImageInfo::load(image_path.join("metadata.json"))
            .context("Failed to load image info")?;

        let rootfs_hash = image_info
            .rootfs_hash
            .context("Rootfs hash not found in image info")?;
        let vm_config = serde_json::json!({
            "rootfs_hash": rootfs_hash,
            "kms_url": cfg.cvm.kms_url,
            "tproxy_url": cfg.cvm.tproxy_url,
        });
        let vm_config_str =
            serde_json::to_string(&vm_config).context("Failed to serialize vm config")?;
        fs::write(shared_dir.join("config.json"), vm_config_str)
            .context("Failed to write vm config")?;

        Ok(work_dir)
    }
}

fn app_address(compose_file: &str) -> String {
    fn truncate40(s: &str) -> &str {
        if s.len() > 40 {
            &s[..40]
        } else {
            s
        }
    }
    truncate40(&hex_sha256(&compose_file)).to_string()
}

impl TeepodRpc for RpcHandler {
    async fn create_vm(self, request: CreateVmRequest) -> Result<VmInfo> {
        let address = app_address(&request.compose_file);
        let id = uuid::Uuid::new_v4().to_string();
        let work_dir = self.prepare_work_dir(&id, &request.compose_file, &request.image)?;
        let manifest = Manifest::builder()
            .id(id.clone())
            .name(request.name)
            .address(address.clone())
            .image(request.image)
            .vcpu(request.vcpu)
            .memory(request.memory)
            .disk_size(request.disk_size)
            .port_map(Default::default())
            .build();

        let serialized_manifest =
            serde_json::to_string(&manifest).context("Failed to serialize manifest")?;
        fs::write(work_dir.join("config.json"), serialized_manifest)
            .context("Failed to write manifest")?;

        self.app.load_vm(work_dir).context("Failed to load VM")?;

        Ok(VmInfo {
            id,
            status: "created".to_string(),
            uptime: "0".to_string(),
        })
    }

    async fn stop_vm(self, request: Id) -> Result<VmInfo> {
        self.app.stop_vm(&request.id)?;
        Ok(VmInfo {
            id: request.id,
            status: Default::default(),
            uptime: Default::default(),
        })
    }

    async fn vm_status(self, request: Id) -> Result<VmInfo> {
        todo!()
    }

    async fn list_vms(self) -> Result<VmListResponse> {
        Ok(VmListResponse {
            vms: self.app.list_vms(),
        })
    }
}

impl RpcCall<App> for RpcHandler {
    type PrpcService = TeepodServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TeepodServer::new(self)
    }

    fn construct(state: &App, _attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler { app: state.clone() })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <TeepodServer<RpcHandler>>::supported_methods()
}
