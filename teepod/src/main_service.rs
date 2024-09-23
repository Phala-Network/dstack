use anyhow::{Context, Result};
use fs_err as fs;
use ra_rpc::{Attestation, RpcCall};
use teepod_rpc::teepod_server::{TeepodRpc, TeepodServer};
use teepod_rpc::{CreateVmRequest, Id, VmInfo, VmListResponse};

use crate::app::{App, Manifest};

fn hex_sha256(data: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub struct RpcHandler {
    app: App,
}

impl TeepodRpc for RpcHandler {
    async fn create_vm(self, request: CreateVmRequest) -> Result<VmInfo> {
        let address = hex_sha256(&request.compose_file);
        let id = uuid::Uuid::new_v4().to_string();
        let work_dir = self.app.vm_dir().join(&id);
        if work_dir.exists() {
            anyhow::bail!("VM already exists at {}", work_dir.display());
        }
        let shared_dir = work_dir.join("shared");
        fs::create_dir_all(&shared_dir).context("Failed to create shared directory")?;
        fs::write(
            shared_dir.join("docker-compose.yaml"),
            &request.compose_file,
        )
        .context("Failed to write compose file")?;

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
        })
    }

    async fn stop_vm(self, request: Id) -> Result<VmInfo> {
        self.app.stop_vm(&request.id)?;
        Ok(VmInfo {
            id: request.id,
            status: Default::default(),
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
