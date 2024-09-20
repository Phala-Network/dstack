use anyhow::{Context, Result};
use rocket::serde::json::Json;
use rocket::{delete, get, post, routes, Route, State};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::app::Manifest;
use crate::App;

#[derive(Serialize, Deserialize)]
struct VM {
    id: String,
    status: String,
}

#[derive(Serialize, Deserialize)]
struct CreateVMRequest {
    name: String,
    image: String,
}

fn sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[post("/vm/create?<vcpu>&<memory>&<image>", data = "<compose_file>")]
fn create_vm(
    app: &State<App>,
    compose_file: &str,
    vcpu: u32,
    memory: u64,
    image: String,
) -> Result<Json<VM>, String> {
    try_create_vm(app, compose_file, vcpu, memory, image).map_err(|e| e.to_string())
}

fn try_create_vm(
    app: &App,
    compose_file: &str,
    vcpu: u32,
    memory: u64,
    image: String,
) -> anyhow::Result<Json<VM>> {
    let address = sha256(compose_file);
    let work_dir = crate::paths::vm_dir().join(&address);
    if work_dir.exists() {
        anyhow::bail!("VM already exists");
    }
    let shared_dir = work_dir.join("shared");
    std::fs::create_dir_all(&shared_dir).context("Failed to create shared directory")?;
    std::fs::write(shared_dir.join("docker-compose.yaml"), compose_file)
        .context("Failed to write compose file")?;

    let manifest = Manifest::builder()
        .name(address.clone())
        .image(image)
        .vcpu(vcpu)
        .memory(memory)
        .port_map(Default::default())
        .build();

    let serialized_manifest =
        serde_json::to_string(&manifest).context("Failed to serialize manifest")?;
    std::fs::write(work_dir.join("config.json"), serialized_manifest)
        .context("Failed to write manifest")?;

    app.load_vm(work_dir)?;

    Ok(Json(VM {
        id: address,
        status: "created".to_string(),
    }))
}

#[delete("/vm/delete?<id>")]
fn delete_vm(app: &State<App>, id: String) -> Json<VM> {
    app.remove_vm(id)?;
}

#[get("/vm/status?<id>")]
fn vm_status(app: &State<App>, id: String) -> Json<VM> {
    Json(VM {
        id,
        status: "running".to_string(),
    })
}

#[get("/vm/logs?<id>")]
fn vm_logs(app: &State<App>, id: String) -> String {
    format!("Logs for VM {}", id)
}

#[get("/vm/list")]
fn list_vms(app: &State<App>) -> Json<Vec<VM>> {
    Json(vec![
        VM {
            id: "teepod-created-vm-1".to_string(),
            status: "running".to_string(),
        },
        VM {
            id: "teepod-created-vm-2".to_string(),
            status: "stopped".to_string(),
        },
    ])
}

pub fn routes() -> Vec<Route> {
    routes![create_vm, delete_vm, vm_status, vm_logs, list_vms]
}
