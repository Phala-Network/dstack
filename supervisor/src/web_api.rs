use anyhow::Context;
use rocket::figment::Figment;
use rocket::serde::json::Json;
use rocket::{delete, get, post, routes, Build, Rocket, State};
use serde::{Deserialize, Serialize};

use crate::process::{ProcessConfig, ProcessInfo};
use crate::supervisor::Supervisor;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response<T> {
    Data(T),
    Error(String),
}

fn to_json<T: Serialize>(r: anyhow::Result<T>) -> Json<Response<T>> {
    match r {
        Ok(data) => Json(Response::Data(data)),
        Err(e) => Json(Response::Error(format!("{e:?}"))),
    }
}

#[post("/deploy", data = "<config>")]
async fn deploy(supervisor: &State<Supervisor>, config: Json<ProcessConfig>) -> Json<Response<()>> {
    to_json(supervisor.deploy(config.into_inner()))
}

#[post("/start/<id>")]
async fn start(supervisor: &State<Supervisor>, id: &str) -> Json<Response<()>> {
    to_json(supervisor.start(&id))
}

#[post("/stop/<id>")]
async fn stop(supervisor: &State<Supervisor>, id: &str) -> Json<Response<()>> {
    to_json(supervisor.stop(&id))
}

#[delete("/remove/<id>")]
async fn remove(supervisor: &State<Supervisor>, id: &str) -> Json<Response<()>> {
    to_json(supervisor.remove(&id))
}

#[get("/list")]
fn list(supervisor: &State<Supervisor>) -> Json<Response<Vec<ProcessInfo>>> {
    to_json(Ok(supervisor.list()))
}

#[get("/info/<id>")]
fn info(supervisor: &State<Supervisor>, id: &str) -> Json<Response<ProcessInfo>> {
    to_json(supervisor.info(id).context("Process not found"))
}

#[get("/ping")]
fn ping() -> Json<Response<&'static str>> {
    Json(Response::Data("pong"))
}

pub fn rocket(figment: Figment) -> Rocket<Build> {
    rocket::custom(figment)
        .manage(Supervisor::new())
        .mount("/", routes![deploy, start, stop, remove, list, info, ping])
}
