use std::time::Duration;

use anyhow::{Context, Result};
use log::info;
use supervisor::{ProcessConfig, ProcessInfo, Response};
use tokio::time::timeout;

mod http;

pub struct SupervisorClient {
    base_url: String,
}

impl SupervisorClient {
    pub fn new(base_url: &str) -> Self {
        SupervisorClient {
            base_url: base_url.to_string(),
        }
    }

    pub async fn connect_uds(
        &self,
        uds: &str,
        supervisor_path: &str,
        pid_file: &str,
        log_file: &str,
    ) -> Result<Self> {
        let uri = format!("unix:{uds}");
        let client = Self::new(&uri);
        let response = timeout(Duration::from_millis(100), client.ping()).await;
        if matches!(response, Ok(Ok(Response::Data(_)))) {
            info!("Connected to supervisor at {uri}");
            return Ok(client);
        }
        info!("Failed to connect to supervisor at {uri}, trying to start supervisor");
        // if the uds exists, remove it
        if std::path::Path::new(uds).exists() {
            fs_err::remove_file(uds)?;
        }
        // start supervisor
        let output = std::process::Command::new(supervisor_path)
            .arg("--address")
            .arg(&uri)
            .arg("--pid-file")
            .arg(pid_file)
            .arg("--log-file")
            .arg(log_file)
            .arg("--detach")
            .output()
            .context("Failed to start supervisor")?;
        if !output.status.success() {
            anyhow::bail!(
                "Failed to start supervisor: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // wait while ping returns pong
        for i in 1..=10 {
            if client.probe(Duration::from_millis(100)).await.is_ok() {
                info!("connected to supervisor at {uri}");
                return Ok(client);
            }
            info!("waiting for supervisor at {uri} to start, attempt {i}");
            tokio::time::sleep(Duration::from_millis(100 * i)).await;
        }
        anyhow::bail!("failed to connect to supervisor at {uri}");
    }

    async fn http_request<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        method: &str,
        path: &str,
        body: B,
    ) -> Result<T> {
        let body_bytes = match method {
            "POST" | "PUT" | "PATCH" => serde_json::to_vec(&body)?,
            _ => vec![],
        };
        let response_bytes = http::http_request(method, &self.base_url, path, &body_bytes).await?;
        Ok(serde_json::from_slice(&response_bytes)?)
    }

    async fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.http_request("GET", path, ()).await
    }

    pub async fn deploy(&self, config: ProcessConfig) -> Result<Response<()>> {
        self.http_request("POST", "/deploy", config).await
    }

    pub async fn start(&self, id: &str) -> Result<Response<()>> {
        self.http_request("POST", &format!("/start/{}", id), ())
            .await
    }

    pub async fn stop(&self, id: &str) -> Result<Response<()>> {
        self.http_request("POST", &format!("/stop/{}", id), ())
            .await
    }

    pub async fn remove(&self, id: &str) -> Result<Response<()>> {
        self.http_request("DELETE", &format!("/remove/{}", id), ())
            .await
    }

    pub async fn list(&self) -> Result<Response<Vec<ProcessInfo>>> {
        self.http_get("/list").await
    }

    pub async fn info(&self, id: &str) -> Result<Response<ProcessInfo>> {
        self.http_get(&format!("/info/{}", id)).await
    }

    pub async fn ping(&self) -> Result<Response<String>> {
        self.http_get("/ping").await
    }

    pub async fn probe(&self, timeout: Duration) -> Result<()> {
        let response = tokio::time::timeout(timeout, self.ping()).await;
        if matches!(response, Ok(Ok(Response::Data(_)))) {
            Ok(())
        } else {
            anyhow::bail!("failed to probe supervisor")
        }
    }
}
