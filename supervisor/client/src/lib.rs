use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use log::info;
use supervisor::{ProcessConfig, ProcessInfo, Response};

pub use supervisor;

mod http;

#[derive(Debug, Clone)]
pub struct SupervisorClient {
    base_url: Arc<String>,
}

impl SupervisorClient {
    pub fn new(base_url: &str) -> Self {
        SupervisorClient {
            base_url: Arc::new(base_url.to_string()),
        }
    }

    pub async fn connect_uds(
        supervisor_path: &str,
        uds: &str,
        pid_file: &str,
        log_file: &str,
    ) -> Result<Self> {
        let uri = format!("unix:{uds}");
        let client = Self::new(&uri);
        if client.probe(Duration::from_millis(100)).await.is_ok() {
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
            .arg("--uds")
            .arg(uds)
            .arg("--pid-file")
            .arg(pid_file)
            .arg("--log-file")
            .arg(log_file)
            .arg("--detach")
            .env("RUST_LOG", "info,rocket=warn")
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
        let response: Response<T> =
            serde_json::from_slice(&response_bytes).context("Failed to parse response")?;
        response.into_result().context("Server returned error")
    }

    async fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.http_request("GET", path, ()).await
    }
}

// Async API
impl SupervisorClient {
    pub async fn deploy(&self, config: ProcessConfig) -> Result<()> {
        self.http_request("POST", "/deploy", config).await
    }

    pub async fn start(&self, id: &str) -> Result<()> {
        self.http_request("POST", &format!("/start/{}", id), ())
            .await
    }

    pub async fn stop(&self, id: &str) -> Result<()> {
        self.http_request("POST", &format!("/stop/{}", id), ())
            .await
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        self.http_request("DELETE", &format!("/remove/{}", id), ())
            .await
    }

    pub async fn list(&self) -> Result<Vec<ProcessInfo>> {
        self.http_get("/list").await
    }

    pub async fn info(&self, id: &str) -> Result<Option<ProcessInfo>> {
        self.http_get(&format!("/info/{}", id)).await
    }

    pub async fn ping(&self) -> Result<String> {
        self.http_get("/ping").await
    }

    pub async fn probe(&self, timeout: Duration) -> Result<()> {
        let response = tokio::time::timeout(timeout, self.ping()).await;
        if matches!(response, Ok(Ok(_))) {
            Ok(())
        } else {
            anyhow::bail!("failed to probe supervisor")
        }
    }

    pub async fn clear(&self) -> Result<()> {
        self.http_request("POST", "/clear", ()).await
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.http_request("POST", "/shutdown", ()).await
    }
}

#[derive(Debug, Clone)]
pub struct SupervisorClientSync {
    client: SupervisorClient,
}

impl From<SupervisorClient> for SupervisorClientSync {
    fn from(client: SupervisorClient) -> Self {
        SupervisorClientSync { client }
    }
}

// Sync API
impl SupervisorClientSync {
    fn http_request<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        method: &str,
        path: &str,
        body: B,
    ) -> Result<T> {
        futures::executor::block_on(async move {
            tokio::time::timeout(
                Duration::from_millis(1000),
                self.client.http_request(method, path, body),
            )
            .await?
        })
    }

    fn http_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.http_request("GET", path, ())
    }

    pub fn deploy(&self, config: ProcessConfig) -> Result<()> {
        self.http_request("POST", "/deploy", config)
    }

    pub fn start(&self, id: &str) -> Result<()> {
        self.http_request("POST", &format!("/start/{}", id), ())
    }

    pub fn stop(&self, id: &str) -> Result<()> {
        self.http_request("POST", &format!("/stop/{}", id), ())
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        self.http_request("DELETE", &format!("/remove/{}", id), ())
    }

    pub fn list(&self) -> Result<Vec<ProcessInfo>> {
        self.http_get("/list")
    }

    pub fn info(&self, id: &str) -> Result<Option<ProcessInfo>> {
        self.http_get(&format!("/info/{}", id))
    }

    pub fn ping(&self) -> Result<String> {
        self.http_get("/ping")
    }

    pub fn probe(&self) -> Result<()> {
        if self.ping().is_ok() {
            Ok(())
        } else {
            anyhow::bail!("failed to probe supervisor")
        }
    }
}
