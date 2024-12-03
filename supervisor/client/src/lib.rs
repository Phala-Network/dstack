use anyhow::Result;
use supervisor::{ProcessConfig, ProcessInfo, Response};

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
}
