use anyhow::Context;
use prpc::{
    client::{Error, RequestClient},
    serde_json, Message,
};
use serde::{de::DeserializeOwned, Serialize};

pub struct PrpcClient {
    base_url: String,
}

impl PrpcClient {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

impl RequestClient for PrpcClient {
    async fn request<T, R>(&self, path: &str, body: T) -> Result<R, Error>
    where
        T: Message + Serialize,
        R: Message + DeserializeOwned,
    {
        let body = serde_json::to_vec(&body).context("Failed to serialize body")?;
        let path = format!("{path}?json");
        let (status, body) = super::http_request("POST", &self.base_url, &path, &body).await?;
        if status != 200 {
            return Err(Error::RpcError(format!("Invalid status code: {status}")));
        }
        let response = serde_json::from_slice(&body).context("Failed to deserialize response")?;
        Ok(response)
    }
}
