use std::time::Duration;

use anyhow::{Context, Result};
use prpc::{
    client::{Error, RequestClient},
    server::ProtoError,
    Message,
};
use reqwest::{Client, Identity};
use serde::{de::DeserializeOwned, Serialize};

pub struct RaClient {
    remote_uri: String,
    client: Client,
}

impl RaClient {
    pub fn new(remote_uri: String, tls_no_check: bool) -> Self {
        let client = Client::builder()
            .tls_sni(true)
            .danger_accept_invalid_certs(tls_no_check)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()
            .expect("failed to create client");
        Self { remote_uri, client }
    }

    pub fn new_mtls(remote_uri: String, cert_pem: String, key_pem: String) -> Result<Self> {
        let identity_pem = format!("{cert_pem}\n{key_pem}");
        let identity =
            Identity::from_pem(identity_pem.as_bytes()).context("Failed to parse identity")?;
        let client = Client::builder()
            .tls_sni(true)
            .danger_accept_invalid_certs(true)
            .identity(identity)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()
            .context("failed to create client")?;
        Ok(Self { remote_uri, client })
    }
}

impl RequestClient for RaClient {
    async fn request<T, R>(&self, path: &str, body: T) -> Result<R, Error>
    where
        T: Message + Serialize,
        R: Message + DeserializeOwned,
    {
        let body = serde_json::to_vec(&body).context("Failed to serialize body")?;
        let url = format!("{}/{}?json", self.remote_uri, path);
        let response = self
            .client
            .post(url)
            .body(body)
            .send()
            .await
            .map_err(|err| Error::RpcError(format!("failed to send request: {:?}", err)))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.bytes().await.unwrap_or_default();
            let error = ProtoError::decode(body.as_ref())
                .unwrap_or_default()
                .message;
            return Err(Error::RpcError(format!(
                "request failed with status={status}, error={error}",
            )));
        }
        let body = response
            .bytes()
            .await
            .map_err(|err| Error::RpcError(format!("failed to read response: {:?}", err)))?
            .to_vec();
        let response = serde_json::from_slice(&body).context("Failed to deserialize response")?;
        Ok(response)
    }
}
