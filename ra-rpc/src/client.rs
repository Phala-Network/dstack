use std::time::Duration;

use anyhow::{Context, Result};
use prpc::{
    client::{Error, RequestClient},
    server::ProtoError,
    Message,
};
use reqwest::{Certificate, Client, Identity};

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
    pub fn new_mtls(
        remote_uri: String,
        ca_cert: String,
        cert_pem: String,
        key_pem: String,
    ) -> Result<Self> {
        let root_ca =
            Certificate::from_pem(ca_cert.as_bytes()).context("Failed to parse CA cert")?;
        let identity_pem = format!("{cert_pem}\n{key_pem}");
        let identity =
            Identity::from_pem(identity_pem.as_bytes()).context("Failed to parse identity")?;
        let client = Client::builder()
            .tls_sni(true)
            .add_root_certificate(root_ca)
            .identity(identity)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()
            .context("failed to create client")?;
        Ok(Self { remote_uri, client })
    }
}

impl RequestClient for RaClient {
    async fn request(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, Error> {
        let url = format!("{}/{}", self.remote_uri, path);
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
        Ok(body)
    }
}
