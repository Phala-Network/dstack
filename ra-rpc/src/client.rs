use std::time::Duration;

use prpc::client::{Error, RequestClient};
use reqwest::Client;

pub struct RaClient {
    remote_uri: String,
    client: Client,
}

impl RaClient {
    pub fn no_check(remote_uri: String, tls_no_check: bool) -> Self {
        let client = Client::builder()
            .tls_sni(true)
            .danger_accept_invalid_certs(tls_no_check)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()
            .expect("failed to create client");
        Self { remote_uri, client }
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
            .map_err(|err| Error::RpcError(format!("failed to send request: {}", err)))?;
        response
            .bytes()
            .await
            .map_err(|err| Error::RpcError(format!("failed to read response: {}", err)))
            .map(|bytes| bytes.to_vec())
    }
}
