use prpc::client::{Error, RequestClient};

pub struct PrpcClient {
    base_url: String,
}

impl PrpcClient {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

impl RequestClient for PrpcClient {
    async fn request(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, Error> {
        let (status, body) = super::http_request("POST", &self.base_url, path, &body).await?;
        if status != 200 {
            return Err(Error::RpcError(format!("Invalid status code: {status}")));
        }
        Ok(body)
    }
}
