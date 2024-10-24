#![allow(async_fn_in_trait)]

use anyhow::Result;
use prpc::{codec::encode_message_to_vec, server::Service as PrpcService};
use tracing::{error, info};

pub use ra_tls::attestation::Attestation;

#[cfg(feature = "rocket")]
pub mod rocket_helper;

#[cfg(feature = "client")]
pub mod client;

pub trait RpcCall<State> {
    type PrpcService: PrpcService + Send + 'static;

    fn construct(state: &State, attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized;
    fn into_prpc_service(self) -> Self::PrpcService;
    async fn call(self, method: String, payload: Vec<u8>, is_json: bool) -> (u16, Vec<u8>)
    where
        Self: Sized,
    {
        dispatch_prpc(method, payload, is_json, self.into_prpc_service()).await
    }
}

async fn dispatch_prpc(
    path: String,
    data: Vec<u8>,
    json: bool,
    server: impl PrpcService + Send + 'static,
) -> (u16, Vec<u8>) {
    use prpc::server::{Error, ProtoError};

    info!("dispatching request: {}", path);
    let result = server.dispatch_request(&path, data, json).await;
    let (code, data) = match result {
        Ok(data) => (200, data),
        Err(err) => {
            error!("rpc error: {:?}", err);
            let (code, error) = match err {
                Error::NotFound => (404, "method Not Found".to_string()),
                Error::DecodeError(err) => (400, format!("DecodeError({err:?})")),
                Error::BadRequest(msg) => (400, msg),
            };
            if json {
                let body = serde_json::to_string_pretty(&serde_json::json!({ "error": error }))
                    .unwrap_or_else(|_| r#"{"error": "failed to encode the error"}"#.to_string())
                    .into_bytes();
                (code, body)
            } else {
                (code, encode_message_to_vec(&ProtoError::new(error)))
            }
        }
    };
    (code, data)
}
