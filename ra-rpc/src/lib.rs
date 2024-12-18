#![allow(async_fn_in_trait)]

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use prpc::{
    codec::encode_message_to_vec,
    server::{ProtoError, Service as PrpcService},
};
use tracing::{error, info};

pub use ra_tls::attestation::Attestation;

#[cfg(feature = "rocket")]
pub mod rocket_helper;

#[cfg(feature = "client")]
pub mod client;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEndpoint {
    Tcp(SocketAddr),
    Quic(SocketAddr),
    Unix(PathBuf),
    Vsock { cid: u32, port: u32 },
    Other(String),
}

#[derive(Clone, bon::Builder)]
pub struct CallContext<'a, State> {
    pub state: &'a State,
    pub attestation: Option<Attestation>,
    pub remote_endpoint: Option<RemoteEndpoint>,
}

pub trait RpcCall<State> {
    type PrpcService: PrpcService + Send + 'static;

    fn construct(context: CallContext<'_, State>) -> Result<Self>
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
    use prpc::server::Error;

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
            (code, encode_error(json, error))
        }
    };
    (code, data)
}

pub fn encode_error(json: bool, error: impl Into<String>) -> Vec<u8> {
    if json {
        serde_json::to_string_pretty(&serde_json::json!({ "error": error.into() }))
            .unwrap_or_else(|_| r#"{"error": "failed to encode the error"}"#.to_string())
            .into_bytes()
    } else {
        encode_message_to_vec(&ProtoError::new(error.into()))
    }
}
