use std::sync::Arc;

use anyhow::{Context, Result};
use ra_rpc::{Attestation, RpcCall};
use ra_tls::{
    cert::{CaCert, CertRequest},
    kdf::derive_ecdsa_key_pair,
};
use tappd_rpc::{
    tappd_server::{TappdRpc, TappdServer},
    DeriveKeyArgs, DeriveKeyResponse, TdxQuoteArgs, TdxQuoteResponse,
};

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    ca: CaCert,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self> {
        let ca = CaCert::load(&config.cert_file, &config.key_file)
            .context("Failed to load CA certificate")?;
        Ok(Self {
            inner: Arc::new(AppStateInner { ca }),
        })
    }
}

pub struct RpcHandler {
    state: AppState,
}

impl TappdRpc for RpcHandler {
    async fn derive_key(self, request: DeriveKeyArgs) -> Result<DeriveKeyResponse> {
        let derived_key =
            derive_ecdsa_key_pair(&self.state.inner.ca.key, &[request.path.as_bytes()])
                .context("Failed to derive key")?;
        let req = CertRequest::builder()
            .subject(&request.subject)
            .key(&derived_key)
            .build();
        let cert = self
            .state
            .inner
            .ca
            .sign(req)
            .context("Failed to sign certificate")?;
        Ok(DeriveKeyResponse {
            key: derived_key.serialize_pem(),
            certificate_chain: vec![cert.pem(), self.state.inner.ca.cert.pem()],
        })
    }

    async fn tdx_quote(self, request: TdxQuoteArgs) -> Result<TdxQuoteResponse> {
        let todo = "add the event log to the response";
        let todo = "define the report data format";
        let report_data = sha2_512(&request.report_data);
        let (_, quote) =
            tdx_attest::get_quote(&report_data, None).context("Failed to get quote")?;
        Ok(TdxQuoteResponse {
            quote,
            event_log: Default::default(),
        })
    }
}

impl RpcCall<AppState> for RpcHandler {
    type PrpcService = TappdServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TappdServer::new(self)
    }

    fn construct(state: &AppState, _attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler {
            state: state.clone(),
        })
    }
}

fn sha2_512(data: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}
