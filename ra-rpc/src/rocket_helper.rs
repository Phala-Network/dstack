use std::{
    convert::Infallible,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use ra_tls::{
    attestation::Attestation,
    qvl::{self, verify::VerifiedReport},
};
use rocket::{
    data::{ByteUnit, Data, Limits, ToByteUnit},
    http::{uri::Origin, ContentType, Status},
    listener::Endpoint,
    mtls::{oid::Oid, Certificate},
    request::{FromRequest, Outcome},
    response::status::Custom,
    Request,
};
use rocket_vsock_listener::VsockEndpoint;
use tracing::{info, warn};

use crate::{encode_error, CallContext, RemoteEndpoint, RpcCall};

#[derive(Debug, Clone)]
pub struct QuoteVerifier {
    pccs_url: String,
    timeout: Duration,
}

pub mod deps {
    pub use super::{PrpcHandler, RpcRequest};
    pub use rocket::response::status::Custom;
    pub use rocket::{Data, State};
}

#[macro_export]
macro_rules! declare_prpc_routes {
    ($post:ident, $get:ident, $state:ty, $handler:ty) => {
        $crate::declare_prpc_routes!(path: "/prpc/<method>?<json>", "/prpc/<method>", $post, $get, $state, $handler);
    };
    (bare: $post:ident, $get:ident, $state:ty, $handler:ty) => {
        $crate::declare_prpc_routes!(path: "/<method>?<json>", "/<method>", $post, $get, $state, $handler);
    };
    (path: $post_path: literal, $get_path: literal, $post:ident, $get:ident, $state:ty, $handler:ty) => {
        #[rocket::post($post_path, data = "<data>")]
        async fn $post<'a: 'd, 'd>(
            state: &'a $crate::rocket_helper::deps::State<$state>,
            method: &'a str,
            data: $crate::rocket_helper::deps::Data<'d>,
            json: bool,
            rpc_request: $crate::rocket_helper::deps::RpcRequest<'a>,
        ) -> $crate::rocket_helper::deps::Custom<Vec<u8>> {
            $crate::rocket_helper::deps::PrpcHandler::builder()
                .state(&**state)
                .request(rpc_request)
                .method(method)
                .data(data)
                .json(json)
                .build()
                .handle::<$handler>()
                .await
        }

        #[rocket::get("/<method>")]
        async fn $get<'a: 'd, 'd>(
            state: &'a $crate::rocket_helper::deps::State<$state>,
            rpc_request: $crate::rocket_helper::deps::RpcRequest<'a>,
            method: &'a str,
        ) -> $crate::rocket_helper::deps::Custom<Vec<u8>> {
            $crate::rocket_helper::deps::PrpcHandler::builder()
                .state(&**state)
                .request(rpc_request)
                .method(method)
                .json(true)
                .build()
                .handle::<$handler>()
                .await
        }
    };
}

macro_rules! from_request {
    ($request:expr) => {
        match FromRequest::from_request($request).await {
            Outcome::Success(v) => v,
            Outcome::Error(e) => return Outcome::Error(e),
            Outcome::Forward(f) => return Outcome::Forward(f),
        }
    };
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r QuoteVerifier {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let state: &rocket::State<QuoteVerifier> = from_request!(request);
        Outcome::Success(state)
    }
}

impl QuoteVerifier {
    pub fn new(pccs_url: String) -> Self {
        Self {
            pccs_url,
            timeout: Duration::from_secs(60),
        }
    }

    pub async fn verify_quote(&self, attestation: &Attestation) -> Result<VerifiedReport> {
        let quote = &attestation.quote;
        let collateral = qvl::collateral::get_collateral(&self.pccs_url, quote, self.timeout)
            .await
            .context("failed to get collateral")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("failed to get current time")?
            .as_secs();
        let report = qvl::verify::verify(quote, &collateral, now)
            .ok()
            .context("quote verification failed")?;
        if let Some(report) = report.report.as_td10() {
            // Replay the event logs
            let rtmrs = attestation
                .replay_event_logs()
                .context("failed to replay event logs")?;
            if rtmrs != [report.rt_mr0, report.rt_mr1, report.rt_mr2, report.rt_mr3] {
                anyhow::bail!("rtmr mismatch");
            }
        }
        Ok(report)
    }
}

async fn read_data(data: Data<'_>, limit: ByteUnit) -> Result<Vec<u8>> {
    let stream = data.open(limit);
    let data = stream.into_bytes().await.context("failed to read data")?;
    if !data.is_complete() {
        anyhow::bail!("payload too large");
    }
    Ok(data.into_inner())
}

fn limit_for_method(method: &str, limits: &Limits) -> ByteUnit {
    if let Some(v) = limits.get(method) {
        return v;
    }
    10.mebibytes()
}

#[derive(bon::Builder)]
pub struct PrpcHandler<'s, 'r, S> {
    state: &'s S,
    request: RpcRequest<'r>,
    method: &'r str,
    json: bool,
    data: Option<Data<'r>>,
}

pub struct RpcRequest<'r> {
    remote_addr: Option<&'r Endpoint>,
    certificate: Option<Certificate<'r>>,
    quote_verifier: Option<&'r QuoteVerifier>,
    orgin: &'r Origin<'r>,
    limits: &'r Limits,
    content_type: Option<&'r ContentType>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RpcRequest<'r> {
    type Error = Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self {
            remote_addr: from_request!(request),
            certificate: from_request!(request),
            quote_verifier: from_request!(request),
            orgin: from_request!(request),
            limits: from_request!(request),
            content_type: from_request!(request),
        })
    }
}

impl<'s, 'r, S> PrpcHandler<'s, 'r, S> {
    pub async fn handle<Call: RpcCall<S>>(self) -> Custom<Vec<u8>> {
        let json = self.json;
        let result = handle_prpc_impl::<S, Call>(self).await;
        match result {
            Ok(output) => output,
            Err(e) => {
                let estr = format!("{e:?}");
                warn!("error handling prpc: {estr}");
                let body = encode_error(json, estr);
                Custom(Status::BadRequest, body)
            }
        }
    }
}

impl From<Endpoint> for RemoteEndpoint {
    fn from(endpoint: Endpoint) -> Self {
        match endpoint {
            Endpoint::Tcp(addr) => RemoteEndpoint::Tcp(addr),
            Endpoint::Quic(addr) => RemoteEndpoint::Quic(addr),
            Endpoint::Unix(path) => RemoteEndpoint::Unix(path),
            _ => {
                let address = endpoint.to_string();
                match address.parse::<VsockEndpoint>() {
                    Ok(addr) => RemoteEndpoint::Vsock {
                        cid: addr.cid,
                        port: addr.port,
                    },
                    Err(_) => RemoteEndpoint::Other(address),
                }
            }
        }
    }
}

pub async fn handle_prpc_impl<S, Call: RpcCall<S>>(
    args: PrpcHandler<'_, '_, S>,
) -> Result<Custom<Vec<u8>>> {
    let PrpcHandler {
        state,
        request,
        method,
        json,
        data,
    } = args;
    let mut attestation = request
        .certificate
        .map(extract_attestation)
        .transpose()?
        .flatten();
    let todo = "verified attestation needs to be a distinct type";
    if let (Some(quote_verifier), Some(attestation)) = (request.quote_verifier, &mut attestation) {
        let verified_report = quote_verifier
            .verify_quote(attestation)
            .await
            .context("invalid quote")?;
        attestation.verified_report = Some(verified_report);
    } else if attestation.is_some() {
        info!("the ra quote is not verified");
    }
    let is_get = data.is_none();
    let payload = match data {
        Some(data) => {
            let limit = limit_for_method(method, request.limits);
            let todo = "confirm this would not truncate the data";
            read_data(data, limit)
                .await
                .context("failed to read data")?
        }
        None => request
            .orgin
            .query()
            .map_or(vec![], |q| q.as_bytes().to_vec()),
    };
    let json = json || request.content_type.map(|t| t.is_json()).unwrap_or(false);
    let context = CallContext {
        state,
        attestation,
        remote_endpoint: request.remote_addr.cloned().map(RemoteEndpoint::from),
    };
    let call = Call::construct(context).context("failed to construct call")?;
    let (status_code, output) = call.call(method.to_string(), payload, json, is_get).await;
    Ok(Custom(Status::new(status_code), output))
}

pub fn extract_attestation(cert: Certificate<'_>) -> Result<Option<Attestation>> {
    let attestation = Attestation::from_ext_getter(|oid| {
        let oid = Oid::from(oid).ok().context("Invalid OID")?;
        let Some(ext) = cert
            .get_extension_unique(&oid)
            .context("Extension not found")?
        else {
            return Ok(None);
        };
        Ok(Some(ext.value.to_vec()))
    })?;
    let todo = "verify the attestation";
    let Some(attestation) = attestation else {
        return Ok(None);
    };
    let pubkey = cert.public_key().raw;
    attestation
        .ensure_quote_for_ra_tls_pubkey(pubkey)
        .context("ratls quote verification failed")?;
    Ok(Some(attestation))
}
