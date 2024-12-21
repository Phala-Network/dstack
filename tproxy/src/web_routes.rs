use crate::main_service::{Proxy, RpcHandler};
use anyhow::Result;
use ra_rpc::rocket_helper::{PrpcHandler, QuoteVerifier};
use rocket::{
    data::{Data, Limits},
    get,
    http::{uri::Origin, ContentType},
    mtls::Certificate,
    post,
    response::{content::RawHtml, status::Custom},
    routes, Route, State,
};

mod route_index;

#[get("/")]
async fn index(state: &State<Proxy>) -> Result<RawHtml<String>, String> {
    route_index::index(state).await.map_err(|e| format!("{e}"))
}

#[post("/prpc/<method>?<json>", data = "<data>")]
#[allow(clippy::too_many_arguments)]
async fn prpc_post(
    state: &State<Proxy>,
    cert: Option<Certificate<'_>>,
    quote_verifier: Option<&State<QuoteVerifier>>,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Custom<Vec<u8>> {
    PrpcHandler::builder()
        .state(&**state)
        .maybe_certificate(cert)
        .maybe_quote_verifier(quote_verifier.map(|v| &**v))
        .method(method)
        .data(data)
        .limits(limits)
        .maybe_content_type(content_type)
        .json(json)
        .build()
        .handle::<RpcHandler>()
        .await
}

#[get("/prpc/<method>")]
async fn prpc_get(
    state: &State<Proxy>,
    cert: Option<Certificate<'_>>,
    quote_verifier: Option<&State<QuoteVerifier>>,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
    origin: &Origin<'_>,
) -> Custom<Vec<u8>> {
    PrpcHandler::builder()
        .state(&**state)
        .maybe_certificate(cert)
        .maybe_quote_verifier(quote_verifier.map(|v| &**v))
        .method(method)
        .limits(limits)
        .maybe_content_type(content_type)
        .json(true)
        .maybe_query(origin.query())
        .build()
        .handle::<RpcHandler>()
        .await
}

pub fn routes() -> Vec<Route> {
    routes![index, prpc_post, prpc_get]
}
