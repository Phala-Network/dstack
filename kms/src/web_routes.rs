use crate::{main_service::KmsState, main_service::RpcHandler};
use ra_rpc::rocket_helper::{PrpcHandler, QuoteVerifier};
use rocket::{
    data::{Data, Limits},
    get,
    http::{uri::Origin, ContentType},
    mtls::Certificate,
    post,
    response::status::Custom,
    routes, Route, State,
};

#[get("/")]
async fn index() -> String {
    "KMS Server is running!\n".to_string()
}

#[post("/prpc/<method>?<json>", data = "<data>")]
#[allow(clippy::too_many_arguments)]
async fn prpc_post(
    state: &State<KmsState>,
    quote_verifier: Option<&State<QuoteVerifier>>,
    cert: Option<Certificate<'_>>,
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
    state: &State<KmsState>,
    quote_verifier: Option<&State<QuoteVerifier>>,
    cert: Option<Certificate<'_>>,
    method: &str,
    origin: &Origin<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
) -> Custom<Vec<u8>> {
    PrpcHandler::builder()
        .state(&**state)
        .maybe_certificate(cert)
        .maybe_quote_verifier(quote_verifier.map(|v| &**v))
        .method(method)
        .limits(limits)
        .maybe_content_type(content_type)
        .maybe_query(origin.query())
        .json(true)
        .build()
        .handle::<RpcHandler>()
        .await
}

pub fn routes() -> Vec<Route> {
    routes![index, prpc_post, prpc_get]
}
