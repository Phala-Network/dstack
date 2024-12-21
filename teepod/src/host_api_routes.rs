use crate::app::App;
use crate::host_api_service::HostApiHandler;
use ra_rpc::rocket_helper::PrpcHandler;
use rocket::{
    data::{Data, Limits},
    get,
    http::{uri::Origin, ContentType},
    listener::Endpoint,
    mtls::Certificate,
    post,
    response::status::Custom,
    routes, Route, State,
};

#[post("/<method>?<json>", data = "<data>")]
#[allow(clippy::too_many_arguments)]
async fn prpc_post(
    endpoint: &Endpoint,
    state: &State<App>,
    cert: Option<Certificate<'_>>,
    method: &str,
    data: Data<'_>,
    limits: &Limits,
    content_type: Option<&ContentType>,
    json: bool,
) -> Custom<Vec<u8>> {
    PrpcHandler::builder()
        .state(&**state)
        .remote_addr(endpoint.clone())
        .maybe_certificate(cert)
        .method(method)
        .data(data)
        .limits(limits)
        .maybe_content_type(content_type)
        .json(json)
        .build()
        .handle::<HostApiHandler>()
        .await
}

#[get("/<method>")]
async fn prpc_get(
    endpoint: &Endpoint,
    state: &State<App>,
    method: &str,
    limits: &Limits,
    content_type: Option<&ContentType>,
    origin: &Origin<'_>,
) -> Custom<Vec<u8>> {
    PrpcHandler::builder()
        .state(&**state)
        .remote_addr(endpoint.clone())
        .method(method)
        .limits(limits)
        .maybe_content_type(content_type)
        .json(true)
        .maybe_query(origin.query())
        .build()
        .handle::<HostApiHandler>()
        .await
}

pub fn routes() -> Vec<Route> {
    routes![prpc_post, prpc_get]
}
