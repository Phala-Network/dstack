use crate::{main_service::KmsState, main_service::RpcHandler};
use rocket::{get, routes, Route};

#[get("/")]
async fn index() -> String {
    "KMS Server is running!\n".to_string()
}

ra_rpc::declare_prpc_routes!(prpc_post, prpc_get, KmsState, RpcHandler);

pub fn routes() -> Vec<Route> {
    routes![index, prpc_post, prpc_get]
}
