use ra_tls::{oids, qvl};
use rocket::{
    get,
    mtls::{oid::Oid, Certificate},
    routes, Route,
};

/// AppState, Request -> UserRpcHandler

// trait ConstructHandler {
//     type AppState;
//     fn construct_handler(app_state: &Self::AppState, request: Request) -> Self
//     where
//         Self: Sized;
// }

#[get("/")]
fn index(cert: Option<Certificate<'_>>) -> String {
    if let Some(cert) = cert {
        let quote_oid = Oid::from(oids::PHALA_RATLS_QUOTE).unwrap();
        match cert.get_extension_unique(&quote_oid) {
            Ok(Some(quote)) => {
                let quote_bytes =
                    yasna::parse_der(&quote.value, |reader| reader.read_bytes()).unwrap();
                match qvl::quote::Quote::parse(&quote_bytes) {
                    Ok(quote) => {
                        format!("KMS: Got quote from client certificate:\n{quote:?}\n")
                    }
                    Err(err) => {
                        format!("KMS: Failed to parse quote from client certificate: {err}\n")
                    }
                }
            }
            _ => "KMS: No TEE quote in client certificate\n".to_string(),
        }
    } else {
        "KMS: Missing client certificate\n".to_string()
    }
}

pub fn routes() -> Vec<Route> {
    routes![index]
}
