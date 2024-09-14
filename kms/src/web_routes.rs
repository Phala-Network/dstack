use anyhow::Context;
use ra_tls::attestation::Attestation;
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
async fn index(cert: Option<Certificate<'_>>) -> String {
    if let Some(cert) = cert {
        let attestation = Attestation::from_ext_getter(|oid| {
            let oid = Oid::from(oid).ok().context("Invalid OID")?;
            let Some(ext) = cert
                .get_extension_unique(&oid)
                .context("Extension not found")?
            else {
                return Ok(None);
            };
            Ok(Some(ext.value.to_vec()))
        });
        match attestation {
            Ok(Some(attestation)) => match attestation.decode_quote() {
                Ok(quote) => format!("KMS: Got quote from client certificate:\n{quote:?}\n"),
                Err(err) => format!("KMS: Failed to decode quote from client certificate: {err}\n"),
            },
            Ok(None) => "KMS: No attestation in client certificate\n".to_string(),
            _ => "KMS: Failed to get attestation from client certificate\n".to_string(),
        }
    } else {
        "KMS: Missing client certificate\n".to_string()
    }
}

pub fn routes() -> Vec<Route> {
    routes![index]
}
