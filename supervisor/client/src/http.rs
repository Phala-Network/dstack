use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use log::debug;

/// Sends an HTTP request to the supervisor.
///
/// # Arguments
///
/// * `method` - The HTTP method to use.
/// * `uri` - The URI to send the request to. Supports Unix sockets: `unix:/path/to/socket` or HTTP: `http://host:port`.
/// * `body` - The body of the request.
pub async fn http_request(method: &str, base: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
    debug!("Sending HTTP request to {base}, path={path}");
    let mut response = if base.starts_with("unix:") {
        let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
        let unix_uri: hyper::Uri = Uri::new(base.strip_prefix("unix:").unwrap(), path).into();
        let req = Request::builder()
            .method(method)
            .uri(unix_uri)
            .body(Full::new(Bytes::copy_from_slice(body)))?;
        client.request(req).await?
    } else {
        let client =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());

        let uri = format!("{}{}", base, path).parse::<hyper::Uri>()?;
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Full::new(Bytes::copy_from_slice(body)))?;
        client.request(req).await?
    };
    debug!("Response: {:?}", response);
    let mut body = Vec::new();
    while let Some(frame_result) = response.frame().await {
        let frame = frame_result?;
        if let Some(segment) = frame.data_ref() {
            body.extend_from_slice(segment.iter().as_slice());
        }
    }
    Ok(body)
}
