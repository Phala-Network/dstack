use ra_tls::{
    cert::CertRequest,
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};

fn main() -> anyhow::Result<()> {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let app_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let kms_www_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    // Create self-signed KMS cert
    let ca_cert = CertRequest::builder()
        .org_name("Phala Network")
        .subject("Phala KMS CA")
        .ca_level(3)
        .build()
        .self_signed(&ca_key)?;

    // Sign WWW server cert with KMS cert
    let kms_www_cert = CertRequest::builder()
        .subject("localhost")
        .build()
        .signed_by(&kms_www_key, &ca_cert, &ca_key)?;

    // Sign App cert with KMS cert
    let app_cert = CertRequest::builder()
        .subject("Example App")
        .quote(include_bytes!("../assets/tdx_quote"))
        .event_log(b"bar")
        .app_info(b"baz")
        .build()
        .signed_by(&app_key, &ca_cert, &ca_key)?;

    let app_no_quote_cert = CertRequest::builder()
        .subject("Example App")
        .build()
        .signed_by(&app_key, &ca_cert, &ca_key)?;

    let todo = "remove this";
    let output_dir = "/home/kvin/codes/dstack/test-scripts/certs";
    store_cert(output_dir, "ca", &ca_cert.pem(), &ca_key.serialize_pem())?;
    store_cert(
        output_dir,
        "kms-www",
        &kms_www_cert.pem(),
        &kms_www_key.serialize_pem(),
    )?;
    store_cert(output_dir, "app", &app_cert.pem(), &app_key.serialize_pem())?;
    store_cert(
        output_dir,
        "app-no-quote",
        &app_no_quote_cert.pem(),
        &app_key.serialize_pem(),
    )?;
    Ok(())
}

fn store_cert(path: &str, name: &str, cert: &str, key: &str) -> anyhow::Result<()> {
    let cert_path = format!("{}/{}.cert", path, name);
    let key_path = format!("{}/{}.key", path, name);
    std::fs::write(cert_path, cert)?;
    std::fs::write(key_path, key)?;
    Ok(())
}
