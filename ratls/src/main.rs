use ratls::{
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
    cert::CertRequest,
};

fn main() -> anyhow::Result<()> {
    let kms_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let app_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    // Create self-signed KMS cert
    let kms_cert = CertRequest::builder()
        .org_name("Phala Network")
        .subject("Phala KMS CA")
        .build()
        .self_signed(&kms_key)?;

    // Sign App cert with KMS cert
    let app_cert = CertRequest::builder()
        .subject("Example App")
        .quote(b"foo")
        .event_log(b"bar")
        .app_info(b"baz")
        .build()
        .signed_by(&app_key, &kms_cert, &kms_key)?;

    println!("KMS cert info:");
    println!("{}", kms_cert.pem());
    println!("{}", kms_key.serialize_pem());

    println!("App cert info:");
    println!("{}", app_cert.pem());
    println!("{}", app_key.serialize_pem());
    Ok(())
}
