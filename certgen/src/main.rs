use ra_tls::{
    cert::CertRequest,
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Domain name for the generated certificates
    #[arg(short, long, default_value = "local")]
    domain: String,

    /// Output directory for the generated certificates
    #[arg(short, long, default_value = "certs")]
    output_dir: String,
}


fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let tmp_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let app_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let kms_www_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let tmp_ra_tls_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let tmp_ca_cert = CertRequest::builder()
        .org_name("Phala Network")
        .subject("Phala KMS Client Temp CA")
        .ca_level(1)
        .key(&tmp_ca_key)
        .build()
        .self_signed()?;

    // Create self-signed KMS cert
    let ca_cert = CertRequest::builder()
        .org_name("Phala Network")
        .subject("Phala KMS CA")
        .ca_level(3)
        .key(&ca_key)
        .build()
        .self_signed()?;

    // Sign WWW server cert with KMS cert
    let kms_www_cert = CertRequest::builder()
        .subject(&format!("kms.{}", args.domain))
        .key(&kms_www_key)
        .build()
        .signed_by(&ca_cert, &ca_key)?;

    let app_no_quote_cert = CertRequest::builder()
        .subject("Example App")
        .key(&app_key)
        .build()
        .signed_by(&ca_cert, &ca_key)?;

    let output_dir = &args.output_dir;
    store_cert(output_dir, "tmp-ca", &tmp_ca_cert.pem(), &tmp_ca_key.serialize_pem())?;
    store_cert(output_dir, "ca", &ca_cert.pem(), &ca_key.serialize_pem())?;
    store_cert(
        output_dir,
        "kms-www",
        &kms_www_cert.pem(),
        &kms_www_key.serialize_pem(),
    )?;
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
