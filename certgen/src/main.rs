use clap::Parser;
use fs_err as fs;
use ra_tls::{
    cert::CertRequest,
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};

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
    let kms_rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let tproxy_rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

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

    let kms_domain = format!("kms.{}", args.domain);
    // Sign WWW server cert with KMS cert
    let kms_rpc_cert = CertRequest::builder()
        .subject(&kms_domain)
        .alt_names(&[kms_domain.clone()])
        .key(&kms_rpc_key)
        .build()
        .signed_by(&ca_cert, &ca_key)?;

    let tproxy_domain = format!("tproxy.{}", args.domain);
    let tproxy_rpc_cert = CertRequest::builder()
        .subject(&tproxy_domain)
        .alt_names(&[tproxy_domain.clone()])
        .key(&tproxy_rpc_key)
        .build()
        .signed_by(&ca_cert, &ca_key)?;

    let output_dir = &args.output_dir;
    store_cert(
        output_dir,
        "tmp-ca",
        &tmp_ca_cert.pem(),
        &tmp_ca_key.serialize_pem(),
    )?;
    store_cert(
        output_dir,
        "root-ca",
        &ca_cert.pem(),
        &ca_key.serialize_pem(),
    )?;
    store_cert(
        output_dir,
        "kms-rpc",
        &kms_rpc_cert.pem(),
        &kms_rpc_key.serialize_pem(),
    )?;
    store_cert(
        output_dir,
        "tproxy-rpc",
        &tproxy_rpc_cert.pem(),
        &tproxy_rpc_key.serialize_pem(),
    )?;
    Ok(())
}

fn store_cert(path: &str, name: &str, cert: &str, key: &str) -> anyhow::Result<()> {
    let cert_path = format!("{}/{}.cert", path, name);
    let key_path = format!("{}/{}.key", path, name);
    fs::write(cert_path, cert)?;
    fs::write(key_path, key)?;
    Ok(())
}
