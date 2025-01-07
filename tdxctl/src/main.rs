use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use cmd_lib::run_cmd as cmd;
use fde_setup::{cmd_setup_fde, SetupFdeArgs};
use fs_err as fs;
use getrandom::getrandom;
use host_api::HostApi;
use ra_tls::{
    attestation::QuoteContentType, cert::CaCert, kdf::derive_ecdsa_key_pair_from_bytes,
    rcgen::KeyPair,
};
use scale::Decode;
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
use tboot::TbootArgs;
use tdx_attest as att;
use tracing::error;
use utils::{extend_rtmr, AppKeys};

mod crypto;
mod fde_setup;
mod host_api;
mod tboot;
mod utils;

/// TDX control utility
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get TDX report given report data from stdin
    Report,
    /// Generate a TDX quote given report data from stdin
    Quote,
    /// Extend RTMRs
    Extend(ExtendArgs),
    /// Show the current RTMR state
    Show,
    /// Hex encode data
    Hex(HexCommand),
    /// Generate a RA-TLS certificate
    GenRaCert(GenRaCertArgs),
    /// Generate a CA certificate
    GenCaCert(GenCaCertArgs),
    /// Generate app keys for an Tapp
    GenAppKeys(GenAppKeysArgs),
    /// Generate random data
    Rand(RandArgs),
    /// Setup Disk Encryption
    SetupFde(SetupFdeArgs),
    /// Boot the Tapp
    Tboot(TbootArgs),
    /// Notify the host about the Tapp
    NotifyHost(HostNotifyArgs),
}

#[derive(Parser)]
/// Hex encode data
struct HexCommand {
    #[clap(value_parser)]
    /// filename to hex encode
    filename: Option<String>,
}

#[derive(Parser)]
/// Extend RTMR
struct ExtendArgs {
    #[clap(short = 'i', long, default_value_t = 3)]
    /// RTMR index (default: 3)
    index: u32,

    #[clap(short = 't', long, default_value_t = 1)]
    /// event type (default: 1)
    event_type: u32,

    #[clap(short, long)]
    /// event name
    event: String,

    #[clap(short, long)]
    /// hex encoded payload of the event
    payload: String,
}

#[derive(Parser)]
/// Generate a certificate
struct GenRaCertArgs {
    /// CA certificate used to sign the RA certificate
    #[arg(long)]
    ca_cert: PathBuf,

    /// CA private key used to sign the RA certificate
    #[arg(long)]
    ca_key: PathBuf,

    #[arg(short, long)]
    /// file path to store the certificate
    cert_path: PathBuf,

    #[arg(short, long)]
    /// file path to store the private key
    key_path: PathBuf,
}

#[derive(Parser)]
/// Generate CA certificate
struct GenCaCertArgs {
    /// path to store the certificate
    #[arg(long)]
    cert: PathBuf,
    /// path to store the private key
    #[arg(long)]
    key: PathBuf,
    /// CA level
    #[arg(long, default_value_t = 1)]
    ca_level: u8,
}

#[derive(Parser)]
/// Generate app keys
struct GenAppKeysArgs {
    /// CA level
    #[arg(long, default_value_t = 1)]
    ca_level: u8,

    /// path to store the app keys
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Parser)]
/// Generate random data
struct RandArgs {
    /// number of bytes to generate
    #[arg(short = 'n', long, default_value_t = 20)]
    bytes: usize,

    /// output to file
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// hex encode output
    #[arg(short = 'x', long)]
    hex: bool,
}

#[derive(Parser)]
/// Test app feature. Print "true" if the feature is supported, otherwise print "false".
struct TestAppFeatureArgs {
    /// path to the app keys
    #[arg(short, long)]
    feature: String,

    /// path to the app compose file
    #[arg(short, long)]
    compose: String,
}

#[derive(Parser)]
/// Notify the host about the Tapp
struct HostNotifyArgs {
    #[arg(short, long)]
    url: Option<String>,
    /// event name
    #[arg(short, long)]
    event: String,
    /// event payload
    #[arg(short = 'd', long)]
    payload: String,
}

fn cmd_quote() -> Result<()> {
    let mut report_data = [0; 64];
    io::stdin()
        .read_exact(&mut report_data)
        .context("Failed to read report data")?;
    let (_key_id, quote) = att::get_quote(&report_data, None).context("Failed to get quote")?;
    io::stdout()
        .write_all(&quote)
        .context("Failed to write quote")?;
    Ok(())
}

fn cmd_extend(extend_args: ExtendArgs) -> Result<()> {
    let payload = hex::decode(&extend_args.payload).context("Failed to decode payload")?;
    extend_rtmr(
        extend_args.index,
        extend_args.event_type,
        &extend_args.event,
        &payload,
    )
}

fn cmd_report() -> Result<()> {
    let mut report_data = [0; 64];
    io::stdin()
        .read_exact(&mut report_data)
        .context("Failed to read report data")?;
    let report = att::get_report(&report_data).context("Failed to get report")?;
    io::stdout()
        .write_all(&report.0)
        .context("Failed to write report")?;
    Ok(())
}

fn cmd_rand(rand_args: RandArgs) -> Result<()> {
    let mut data = vec![0u8; rand_args.bytes];
    getrandom(&mut data).context("Failed to generate random data")?;
    if rand_args.hex {
        data = hex::encode(data).into_bytes();
    }
    io::stdout()
        .write_all(&data)
        .context("Failed to write random data")?;
    Ok(())
}

#[derive(Decode)]
struct ParsedReport {
    attributes: [u8; 8],
    xfam: [u8; 8],
    mrtd: [u8; 48],
    mrconfigid: [u8; 48],
    mrowner: [u8; 48],
    mrownerconfig: [u8; 48],
    rtmr0: [u8; 48],
    rtmr1: [u8; 48],
    rtmr2: [u8; 48],
    rtmr3: [u8; 48],
    servtd_hash: [u8; 48],
}

impl core::fmt::Debug for ParsedReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use hex_fmt::HexFmt as HF;

        f.debug_struct("ParsedReport")
            .field("attributes", &HF(&self.attributes))
            .field("xfam", &HF(&self.xfam))
            .field("mrtd", &HF(&self.mrtd))
            .field("mrconfigid", &HF(&self.mrconfigid))
            .field("mrowner", &HF(&self.mrowner))
            .field("mrownerconfig", &HF(&self.mrownerconfig))
            .field("rtmr0", &HF(&self.rtmr0))
            .field("rtmr1", &HF(&self.rtmr1))
            .field("rtmr2", &HF(&self.rtmr2))
            .field("rtmr3", &HF(&self.rtmr3))
            .field("servtd_hash", &HF(&self.servtd_hash))
            .finish()
    }
}

fn cmd_show() -> Result<()> {
    let report_data = [0; 64];
    let report = att::get_report(&report_data).context("Failed to get report")?;
    let parsed_report =
        ParsedReport::decode(&mut report.0.get(512..).context("Failed to get report")?)
            .context("Failed to decode report")?;
    println!("{:#?}", parsed_report);
    Ok(())
}

fn cmd_hex(hex_args: HexCommand) -> Result<()> {
    fn hex_encode_io(io: &mut impl Read) -> Result<()> {
        loop {
            let mut buf = [0; 1024];
            let n = io.read(&mut buf).context("Failed to read from stdin")?;
            if n == 0 {
                break;
            }
            print!("{}", hex_fmt::HexFmt(&buf[..n]));
        }
        Ok(())
    }
    if let Some(filename) = hex_args.filename {
        let mut input =
            fs::File::open(&filename).context(format!("Failed to open {}", filename))?;
        hex_encode_io(&mut input)?;
    } else {
        hex_encode_io(&mut io::stdin())?;
    };
    Ok(())
}

fn cmd_gen_ra_cert(args: GenRaCertArgs) -> Result<()> {
    let ca_cert = fs::read_to_string(args.ca_cert)?;
    let ca_key = fs::read_to_string(args.ca_key)?;
    let (cert, key) = gen_ra_cert(ca_cert, ca_key)?;
    fs::write(&args.cert_path, cert).context("Failed to write certificate")?;
    fs::write(&args.key_path, key).context("Failed to write private key")?;
    Ok(())
}

fn gen_ra_cert(ca_cert_pem: String, ca_key_pem: String) -> Result<(String, String)> {
    use ra_tls::cert::CertRequest;
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let ca = CaCert::new(ca_cert_pem, ca_key_pem)?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let (_, quote) = att::get_quote(&report_data, None).context("Failed to get quote")?;
    let event_logs = att::eventlog::read_event_logs().context("Failed to read event logs")?;
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;
    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .quote(&quote)
        .event_log(&event_log)
        .key(&key)
        .build();
    let cert = ca.sign(req).context("Failed to sign certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn cmd_gen_ca_cert(args: GenCaCertArgs) -> Result<()> {
    use ra_tls::cert::CertRequest;
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::KmsRootCa.to_report_data(&pubkey);
    let (_, quote) = att::get_quote(&report_data, None).context("Failed to get quote")?;
    let event_logs = att::eventlog::read_event_logs().context("Failed to read event logs")?;
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;

    let req = CertRequest::builder()
        .subject("App Root CA")
        .quote(&quote)
        .event_log(&event_log)
        .key(&key)
        .ca_level(args.ca_level)
        .build();

    let cert = req
        .self_signed()
        .context("Failed to self-sign certificate")?;
    fs::write(&args.cert, cert.pem()).context("Failed to write certificate")?;
    fs::write(&args.key, key.serialize_pem()).context("Failed to write private key")?;
    Ok(())
}

fn cmd_gen_app_keys(args: GenAppKeysArgs) -> Result<()> {
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let disk_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let app_keys = make_app_keys(key, disk_key, args.ca_level)?;
    let app_keys = serde_json::to_string(&app_keys).context("Failed to serialize app keys")?;
    fs::write(&args.output, app_keys).context("Failed to write app keys")?;
    Ok(())
}

fn gen_app_keys_from_seed(seed: &[u8]) -> Result<AppKeys> {
    let key = derive_ecdsa_key_pair_from_bytes(seed, &["app-key".as_bytes()])?;
    let disk_key = derive_ecdsa_key_pair_from_bytes(seed, &["app-disk-key".as_bytes()])?;
    make_app_keys(key, disk_key, 1)
}

fn make_app_keys(app_key: KeyPair, disk_key: KeyPair, ca_level: u8) -> Result<AppKeys> {
    use ra_tls::cert::CertRequest;
    let pubkey = app_key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let (_, quote) = att::get_quote(&report_data, None).context("Failed to get quote")?;
    let event_logs = att::eventlog::read_event_logs().context("Failed to read event logs")?;
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;
    let req = CertRequest::builder()
        .subject("App Root Cert")
        .quote(&quote)
        .event_log(&event_log)
        .key(&app_key)
        .ca_level(ca_level)
        .build();
    let cert = req
        .self_signed()
        .context("Failed to self-sign certificate")?;

    Ok(AppKeys {
        app_key: app_key.serialize_pem(),
        disk_crypt_key: sha256(&disk_key.serialize_der()),
        certificate_chain: vec![cert.pem()],
        env_crypt_key: vec![],
    })
}

async fn cmd_notify_host(args: HostNotifyArgs) -> Result<()> {
    let client = HostApi::load_or_default(args.url)?;
    client.notify(&args.event, &args.payload).await?;
    Ok(())
}

fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    let mut sha256 = sha2::Sha256::new();
    sha256.update(data);
    hex::encode(sha256.finalize())
}

#[tokio::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Report => cmd_report()?,
        Commands::Quote => cmd_quote()?,
        Commands::Show => cmd_show()?,
        Commands::Extend(extend_args) => {
            cmd_extend(extend_args)?;
        }
        Commands::Hex(hex_args) => {
            cmd_hex(hex_args)?;
        }
        Commands::GenRaCert(args) => {
            cmd_gen_ra_cert(args)?;
        }
        Commands::Rand(rand_args) => {
            cmd_rand(rand_args)?;
        }
        Commands::GenCaCert(args) => {
            cmd_gen_ca_cert(args)?;
        }
        Commands::GenAppKeys(args) => {
            cmd_gen_app_keys(args)?;
        }
        Commands::SetupFde(args) => {
            cmd_setup_fde(args).await?;
        }
        Commands::Tboot(args) => {
            if let Err(err) = tboot::tboot(&args).await {
                error!("{:?}", err);
                if args.shutdown_on_fail {
                    cmd!(systemctl poweroff)?;
                }
                bail!("Failed to boot the Tapp");
            }
        }
        Commands::NotifyHost(args) => {
            cmd_notify_host(args).await?;
        }
    }

    Ok(())
}
