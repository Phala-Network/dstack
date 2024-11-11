use crate::codecs::VecOf;
use anyhow::{Context, Result};
use scale::Decode;
use serde::{Deserialize, Serialize};
use tcg::{TcgDigest, TcgEfiSpecIdEvent};

mod tcg;

/// This is the common struct for tcg event logs to be delivered in different formats.
/// Currently TCG supports several event log formats defined in TCG_PCClient Spec,
/// Canonical Eventlog Spec, etc.
/// This struct provides the functionality to convey event logs in different format
/// according to request.
#[derive(Clone, scale::Decode)]
pub struct TcgEventLog {
    /// IMR index, starts from 1
    pub imr_index: u32,
    /// Event type
    pub event_type: u32,
    /// List of digests
    pub digests: VecOf<u32, TcgDigest>,
    /// Raw event data
    pub event: VecOf<u32, u8>,
}

/// This is the TDX event log format that is used to store the event log in the TDX guest.
/// It is a simplified version of the TCG event log format, containing only a single digest
/// and the raw event data. The IMR index is zero-based, unlike the TCG event log format
/// which is one-based.
#[derive(Clone, Serialize, Deserialize)]
pub struct TdxEventLog {
    /// IMR index, starts from 0
    pub imr: u32,
    /// Event type
    pub event_type: u32,
    /// Digest
    #[serde(with = "serde_human_bytes")]
    pub digest: [u8; 48],
    /// Raw event data
    #[serde(with = "serde_human_bytes")]
    pub event: Vec<u8>,
}

impl TryFrom<TcgEventLog> for TdxEventLog {
    type Error = anyhow::Error;

    fn try_from(value: TcgEventLog) -> Result<Self> {
        if value.digests.len() != 1 {
            return Err(anyhow::anyhow!(
                "expected 1 digest, got {}",
                value.digests.len()
            ));
        }
        let digest = value
            .digests
            .into_inner()
            .into_iter()
            .next()
            .context("digest not found")?
            .hash
            .try_into()
            .ok()
            .context("invalid digest size")?;
        Ok(TdxEventLog {
            imr: value
                .imr_index
                .checked_sub(1)
                .context("invalid imr index")?,
            event_type: value.event_type,
            digest,
            event: value.event.into(),
        })
    }
}

impl core::fmt::Debug for TcgEventLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcgEventLog")
            .field("imr_index", &self.imr_index)
            .field("event_type", &self.event_type)
            .field(
                "digests",
                &self
                    .digests
                    .iter()
                    .map(|d| hex::encode(&d.hash))
                    .collect::<Vec<_>>(),
            )
            .field("event", &hex::encode(&self.event))
            .finish()
    }
}

const fn alg_id_to_digest_size(alg_id: u16) -> Option<u8> {
    use tcg::*;
    match alg_id {
        TPM_ALG_SHA1 => Some(20),
        TPM_ALG_SHA256 => Some(32),
        TPM_ALG_SHA384 => Some(48),
        TPM_ALG_SHA512 => Some(64),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct EventLogs {
    pub spec_id_header_event: TcgEfiSpecIdEvent,
    pub event_logs: Vec<TcgEventLog>,
}

impl scale::Decode for TcgDigest {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let algo_id = u16::decode(input)?;
        let digest_size =
            alg_id_to_digest_size(algo_id).ok_or(scale::Error::from("Unsupported algorithm ID"))?;
        let mut digest_data = vec![0; digest_size as usize];
        input
            .read(&mut digest_data)
            .map_err(|_| scale::Error::from("failed to read digest_data"))?;
        Ok(TcgDigest {
            algo_id,
            hash: digest_data,
        })
    }
}

impl EventLogs {
    pub fn decode(input: &mut &[u8]) -> Result<Self> {
        let (_spec_id_header, spec_id_header_event) =
            parse_spec_id_event_log(input).context("Failed to parse spec id event")?;
        let mut event_logs = vec![];
        loop {
            // A tmp head_buffer is used to peek the imr and event type
            let head_buffer = &mut &input[..];
            let imr = u32::decode(head_buffer).context("failed to decode imr")?;
            if imr == 0xFFFFFFFF {
                break;
            }
            let event_log = TcgEventLog::decode(input).context("Failed to parse event log")?;
            event_logs.push(event_log);
        }
        Ok(EventLogs {
            spec_id_header_event,
            event_logs,
        })
    }

    pub fn decode_from_ccel_file() -> Result<Self> {
        const CCEL_FILE: &str = "/sys/firmware/acpi/tables/data/CCEL";

        let data = fs_err::read(CCEL_FILE).context("Failed to read CCEL")?;
        Self::decode(&mut data.as_slice())
    }

    pub fn into_tdx_event_logs(self) -> Result<Vec<TdxEventLog>> {
        self.event_logs
            .into_iter()
            .map(TdxEventLog::try_from)
            .collect()
    }

    pub fn to_tdx_event_logs(&self) -> Result<Vec<TdxEventLog>> {
        self.event_logs
            .iter()
            .cloned()
            .map(TdxEventLog::try_from)
            .collect()
    }
}

fn parse_spec_id_event_log<I: scale::Input>(
    input: &mut I,
) -> Result<(TcgEventLog, TcgEfiSpecIdEvent)> {
    #[derive(Decode)]
    struct Header {
        imr_index: u32,
        header_event_type: u32,
        digest_hash: [u8; 20],
        header_event: VecOf<u32, u8>,
    }

    let decoded_header = Header::decode(input).context("failed to decode log_item")?;
    // Parse EFI Spec Id Event structure
    let input = &mut decoded_header.header_event.as_slice();
    let spec_id_event =
        TcgEfiSpecIdEvent::decode(input).context("failed to decode TcgEfiSpecIdEvent")?;

    let digests = vec![TcgDigest {
        algo_id: tcg::TPM_ALG_ERROR,
        hash: decoded_header.digest_hash.to_vec(),
    }];
    let spec_id_header = TcgEventLog {
        imr_index: decoded_header.imr_index,
        event_type: decoded_header.header_event_type,
        digests: (digests.len() as u32, digests).into(),
        event: decoded_header.header_event,
    };
    Ok((spec_id_header, spec_id_event))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ccel() {
        let boot_time_data = include_bytes!("../samples/ccel.bin");
        let event_logs = EventLogs::decode(&mut boot_time_data.as_slice()).unwrap();
        insta::assert_debug_snapshot!(&event_logs.event_logs);
        let tdx_event_logs = event_logs.to_tdx_event_logs().unwrap();
        let json = serde_json::to_string_pretty(&tdx_event_logs).unwrap();
        insta::assert_snapshot!(json);
    }
}
