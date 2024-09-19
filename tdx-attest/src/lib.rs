pub use tdx_attest_sys as sys;

use std::ptr;
use std::slice;

use sys::*;

use num_enum::FromPrimitive;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, TdxAttestError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdxUuid(pub [u8; TDX_UUID_SIZE as usize]);

pub type TdxReportData = [u8; TDX_REPORT_DATA_SIZE as usize];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdxReport(pub [u8; TDX_REPORT_SIZE as usize]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxRtmrEvent {
    pub version: u32,
    pub rtmr_index: u64,
    pub digest: [u8; 48usize],
    pub event_type: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, Error)]
pub enum TdxAttestError {
    #[error("unexpected")]
    Unexpected = _tdx_attest_error_t::TDX_ATTEST_ERROR_UNEXPECTED,
    #[error("invalid parameter")]
    InvalidParameter = _tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_PARAMETER,
    #[error("out of memory")]
    OutOfMemory = _tdx_attest_error_t::TDX_ATTEST_ERROR_OUT_OF_MEMORY,
    #[error("vsock failure")]
    VsockFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_VSOCK_FAILURE,
    #[error("report failure")]
    ReportFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_REPORT_FAILURE,
    #[error("extend failure")]
    ExtendFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_EXTEND_FAILURE,
    #[error("not supported")]
    NotSupported = _tdx_attest_error_t::TDX_ATTEST_ERROR_NOT_SUPPORTED,
    #[error("quote failure")]
    QuoteFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_QUOTE_FAILURE,
    #[error("busy")]
    Busy = _tdx_attest_error_t::TDX_ATTEST_ERROR_BUSY,
    #[error("device failure")]
    DeviceFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_DEVICE_FAILURE,
    #[error("invalid rtmr index")]
    InvalidRtmrIndex = _tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_RTMR_INDEX,
    #[error("unsupported att key id")]
    UnsupportedAttKeyId = _tdx_attest_error_t::TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID,
    #[num_enum(catch_all)]
    #[error("unknown error ({0})")]
    UnknownError(u32),
}

pub fn get_quote(
    report_data: &TdxReportData,
    att_key_id_list: Option<&[TdxUuid]>,
) -> Result<(TdxUuid, Vec<u8>)> {
    let mut att_key_id = TdxUuid([0; TDX_UUID_SIZE as usize]);
    let mut quote_ptr = ptr::null_mut();
    let mut quote_size = 0;

    let error = unsafe {
        let key_id_list_ptr = att_key_id_list
            .map(|list| list.as_ptr() as *const tdx_uuid_t)
            .unwrap_or(ptr::null());
        tdx_att_get_quote(
            report_data as *const TdxReportData as *const tdx_report_data_t,
            key_id_list_ptr,
            att_key_id_list.map_or(0, |list| list.len() as u32),
            &mut att_key_id as *mut TdxUuid as *mut tdx_uuid_t,
            &mut quote_ptr,
            &mut quote_size,
            0,
        )
    };

    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }

    let quote = unsafe { slice::from_raw_parts(quote_ptr, quote_size as usize).to_vec() };

    unsafe {
        tdx_att_free_quote(quote_ptr);
    }

    Ok((att_key_id, quote))
}

pub fn get_report(report_data: &TdxReportData) -> Result<TdxReport> {
    let mut report = TdxReport([0; TDX_REPORT_SIZE as usize]);

    let error = unsafe {
        tdx_att_get_report(
            report_data as *const TdxReportData as *const tdx_report_data_t,
            &mut report as *mut TdxReport as *mut tdx_report_t,
        )
    };

    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }

    Ok(report)
}

pub fn extend_rtmr(rtmr_event: &TdxRtmrEvent) -> Result<()> {
    let event = tdx_rtmr_event_t {
        version: rtmr_event.version,
        rtmr_index: rtmr_event.rtmr_index,
        extend_data: rtmr_event.digest,
        event_type: rtmr_event.event_type,
        event_data_size: 0,
        event_data: Default::default(),
    };
    let error = unsafe { tdx_att_extend(&event) };
    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }
    Ok(())
}

pub fn get_supported_att_key_ids() -> Result<Vec<TdxUuid>> {
    let mut list_size = 0;
    let error = unsafe { tdx_att_get_supported_att_key_ids(ptr::null_mut(), &mut list_size) };

    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }

    let mut att_key_id_list = vec![TdxUuid([0; TDX_UUID_SIZE as usize]); list_size as usize];

    let error = unsafe {
        tdx_att_get_supported_att_key_ids(
            att_key_id_list.as_mut_ptr() as *mut tdx_uuid_t,
            &mut list_size,
        )
    };

    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }

    Ok(att_key_id_list)
}
