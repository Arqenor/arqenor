//! Phase 2 — TDH (Trace Data Helper) property parsing for ETW events.
//!
//! Decodes the raw `UserData` bytes of an `EVENT_RECORD` into named key/value
//! pairs using the Windows TDH API (`tdh.dll`).
//!
//! # Safety contract
//! The `EVENT_RECORD` pointer passed to [`parse_event_properties`] **must** be
//! called from within the ETW callback — the pointer is invalidated once the
//! callback returns.
//!
//! All failures are non-fatal: the function returns an empty map on any error
//! so the caller can continue processing with the raw header fields.

use std::collections::HashMap;

use windows::{
    core::PCWSTR,
    Win32::System::Diagnostics::Etw::{
        EVENT_PROPERTY_INFO, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR, TRACE_EVENT_INFO,
        TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize,
    },
};

// Win32 error codes (raw)
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse ETW event properties via TDH.
///
/// The `record` pointer is only valid during the ETW callback — call
/// immediately inside `event_record_callback`.
///
/// Returns an empty map on any failure (non-fatal).
pub fn parse_event_properties(record: *const EVENT_RECORD) -> HashMap<String, String> {
    // SAFETY: caller guarantees `record` is valid for the duration of the ETW
    // callback.  All unsafe blocks below are bounded to that lifetime.
    unsafe { parse_impl(record) }.unwrap_or_default()
}

// ── Implementation ────────────────────────────────────────────────────────────

unsafe fn parse_impl(record: *const EVENT_RECORD) -> Option<HashMap<String, String>> {
    // ── Pass 1: determine required buffer size ────────────────────────────────
    let mut buf_size: u32 = 0;
    let rc = unsafe {
        TdhGetEventInformation(record, None, None, &mut buf_size)
    };

    if rc != ERROR_INSUFFICIENT_BUFFER && rc != 0 {
        // Provider schema not available (e.g., WPP, MOF without schema in registry)
        return None;
    }

    if buf_size == 0 {
        return Some(HashMap::new());
    }

    // ── Pass 2: fill the buffer ───────────────────────────────────────────────
    let mut buf = vec![0u8; buf_size as usize];
    let rc = unsafe {
        TdhGetEventInformation(
            record,
            None,
            Some(buf.as_mut_ptr() as *mut TRACE_EVENT_INFO),
            &mut buf_size,
        )
    };

    if rc != 0 {
        return None;
    }

    // SAFETY: TdhGetEventInformation filled `buf` with a valid TRACE_EVENT_INFO
    // followed by variable-length data.  The buffer is aligned to u8, and
    // TRACE_EVENT_INFO begins at offset 0.
    let info = unsafe { &*(buf.as_ptr() as *const TRACE_EVENT_INFO) };
    let property_count = info.PropertyCount;

    if property_count == 0 {
        return Some(HashMap::new());
    }

    // The EventPropertyInfoArray is a flexible array member — index past the
    // first element using a raw pointer.
    let prop_array_ptr: *const EVENT_PROPERTY_INFO =
        &info.EventPropertyInfoArray as *const [EVENT_PROPERTY_INFO; 1] as *const EVENT_PROPERTY_INFO;

    let mut props = HashMap::with_capacity(property_count as usize);

    for i in 0..property_count {
        // SAFETY: TDH guarantees `property_count` contiguous EVENT_PROPERTY_INFO
        // entries starting at EventPropertyInfoArray.
        let prop = unsafe { &*prop_array_ptr.add(i as usize) };

        let name = read_wstr_at_offset(&buf, prop.NameOffset as usize);
        if name.is_empty() {
            continue;
        }

        let value = read_property_value(record, &name, prop);
        props.insert(name, value);
    }

    Some(props)
}

// ── Property value reader ─────────────────────────────────────────────────────

fn read_property_value(
    record: *const EVENT_RECORD,
    name: &str,
    prop: &EVENT_PROPERTY_INFO,
) -> String {
    // Null-terminated wide name for PROPERTY_DATA_DESCRIPTOR.
    let name_wide: Vec<u16> = name.encode_utf16().chain([0u16]).collect();

    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name_wide.as_ptr() as u64,
        ArrayIndex: 0xFFFF_FFFF, // scalar (not an array element)
        Reserved: 0,
    };

    // ── Size query ────────────────────────────────────────────────────────────
    let mut data_size: u32 = 0;
    let rc = unsafe {
        TdhGetPropertySize(record, None, &[desc], &mut data_size)
    };

    if rc != 0 || data_size == 0 {
        return String::new();
    }

    // ── Data retrieval ────────────────────────────────────────────────────────
    let mut data = vec![0u8; data_size as usize];
    let rc = unsafe {
        TdhGetProperty(record, None, &[desc], &mut data)
    };

    if rc != 0 {
        return String::new();
    }

    // ── Decode according to InType ────────────────────────────────────────────
    // SAFETY: `nonStructType` is the default active union arm for scalar
    // properties (the only ones we query here — struct-type properties are
    // skipped implicitly because their InType is 0 / TDH_INTYPE_NULL).
    let intype: u16 = unsafe { prop.Anonymous1.nonStructType.InType };
    format_value(&data, intype)
}

// ── Value formatter ───────────────────────────────────────────────────────────

fn format_value(data: &[u8], intype: u16) -> String {
    match intype {
        // TDH_INTYPE_UNICODESTRING
        1 => decode_utf16(data),
        // TDH_INTYPE_ANSISTRING
        2 => String::from_utf8_lossy(data)
            .trim_end_matches('\0')
            .to_owned(),
        // TDH_INTYPE_INT8
        3 => data.first().copied().map(|b| (b as i8).to_string()).unwrap_or_default(),
        // TDH_INTYPE_UINT8
        4 => data.first().copied().map(|b| b.to_string()).unwrap_or_default(),
        // TDH_INTYPE_INT16
        5 => read_le_i16(data).to_string(),
        // TDH_INTYPE_UINT16
        6 => read_le_u16(data).to_string(),
        // TDH_INTYPE_INT32
        7 => read_le_i32(data).to_string(),
        // TDH_INTYPE_UINT32
        8 => read_le_u32(data).to_string(),
        // TDH_INTYPE_INT64
        10 => read_le_i64(data).to_string(),
        // TDH_INTYPE_UINT64
        11 => read_le_u64(data).to_string(),
        // TDH_INTYPE_FLOAT
        12 => {
            if data.len() >= 4 {
                f32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string()
            } else {
                hex::encode(data)
            }
        }
        // TDH_INTYPE_DOUBLE
        13 => {
            if data.len() >= 8 {
                f64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                ])
                .to_string()
            } else {
                hex::encode(data)
            }
        }
        // TDH_INTYPE_BOOLEAN
        14 => {
            if data.first() == Some(&0) { "false".into() } else { "true".into() }
        }
        // TDH_INTYPE_BINARY / unknown → raw hex
        _ => hex::encode(data),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read a null-terminated UTF-16LE string from `buf` at byte `offset`.
fn read_wstr_at_offset(buf: &[u8], offset: usize) -> String {
    if offset >= buf.len() {
        return String::new();
    }
    // SAFETY: `ptr` points inside the valid slice `buf[offset..]`.
    // PCWSTR::to_string() scans until the first null u16.
    let ptr = buf[offset..].as_ptr() as *const u16;
    unsafe { PCWSTR(ptr).to_string().unwrap_or_default() }
}

fn decode_utf16(data: &[u8]) -> String {
    let words: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&words)
        .trim_end_matches('\0')
        .to_owned()
}

// Numeric LE readers — return 0 on short buffers (non-panicking).
fn read_le_i16(data: &[u8]) -> i16 {
    if data.len() >= 2 { i16::from_le_bytes([data[0], data[1]]) } else { 0 }
}
fn read_le_u16(data: &[u8]) -> u16 {
    if data.len() >= 2 { u16::from_le_bytes([data[0], data[1]]) } else { 0 }
}
fn read_le_i32(data: &[u8]) -> i32 {
    if data.len() >= 4 { i32::from_le_bytes([data[0], data[1], data[2], data[3]]) } else { 0 }
}
fn read_le_u32(data: &[u8]) -> u32 {
    if data.len() >= 4 { u32::from_le_bytes([data[0], data[1], data[2], data[3]]) } else { 0 }
}
fn read_le_i64(data: &[u8]) -> i64 {
    if data.len() >= 8 {
        i64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ])
    } else {
        0
    }
}
fn read_le_u64(data: &[u8]) -> u64 {
    if data.len() >= 8 {
        u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ])
    } else {
        0
    }
}
