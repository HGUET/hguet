//! RFC 8785 canonical JSON restricted to the HGUET profile: integers only (|n| <= 2^53-1), no floats, object keys
//! ordered by UTF-16 code units. Signed payloads additionally require ASCII-only keys so that UTF-8 and UTF-16 order
//! coincide and any JCS library produces the same bytes.

use crate::{strict_json, Error, Result};
use serde_json::Value;

const MAX_SAFE_INT: u64 = (1 << 53) - 1;

fn string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn emit(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(Error("JCS_FLOAT_NOT_ALLOWED"));
            }
            match n.as_u64().or_else(|| n.as_i64().map(i64::unsigned_abs)) {
                Some(m) if m <= MAX_SAFE_INT => out.push_str(&n.to_string()),
                _ => return Err(Error("JCS_INTEGER_OUT_OF_RANGE")),
            }
        }
        Value::String(s) => string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                emit(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|entry| entry.0.encode_utf16().collect::<Vec<u16>>());
            out.push('{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(key, out);
                out.push(':');
                emit(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn ascii_keys(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().all(|(k, v)| k.is_ascii() && ascii_keys(v)),
        Value::Array(items) => items.iter().all(ascii_keys),
        _ => true,
    }
}

/// Canonical bytes of a value that will be signed or hashed.
pub fn canonicalize_signed_payload(value: &Value) -> Result<Vec<u8>> {
    if !ascii_keys(value) {
        return Err(Error("JCS_NON_ASCII_KEY"));
    }
    let mut out = String::new();
    emit(value, &mut out)?;
    Ok(out.into_bytes())
}

/// Parses strictly (no duplicate keys, floats, BOM, trailing data) and requires `data` to already be canonical:
/// returns the value only if re-canonicalizing it reproduces `data` byte for byte.
pub fn parse_canonical(data: &[u8]) -> Result<Value> {
    let value = strict_json::parse(data)?;
    if canonicalize_signed_payload(&value)? != data {
        return Err(Error("JSON_NOT_CANONICAL"));
    }
    Ok(value)
}
