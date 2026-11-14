//! Critical / unknown Protobuf field policy (S7.1 PROPOSAL) for an `Envelope`, applied by the client to every frame it
//! receives and by tests to what it builds. The field table is GENERATED from this repository's hguet.proto.
//!
//! Rules (first violation in wire order wins; the same order is used by the reference implementation):
//! * field number 0, group wire types, truncation, overlong (non-minimal) or endless varints are errors;
//! * an unknown field number >= 1000 is a non-critical extension and is ignored; any other unknown field is
//!   critical -> `PROTO_UNKNOWN_CRITICAL_FIELD` (maps to ERROR_UNKNOWN_CRITICAL_FIELD);
//! * a singular field may appear at most once (last-wins would make a hashed value ambiguous);
//! * at most one member of a `oneof`; wire type must match the declared type; strings are UTF-8;
//!   bool is 0 or 1; uint32 fits 32 bits; enum values must be defined;
//! * nesting depth <= 6 and the Envelope <= 1 MiB.

use crate::proto_table::{ENUMS, MESSAGES};
use crate::{Error, Result};
use std::collections::BTreeSet;

pub const EXTENSION_FLOOR: u64 = 1000;
pub const MAX_ENVELOPE: usize = 1 << 20;

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    String,
    Bytes,
    Bool,
    U32,
    U64,
    Enum(&'static str),
    Message(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub number: u32,
    pub kind: Kind,
    pub repeated: bool,
    pub oneof: Option<&'static str>,
}

fn varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let start = *pos;
    let (mut value, mut shift) = (0u64, 0u32);
    loop {
        if *pos >= data.len() {
            return Err(Error("PROTO_TRUNCATED"));
        }
        if shift > 63 {
            return Err(Error("PROTO_OVERLONG_VARINT"));
        }
        let byte = data[*pos];
        *pos += 1;
        value |= ((byte & 0x7f) as u64).checked_shl(shift).unwrap_or(0);
        if byte & 0x80 == 0 {
            if *pos - start > 1 && byte == 0 {
                return Err(Error("PROTO_OVERLONG_VARINT"));
            }
            return Ok(value);
        }
        shift += 7;
    }
}

fn message_fields(name: &str) -> &'static [Field] {
    MESSAGES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| *f)
        .expect("message in generated table")
}

fn enum_values(name: &str) -> &'static [i64] {
    ENUMS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| *v)
        .expect("enum in generated table")
}

fn is_numeric(kind: Kind) -> bool {
    matches!(kind, Kind::Bool | Kind::U32 | Kind::U64 | Kind::Enum(_))
}

fn check_scalar(kind: Kind, value: u64) -> Result<()> {
    match kind {
        Kind::Bool if value > 1 => Err(Error("PROTO_INVALID_BOOL")),
        Kind::U32 if value >= 1 << 32 => Err(Error("PROTO_INTEGER_OVERFLOW")),
        Kind::Enum(name)
            if !enum_values(name).contains(&(value as i64)) || value > i64::MAX as u64 =>
        {
            Err(Error("PROTO_UNKNOWN_ENUM_VALUE"))
        }
        _ => Ok(()),
    }
}

/// Checks one client `Envelope` (without the 4-byte frame header).
pub fn check_envelope(data: &[u8]) -> Result<()> {
    if data.len() > MAX_ENVELOPE {
        return Err(Error("PROTO_FRAME_TOO_LARGE"));
    }
    scan("Envelope", data, 0)
}

fn scan(message: &str, data: &[u8], depth: u32) -> Result<()> {
    if depth > 6 {
        return Err(Error("PROTO_DEPTH"));
    }
    let fields = message_fields(message);
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut oneofs: Vec<(&str, u64)> = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let tag = varint(data, &mut pos)?;
        let (number, wire) = (tag >> 3, (tag & 7) as u8);
        if number == 0 {
            return Err(Error("PROTO_FIELD_NUMBER_ZERO"));
        }
        if wire == 3 || wire == 4 {
            return Err(Error("PROTO_GROUP_WIRE_TYPE"));
        }
        if !matches!(wire, 0 | 1 | 2 | 5) {
            return Err(Error("PROTO_WIRE_TYPE_MISMATCH"));
        }
        let field = fields.iter().find(|f| f.number as u64 == number);
        let (mut value, mut chunk): (u64, &[u8]) = (0, &[]);
        match wire {
            0 => value = varint(data, &mut pos)?,
            1 => {
                if pos + 8 > data.len() {
                    return Err(Error("PROTO_TRUNCATED"));
                }
                pos += 8;
            }
            5 => {
                if pos + 4 > data.len() {
                    return Err(Error("PROTO_TRUNCATED"));
                }
                pos += 4;
            }
            _ => {
                let length = varint(data, &mut pos)? as usize;
                if length > data.len() - pos {
                    return Err(Error("PROTO_TRUNCATED"));
                }
                chunk = &data[pos..pos + length];
                pos += length;
            }
        }
        let Some(field) = field else {
            if number >= EXTENSION_FLOOR {
                continue;
            }
            return Err(Error("PROTO_UNKNOWN_CRITICAL_FIELD"));
        };
        if !field.repeated && !seen.insert(number) {
            return Err(Error("PROTO_DUPLICATE_FIELD"));
        }
        if field.repeated {
            seen.insert(number);
        }
        if let Some(group) = field.oneof {
            match oneofs.iter().find(|(g, _)| *g == group) {
                Some((_, previous)) if *previous != number => {
                    return Err(Error("PROTO_ONEOF_CONFLICT"))
                }
                Some(_) => {}
                None => oneofs.push((group, number)),
            }
        }
        match wire {
            0 => {
                if !is_numeric(field.kind) {
                    return Err(Error("PROTO_WIRE_TYPE_MISMATCH"));
                }
                check_scalar(field.kind, value)?;
            }
            2 => match field.kind {
                Kind::String => {
                    if std::str::from_utf8(chunk).is_err() {
                        return Err(Error("PROTO_INVALID_UTF8"));
                    }
                }
                Kind::Bytes => {}
                Kind::Message(name) => scan(name, chunk, depth + 1)?,
                kind if is_numeric(kind) && field.repeated => {
                    let mut inner = 0usize;
                    while inner < chunk.len() {
                        let item = varint(chunk, &mut inner)?;
                        check_scalar(kind, item)?;
                    }
                }
                _ => return Err(Error("PROTO_WIRE_TYPE_MISMATCH")),
            },
            _ => return Err(Error("PROTO_WIRE_TYPE_MISMATCH")),
        }
    }
    Ok(())
}
