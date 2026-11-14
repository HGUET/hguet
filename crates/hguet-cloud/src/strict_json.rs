//! Strict JSON for the S7.1 profile: no BOM, valid UTF-8, no duplicate keys, no floats or non-JSON tokens, no
//! trailing data. serde_json alone silently keeps the last duplicate key, which a hashed profile cannot allow.

use crate::{Error, Result};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;
use std::fmt;

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("strict JSON")
            }
            fn visit_bool<E>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Number(Number::from(v))))
            }
            fn visit_u64<E>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Number(Number::from(v))))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Strict, E> {
                Err(E::custom("JSON_FLOAT_NOT_ALLOWED"))
            }
            fn visit_str<E>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_unit<E>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Strict(Value::Array(items)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut seen = BTreeSet::new();
                let mut map = Map::new();
                while let Some((key, Strict(item))) = access.next_entry::<String, Strict>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("JSON_DUPLICATE_KEY"));
                    }
                    map.insert(key, item);
                }
                Ok(Strict(Value::Object(map)))
            }
        }
        deserializer.deserialize_any(V)
    }
}

pub fn parse(data: &[u8]) -> Result<Value> {
    if data.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(Error("JSON_BOM"));
    }
    let text = std::str::from_utf8(data).map_err(|_| Error("JSON_INVALID_UTF8"))?;
    match serde_json::from_str::<Strict>(text) {
        Ok(Strict(value)) => Ok(value),
        Err(error) => {
            let message = error.to_string();
            for code in ["JSON_DUPLICATE_KEY", "JSON_FLOAT_NOT_ALLOWED"] {
                if message.contains(code) {
                    return Err(Error(code));
                }
            }
            Err(Error("JSON_MALFORMED"))
        }
    }
}
