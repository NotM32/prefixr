//! RPSL text deserializer.
//!
//! This module provides the top-level entry points for turning RPSL text
//! into typed [`RpslObject`]s. The pipeline is:
//!
//! 1. [`crate::rpsl::lex::lex`] folds raw text into [`RawObject`]s.
//! 2. [`parse_object`] dispatches on the leading `object-class:` attribute
//!    to the right [`RpslClass`] implementation, which parses the typed
//!    fields and validates mandatory/optional constraints.
//! 3. [`parse`] runs the above for every object in the input and returns
//!    a `Vec<RpslObject>`.
//!
//! A serde `Deserializer` adapter is provided so that callers can use
//! `RpslObject::deserialize(RpslTextDeserializer::new(text))` if they
//! prefer the serde API surface. The serde adapter is a thin wrapper
//! around the native parser: it parses the first object and feeds the
//! resulting [`RpslObject`] (which itself derives `Deserialize`) into
//! serde's `IntoDeserializer`.

use serde::de::{self, Deserializer as SerdeDeserializer};
use std::fmt;

use crate::rpsl::error::{RpslError, RpslResult};
use crate::rpsl::lex::{lex, RawObject};
use crate::rpsl::object::*;
use crate::rpsl::signed::SignedRpsl;
use crate::rpsl::RpslObject;

/// Parse a single [`RawObject`] into a typed [`RpslObject`].
///
/// Dispatches on the leading attribute's name (case-insensitive) to the
/// matching [`RpslClass::from_raw`] implementation. If the object carries
/// RFC 7909 envelope attributes (`uri:` + `digest:` + `signature:`), it is
/// parsed as a [`SignedRpsl`] wrapper instead.
pub fn parse_object(raw: &RawObject) -> RpslResult<RpslObject> {
    // Detect RFC 7909 signed envelope.
    if raw.has("uri") && raw.has("digest") && raw.has("signature") {
        let signed = SignedRpsl::from_raw(raw)?;
        return Ok(RpslObject::Signed(Box::new(signed)));
    }

    let class = raw
        .class()
        .ok_or_else(|| RpslError::lex(0, "object has no attributes"))?;
    match class.as_str() {
        "route" => Ok(RpslObject::Route(Route::from_raw(raw)?)),
        "route6" => Ok(RpslObject::Route6(Route6::from_raw(raw)?)),
        "aut-num" => Ok(RpslObject::AutNum(AutNum::from_raw(raw)?)),
        "as-set" => Ok(RpslObject::AsSet(AsSet::from_raw(raw)?)),
        "route-set" => Ok(RpslObject::RouteSet(RouteSet::from_raw(raw)?)),
        "filter-set" => Ok(RpslObject::FilterSet(FilterSet::from_raw(raw)?)),
        "peering-set" => Ok(RpslObject::PeeringSet(PeeringSet::from_raw(raw)?)),
        "rtr-set" => Ok(RpslObject::RtrSet(RtrSet::from_raw(raw)?)),
        "inet-rtr" => Ok(RpslObject::InetRtr(InetRtr::from_raw(raw)?)),
        "mntner" => Ok(RpslObject::Mntner(Mntner::from_raw(raw)?)),
        "person" => Ok(RpslObject::Person(Person::from_raw(raw)?)),
        "role" => Ok(RpslObject::Role(Role::from_raw(raw)?)),
        "key-cert" => Ok(RpslObject::KeyCert(KeyCert::from_raw(raw)?)),
        other => Err(RpslError::UnknownClass(other.to_string())),
    }
}

/// Parse a full RPSL document (possibly containing many objects) into a
/// vector of typed [`RpslObject`]s.
pub fn parse(input: &str) -> RpslResult<Vec<RpslObject>> {
    let raws = lex(input)?;
    raws.iter().map(parse_object).collect()
}

/// Parse exactly one object from the input. Returns an error if the input
/// contains zero or more than one object.
pub fn parse_one(input: &str) -> RpslResult<RpslObject> {
    let mut objs = parse(input)?;
    match objs.len() {
        0 => Err(RpslError::lex(0, "expected one object, found none")),
        1 => Ok(objs.pop().unwrap()),
        n => Err(RpslError::lex(
            0,
            format!("expected one object, found {n}"),
        )),
    }
}

// ----------------------------------------------------------------------
// serde Deserializer adapter
// ----------------------------------------------------------------------

/// A serde `Deserializer` that reads RPSL text and produces a single
/// [`RpslObject`].
///
/// This adapter lets callers use the familiar `serde::Deserialize` API to
/// parse RPSL text, even though the actual parsing is done by the native
/// [`parse_one`] function. The adapter implements only the subset of the
/// `serde::Deserializer` trait needed to drive `RpslObject`'s derived
/// `Deserialize` impl, which — because `RpslObject` is an internally-tagged
/// enum — only requires `deserialize_enum`.
///
/// Usage:
/// ```ignore
/// use serde::Deserialize;
/// use prefixify::rpsl::{RpslObject, de::RpslTextDeserializer};
///
/// let text = "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: R\n";
/// let obj = RpslObject::deserialize(RpslTextDeserializer::new(text)).unwrap();
/// ```
///
/// In practice, callers should prefer the direct [`parse_one`] / [`parse`]
/// functions; this adapter exists primarily to satisfy the "Serde
/// (de)serializer" requirement and to interoperate with code that expects
/// a `serde::Deserialize` bound.
pub struct RpslTextDeserializer<'a> {
    input: &'a str,
}

impl<'a> RpslTextDeserializer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input }
    }
}

impl<'de, 'a> SerdeDeserializer<'de> for RpslTextDeserializer<'a> {
    type Error = RpslSerdeError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        // We cannot meaningfully drive an arbitrary visitor from RPSL text
        // without re-implementing a full serde deserializer for the RPSL
        // data model. Instead we parse the object natively, convert it to
        // a `serde_json::Value` (serde_json is already a dependency of this
        // crate), and then drive the visitor from that value's
        // `IntoDeserializer` impl. Each `serde_json::Value` kind maps to a
        // specific `visit_*` method, so we dispatch by kind here.
        let obj = parse_one(self.input).map_err(RpslSerdeError)?;
        let value = serde_json::to_value(&obj).map_err(|e| {
            RpslSerdeError(RpslError::Parse {
                attribute: "serde".to_string(),
                line: 0,
                message: format!("internal serde_json error: {e}"),
            })
        })?;
        drive_visitor_from_json(value, visitor)
    }

    // The remaining methods all forward to deserialize_any, which is the
    // standard pattern for self-describing formats.
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq
        map enum identifier struct tuple_struct tuple ignored_any
    }
}

/// Newtype wrapper around [`RpslError`] so it can implement
/// `serde::de::Error`.
#[derive(Debug)]
pub struct RpslSerdeError(pub RpslError);

impl fmt::Display for RpslSerdeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for RpslSerdeError {}

impl de::Error for RpslSerdeError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self(RpslError::Parse {
            attribute: "serde".to_string(),
            line: 0,
            message: msg.to_string(),
        })
    }
}

impl From<RpslError> for RpslSerdeError {
    fn from(e: RpslError) -> Self {
        Self(e)
    }
}

/// Drive a `serde::de::Visitor` from a `serde_json::Value` by dispatching
/// on the value's kind to the appropriate `visit_*` method. This is the
/// glue that lets the native RPSL parser expose a `serde::Deserializer`
/// impl without re-implementing the entire deserialization for every Rust
/// type — `serde_json::Value` acts as an intermediate, self-describing
/// representation.
fn drive_visitor_from_json<'de, V>(
    value: serde_json::Value,
    visitor: V,
) -> Result<V::Value, RpslSerdeError>
where
    V: de::Visitor<'de>,
{
    match value {
        serde_json::Value::Null => visitor.visit_unit(),
        serde_json::Value::Bool(b) => visitor.visit_bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                visitor.visit_i64(i)
            } else if let Some(u) = n.as_u64() {
                visitor.visit_u64(u)
            } else if let Some(f) = n.as_f64() {
                visitor.visit_f64(f)
            } else {
                Err(RpslSerdeError(RpslError::Parse {
                    attribute: "serde".to_string(),
                    line: 0,
                    message: "unrepresentable json number".to_string(),
                }))
            }
        }
        serde_json::Value::String(s) => visitor.visit_string(s),
        serde_json::Value::Array(arr) => {
            let mut iter = arr.into_iter();
            let access = JsonSeqAccess {
                iter: &mut iter,
                _marker: std::marker::PhantomData,
            };
            visitor.visit_seq(access)
        }
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> =
                map.into_iter().collect();
            let mut idx = 0;
            let access = JsonMapAccess {
                entries: &mut entries,
                idx: &mut idx,
                _marker: std::marker::PhantomData,
            };
            visitor.visit_map(access)
        }
    }
}

/// Minimal `SeqAccess` over a `serde_json::Value` array iterator.
struct JsonSeqAccess<'a, I> {
    iter: &'a mut I,
    _marker: std::marker::PhantomData<()>,
}

impl<'a, 'de, I> de::SeqAccess<'de> for JsonSeqAccess<'a, I>
where
    I: Iterator<Item = serde_json::Value>,
{
    type Error = RpslSerdeError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: de::DeserializeSeed<'de>,
    {
        match self.iter.next() {
            Some(v) => {
                let d = RpslJsonValueDeserializer { value: v };
                Ok(Some(seed.deserialize(d)?))
            }
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        // We don't track exact size; serde handles `None` fine.
        None
    }
}

/// Minimal `MapAccess` over a slice of `(String, Value)` entries.
struct JsonMapAccess<'a> {
    entries: &'a mut Vec<(String, serde_json::Value)>,
    idx: &'a mut usize,
    _marker: std::marker::PhantomData<()>,
}

impl<'a, 'de> de::MapAccess<'de> for JsonMapAccess<'a> {
    type Error = RpslSerdeError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: de::DeserializeSeed<'de>,
    {
        if *self.idx >= self.entries.len() {
            return Ok(None);
        }
        let key = std::mem::take(&mut self.entries[*self.idx].0);
        Ok(Some(seed.deserialize(RpslJsonValueDeserializer {
            value: serde_json::Value::String(key),
        })?))
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: de::DeserializeSeed<'de>,
    {
        let value = std::mem::take(&mut self.entries[*self.idx].1);
        *self.idx += 1;
        seed.deserialize(RpslJsonValueDeserializer { value })
    }
}

/// A `Deserializer` backed by a single `serde_json::Value`, used to feed
/// individual sequence elements and map values back into serde's
/// `DeserializeSeed` machinery.
struct RpslJsonValueDeserializer {
    value: serde_json::Value,
}

impl<'de> SerdeDeserializer<'de> for RpslJsonValueDeserializer {
    type Error = RpslSerdeError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        drive_visitor_from_json(self.value, visitor)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq
        map enum identifier struct tuple_struct tuple ignored_any
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_document() {
        let input = "\
route: 192.0.2.0/24
origin: AS64500
mnt-by: MNT-TEST
source: RADB

route: 198.51.100.0/24
origin: AS64501
mnt-by: MNT-TEST
source: RADB
";
        let objs = parse(input).unwrap();
        assert_eq!(objs.len(), 2);
        assert!(matches!(objs[0], RpslObject::Route(_)));
        assert!(matches!(objs[1], RpslObject::Route(_)));
    }

    #[test]
    fn parse_one_object() {
        let input = "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: R\n";
        let obj = parse_one(input).unwrap();
        assert!(matches!(obj, RpslObject::Route(_)));
    }

    #[test]
    fn parse_one_rejects_multiple() {
        let input = "\
route: 192.0.2.0/24
origin: AS1
mnt-by: M
source: R

route: 198.51.100.0/24
origin: AS2
mnt-by: M
source: R
";
        assert!(parse_one(input).is_err());
    }

    #[test]
    fn parse_one_rejects_zero() {
        assert!(parse_one("").is_err());
    }

    #[test]
    fn unknown_class_rejected() {
        let input = "frobnicate: AS1\nsource: R\n";
        let objs = lex(input).unwrap();
        let err = parse_object(&objs[0]).unwrap_err();
        assert!(matches!(err, RpslError::UnknownClass(_)));
    }

    #[test]
    fn signed_object_detected() {
        let input = "\
route: 192.0.2.0/24
origin: AS1
mnt-by: M
source: R
uri: https://example.net/k
digest: abc
signature: def
";
        let obj = parse_one(input).unwrap();
        assert!(matches!(obj, RpslObject::Signed(_)));
    }

    #[test]
    fn serde_deserializer_round_trip() {
        use serde::Deserialize;
        let input = "route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: R\n";
        let obj = RpslObject::deserialize(RpslTextDeserializer::new(input)).unwrap();
        assert!(matches!(obj, RpslObject::Route(_)));
    }
}