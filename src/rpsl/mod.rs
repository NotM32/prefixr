//! RPSL (Routing Policy Specification Language) parser library.
//!
//! This crate implements a self-contained, dependency-light parser and
//! serializer for RPSL as defined by:
//!
//! * **RFC 2280** — RPSL base specification.
//! * **RFC 4012** — RPSLng: IPv6 and multicast extensions (`mp-*`
//!   attributes, `route6`, IPv6 prefixes, `afi` clauses).
//! * **RFC 7909** — Signed RPSL (parsing only; cryptographic verification
//!   is stubbed and requires a future `signed` cargo feature with a crypto
//!   crate).
//!
//! The crate exposes:
//!
//! * [`RpslObject`] — a tagged enum over all 13 implemented object
//!   classes.
//! * [`parse`] / [`parse_one`] — text → typed objects.
//! * [`serialize`] / [`serialize_many`] — typed objects → canonical text.
//! * A [`serde`] adapter ([`de::RpslTextDeserializer`],
//!   [`ser::RpslTextSerializer`]) for callers that prefer the serde API
//!   surface.
//!
//! # Example
//!
//! ```
//! use prefixify::rpsl::{parse_one, serialize};
//!
//! let text = "\
//! route: 192.0.2.0/24
//! origin: AS64500
//! mnt-by: MNT-TEST
//! source: RADB
//! ";
//! let obj = parse_one(text).unwrap();
//! let text2 = serialize(&obj);
//! // text2 round-trips back to the same typed object.
//! ```
//!
//! # Module layout
//!
//! | Module    | Responsibility |
//! |-----------|----------------|
//! | [`lex`]   | Text folding: line continuation, comments, blank-line separation. |
//! | [`common`]| Shared value types: `AsNumber`, `IpPrefix`, `PrefixRange`, ... |
//! | [`filter`]| RFC 2280 §6 / RFC 4012 §2.4 filter grammar AST + parser. |
//! | [`policy`]| `import:`/`export:`/`default:`/`mp-*` policy expressions. |
//! | [`object`]| The 13 object class structs + `RpslClass` trait. |
//! | [`signed`]| RFC 7909 signed-object envelope (parsing stubbed, verify stubbed). |
//! | [`de`]    | Text deserializer + serde `Deserializer` adapter. |
//! | [`ser`]    | Text serializer + serde `Serializer` adapter. |
//! | [`error`] | `RpslError` type. |

#![allow(dead_code, unused_imports)]

pub mod common;
pub mod de;
pub mod error;
pub mod filter;
pub mod lex;
pub mod object;
pub mod policy;
pub mod ser;
pub mod signed;

use serde::{Deserialize, Serialize};

pub use de::{RpslTextDeserializer, parse, parse_object, parse_one};
pub use error::{RpslError, RpslResult};
pub use lex::{RawAttribute, RawObject, lex};
pub use ser::{RpslTextSerializer, serialize, serialize_many, serialize_raw, serialize_raw_many};

pub use common::{
    AddressFamily, AsNumber, IpAddress, IpPrefix, MntnerRef, NicHandle, ObjectName, PrefixRange,
    RangeOperator, RpslPk, SetRef,
};
pub use object::{
    AsSet, AutNum, CommonMeta, FilterSet, InetRtr, KeyCert, Member, Mntner, PeeringSet, Person,
    Role, Route, Route6, RouteSet, RpslClass, RtrSet,
};
pub use signed::SignedRpsl;

/// The tagged union over all implemented RPSL object classes.
///
/// Every variant holds the fully-typed struct from [`object`] (or
/// [`signed`] for the RFC 7909 envelope). The enum implements
/// [`RpslObject::to_raw`] so the serializer can render any variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "object_class")]
pub enum RpslObject {
    /// `route` — IPv4 route registration (RFC 2280 §5.1).
    Route(Route),
    /// `route6` — IPv6 route registration (RFC 4012 §2.2).
    Route6(Route6),
    /// `aut-num` — AS number + routing policy (RFC 2280 §5.2).
    AutNum(AutNum),
    /// `as-set` — group of AS numbers / AS-sets (RFC 2280 §5.3).
    AsSet(AsSet),
    /// `route-set` — group of prefixes (RFC 2280 §5.4).
    RouteSet(RouteSet),
    /// `filter-set` — named filter expression (RFC 2280 §5.5).
    FilterSet(FilterSet),
    /// `peering-set` — named peering expression (RFC 2280 §5.6).
    PeeringSet(PeeringSet),
    /// `rtr-set` — group of routers (RFC 2280 §5.7).
    RtrSet(RtrSet),
    /// `inet-rtr` — router object (RFC 2280 §5.8).
    InetRtr(InetRtr),
    /// `mntner` — maintainer (RFC 2280 §5.9).
    Mntner(Mntner),
    /// `person` — contact person (RFC 2280 §5.10).
    Person(Person),
    /// `role` — contact role (RFC 2280 §5.11).
    Role(Role),
    /// `key-cert` — PGP key certificate (RFC 2280 §5.12).
    KeyCert(KeyCert),
    /// RFC 7909 signed envelope wrapping any of the above. Verification
    /// is stubbed ([`SignedRpsl::verify`] returns
    /// [`RpslError::SignedNotVerified`]).
    Signed(Box<SignedRpsl>),
}

impl RpslObject {
    /// Render this object back into a [`RawObject`] suitable for the text
    /// serializer. This dispatches to the per-class `to_raw` impl, with a
    /// special case for the [`Signed`] variant which appends the RFC 7909
    /// envelope attributes.
    ///
    /// [`Signed`]: RpslObject::Signed
    pub fn to_raw(&self) -> RawObject {
        match self {
            Self::Route(o) => o.to_raw(),
            Self::Route6(o) => o.to_raw(),
            Self::AutNum(o) => o.to_raw(),
            Self::AsSet(o) => o.to_raw(),
            Self::RouteSet(o) => o.to_raw(),
            Self::FilterSet(o) => o.to_raw(),
            Self::PeeringSet(o) => o.to_raw(),
            Self::RtrSet(o) => o.to_raw(),
            Self::InetRtr(o) => o.to_raw(),
            Self::Mntner(o) => o.to_raw(),
            Self::Person(o) => o.to_raw(),
            Self::Role(o) => o.to_raw(),
            Self::KeyCert(o) => o.to_raw(),
            Self::Signed(s) => s.to_raw(),
        }
    }

    /// Returns the canonical lowercased class name for this object.
    pub fn class_name(&self) -> &'static str {
        match self {
            Self::Route(_) => Route::class_name(),
            Self::Route6(_) => Route6::class_name(),
            Self::AutNum(_) => AutNum::class_name(),
            Self::AsSet(_) => AsSet::class_name(),
            Self::RouteSet(_) => RouteSet::class_name(),
            Self::FilterSet(_) => FilterSet::class_name(),
            Self::PeeringSet(_) => PeeringSet::class_name(),
            Self::RtrSet(_) => RtrSet::class_name(),
            Self::InetRtr(_) => InetRtr::class_name(),
            Self::Mntner(_) => Mntner::class_name(),
            Self::Person(_) => Person::class_name(),
            Self::Role(_) => Role::class_name(),
            Self::KeyCert(_) => KeyCert::class_name(),
            Self::Signed(_) => "signed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RPSL_ASN: &str = "aut-num:        AS14061
as-name:        DIGITALOCEAN
descr:          DigitalOcean
member-of:      AS-14061
admin-c:        NOC32014-ARIN
tech-c:         NOC32014-ARIN
mnt-by:         MNT-DO-13
source:         ARIN

aut-num:        AS14061
as-name:        DIGITALOCEAN
descr:          DigitalOcean, LLC.
member-of:      AS-62567
import:         from AS-ANY   accept ANY
export:         to AS-ANY   announce AS-14061 AND NOT {0.0.0.0/0}
admin-c:        DigitalOcean NOC
tech-c:         DigitalOcean NOC
remarks:        Please report abuse at https://www.digitalocean.com/company/contact/
mnt-by:         MAINT-AS14061
changed:        ngeyer@digitalocean.com 20210913
source:         RADB
";

    #[test]
    fn parse_full_fixture() {
        let objs = parse(RPSL_ASN).unwrap();
        assert_eq!(objs.len(), 2);
        assert!(matches!(objs[0], RpslObject::AutNum(_)));
        assert!(matches!(objs[1], RpslObject::AutNum(_)));
    }

    #[test]
    fn round_trip_full_fixture() {
        let objs = parse(RPSL_ASN).unwrap();
        let text = serialize_many(&objs);
        let objs2 = parse(&text).unwrap();
        assert_eq!(objs, objs2);
    }

    #[test]
    fn class_name_dispatch() {
        let obj = parse_one("route: 192.0.2.0/24\norigin: AS1\nmnt-by: M\nsource: R\n").unwrap();
        assert_eq!(obj.class_name(), "route");
    }
}
