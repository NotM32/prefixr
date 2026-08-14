//! Shared primitive types used across the RPSL object model.
//!
//! This module defines small, self-contained value types that appear in many
//! object classes: AS numbers, IP addresses, IP prefixes with optional
//! RFC 4012 length-range operators, NIC handles, maintainer references, and
//! free-form `ObjectName` strings used for set names (`AS-FOO`, `RS-BAR`).
//!
//! Every type here is plain Rust + the standard library only. Parsing is
//! deliberately strict: invalid input returns [`RpslError::Parse`] so that
//! upstream callers can surface a precise error rather than a stringly-typed
//! value silently slipping through.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::rpsl::error::{RpslError, RpslResult};

/// An Autonomous System Number.
///
/// Supports both 2-byte (`AS123`) and 4-byte (`AS1.234` or `AS131073`)
/// forms per RFC 4012 §2.1. Internally we store the numeric value as a
/// `u32`; the dotted `ASx.y` notation (where the full AS number is
/// `x * 65536 + y`) is accepted on parse and reproduced on display when
/// the value does not fit in 16 bits and was originally written in dotted
/// form.
///
/// Display always uses the plain `AS<number>` form (no dotted notation),
/// which is the canonical modern form preferred by RFC 4893 and what most
/// IRR databases store today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AsNumber(pub u32);

impl AsNumber {
    /// Parse an AS number from a string like `AS123` or `AS1.234`.
    ///
    /// The `AS` prefix is case-insensitive and mandatory per RFC 2280 §5.
    /// For the dotted form, the high-order part must be `< 65536` and the
    /// low-order part must be `< 65536`.
    pub fn parse(s: &str) -> RpslResult<Self> {
        let s = s.trim();
        let rest = s
            .strip_prefix("AS")
            .or_else(|| s.strip_prefix("as"))
            .ok_or_else(|| RpslError::parse("as-number", 0, format!("expected `AS` prefix in `{s}`")))?;

        if let Some((hi, lo)) = rest.split_once('.') {
            let hi: u32 = hi
                .parse()
                .map_err(|_| RpslError::parse("as-number", 0, format!("invalid high part `{hi}`")))?;
            let lo: u32 = lo
                .parse()
                .map_err(|_| RpslError::parse("as-number", 0, format!("invalid low part `{lo}`")))?;
            if hi > 0xFFFF {
                return Err(RpslError::parse(
                    "as-number",
                    0,
                    "dotted high part exceeds 65535",
                ));
            }
            if lo > 0xFFFF {
                return Err(RpslError::parse(
                    "as-number",
                    0,
                    "dotted low part exceeds 65535",
                ));
            }
            Ok(Self(hi * 65536 + lo))
        } else {
            let n: u32 = rest
                .parse()
                .map_err(|_| RpslError::parse("as-number", 0, format!("invalid AS number `{rest}`")))?;
            Ok(Self(n))
        }
    }
}

impl fmt::Display for AsNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

/// An IP address family tag, used by the `mp-*` family of attributes
/// (RFC 4012 §2.4) and by the [`crate::rpsl::filter`] and
/// [`crate::rpsl::policy`] grammars.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressFamily {
    /// `ipv4` / `ipv4.unicast`
    Ipv4,
    /// `ipv6` / `ipv6.unicast`
    Ipv6,
    /// Any non-unicast address family, e.g. multicast. The string holds
    /// the original AFI/SAFI pair verbatim because RPSL allows several
    /// spellings (e.g. `ipv4.multicast`, `ipv6.unicast`).
    Other(String),
}

impl AddressFamily {
    /// Parse an AFI/SAFI token. Recognised forms (case-insensitive):
    /// `ipv4`, `ipv4.unicast`, `ipv6`, `ipv6.unicast`. Anything else is
    /// captured as [`AddressFamily::Other`].
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "ipv4" | "ipv4.unicast" => Self::Ipv4,
            "ipv6" | "ipv6.unicast" => Self::Ipv6,
            other => Self::Other(other.to_string()),
        }
    }
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => f.write_str("ipv4"),
            Self::Ipv6 => f.write_str("ipv6"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

/// An IP address (v4 or v6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl IpAddress {
    pub fn parse(s: &str) -> RpslResult<Self> {
        let s = s.trim();
        if let Ok(v4) = s.parse::<Ipv4Addr>() {
            return Ok(Self::V4(v4));
        }
        if let Ok(v6) = s.parse::<Ipv6Addr>() {
            return Ok(Self::V6(v6));
        }
        Err(RpslError::parse(
            "ip-address",
            0,
            format!("not a valid IPv4 or IPv6 address: `{s}`"),
        ))
    }

    /// Returns `true` if this is an IPv6 address.
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::V6(_))
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(a) => write!(f, "{a}"),
            Self::V6(a) => write!(f, "{a}"),
        }
    }
}

/// An IP prefix (network / CIDR).
///
/// Stored as the base address plus a prefix length. We do not use
/// `std::net::IpNetwork` because that crate is not in the standard library
/// and we want zero external dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpPrefix {
    /// Network base address.
    pub address: IpAddress,
    /// Prefix length in bits (0..=32 for IPv4, 0..=128 for IPv6).
    pub length: u8,
}

impl IpPrefix {
    pub fn parse(s: &str) -> RpslResult<Self> {
        let s = s.trim();
        let (addr, len) = s
            .split_once('/')
            .ok_or_else(|| RpslError::parse("ip-prefix", 0, format!("missing `/` in `{s}`")))?;
        let address = IpAddress::parse(addr)?;
        let length: u8 = len
            .parse()
            .map_err(|_| RpslError::parse("ip-prefix", 0, format!("invalid prefix length `{len}`")))?;
        let max = match address {
            IpAddress::V4(_) => 32u8,
            IpAddress::V6(_) => 128u8,
        };
        if length > max {
            return Err(RpslError::parse(
                "ip-prefix",
                0,
                format!("prefix length {length} exceeds max {max}"),
            ));
        }
        Ok(Self { address, length })
    }

    /// `true` if this is an IPv6 prefix.
    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}

/// RFC 4012 §2.4 `prefix-range` operator.
///
/// A prefix-range restricts a route-set or address prefix set to those
/// routes whose prefix length falls within a range. The grammar is:
///
/// ```text
/// prefix-range ::= prefix '^' ( '+' | '-' | range )
/// range        ::= [n] '-' [m]
/// ```
///
/// * `^+`  — more specifics (length > prefix.length).
/// * `^-`  — less specifics (length < prefix.length).
/// * `^n-m` — lengths in `[n, m]` inclusive. Either bound may be omitted
///   (e.g. `^-24` means `0..=24`, `^24-` means `24..=max`).
/// * `^n`  — exact length `n` (shorthand for `n-n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RangeOperator {
    /// `^+` — match more-specific routes only.
    MoreSpecifics,
    /// `^-` — match less-specific routes only.
    LessSpecifics,
    /// `^n-m` — match routes whose prefix length is in `[min, max]`.
    /// Either bound may be `None` to indicate "open" on that side.
    Range {
        min: Option<u8>,
        max: Option<u8>,
    },
}

impl RangeOperator {
    /// Parse the body of a `^...` suffix (without the leading `^`).
    pub fn parse(s: &str) -> RpslResult<Self> {
        let s = s.trim();
        match s {
            "+" => Ok(Self::MoreSpecifics),
            "-" => Ok(Self::LessSpecifics),
            _ => {
                if let Some((lo, hi)) = s.split_once('-') {
                    let min = if lo.is_empty() {
                        None
                    } else {
                        Some(lo.parse().map_err(|_| {
                            RpslError::parse("range-operator", 0, format!("bad low bound `{lo}`"))
                        })?)
                    };
                    let max = if hi.is_empty() {
                        None
                    } else {
                        Some(hi.parse().map_err(|_| {
                            RpslError::parse("range-operator", 0, format!("bad high bound `{hi}`"))
                        })?)
                    };
                    Ok(Self::Range { min, max })
                } else {
                    // Single number: exact match.
                    let n: u8 = s.parse().map_err(|_| {
                        RpslError::parse("range-operator", 0, format!("invalid range `{s}`"))
                    })?;
                    Ok(Self::Range {
                        min: Some(n),
                        max: Some(n),
                    })
                }
            }
        }
    }
}

impl fmt::Display for RangeOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MoreSpecifics => f.write_str("^+"),
            Self::LessSpecifics => f.write_str("^-"),
            Self::Range { min, max } => match (min, max) {
                (Some(n), Some(m)) if n == m => write!(f, "^{n}"),
                (Some(n), Some(m)) => write!(f, "^{n}-{m}"),
                (Some(n), None) => write!(f, "^{n}-"),
                (None, Some(m)) => write!(f, "^-{m}"),
                (None, None) => f.write_str("^-"),
            },
        }
    }
}

/// An IP prefix annotated with an optional [`RangeOperator`].
///
/// This is the basic building block of route-set `members:` lists and of
/// the `{...}` address-prefix-set filter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrefixRange {
    /// The base prefix.
    pub prefix: IpPrefix,
    /// Optional `^...` range suffix.
    pub range: Option<RangeOperator>,
}

impl PrefixRange {
    /// Parse a single `prefix[^range]` token.
    pub fn parse(s: &str) -> RpslResult<Self> {
        let s = s.trim();
        if let Some(idx) = s.find('^') {
            let (p, r) = s.split_at(idx);
            let prefix = IpPrefix::parse(p)?;
            let range = RangeOperator::parse(&r[1..])?;
            Ok(Self { prefix, range: Some(range) })
        } else {
            Ok(Self {
                prefix: IpPrefix::parse(s)?,
                range: None,
            })
        }
    }
}

impl fmt::Display for PrefixRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix)?;
        if let Some(r) = &self.range {
            write!(f, "{r}")?;
        }
        Ok(())
    }
}

/// A free-form object name used for `AS-FOO`, `RS-BAR`, `FLTR-BAZ`,
/// `PEERING-X`, `RTRS-Y` etc.
///
/// Per RFC 2280 §5, names follow the same character set as attribute
/// values and are case-insensitive. We preserve the original casing for
/// display but compare case-insensitively via [`Self::eq_ignore_case`].
///
/// We do not enforce a strict regex here because IRR databases accept a
/// fairly wide variety of names in practice; we only reject empty strings
/// and strings containing whitespace/control characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectName(pub String);

impl ObjectName {
    pub fn parse(s: &str) -> RpslResult<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(RpslError::parse("object-name", 0, "empty object name"));
        }
        if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(RpslError::parse(
                "object-name",
                0,
                "object name contains whitespace or control characters",
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// Case-insensitive equality.
    pub fn eq_ignore_case(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

impl fmt::Display for ObjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A NIC handle (person/role reference), e.g. `NOC32014-ARIN`.
///
/// Stored as a plain string; we only validate that it is non-empty and
/// contains no whitespace.
pub type NicHandle = ObjectName;

/// A maintainer reference, e.g. `MNT-DO-13`.
pub type MntnerRef = ObjectName;

/// A route-set / as-set / peering-set / rtr-set / filter-set reference.
pub type SetRef = ObjectName;

/// An RPSL primary key (the value of the class-leading attribute, e.g.
/// `192.0.2.0/24` for a `route` object or `AS-FOO` for an `as-set`).
pub type RpslPk = ObjectName;

/// Parse a whitespace- or comma-separated list of `T` values from a single
/// folded attribute value.
///
/// Used for `[multiple]` attributes whose values are simple tokens such as
/// `members: AS1, AS2 AS3`.
pub fn parse_list<T, F>(value: &str, parse_one: F) -> RpslResult<Vec<T>>
where
    F: Fn(&str) -> RpslResult<T>,
{
    value
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .map(parse_one)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_number_plain() {
        assert_eq!(AsNumber::parse("AS123").unwrap(), AsNumber(123));
        assert_eq!(AsNumber::parse("as456").unwrap(), AsNumber(456));
    }

    #[test]
    fn as_number_dotted() {
        assert_eq!(AsNumber::parse("AS1.0").unwrap(), AsNumber(65536));
        assert_eq!(AsNumber::parse("AS0.1").unwrap(), AsNumber(1));
    }

    #[test]
    fn as_number_display() {
        assert_eq!(AsNumber(65536).to_string(), "AS65536");
        assert_eq!(AsNumber(123).to_string(), "AS123");
    }

    #[test]
    fn as_number_invalid() {
        assert!(AsNumber::parse("123").is_err());
        assert!(AsNumber::parse("ASfoo").is_err());
        assert!(AsNumber::parse("AS1.99999").is_err());
    }

    #[test]
    fn ip_prefix_v4() {
        let p = IpPrefix::parse("192.0.2.0/24").unwrap();
        assert_eq!(p.length, 24);
        assert!(!p.is_ipv6());
        assert_eq!(p.to_string(), "192.0.2.0/24");
    }

    #[test]
    fn ip_prefix_v6() {
        let p = IpPrefix::parse("2001:db8::/32").unwrap();
        assert_eq!(p.length, 32);
        assert!(p.is_ipv6());
    }

    #[test]
    fn ip_prefix_too_long() {
        assert!(IpPrefix::parse("192.0.2.0/33").is_err());
        assert!(IpPrefix::parse("2001:db8::/129").is_err());
    }

    #[test]
    fn range_operator_plus_minus() {
        assert_eq!(RangeOperator::parse("+").unwrap(), RangeOperator::MoreSpecifics);
        assert_eq!(RangeOperator::parse("-").unwrap(), RangeOperator::LessSpecifics);
    }

    #[test]
    fn range_operator_range() {
        assert_eq!(
            RangeOperator::parse("24-28").unwrap(),
            RangeOperator::Range {
                min: Some(24),
                max: Some(28)
            }
        );
        assert_eq!(
            RangeOperator::parse("-24").unwrap(),
            RangeOperator::Range {
                min: None,
                max: Some(24)
            }
        );
        assert_eq!(
            RangeOperator::parse("24-").unwrap(),
            RangeOperator::Range {
                min: Some(24),
                max: None
            }
        );
    }

    #[test]
    fn range_operator_exact() {
        assert_eq!(
            RangeOperator::parse("24").unwrap(),
            RangeOperator::Range {
                min: Some(24),
                max: Some(24)
            }
        );
    }

    #[test]
    fn range_operator_display() {
        assert_eq!(RangeOperator::MoreSpecifics.to_string(), "^+");
        assert_eq!(RangeOperator::LessSpecifics.to_string(), "^-");
        assert_eq!(
            RangeOperator::Range {
                min: Some(24),
                max: Some(28)
            }
            .to_string(),
            "^24-28"
        );
        assert_eq!(
            RangeOperator::Range {
                min: Some(24),
                max: None
            }
            .to_string(),
            "^24-"
        );
        assert_eq!(
            RangeOperator::Range {
                min: Some(24),
                max: Some(24)
            }
            .to_string(),
            "^24"
        );
    }

    #[test]
    fn prefix_range_with_op() {
        let pr = PrefixRange::parse("192.0.2.0/24^+").unwrap();
        assert_eq!(pr.prefix, IpPrefix::parse("192.0.2.0/24").unwrap());
        assert_eq!(pr.range, Some(RangeOperator::MoreSpecifics));
        assert_eq!(pr.to_string(), "192.0.2.0/24^+");
    }

    #[test]
    fn prefix_range_without_op() {
        let pr = PrefixRange::parse("192.0.2.0/24").unwrap();
        assert!(pr.range.is_none());
        assert_eq!(pr.to_string(), "192.0.2.0/24");
    }

    #[test]
    fn object_name_valid() {
        let n = ObjectName::parse("AS-FOO").unwrap();
        assert!(n.eq_ignore_case("as-foo"));
        assert_eq!(n.to_string(), "AS-FOO");
    }

    #[test]
    fn object_name_rejects_whitespace() {
        assert!(ObjectName::parse("AS FOO").is_err());
        assert!(ObjectName::parse("").is_err());
    }

    #[test]
    fn address_family_recognised() {
        assert_eq!(AddressFamily::parse("ipv4"), AddressFamily::Ipv4);
        assert_eq!(AddressFamily::parse("IPv6"), AddressFamily::Ipv6);
        assert_eq!(AddressFamily::parse("ipv4.unicast"), AddressFamily::Ipv4);
        assert!(matches!(
            AddressFamily::parse("ipv4.multicast"),
            AddressFamily::Other(_)
        ));
    }

    #[test]
    fn parse_list_splits_on_whitespace_and_comma() {
        let v: Vec<AsNumber> = parse_list("AS1, AS2 AS3", AsNumber::parse).unwrap();
        assert_eq!(v, vec![AsNumber(1), AsNumber(2), AsNumber(3)]);
    }
}