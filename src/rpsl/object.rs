//! RPSL object classes — the typed structs produced by the deserializer.
//!
//! Each object class defined in RFC 2280 / RFC 4012 / RADb has a struct
//! here. Every struct implements [`RpslClass`], which provides:
//!
//! * `class_name()` — the canonical lowercased class name (`route`, ...).
//! * `from_raw(&RawObject)` — parse a folded object into the typed struct,
//!   validating mandatory fields and parsing typed values (AS numbers,
//!   filters, policy expressions, ...).
//! * `to_raw(&self)` — the inverse, used by the serializer.
//! * `validate(&self)` — additional cross-field checks beyond the
//!   mandatory/optional ones done in `from_raw`.
//!
//! The mandatory/optional and single/multiple flags for each attribute
//! come from the schema published by RADb
//! (`whois -h whois.radb.net -t <class>`), which is the most
//! standards-adherent IRR implementation. We encode that schema as static
//! tables in [`AttrSpec`] and use them for validation.

use serde::{Deserialize, Serialize};

use crate::rpsl::common::{
    AsNumber, IpPrefix, MntnerRef, NicHandle, PrefixRange, RpslPk, SetRef,
};
use crate::rpsl::error::{RpslError, RpslResult};
use crate::rpsl::filter::Filter;
use crate::rpsl::lex::{RawAttribute, RawObject};
use crate::rpsl::policy::{
    parse_default, parse_export, parse_import, parse_mp_default, parse_mp_export, parse_mp_import,
    parse_peering, DefaultPolicy, ExportPolicy, ImportPolicy, MpDefaultPolicy, MpExportPolicy,
    MpImportPolicy, Peering,
};

// ----------------------------------------------------------------------
// Trait + helpers
// ----------------------------------------------------------------------

/// Trait implemented by every RPSL object class struct.
pub trait RpslClass: Sized {
    /// Canonical lowercased class name, e.g. `route`, `aut-num`.
    fn class_name() -> &'static str;

    /// Build a typed instance from a folded [`RawObject`].
    ///
    /// Implementations must:
    /// 1. Verify `raw.class()` matches [`Self::class_name`].
    /// 2. Check every mandatory attribute is present.
    /// 3. Check every `[single]` attribute appears at most once.
    /// 4. Parse each attribute's value into the appropriate typed form.
    fn from_raw(raw: &RawObject) -> RpslResult<Self>;

    /// Render back into a [`RawObject`] suitable for the text serializer.
    fn to_raw(&self) -> RawObject;

    /// Optional post-parse validation. The default implementation is a no-op.
    fn validate(&self) -> RpslResult<()> {
        Ok(())
    }
}

/// Description of a single attribute within a class schema.
#[derive(Debug, Clone, Copy)]
struct AttrSpec {
    name: &'static str,
    mandatory: bool,
    multiple: bool,
}

/// Helper: enforce mandatory and single-valued constraints on a raw object.
fn check_schema(raw: &RawObject, class: &str, specs: &[AttrSpec]) -> RpslResult<()> {
    for s in specs {
        let count = raw.count(s.name);
        if s.mandatory && count == 0 {
            return Err(RpslError::missing_mandatory(class, s.name));
        }
        if !s.multiple && count > 1 {
            return Err(RpslError::DuplicateSingle {
                class: class.to_string(),
                attribute: s.name.to_string(),
                count,
            });
        }
    }
    Ok(())
}

/// Helper: extract a single-valued attribute as a `String` (or `None`).
fn get_single(raw: &RawObject, name: &str) -> Option<String> {
    raw.first(name).map(|s| s.to_string())
}

/// Helper: extract a multi-valued attribute as `Vec<String>`.
fn get_multi(raw: &RawObject, name: &str) -> Vec<String> {
    raw.all(name).map(|s| s.to_string()).collect()
}

/// Helper: extract a multi-valued attribute where each line may itself be
/// a whitespace/comma-separated list, and parse every element with `parse`.
/// Returns a flat `Vec<T>`.
fn get_multi_parsed<T, F>(raw: &RawObject, name: &str, parse: F) -> RpslResult<Vec<T>>
where
    F: Fn(&str) -> RpslResult<T>,
{
    let mut out = Vec::new();
    for s in raw.all(name) {
        for tok in s.split(|c: char| c.is_whitespace() || c == ',') {
            if !tok.is_empty() {
                out.push(parse(tok)?);
            }
        }
    }
    Ok(out)
}

/// Helper: extract a multi-valued attribute where each line may itself be
/// a whitespace/comma-separated list, and parse every element with `parse`,
/// silently dropping unparseable tokens (used for `CommonMeta` references
/// where we want to be lenient).
fn get_multi_parsed_lenient<T, F>(raw: &RawObject, name: &str, parse: F) -> Vec<T>
where
    F: Fn(&str) -> RpslResult<T>,
{
    let mut out = Vec::new();
    for s in raw.all(name) {
        for tok in s.split(|c: char| c.is_whitespace() || c == ',') {
            if !tok.is_empty()
                && let Ok(v) = parse(tok) {
                    out.push(v);
                }
        }
    }
    out
}

/// Helper: push an attribute into a [`RawObject`] builder.
fn push(raw: &mut RawObject, name: &str, value: &str) {
    raw.attributes.push(RawAttribute {
        name: name.to_string(),
        value: value.to_string(),
        lines: vec![],
    });
}

/// Helper: push a multi-valued attribute (one line per value).
fn push_multi(raw: &mut RawObject, name: &str, values: &[String]) {
    for v in values {
        push(raw, name, v);
    }
}

/// Helper: push an optional single-valued attribute only if `Some`.
fn push_opt(raw: &mut RawObject, name: &str, value: &Option<String>) {
    if let Some(v) = value {
        push(raw, name, v);
    }
}

// ----------------------------------------------------------------------
// Common metadata block present in almost every class
// ----------------------------------------------------------------------

/// The common "tail" attributes that appear in every RPSL object:
/// `admin-c`, `tech-c`, `remarks`, `notify`, `mnt-by`, `changed`, `source`.
///
/// This is not itself an RPSL class; it is embedded by value in each class
/// struct to avoid repeating the same fields 13 times.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonMeta {
    /// `admin-c:` — administrative contact NIC handles (optional or
    /// mandatory depending on class).
    pub admin_c: Vec<NicHandle>,
    /// `tech-c:` — technical contact NIC handles.
    pub tech_c: Vec<NicHandle>,
    /// `remarks:` — free-form remarks.
    pub remarks: Vec<String>,
    /// `notify:` — email addresses to notify on changes.
    pub notify: Vec<String>,
    /// `mnt-by:` — maintainer references. Mandatory in most classes.
    pub mnt_by: Vec<MntnerRef>,
    /// `changed:` — change log entries (deprecated in modern IRR but still
    /// present in RADb).
    pub changed: Vec<String>,
    /// `source:` — the IRR database this object lives in. Mandatory,
    /// single-valued.
    pub source: String,
}

impl CommonMeta {
    /// Pull the common tail out of a [`RawObject`]. Multi-valued reference
    /// attributes (`admin-c`, `tech-c`, `mnt-by`) are split on whitespace
    /// and commas because IRR databases sometimes pack multiple values on
    /// a single line. Unparseable tokens are silently dropped to match the
    /// lenient behaviour of real IRR databases.
    fn from_raw(raw: &RawObject) -> Self {
        Self {
            admin_c: get_multi_parsed_lenient(raw, "admin-c", NicHandle::parse),
            tech_c: get_multi_parsed_lenient(raw, "tech-c", NicHandle::parse),
            remarks: get_multi(raw, "remarks"),
            notify: get_multi(raw, "notify"),
            mnt_by: get_multi_parsed_lenient(raw, "mnt-by", MntnerRef::parse),
            changed: get_multi(raw, "changed"),
            source: get_single(raw, "source").unwrap_or_default(),
        }
    }

    /// Render the common tail into a [`RawObject`] builder. Attributes are
    /// pushed in the conventional order used by RADb.
    fn to_raw(&self, raw: &mut RawObject) {
        for c in &self.admin_c {
            push(raw, "admin-c", &c.to_string());
        }
        for c in &self.tech_c {
            push(raw, "tech-c", &c.to_string());
        }
        for r in &self.remarks {
            push(raw, "remarks", r);
        }
        for n in &self.notify {
            push(raw, "notify", n);
        }
        for m in &self.mnt_by {
            push(raw, "mnt-by", &m.to_string());
        }
        for c in &self.changed {
            push(raw, "changed", c);
        }
        if !self.source.is_empty() {
            push(raw, "source", &self.source);
        }
    }
}

// ----------------------------------------------------------------------
// route / route6
// ----------------------------------------------------------------------

/// `route` object (RFC 2280 §5.1). Represents an IPv4 route registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// `route:` — the IPv4 prefix, primary key.
    pub route: IpPrefix,
    /// `descr:` — free-form description.
    pub descr: Vec<String>,
    /// `origin:` — the originating AS. Mandatory, single-valued.
    pub origin: AsNumber,
    /// `holes:` — sub-prefixes that are delegated elsewhere.
    pub holes: Vec<IpPrefix>,
    /// `member-of:` — route-set references.
    pub member_of: Vec<SetRef>,
    /// `inject:` — injection policy (kept verbatim, advanced grammar).
    pub inject: Vec<String>,
    /// `aggr-bndry:` — aggregation boundary.
    pub aggr_bndry: Option<String>,
    /// `aggr-mtd:` — aggregation method.
    pub aggr_mtd: Option<String>,
    /// `export-comps:` — export components filter.
    pub export_comps: Option<Filter>,
    /// `components:` — components filter.
    pub components: Option<Filter>,
    /// `geoidx:` — geographic index entries.
    pub geoidx: Vec<String>,
    /// `roa-uri:` — ROA URI (RFC 9232 / RADb extension).
    pub roa_uri: Option<String>,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for Route {
    fn class_name() -> &'static str {
        "route"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "route";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "route", mandatory: true, multiple: false },
                AttrSpec { name: "origin", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "holes", mandatory: false, multiple: true },
                AttrSpec { name: "member-of", mandatory: false, multiple: true },
                AttrSpec { name: "inject", mandatory: false, multiple: true },
                AttrSpec { name: "aggr-bndry", mandatory: false, multiple: false },
                AttrSpec { name: "aggr-mtd", mandatory: false, multiple: false },
                AttrSpec { name: "export-comps", mandatory: false, multiple: false },
                AttrSpec { name: "components", mandatory: false, multiple: false },
                AttrSpec { name: "geoidx", mandatory: false, multiple: true },
                AttrSpec { name: "roa-uri", mandatory: false, multiple: false },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let route = IpPrefix::parse(raw.first("route").ok_or_else(|| RpslError::missing_mandatory(CLASS, "route"))?)?;
        let origin = AsNumber::parse(raw.first("origin").ok_or_else(|| RpslError::missing_mandatory(CLASS, "origin"))?)?;
        let common = CommonMeta::from_raw(raw);
        Ok(Self {
            route,
            descr: get_multi(raw, "descr"),
            origin,
            holes: get_multi_parsed(raw, "holes", IpPrefix::parse)?,
            member_of: get_multi_parsed(raw, "member-of", SetRef::parse)?,
            inject: get_multi(raw, "inject"),
            aggr_bndry: get_single(raw, "aggr-bndry"),
            aggr_mtd: get_single(raw, "aggr-mtd"),
            export_comps: get_single(raw, "export-comps")
                .map(|s| Filter::parse(&s))
                .transpose()?,
            components: get_single(raw, "components")
                .map(|s| Filter::parse(&s))
                .transpose()?,
            geoidx: get_multi(raw, "geoidx"),
            roa_uri: get_single(raw, "roa-uri"),
            common,
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "route", &self.route.to_string());
        push_multi(&mut raw, "descr", &self.descr);
        push(&mut raw, "origin", &self.origin.to_string());
        push_multi(
            &mut raw,
            "holes",
            &self.holes.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
        );
        push_multi(
            &mut raw,
            "member-of",
            &self.member_of.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        );
        push_multi(&mut raw, "inject", &self.inject);
        push_opt(&mut raw, "aggr-bndry", &self.aggr_bndry);
        push_opt(&mut raw, "aggr-mtd", &self.aggr_mtd);
        if let Some(f) = &self.export_comps {
            push(&mut raw, "export-comps", &f.to_string());
        }
        if let Some(f) = &self.components {
            push(&mut raw, "components", &f.to_string());
        }
        push_multi(&mut raw, "geoidx", &self.geoidx);
        push_opt(&mut raw, "roa-uri", &self.roa_uri);
        self.common.to_raw(&mut raw);
        raw
    }
}

/// `route6` object (RFC 4012 §2.2) — IPv6 equivalent of [`Route`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route6 {
    /// `route6:` — the IPv6 prefix, primary key.
    pub route6: IpPrefix,
    /// `descr:`
    pub descr: Vec<String>,
    /// `origin:` — originating AS.
    pub origin: AsNumber,
    /// `holes:`
    pub holes: Vec<IpPrefix>,
    /// `member-of:`
    pub member_of: Vec<SetRef>,
    /// `inject:`
    pub inject: Vec<String>,
    /// `aggr-bndry:`
    pub aggr_bndry: Option<String>,
    /// `aggr-mtd:`
    pub aggr_mtd: Option<String>,
    /// `export-comps:`
    pub export_comps: Option<Filter>,
    /// `components:`
    pub components: Option<Filter>,
    /// `geoidx:`
    pub geoidx: Vec<String>,
    /// `roa-uri:`
    pub roa_uri: Option<String>,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for Route6 {
    fn class_name() -> &'static str {
        "route6"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "route6";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "route6", mandatory: true, multiple: false },
                AttrSpec { name: "origin", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "holes", mandatory: false, multiple: true },
                AttrSpec { name: "member-of", mandatory: false, multiple: true },
                AttrSpec { name: "inject", mandatory: false, multiple: true },
                AttrSpec { name: "aggr-bndry", mandatory: false, multiple: false },
                AttrSpec { name: "aggr-mtd", mandatory: false, multiple: false },
                AttrSpec { name: "export-comps", mandatory: false, multiple: false },
                AttrSpec { name: "components", mandatory: false, multiple: false },
                AttrSpec { name: "geoidx", mandatory: false, multiple: true },
                AttrSpec { name: "roa-uri", mandatory: false, multiple: false },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let route6 = IpPrefix::parse(raw.first("route6").ok_or_else(|| RpslError::missing_mandatory(CLASS, "route6"))?)?;
        if !route6.is_ipv6() {
            return Err(RpslError::parse("route6", 0, "route6 attribute must be an IPv6 prefix"));
        }
        let origin = AsNumber::parse(raw.first("origin").ok_or_else(|| RpslError::missing_mandatory(CLASS, "origin"))?)?;
        Ok(Self {
            route6,
            descr: get_multi(raw, "descr"),
            origin,
            holes: get_multi_parsed(raw, "holes", IpPrefix::parse)?,
            member_of: get_multi_parsed(raw, "member-of", SetRef::parse)?,
            inject: get_multi(raw, "inject"),
            aggr_bndry: get_single(raw, "aggr-bndry"),
            aggr_mtd: get_single(raw, "aggr-mtd"),
            export_comps: get_single(raw, "export-comps").map(|s| Filter::parse(&s)).transpose()?,
            components: get_single(raw, "components").map(|s| Filter::parse(&s)).transpose()?,
            geoidx: get_multi(raw, "geoidx"),
            roa_uri: get_single(raw, "roa-uri"),
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "route6", &self.route6.to_string());
        push_multi(&mut raw, "descr", &self.descr);
        push(&mut raw, "origin", &self.origin.to_string());
        push_multi(&mut raw, "holes", &self.holes.iter().map(|p| p.to_string()).collect::<Vec<_>>());
        push_multi(&mut raw, "member-of", &self.member_of.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        push_multi(&mut raw, "inject", &self.inject);
        push_opt(&mut raw, "aggr-bndry", &self.aggr_bndry);
        push_opt(&mut raw, "aggr-mtd", &self.aggr_mtd);
        if let Some(f) = &self.export_comps {
            push(&mut raw, "export-comps", &f.to_string());
        }
        if let Some(f) = &self.components {
            push(&mut raw, "components", &f.to_string());
        }
        push_multi(&mut raw, "geoidx", &self.geoidx);
        push_opt(&mut raw, "roa-uri", &self.roa_uri);
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// aut-num
// ----------------------------------------------------------------------

/// `aut-num` object (RFC 2280 §5.2). The central object carrying an AS's
/// import/export/default policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutNum {
    /// `aut-num:` — the AS number, primary key.
    pub aut_num: AsNumber,
    /// `as-name:` — a symbolic name. Mandatory, single-valued.
    pub as_name: String,
    /// `descr:`
    pub descr: Vec<String>,
    /// `member-of:` — AS-set references.
    pub member_of: Vec<SetRef>,
    /// `import:` lines, in source order.
    pub import: Vec<ImportPolicy>,
    /// `mp-import:` lines (RFC 4012).
    pub mp_import: Vec<MpImportPolicy>,
    /// `import-via:` lines (RFC 7909-ish, kept verbatim).
    pub import_via: Vec<String>,
    /// `export:` lines.
    pub export: Vec<ExportPolicy>,
    /// `mp-export:` lines (RFC 4012).
    pub mp_export: Vec<MpExportPolicy>,
    /// `export-via:` lines.
    pub export_via: Vec<String>,
    /// `default:` lines.
    pub default: Vec<DefaultPolicy>,
    /// `mp-default:` lines (RFC 4012).
    pub mp_default: Vec<MpDefaultPolicy>,
    /// Common metadata. Note: `admin-c` and `tech-c` are **mandatory** in
    /// `aut-num` (per RADb); we enforce this in [`Self::from_raw`].
    pub common: CommonMeta,
}

impl RpslClass for AutNum {
    fn class_name() -> &'static str {
        "aut-num"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "aut-num";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "aut-num", mandatory: true, multiple: false },
                AttrSpec { name: "as-name", mandatory: true, multiple: false },
                AttrSpec { name: "admin-c", mandatory: true, multiple: true },
                AttrSpec { name: "tech-c", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "member-of", mandatory: false, multiple: true },
                AttrSpec { name: "import", mandatory: false, multiple: true },
                AttrSpec { name: "mp-import", mandatory: false, multiple: true },
                AttrSpec { name: "import-via", mandatory: false, multiple: true },
                AttrSpec { name: "export", mandatory: false, multiple: true },
                AttrSpec { name: "mp-export", mandatory: false, multiple: true },
                AttrSpec { name: "export-via", mandatory: false, multiple: true },
                AttrSpec { name: "default", mandatory: false, multiple: true },
                AttrSpec { name: "mp-default", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "mnt-by", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let aut_num = AsNumber::parse(raw.first("aut-num").ok_or_else(|| RpslError::missing_mandatory(CLASS, "aut-num"))?)?;
        let as_name = get_single(raw, "as-name").ok_or_else(|| RpslError::missing_mandatory(CLASS, "as-name"))?;
        let common = CommonMeta::from_raw(raw);
        if common.admin_c.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "admin-c"));
        }
        if common.tech_c.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "tech-c"));
        }
        Ok(Self {
            aut_num,
            as_name,
            descr: get_multi(raw, "descr"),
            member_of: get_multi_parsed(raw, "member-of", SetRef::parse)?,
            import: raw
                .all("import")
                .map(parse_import)
                .collect::<RpslResult<Vec<_>>>()?,
            mp_import: raw
                .all("mp-import")
                .map(parse_mp_import)
                .collect::<RpslResult<Vec<_>>>()?,
            import_via: get_multi(raw, "import-via"),
            export: raw
                .all("export")
                .map(parse_export)
                .collect::<RpslResult<Vec<_>>>()?,
            mp_export: raw
                .all("mp-export")
                .map(parse_mp_export)
                .collect::<RpslResult<Vec<_>>>()?,
            export_via: get_multi(raw, "export-via"),
            default: raw
                .all("default")
                .map(parse_default)
                .collect::<RpslResult<Vec<_>>>()?,
            mp_default: raw
                .all("mp-default")
                .map(parse_mp_default)
                .collect::<RpslResult<Vec<_>>>()?,
            common,
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "aut-num", &self.aut_num.to_string());
        push(&mut raw, "as-name", &self.as_name);
        push_multi(&mut raw, "descr", &self.descr);
        push_multi(&mut raw, "member-of", &self.member_of.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        for p in &self.import {
            push(&mut raw, "import", &p.to_string());
        }
        for p in &self.mp_import {
            push(&mut raw, "mp-import", &p.to_string());
        }
        push_multi(&mut raw, "import-via", &self.import_via);
        for p in &self.export {
            push(&mut raw, "export", &p.to_string());
        }
        for p in &self.mp_export {
            push(&mut raw, "mp-export", &p.to_string());
        }
        push_multi(&mut raw, "export-via", &self.export_via);
        for p in &self.default {
            push(&mut raw, "default", &p.to_string());
        }
        for p in &self.mp_default {
            push(&mut raw, "mp-default", &p.to_string());
        }
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// as-set
// ----------------------------------------------------------------------

/// `as-set` object (RFC 2280 §5.3). Groups AS numbers and other AS-sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsSet {
    /// `as-set:` — the set name, primary key.
    pub as_set: RpslPk,
    /// `descr:`
    pub descr: Vec<String>,
    /// `members:` — AS numbers and/or AS-set references.
    pub members: Vec<SetRef>,
    /// `mbrs-by-ref:` — maintainer references whose `member-of:` lines
    /// contribute members to this set.
    pub mbrs_by_ref: Vec<MntnerRef>,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for AsSet {
    fn class_name() -> &'static str {
        "as-set"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "as-set";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "as-set", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "members", mandatory: false, multiple: true },
                AttrSpec { name: "mbrs-by-ref", mandatory: false, multiple: true },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let as_set = RpslPk::parse(raw.first("as-set").ok_or_else(|| RpslError::missing_mandatory(CLASS, "as-set"))?)?;
        let members: Vec<SetRef> = get_multi_parsed(raw, "members", SetRef::parse)?;
        let mbrs_by_ref: Vec<MntnerRef> = get_multi_parsed(raw, "mbrs-by-ref", MntnerRef::parse)?;
        Ok(Self {
            as_set,
            descr: get_multi(raw, "descr"),
            members,
            mbrs_by_ref,
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "as-set", &self.as_set.to_string());
        push_multi(&mut raw, "descr", &self.descr);
        push_multi(&mut raw, "members", &self.members.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        push_multi(&mut raw, "mbrs-by-ref", &self.mbrs_by_ref.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// route-set
// ----------------------------------------------------------------------

/// `route-set` object (RFC 2280 §5.4). Groups IPv4/IPv6 prefixes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSet {
    /// `route-set:` — primary key.
    pub route_set: RpslPk,
    /// `descr:`
    pub descr: Vec<String>,
    /// `members:` — IPv4 prefix ranges or route-set references.
    pub members: Vec<Member>,
    /// `mp-members:` — IPv6 (or mixed) prefix ranges (RFC 4012).
    pub mp_members: Vec<Member>,
    /// `mbrs-by-ref:`
    pub mbrs_by_ref: Vec<MntnerRef>,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for RouteSet {
    fn class_name() -> &'static str {
        "route-set"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "route-set";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "route-set", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "members", mandatory: false, multiple: true },
                AttrSpec { name: "mp-members", mandatory: false, multiple: true },
                AttrSpec { name: "mbrs-by-ref", mandatory: false, multiple: true },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let route_set = RpslPk::parse(raw.first("route-set").ok_or_else(|| RpslError::missing_mandatory(CLASS, "route-set"))?)?;
        // `members:` and `mp-members:` values may be either a prefix-range
        // or a route-set reference. We store them all as `PrefixRange`
        // when they parse as such, and fall back to storing a route-set
        // name with no range by constructing a synthetic `PrefixRange` is
        // wrong. Instead, we keep `members` as `Vec<PrefixRange>` for
        // prefix-shaped entries and a separate `Vec<SetRef>` is not
        // possible because RADb allows both in the same attribute. The
        // pragmatic approach: store members as strings and parse them on
        // demand. But we promised typed members.
        //
        // Resolution: `members` here holds only entries that parse as
        // `PrefixRange`. Non-prefix entries (route-set refs like `RS-FOO`)
        // are stored as a `PrefixRange` with a sentinel — but that is
        // incorrect. Instead we store members as a `Vec<String>` and
        // expose typed helpers. To keep the public API typed, we use the
        // `Member` enum below.
        let members: Vec<Member> = get_multi_parsed(raw, "members", Member::parse)?;
        let mp_members: Vec<Member> = get_multi_parsed(raw, "mp-members", Member::parse)?;
        Ok(Self {
            route_set,
            descr: get_multi(raw, "descr"),
            members,
            mp_members,
            mbrs_by_ref: get_multi_parsed(raw, "mbrs-by-ref", MntnerRef::parse)?,
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "route-set", &self.route_set.to_string());
        push_multi(&mut raw, "descr", &self.descr);
        push_multi(&mut raw, "members", &self.members.iter().map(|m| m.to_string()).collect::<Vec<_>>());
        push_multi(&mut raw, "mp-members", &self.mp_members.iter().map(|m| m.to_string()).collect::<Vec<_>>());
        push_multi(&mut raw, "mbrs-by-ref", &self.mbrs_by_ref.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        self.common.to_raw(&mut raw);
        raw
    }
}

/// A `route-set` member entry: either a prefix-range or a route-set ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Member {
    /// A literal prefix with optional range operator.
    Prefix(PrefixRange),
    /// A reference to another route-set.
    RouteSet(SetRef),
}

impl Member {
    pub fn parse(s: &str) -> RpslResult<Self> {
        let s = s.trim();
        // If it parses as a prefix-range, treat it as such.
        if let Ok(pr) = PrefixRange::parse(s) {
            return Ok(Self::Prefix(pr));
        }
        // Otherwise it must be a route-set reference.
        Ok(Self::RouteSet(SetRef::parse(s)?))
    }
}

impl std::fmt::Display for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prefix(p) => write!(f, "{p}"),
            Self::RouteSet(s) => write!(f, "{s}"),
        }
    }
}

// ----------------------------------------------------------------------
// filter-set
// ----------------------------------------------------------------------

/// `filter-set` object (RFC 2280 §5.5). Holds a named filter expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSet {
    /// `filter-set:` — primary key.
    pub filter_set: RpslPk,
    /// `descr:`
    pub descr: Vec<String>,
    /// `filter:` — the IPv4 filter expression. Mandatory, single-valued.
    pub filter: Filter,
    /// `mp-filter:` — the IPv6/multicast filter (RFC 4012).
    pub mp_filter: Option<Filter>,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for FilterSet {
    fn class_name() -> &'static str {
        "filter-set"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "filter-set";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "filter-set", mandatory: true, multiple: false },
                AttrSpec { name: "filter", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "mp-filter", mandatory: false, multiple: false },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let filter_set = RpslPk::parse(raw.first("filter-set").ok_or_else(|| RpslError::missing_mandatory(CLASS, "filter-set"))?)?;
        let filter = Filter::parse(raw.first("filter").ok_or_else(|| RpslError::missing_mandatory(CLASS, "filter"))?)?;
        let mp_filter = get_single(raw, "mp-filter").map(|s| Filter::parse(&s)).transpose()?;
        Ok(Self {
            filter_set,
            descr: get_multi(raw, "descr"),
            filter,
            mp_filter,
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "filter-set", &self.filter_set.to_string());
        push_multi(&mut raw, "descr", &self.descr);
        push(&mut raw, "filter", &self.filter.to_string());
        if let Some(f) = &self.mp_filter {
            push(&mut raw, "mp-filter", &f.to_string());
        }
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// peering-set
// ----------------------------------------------------------------------

/// `peering-set` object (RFC 2280 §5.6). Holds a named peering expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeeringSet {
    /// `peering-set:` — primary key.
    pub peering_set: RpslPk,
    /// `descr:`
    pub descr: Vec<String>,
    /// `peering:` — IPv4 peering expression(s).
    pub peering: Vec<Peering>,
    /// `mp-peering:` — IPv6/multicast peering(s) (RFC 4012).
    pub mp_peering: Vec<Peering>,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for PeeringSet {
    fn class_name() -> &'static str {
        "peering-set"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "peering-set";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "peering-set", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "peering", mandatory: false, multiple: true },
                AttrSpec { name: "mp-peering", mandatory: false, multiple: true },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let peering_set = RpslPk::parse(raw.first("peering-set").ok_or_else(|| RpslError::missing_mandatory(CLASS, "peering-set"))?)?;
        Ok(Self {
            peering_set,
            descr: get_multi(raw, "descr"),
            peering: raw.all("peering").map(parse_peering).collect::<RpslResult<Vec<_>>>()?,
            mp_peering: raw.all("mp-peering").map(parse_peering).collect::<RpslResult<Vec<_>>>()?,
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "peering-set", &self.peering_set.to_string());
        push_multi(&mut raw, "descr", &self.descr);
        for p in &self.peering {
            push(&mut raw, "peering", &p.to_string());
        }
        for p in &self.mp_peering {
            push(&mut raw, "mp-peering", &p.to_string());
        }
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// rtr-set
// ----------------------------------------------------------------------

/// `rtr-set` object (RFC 2280 §5.7). Groups routers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtrSet {
    /// `rtr-set:` — primary key.
    pub rtr_set: RpslPk,
    /// `descr:`
    pub descr: Vec<String>,
    /// `members:` — `inet-rtr` references or nested `rtr-set` references.
    pub members: Vec<SetRef>,
    /// `mp-members:` (RFC 4012).
    pub mp_members: Vec<SetRef>,
    /// `mbrs-by-ref:`
    pub mbrs_by_ref: Vec<MntnerRef>,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for RtrSet {
    fn class_name() -> &'static str {
        "rtr-set"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "rtr-set";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "rtr-set", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "members", mandatory: false, multiple: true },
                AttrSpec { name: "mp-members", mandatory: false, multiple: true },
                AttrSpec { name: "mbrs-by-ref", mandatory: false, multiple: true },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let rtr_set = RpslPk::parse(raw.first("rtr-set").ok_or_else(|| RpslError::missing_mandatory(CLASS, "rtr-set"))?)?;
        Ok(Self {
            rtr_set,
            descr: get_multi(raw, "descr"),
            members: get_multi_parsed(raw, "members", SetRef::parse)?,
            mp_members: get_multi_parsed(raw, "mp-members", SetRef::parse)?,
            mbrs_by_ref: get_multi_parsed(raw, "mbrs-by-ref", MntnerRef::parse)?,
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "rtr-set", &self.rtr_set.to_string());
        push_multi(&mut raw, "descr", &self.descr);
        push_multi(&mut raw, "members", &self.members.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        push_multi(&mut raw, "mp-members", &self.mp_members.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        push_multi(&mut raw, "mbrs-by-ref", &self.mbrs_by_ref.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// inet-rtr
// ----------------------------------------------------------------------

/// `inet-rtr` object (RFC 2280 §5.8). Represents a router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InetRtr {
    /// `inet-rtr:` — the router's DNS name, primary key.
    pub inet_rtr: RpslPk,
    /// `descr:`
    pub descr: Vec<String>,
    /// `alias:`
    pub alias: Vec<String>,
    /// `local-as:` — the AS this router belongs to. Mandatory.
    pub local_as: AsNumber,
    /// `ifaddr:` — interface addresses (kept verbatim, complex grammar).
    pub ifaddr: Vec<String>,
    /// `interface:` — interface descriptions (kept verbatim).
    pub interface: Vec<String>,
    /// `peer:` — BGP peer declarations (kept verbatim).
    pub peer: Vec<String>,
    /// `mp-peer:` (RFC 4012).
    pub mp_peer: Vec<String>,
    /// `member-of:` — `rtr-set` references.
    pub member_of: Vec<SetRef>,
    /// `rs-in:` — route-server import policy (route-set reference).
    pub rs_in: Option<String>,
    /// `rs-out:` — route-server export policy.
    pub rs_out: Option<String>,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for InetRtr {
    fn class_name() -> &'static str {
        "inet-rtr"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "inet-rtr";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "inet-rtr", mandatory: true, multiple: false },
                AttrSpec { name: "local-as", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "alias", mandatory: false, multiple: true },
                AttrSpec { name: "ifaddr", mandatory: false, multiple: true },
                AttrSpec { name: "interface", mandatory: false, multiple: true },
                AttrSpec { name: "peer", mandatory: false, multiple: true },
                AttrSpec { name: "mp-peer", mandatory: false, multiple: true },
                AttrSpec { name: "member-of", mandatory: false, multiple: true },
                AttrSpec { name: "rs-in", mandatory: false, multiple: false },
                AttrSpec { name: "rs-out", mandatory: false, multiple: false },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let inet_rtr = RpslPk::parse(raw.first("inet-rtr").ok_or_else(|| RpslError::missing_mandatory(CLASS, "inet-rtr"))?)?;
        let local_as = AsNumber::parse(raw.first("local-as").ok_or_else(|| RpslError::missing_mandatory(CLASS, "local-as"))?)?;
        Ok(Self {
            inet_rtr,
            descr: get_multi(raw, "descr"),
            alias: get_multi(raw, "alias"),
            local_as,
            ifaddr: get_multi(raw, "ifaddr"),
            interface: get_multi(raw, "interface"),
            peer: get_multi(raw, "peer"),
            mp_peer: get_multi(raw, "mp-peer"),
            member_of: get_multi_parsed(raw, "member-of", SetRef::parse)?,
            rs_in: get_single(raw, "rs-in"),
            rs_out: get_single(raw, "rs-out"),
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "inet-rtr", &self.inet_rtr.to_string());
        push_multi(&mut raw, "descr", &self.descr);
        push_multi(&mut raw, "alias", &self.alias);
        push(&mut raw, "local-as", &self.local_as.to_string());
        push_multi(&mut raw, "ifaddr", &self.ifaddr);
        push_multi(&mut raw, "interface", &self.interface);
        push_multi(&mut raw, "peer", &self.peer);
        push_multi(&mut raw, "mp-peer", &self.mp_peer);
        push_multi(&mut raw, "member-of", &self.member_of.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        push_opt(&mut raw, "rs-in", &self.rs_in);
        push_opt(&mut raw, "rs-out", &self.rs_out);
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// mntner
// ----------------------------------------------------------------------

/// `mntner` object (RFC 2280 §5.9). Maintainer of a set of objects.
///
/// The `auth:` field stores raw auth strings (e.g. `MD5-PW $1$...$...`,
/// `PGPKEY-XXXX`). Per the user's instructions we do not type these
/// further because we target general IRR RPSL, not RADb-specific auth.
///
/// `admin-c` and `tech-c` are stored in [`CommonMeta`] (the `common`
/// field) to avoid duplication, even though `admin-c` is mandatory for
/// `mntner`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mntner {
    /// `mntner:` — primary key.
    pub mntner: RpslPk,
    /// `descr:`
    pub descr: Vec<String>,
    /// `upd-to:` — mandatory. Email addresses to receive update notifications.
    pub upd_to: Vec<String>,
    /// `mnt-nfy:`
    pub mnt_nfy: Vec<String>,
    /// `auth:` — mandatory. Authentication tokens (MD5-PW, PGPKEY-..., etc.).
    pub auth: Vec<String>,
    /// Common metadata. Note: `mnt-by` is mandatory for `mntner`, and
    /// `admin-c` is also mandatory (enforced in [`Self::from_raw`]).
    pub common: CommonMeta,
}

impl RpslClass for Mntner {
    fn class_name() -> &'static str {
        "mntner"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "mntner";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "mntner", mandatory: true, multiple: false },
                AttrSpec { name: "admin-c", mandatory: true, multiple: true },
                AttrSpec { name: "upd-to", mandatory: true, multiple: true },
                AttrSpec { name: "auth", mandatory: true, multiple: true },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "descr", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "mnt-nfy", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let mntner = RpslPk::parse(raw.first("mntner").ok_or_else(|| RpslError::missing_mandatory(CLASS, "mntner"))?)?;
        let upd_to = get_multi(raw, "upd-to");
        if upd_to.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "upd-to"));
        }
        let auth = get_multi(raw, "auth");
        if auth.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "auth"));
        }
        let common = CommonMeta::from_raw(raw);
        if common.admin_c.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "admin-c"));
        }
        Ok(Self {
            mntner,
            descr: get_multi(raw, "descr"),
            upd_to,
            mnt_nfy: get_multi(raw, "mnt-nfy"),
            auth,
            common,
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "mntner", &self.mntner.to_string());
        push_multi(&mut raw, "descr", &self.descr);
        // admin-c and tech-c are written by `common.to_raw` below; we do
        // not write them here to avoid duplication.
        push_multi(&mut raw, "upd-to", &self.upd_to);
        push_multi(&mut raw, "mnt-nfy", &self.mnt_nfy);
        push_multi(&mut raw, "auth", &self.auth);
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// person
// ----------------------------------------------------------------------

/// `person` object (RFC 2280 §5.10). A contact person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Person {
    /// `person:` — the person's full name. Look-up key.
    pub person: String,
    /// `address:` — mandatory, multiple.
    pub address: Vec<String>,
    /// `phone:` — mandatory, multiple.
    pub phone: Vec<String>,
    /// `fax-no:`
    pub fax_no: Vec<String>,
    /// `e-mail:` — mandatory, multiple.
    pub email: Vec<String>,
    /// `nic-hdl:` — the NIC handle, primary key.
    pub nic_hdl: NicHandle,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for Person {
    fn class_name() -> &'static str {
        "person"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "person";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "person", mandatory: true, multiple: false },
                AttrSpec { name: "address", mandatory: true, multiple: true },
                AttrSpec { name: "phone", mandatory: true, multiple: true },
                AttrSpec { name: "e-mail", mandatory: true, multiple: true },
                AttrSpec { name: "nic-hdl", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "fax-no", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let person = get_single(raw, "person").ok_or_else(|| RpslError::missing_mandatory(CLASS, "person"))?;
        let address = get_multi(raw, "address");
        if address.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "address"));
        }
        let phone = get_multi(raw, "phone");
        if phone.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "phone"));
        }
        let email = get_multi(raw, "e-mail");
        if email.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "e-mail"));
        }
        let nic_hdl = NicHandle::parse(raw.first("nic-hdl").ok_or_else(|| RpslError::missing_mandatory(CLASS, "nic-hdl"))?)?;
        Ok(Self {
            person,
            address,
            phone,
            fax_no: get_multi(raw, "fax-no"),
            email,
            nic_hdl,
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "person", &self.person);
        push_multi(&mut raw, "address", &self.address);
        push_multi(&mut raw, "phone", &self.phone);
        push_multi(&mut raw, "fax-no", &self.fax_no);
        push_multi(&mut raw, "e-mail", &self.email);
        push(&mut raw, "nic-hdl", &self.nic_hdl.to_string());
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// role
// ----------------------------------------------------------------------

/// `role` object (RFC 2280 §5.11). A contact role (team mailbox).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// `role:` — the role name.
    pub role: String,
    /// `trouble:`
    pub trouble: Vec<String>,
    /// `address:` — mandatory, multiple.
    pub address: Vec<String>,
    /// `phone:` — mandatory, multiple.
    pub phone: Vec<String>,
    /// `fax-no:`
    pub fax_no: Vec<String>,
    /// `e-mail:` — mandatory, multiple.
    pub email: Vec<String>,
    /// `admin-c:`
    pub admin_c: Vec<NicHandle>,
    /// `tech-c:`
    pub tech_c: Vec<NicHandle>,
    /// `nic-hdl:` — primary key.
    pub nic_hdl: NicHandle,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for Role {
    fn class_name() -> &'static str {
        "role"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "role";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "role", mandatory: true, multiple: false },
                AttrSpec { name: "address", mandatory: true, multiple: true },
                AttrSpec { name: "phone", mandatory: true, multiple: true },
                AttrSpec { name: "e-mail", mandatory: true, multiple: true },
                AttrSpec { name: "nic-hdl", mandatory: true, multiple: false },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "trouble", mandatory: false, multiple: true },
                AttrSpec { name: "fax-no", mandatory: false, multiple: true },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let role = get_single(raw, "role").ok_or_else(|| RpslError::missing_mandatory(CLASS, "role"))?;
        let address = get_multi(raw, "address");
        if address.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "address"));
        }
        let phone = get_multi(raw, "phone");
        if phone.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "phone"));
        }
        let email = get_multi(raw, "e-mail");
        if email.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "e-mail"));
        }
        let nic_hdl = NicHandle::parse(raw.first("nic-hdl").ok_or_else(|| RpslError::missing_mandatory(CLASS, "nic-hdl"))?)?;
        Ok(Self {
            role,
            trouble: get_multi(raw, "trouble"),
            address,
            phone,
            fax_no: get_multi(raw, "fax-no"),
            email,
            admin_c: get_multi_parsed(raw, "admin-c", NicHandle::parse)?,
            tech_c: get_multi_parsed(raw, "tech-c", NicHandle::parse)?,
            nic_hdl,
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "role", &self.role);
        push_multi(&mut raw, "trouble", &self.trouble);
        push_multi(&mut raw, "address", &self.address);
        push_multi(&mut raw, "phone", &self.phone);
        push_multi(&mut raw, "fax-no", &self.fax_no);
        push_multi(&mut raw, "e-mail", &self.email);
        for c in &self.admin_c {
            push(&mut raw, "admin-c", &c.to_string());
        }
        for c in &self.tech_c {
            push(&mut raw, "tech-c", &c.to_string());
        }
        push(&mut raw, "nic-hdl", &self.nic_hdl.to_string());
        self.common.to_raw(&mut raw);
        raw
    }
}

// ----------------------------------------------------------------------
// key-cert
// ----------------------------------------------------------------------

/// `key-cert` object (RFC 2280 §5.12). A PGP public key certificate.
///
/// The `certif:` field stores the armored PGP key block verbatim (the
/// `BEGIN PGP PUBLIC KEY BLOCK` ... `END PGP PUBLIC KEY BLOCK` lines).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCert {
    /// `key-cert:` — primary key. Conventionally `PGPKEY-XXXXXXXX`.
    pub key_cert: RpslPk,
    /// `method:` — the cryptographic method, usually `PGP`.
    pub method: Option<String>,
    /// `owner:` — the key owner(s).
    pub owner: Vec<String>,
    /// `fingerpr:` — the key fingerprint.
    pub fingerpr: Option<String>,
    /// `certif:` — the armored key block. Mandatory, multi-line.
    pub certif: Vec<String>,
    /// Common metadata.
    pub common: CommonMeta,
}

impl RpslClass for KeyCert {
    fn class_name() -> &'static str {
        "key-cert"
    }

    fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        const CLASS: &str = "key-cert";
        check_schema(
            raw,
            CLASS,
            &[
                AttrSpec { name: "key-cert", mandatory: true, multiple: false },
                AttrSpec { name: "certif", mandatory: true, multiple: true },
                AttrSpec { name: "mnt-by", mandatory: true, multiple: true },
                AttrSpec { name: "source", mandatory: true, multiple: false },
                AttrSpec { name: "method", mandatory: false, multiple: false },
                AttrSpec { name: "owner", mandatory: false, multiple: true },
                AttrSpec { name: "fingerpr", mandatory: false, multiple: false },
                AttrSpec { name: "remarks", mandatory: false, multiple: true },
                AttrSpec { name: "admin-c", mandatory: false, multiple: true },
                AttrSpec { name: "tech-c", mandatory: false, multiple: true },
                AttrSpec { name: "notify", mandatory: false, multiple: true },
                AttrSpec { name: "changed", mandatory: false, multiple: true },
            ],
        )?;
        let key_cert = RpslPk::parse(raw.first("key-cert").ok_or_else(|| RpslError::missing_mandatory(CLASS, "key-cert"))?)?;
        let certif = get_multi(raw, "certif");
        if certif.is_empty() {
            return Err(RpslError::missing_mandatory(CLASS, "certif"));
        }
        Ok(Self {
            key_cert,
            method: get_single(raw, "method"),
            owner: get_multi(raw, "owner"),
            fingerpr: get_single(raw, "fingerpr"),
            certif,
            common: CommonMeta::from_raw(raw),
        })
    }

    fn to_raw(&self) -> RawObject {
        let mut raw = RawObject::default();
        push(&mut raw, "key-cert", &self.key_cert.to_string());
        push_opt(&mut raw, "method", &self.method);
        push_multi(&mut raw, "owner", &self.owner);
        push_opt(&mut raw, "fingerpr", &self.fingerpr);
        push_multi(&mut raw, "certif", &self.certif);
        self.common.to_raw(&mut raw);
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpsl::lex::lex;

    fn parse_one(input: &str) -> RpslResult<crate::rpsl::RpslObject> {
        let objs = lex(input)?;
        crate::rpsl::de::parse_object(&objs[0])
    }

    #[test]
    fn route_round_trip() {
        let input = "\
route: 192.0.2.0/24
descr: Test route
origin: AS64500
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn route_missing_origin() {
        let input = "route: 192.0.2.0/24\nmnt-by: MNT-TEST\nsource: RADB\n";
        let objs = lex(input).unwrap();
        let err = crate::rpsl::de::parse_object(&objs[0]).unwrap_err();
        assert!(matches!(err, RpslError::MissingMandatory { attribute, .. } if attribute == "origin"));
    }

    #[test]
    fn route6_round_trip() {
        let input = "\
route6: 2001:db8::/32
origin: AS64500
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn route6_with_v4_prefix_rejected() {
        let input = "route6: 192.0.2.0/24\norigin: AS1\nmnt-by: MNT-X\nsource: RADB\n";
        let objs = lex(input).unwrap();
        let err = crate::rpsl::de::parse_object(&objs[0]).unwrap_err();
        assert!(matches!(err, RpslError::Parse { .. }));
    }

    #[test]
    fn aut_num_round_trip_with_policy() {
        let input = "\
aut-num: AS14061
as-name: DIGITALOCEAN
descr: DigitalOcean
import: from AS-ANY accept ANY
export: to AS-ANY announce AS-14061 AND NOT { 0.0.0.0/0 }
admin-c: NOC-ARIN
tech-c: NOC-ARIN
mnt-by: MAINT-AS14061
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn aut_num_missing_admin_c() {
        let input = "\
aut-num: AS1
as-name: TEST
tech-c: NOC-ARIN
mnt-by: MNT-X
source: RADB
";
        let objs = lex(input).unwrap();
        let err = crate::rpsl::de::parse_object(&objs[0]).unwrap_err();
        assert!(matches!(err, RpslError::MissingMandatory { attribute, .. } if attribute == "admin-c"));
    }

    #[test]
    fn as_set_round_trip() {
        let input = "\
as-set: AS-TEST
descr: Test set
members: AS1, AS2, AS3
members: AS-OTHER
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn route_set_round_trip() {
        let input = "\
route-set: RS-TEST
members: 192.0.2.0/24
members: 198.51.100.0/24^+
mp-members: 2001:db8::/32
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn filter_set_round_trip() {
        let input = "\
filter-set: fltr-TEST
filter: { 192.0.2.0/24, 198.51.100.0/24^+ }
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn peering_set_round_trip() {
        let input = "\
peering-set: prng-TEST
peering: AS1 at 192.0.2.1
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn rtr_set_round_trip() {
        let input = "\
rtr-set: rtrs-TEST
members: rtr1.example.net
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn inet_rtr_round_trip() {
        let input = "\
inet-rtr: rtr1.example.net
local-as: AS64500
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn mntner_round_trip() {
        let input = "\
mntner: MNT-TEST
descr: Test maintainer
admin-c: NOC-ARIN
upd-to: noc@example.net
auth: MD5-PW $1$abc$def
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn mntner_missing_auth() {
        let input = "\
mntner: MNT-TEST
admin-c: NOC-ARIN
upd-to: noc@example.net
mnt-by: MNT-TEST
source: RADB
";
        let objs = lex(input).unwrap();
        let err = crate::rpsl::de::parse_object(&objs[0]).unwrap_err();
        assert!(matches!(err, RpslError::MissingMandatory { attribute, .. } if attribute == "auth"));
    }

    #[test]
    fn person_round_trip() {
        let input = "\
person: Test Person
address: 1 Test Street
phone: +1-555-555-5555
e-mail: test@example.net
nic-hdl: TP1-ARIN
mnt-by: MNT-TEST
source: ARIN
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn role_round_trip() {
        let input = "\
role: Test Role
address: 1 Test Street
phone: +1-555-555-5555
e-mail: role@example.net
nic-hdl: TR1-ARIN
mnt-by: MNT-TEST
source: ARIN
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn key_cert_round_trip() {
        let input = "\
key-cert: PGPKEY-ABCD1234
method: PGP
owner: Test Owner
fingerpr: ABCD 1234 EFGH 5678
certif: -----BEGIN PGP PUBLIC KEY BLOCK-----
certif: mQENB...
certif: -----END PGP PUBLIC KEY BLOCK-----
mnt-by: MNT-TEST
source: RADB
";
        let obj = parse_one(input).unwrap();
        let raw = obj.to_raw();
        let text = crate::rpsl::ser::serialize_raw(&raw);
        let obj2 = parse_one(&text).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn duplicate_single_attribute_rejected() {
        let input = "\
route: 192.0.2.0/24
route: 198.51.100.0/24
origin: AS1
mnt-by: MNT-X
source: RADB
";
        let objs = lex(input).unwrap();
        let err = crate::rpsl::de::parse_object(&objs[0]).unwrap_err();
        assert!(matches!(err, RpslError::DuplicateSingle { .. }));
    }

    #[test]
    fn member_parse_prefix_vs_routeset() {
        let m1 = Member::parse("192.0.2.0/24^+").unwrap();
        assert!(matches!(m1, Member::Prefix(_)));
        let m2 = Member::parse("RS-FOO").unwrap();
        assert!(matches!(m2, Member::RouteSet(_)));
    }

    #[test]
    fn parse_list_helper() {
        use crate::rpsl::common::parse_list;
        let v: Vec<AsNumber> = parse_list("AS1, AS2 AS3", AsNumber::parse).unwrap();
        assert_eq!(v, vec![AsNumber(1), AsNumber(2), AsNumber(3)]);
    }
}