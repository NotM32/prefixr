//! Signed RPSL — RFC 7909 stub.
//!
//! RFC 7909 defines a mechanism for cryptographically signing RPSL objects
//! by wrapping them in a `signed` envelope carrying `uri:`, `digest:`,
//! `signature-method:` and `signature:` attributes. Verification requires
//! fetching the signer's public key from the `uri:` (typically a
//! `https://` URL or `pgpkey:` reference) and performing a cryptographic
//! digest/signature check.
//!
//! This module **parses** signed objects (so they do not break the
//! deserializer) and exposes their inner object plus metadata, but it does
//! **not** implement cryptographic verification. Verification would
//! require an external crypto crate (e.g. `ring`, `rsa`, or `pgp`), which
//! this crate intentionally avoids. Calling [`SignedRpsl::verify`]
//! returns [`RpslError::SignedNotVerified`].
//!
//! When the `signed` cargo feature is enabled in the future, this module
//! will be replaced with a real implementation behind the same API.

use serde::{Deserialize, Serialize};

use crate::rpsl::error::{RpslError, RpslResult};
use crate::rpsl::lex::RawObject;
use crate::rpsl::RpslObject;

/// A parsed signed-RPSL envelope (RFC 7909).
///
/// The inner object is stored as a boxed [`RpslObject`] so that any class
/// can be signed. The signature metadata is kept as raw strings because
/// we do not interpret it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRpsl {
    /// The wrapped, unsigned RPSL object.
    pub inner: Box<RpslObject>,
    /// `uri:` — the location of the signer's public key / certificate.
    pub uri: String,
    /// `digest:` — the cryptographic digest of the inner object, as a
    /// hex/base64 string verbatim.
    pub digest: String,
    /// `signature-method:` — e.g. `pgpkey-...` or `rsasha256`.
    pub signature_method: String,
    /// `signature:` — the base64 signature blob.
    pub signature: String,
}

impl SignedRpsl {
    /// Verify the signature against the inner object.
    ///
    /// **Not implemented.** This is a stub. Returns
    /// [`RpslError::SignedNotVerified`]. A future revision behind the
    /// `signed` cargo feature will perform real verification once a
    /// crypto crate is added to the dependency tree.
    pub fn verify(&self) -> RpslResult<()> {
        Err(RpslError::SignedNotVerified)
    }

    /// Parse a signed RPSL object from a [`RawObject`] that contains the
    /// RFC 7909 envelope attributes.
    ///
    /// The envelope attributes (`uri:`, `digest:`, `signature-method:`,
    /// `signature:`) are stripped from the inner object before it is
    /// parsed by the regular class dispatcher.
    pub fn from_raw(raw: &RawObject) -> RpslResult<Self> {
        // RFC 7909 §3: the envelope attributes are added to a regular
        // object. We split them off and parse the remainder as a normal
        // RPSL object.
        let inner_raw = strip_envelope(raw);
        let inner = crate::rpsl::de::parse_object(&inner_raw)?;
        Ok(Self {
            inner: Box::new(inner),
            uri: raw.first("uri").unwrap_or_default().to_string(),
            digest: raw.first("digest").unwrap_or_default().to_string(),
            signature_method: raw
                .first("signature-method")
                .unwrap_or_default()
                .to_string(),
            signature: raw.first("signature").unwrap_or_default().to_string(),
        })
    }

    /// Render this signed object back into a [`RawObject`].
    pub fn to_raw(&self) -> RawObject {
        let mut inner_raw = self.inner.to_raw();
        // Append the envelope attributes after the inner object's
        // attributes, matching RFC 7909's ordering convention.
        inner_raw.attributes.push(raw_attribute_for("uri", &self.uri));
        inner_raw.attributes.push(raw_attribute_for("digest", &self.digest));
        inner_raw
            .attributes
            .push(raw_attribute_for("signature-method", &self.signature_method));
        inner_raw
            .attributes
            .push(raw_attribute_for("signature", &self.signature));
        inner_raw
    }
}

/// Convenience constructor for a [`crate::rpsl::lex::RawAttribute`].
fn raw_attribute_for(name: &str, value: &str) -> crate::rpsl::lex::RawAttribute {
    crate::rpsl::lex::RawAttribute {
        name: name.to_string(),
        value: value.to_string(),
        lines: vec![],
    }
}

/// Remove the RFC 7909 envelope attributes from a [`RawObject`], returning
/// a new [`RawObject`] containing only the inner object's attributes.
fn strip_envelope(raw: &RawObject) -> RawObject {
    const ENVELOPE: &[&str] = &["uri", "digest", "signature-method", "signature"];
    let attrs: Vec<_> = raw
        .attributes
        .iter()
        .filter(|a| !ENVELOPE.iter().any(|e| a.is_named(e)))
        .cloned()
        .collect();
    RawObject { attributes: attrs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpsl::lex::lex;

    #[test]
    fn verify_is_stubbed() {
        // Verification is intentionally not implemented.
        let s = SignedRpsl {
            inner: Box::new(RpslObject::Route(crate::rpsl::object::Route {
                route: crate::rpsl::common::IpPrefix::parse("192.0.2.0/24").unwrap(),
                descr: vec![],
                origin: crate::rpsl::common::AsNumber(64500),
                holes: vec![],
                member_of: vec![],
                inject: vec![],
                aggr_bndry: None,
                aggr_mtd: None,
                export_comps: None,
                components: None,
                geoidx: vec![],
                roa_uri: None,
                common: crate::rpsl::object::CommonMeta {
                    mnt_by: vec![crate::rpsl::common::MntnerRef::parse("MNT-X").unwrap()],
                    source: "RADB".to_string(),
                    ..Default::default()
                },
            })),
            uri: "https://example.net/key".to_string(),
            digest: "deadbeef".to_string(),
            signature_method: "rsasha256".to_string(),
            signature: "YmFzZTY0...".to_string(),
        };
        let err = s.verify().unwrap_err();
        assert!(matches!(err, RpslError::SignedNotVerified));
    }

    #[test]
    fn signed_object_parses_inner() {
        let input = "\
route: 192.0.2.0/24
origin: AS64500
mnt-by: MNT-X
source: RADB
uri: https://example.net/key
digest: deadbeef
signature-method: rsasha256
signature: YmFzZTY0
";
        let objs = lex(input).unwrap();
        let signed = SignedRpsl::from_raw(&objs[0]).unwrap();
        assert_eq!(signed.uri, "https://example.net/key");
        assert_eq!(signed.digest, "deadbeef");
        assert!(matches!(*signed.inner, RpslObject::Route(_)));
    }
}