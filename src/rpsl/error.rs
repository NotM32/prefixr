//! Error types for the RPSL parser library.
//!
//! All public functions in this crate return [`Result<T, RpslError>`]. The
//! error enum is derived via `thiserror` so that callers get idiomatic
//! `Display`/`std::error::Error` implementations for free, and can pattern
//! match on the structured variants when they need to react to a specific
//! failure mode (e.g. a missing mandatory attribute vs. a syntactically
//! invalid filter expression).
//!
//! The variants intentionally mirror the layered architecture of the crate:
//!
//! 1. [`RpslError::Lex`](RpslError::Lex) — low level text folding problems
//!    (bad continuation, no attribute name on a line, etc.).
//! 2. [`RpslError::Parse`](RpslError::Parse) — attribute values that do not
//!    conform to the grammar for their type (filters, peerings, AS numbers,
//!    IPv4/IPv6 prefixes, ...).
//! 3. [`RpslError::MissingMandatory`](RpslError::MissingMandatory) — the
//!    object is structurally complete but is missing an attribute that
//!    RFC 2280 / RFC 4012 / RADb declare as mandatory for the class.
//! 4. [`RpslError::UnknownClass`](RpslError::UnknownClass) — the leading
//!    `object-class:` attribute names a class the parser does not know.
//! 5. [`RpslError::SignedNotVerified`](RpslError::SignedNotVerified) —
//!    raised by the RFC 7909 stub when a caller attempts to verify a
//!    signed object. Cryptographic verification is intentionally not
//!    implemented in this crate (it would require an external crypto
//!    dependency); the variant exists so callers can detect this case
//!    without a runtime panic.

use thiserror::Error;

/// Top-level error type returned by every public function in [`crate::rpsl`].
#[derive(Debug, Error)]
pub enum RpslError {
    /// A lexing error: malformed continuation, missing colon, empty
    /// attribute name, etc. Carries the 1-based line number and a
    /// human-readable description.
    #[error("lex error at line {line}: {message}")]
    Lex {
        /// 1-based line number where the lexer failed.
        line: usize,
        /// Description of the lexing problem.
        message: String,
    },

    /// A parse error: the attribute value does not match the grammar
    /// expected for its type (filter, peering, AS number, prefix, ...).
    #[error("parse error on attribute `{attribute}` at line {line}: {message}")]
    Parse {
        /// Name of the attribute being parsed (e.g. `import`, `route`).
        attribute: String,
        /// 1-based line number of the attribute's first line.
        line: usize,
        /// Description of the parse failure.
        message: String,
    },

    /// The object is missing a mandatory attribute for its class.
    ///
    /// Mandatory/optional alignment follows RFC 2280, RFC 4012 and the
    /// schema published by RADb (`whois -h whois.radb.net -t <class>`).
    #[error("missing mandatory attribute `{attribute}` for class `{class}`")]
    MissingMandatory {
        /// The class name (e.g. `route`, `aut-num`).
        class: String,
        /// The attribute that was expected but absent.
        attribute: String,
    },

    /// The leading attribute names an object class the parser does not
    /// recognise. The string carries the offending class name verbatim.
    #[error("unknown RPSL object class `{0}`")]
    UnknownClass(String),

    /// An internal inconsistency: an attribute appeared more than once
    /// but the class declares it `[single]`.
    #[error("attribute `{attribute}` is single-valued but appeared {count} times in class `{class}`")]
    DuplicateSingle {
        /// The class name.
        class: String,
        /// The attribute that was repeated.
        attribute: String,
        /// Number of times the attribute appeared.
        count: usize,
    },

    /// RFC 7909 signed RPSL support is stubbed: parsing succeeds and
    /// exposes the inner object plus the signature metadata, but
    /// cryptographic verification is intentionally not implemented.
    /// This variant is returned by [`crate::rpsl::signed::SignedRpsl::verify`].
    #[error("signed RPSL verification is not implemented; the `signed` feature must be enabled at build time")]
    SignedNotVerified,

    /// An I/O error wrapping [`std::io::Error`]. Returned by helpers
    /// that read RPSL from files or streams.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl RpslError {
    /// Convenience constructor for [`RpslError::Lex`](RpslError::Lex).
    #[inline]
    pub fn lex(line: usize, message: impl Into<String>) -> Self {
        Self::Lex {
            line,
            message: message.into(),
        }
    }

    /// Convenience constructor for [`RpslError::Parse`](RpslError::Parse).
    #[inline]
    pub fn parse(attribute: impl Into<String>, line: usize, message: impl Into<String>) -> Self {
        Self::Parse {
            attribute: attribute.into(),
            line,
            message: message.into(),
        }
    }

    /// Convenience constructor for
    /// [`RpslError::MissingMandatory`](RpslError::MissingMandatory).
    #[inline]
    pub fn missing_mandatory(class: impl Into<String>, attribute: impl Into<String>) -> Self {
        Self::MissingMandatory {
            class: class.into(),
            attribute: attribute.into(),
        }
    }
}

/// Type alias used throughout the crate for brevity.
pub type RpslResult<T> = Result<T, RpslError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_lex_error() {
        let e = RpslError::lex(7, "bad continuation");
        assert_eq!(
            e.to_string(),
            "lex error at line 7: bad continuation"
        );
    }

    #[test]
    fn display_parse_error() {
        let e = RpslError::parse("import", 3, "unexpected token");
        assert_eq!(
            e.to_string(),
            "parse error on attribute `import` at line 3: unexpected token"
        );
    }

    #[test]
    fn display_missing_mandatory() {
        let e = RpslError::missing_mandatory("route", "origin");
        assert_eq!(
            e.to_string(),
            "missing mandatory attribute `origin` for class `route`"
        );
    }
}