//! RPSL text lexer.
//!
//! This module turns raw RPSL text into a sequence of [`RawObject`]s, where
//! each `RawObject` is an ordered list of [`RawAttribute`]s. The lexer is
//! the foundation of the parser stack: every higher layer (the per-class
//! field parsers in [`crate::rpsl::object`], the filter/policy parsers in
//! [`crate::rpsl::filter`] and [`crate::rpsl::policy`]) consumes
//! `RawAttribute`s rather than raw text.
//!
//! # RPSL text rules handled here
//!
//! Per RFC 2280 §2 ("RPSL Syntax and Ad-hoc Routing Policies"):
//!
//! * **Attributes** are written `name: value`. Whitespace around the colon
//!   is insignificant and is collapsed to a single separating space when
//!   re-serialised. The attribute *name* is case-insensitive; we preserve
//!   the original casing in [`RawAttribute::name`] for fidelity but compare
//!   case-insensitively via [`RawAttribute::is_named`].
//! * **Continuation lines** begin with whitespace (` `, `\t`) and append to
//!   the previous attribute's value. RFC 2280 allows an optional leading
//!   `+` on the continuation to make the append explicit; both forms are
//!   supported and joined with a single space.
//! * **Comments** start with `#` and run to end of line. A `#` may appear
//!   in the middle of a value (e.g. `changed: foo@bar 20210913 #06:39:16Z`)
//!   in which case everything from the `#` onwards is stripped. Lines that
//!   are *only* a comment (after optional leading whitespace) are dropped.
//! * **Blank lines** separate objects. One or more consecutive blank/whitespace-
//!   only lines terminate the current object; the next non-blank, non-comment
//!   line starts a new object.
//! * **CRLF and LF** line endings are both accepted. A trailing carriage
//!   return is stripped from each line before processing.
//!
//! The lexer does not interpret attribute *values*: it returns them as
//! strings (with comments stripped and continuations joined). Higher layers
//! are responsible for turning `import:`'s value into an [`ImportPolicy`]
//! etc.
//!
//! [`ImportPolicy`]: crate::rpsl::policy::ImportPolicy

use crate::rpsl::error::{RpslError, RpslResult};

/// A single folded attribute produced by the lexer.
///
/// `value` has had:
///
/// * leading/trailing whitespace trimmed,
/// * trailing comments (`#...`) removed,
/// * continuation lines joined with a single space.
///
/// `lines` records the 1-based source line numbers of every line that
/// contributed to this attribute (the first line plus any continuation
/// lines), so that downstream parsers can report accurate locations in
/// [`RpslError::Parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttribute {
    /// Attribute name as written (e.g. `import`, `route6`, `mnt-by`).
    /// Casing is preserved but comparisons should use [`Self::is_named`].
    pub name: String,
    /// Folded, comment-stripped, continuation-joined value.
    pub value: String,
    /// 1-based source line numbers that contributed to this attribute.
    pub lines: Vec<usize>,
}

impl RawAttribute {
    /// Case-insensitive name comparison. Use this instead of direct
    /// string equality on [`RawAttribute::name`].
    #[inline]
    pub fn is_named(&self, expected: &str) -> bool {
        self.name.eq_ignore_ascii_case(expected)
    }

    /// Split the folded value on whitespace into tokens. Useful for
    /// list-valued attributes such as `members:` whose values are
    /// whitespace- or comma-separated.
    pub fn tokens(&self) -> Vec<&str> {
        self.value
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .collect()
    }
}

/// A complete folded object: an ordered list of [`RawAttribute`]s.
///
/// The order matches the source text so that serializers can reproduce
/// it. The first attribute is always the class key (e.g. `route:`,
/// `aut-num:`); [`Self::class`] returns its lowercased name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawObject {
    /// Attributes in source order.
    pub attributes: Vec<RawAttribute>,
}

impl RawObject {
    /// Returns the lowercased class name derived from the first attribute.
    ///
    /// Returns `None` if the object is empty. The returned `String` is
    /// owned because lowercasing may need to allocate; callers that only
    /// need to check the class should use [`Self::class_eq`].
    pub fn class(&self) -> Option<String> {
        self.attributes.first().map(|a| a.name.to_ascii_lowercase())
    }

    /// Returns `true` if the first attribute's name matches `expected`
    /// (case-insensitive). Convenience over [`Self::class`].
    pub fn class_eq(&self, expected: &str) -> bool {
        self.attributes
            .first()
            .map(|a| a.is_named(expected))
            .unwrap_or(false)
    }

    /// Returns the value of the first attribute matching `name`
    /// (case-insensitive), or `None`.
    pub fn first(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.is_named(name))
            .map(|a| a.value.as_str())
    }

    /// Returns all values of attributes matching `name`, in source order.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.attributes
            .iter()
            .filter(move |a| a.is_named(name))
            .map(|a| a.value.as_str())
    }

    /// Returns the number of attributes matching `name` (case-insensitive).
    pub fn count(&self, name: &str) -> usize {
        self.attributes.iter().filter(|a| a.is_named(name)).count()
    }

    /// Returns `true` if at least one attribute matches `name`.
    pub fn has(&self, name: &str) -> bool {
        self.attributes.iter().any(|a| a.is_named(name))
    }
}

/// Tokenise a full RPSL document into one [`RawObject`] per logical object.
///
/// Objects are separated by blank lines (per RFC 2280 §2). Trailing blank
/// lines/whitespace do not produce empty objects. Comment-only lines are
/// treated as blank for the purpose of object separation.
///
/// # Errors
///
/// Returns [`RpslError::Lex`] if:
///
/// * a line starts with whitespace (continuation) but there is no
///   current attribute to continue,
/// * an attribute line has no `:` separator.
pub fn lex(input: &str) -> RpslResult<Vec<RawObject>> {
    let mut objects: Vec<RawObject> = Vec::new();
    let mut current: Option<RawObject> = None;
    // The attribute currently receiving continuation lines, indexed within
    // `current.attributes`. `None` means "no attribute is open".
    let mut open_attr: Option<usize> = None;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        // Normalise CRLF: `lines()` already strips `\n` but not a trailing
        // `\r` on CRLF input.
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);

        // Strip a trailing inline comment. RFC 2280 allows `#` anywhere;
        // everything from the first unquoted `#` to EOL is a comment.
        // RPSL has no quoting construct that would embed a `#`, so a simple
        // find-and-split is correct.
        let (body, comment) = split_comment(line);

        // A line that is blank after comment removal may be either a true
        // blank line (object separator) or a comment-only line. RFC 2280
        // treats comment-only lines as ignored whitespace: they do **not**
        // terminate the current object. We distinguish by checking whether
        // the original line (before comment stripping) had any non-comment
        // content.
        if body.trim().is_empty() {
            // If the original line was entirely whitespace (no comment),
            // it is a real blank line — terminate the current object.
            // If it had a comment, it is an ignored comment-only line.
            if comment.is_empty() {
                if let Some(obj) = current.take()
                    && !obj.attributes.is_empty() {
                        objects.push(obj);
                    }
                open_attr = None;
            }
            // Comment-only lines: drop, do not affect object boundaries.
            continue;
        }

        // Determine whether this is a continuation line (starts with
        // whitespace) or a new attribute.
        let starts_with_ws = line
            .chars()
            .next()
            .map(|c| c == ' ' || c == '\t')
            .unwrap_or(false);

        if starts_with_ws {
            // Continuation of the previous attribute.
            let Some(obj) = current.as_mut() else {
                return Err(RpslError::lex(
                    line_no,
                    "continuation line with no preceding attribute",
                ));
            };
            let Some(attr_idx) = open_attr else {
                return Err(RpslError::lex(
                    line_no,
                    "continuation line with no open attribute",
                ));
            };
            let attr = &mut obj.attributes[attr_idx];

            // Optional leading `+` denotes explicit continuation and is
            // not part of the value.
            let mut v = body.trim_start();
            if let Some(rest) = v.strip_prefix('+') {
                v = rest.trim_start();
            }
            let v = v.trim_end();
            if !v.is_empty() {
                if !attr.value.is_empty() {
                    attr.value.push(' ');
                }
                attr.value.push_str(v);
            }
            attr.lines.push(line_no);
        } else {
            // New attribute: `name: value`.
            let Some(colon) = body.find(':') else {
                return Err(RpslError::lex(
                    line_no,
                    format!("attribute line missing `:` separator: `{body}`"),
                ));
            };
            let name = body[..colon].trim();
            if name.is_empty() {
                return Err(RpslError::lex(
                    line_no,
                    "attribute line has empty name before `:`",
                ));
            }
            let value = body[colon + 1..].trim();

            // Lazily create the current object on the first attribute.
            let obj = current.get_or_insert_with(RawObject::default);
            obj.attributes.push(RawAttribute {
                name: name.to_string(),
                value: value.to_string(),
                lines: vec![line_no],
            });
            open_attr = Some(obj.attributes.len() - 1);
        }
    }

    // Flush the final object if the input did not end with a blank line.
    if let Some(obj) = current.take()
        && !obj.attributes.is_empty() {
            objects.push(obj);
        }

    Ok(objects)
}

/// Split a line into `(value, comment)` at the first `#`.
///
/// The returned `value` is not trimmed; the caller trims as needed. The
/// `comment` includes the leading `#` (or is empty if there was none).
fn split_comment(line: &str) -> (&str, &str) {
    match line.find('#') {
        Some(idx) => (&line[..idx], &line[idx..]),
        None => (line, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_object() {
        let input = "route: 192.0.2.0/24\norigin: AS64500\nsource: RADB\n";
        let objs = lex(input).unwrap();
        assert_eq!(objs.len(), 1);
        let o = &objs[0];
        assert_eq!(o.class(), Some("route".to_string()));
        assert_eq!(o.first("route"), Some("192.0.2.0/24"));
        assert_eq!(o.first("origin"), Some("AS64500"));
        assert_eq!(o.first("source"), Some("RADB"));
        assert_eq!(o.attributes.len(), 3);
    }

    #[test]
    fn multiple_objects_separated_by_blank_lines() {
        let input = "route: 192.0.2.0/24\norigin: AS64500\nsource: RADB\n\nroute: 198.51.100.0/24\norigin: AS64501\nsource: RADB\n";
        let objs = lex(input).unwrap();
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0].first("route"), Some("192.0.2.0/24"));
        assert_eq!(objs[1].first("route"), Some("198.51.100.0/24"));
    }

    #[test]
    fn continuation_with_space() {
        let input = "import: from AS1\n  accept ANY\nsource: RADB\n";
        let objs = lex(input).unwrap();
        assert_eq!(objs[0].first("import"), Some("from AS1 accept ANY"));
    }

    #[test]
    fn continuation_with_plus() {
        // RFC 2280: continuation lines start with whitespace; an optional
        // `+` after the whitespace makes the append explicit.
        let input = "import: from AS1\n + accept ANY\nsource: RADB\n";
        let objs = lex(input).unwrap();
        assert_eq!(objs[0].first("import"), Some("from AS1 accept ANY"));
    }

    #[test]
    fn multiple_continuations_join_with_single_space() {
        let input = "import: from\n  AS1\n  accept\n  ANY\nsource: RADB\n";
        let objs = lex(input).unwrap();
        assert_eq!(objs[0].first("import"), Some("from AS1 accept ANY"));
    }

    #[test]
    fn inline_comment_stripped() {
        let input = "changed: foo@bar 20210913 #06:39:16Z\nsource: RADB\n";
        let objs = lex(input).unwrap();
        assert_eq!(objs[0].first("changed"), Some("foo@bar 20210913"));
    }

    #[test]
    fn full_line_comment_dropped() {
        let input = "route: 192.0.2.0/24\n# this is a comment\norigin: AS64500\nsource: RADB\n";
        let objs = lex(input).unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].attributes.len(), 3);
    }

    #[test]
    fn comment_only_line_does_not_create_empty_object() {
        let input = "route: 192.0.2.0/24\norigin: AS64500\nsource: RADB\n# trailing comment\n";
        let objs = lex(input).unwrap();
        assert_eq!(objs.len(), 1);
    }

    #[test]
    fn repeated_attribute_folds_into_all() {
        let input = "members: AS1\nmembers: AS2\nmembers: AS3\nsource: RADB\nmnt-by: MNT\nas-set: AS-TEST\n";
        let objs = lex(input).unwrap();
        let members: Vec<&str> = objs[0].all("members").collect();
        assert_eq!(members, vec!["AS1", "AS2", "AS3"]);
        assert_eq!(objs[0].count("members"), 3);
    }

    #[test]
    fn crlf_line_endings() {
        let input = "route: 192.0.2.0/24\r\norigin: AS64500\r\nsource: RADB\r\n";
        let objs = lex(input).unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].first("route"), Some("192.0.2.0/24"));
    }

    #[test]
    fn continuation_records_all_line_numbers() {
        let input = "import: from AS1\n  accept ANY\n  except AS2\nsource: RADB\n";
        let objs = lex(input).unwrap();
        let import = objs[0]
            .attributes
            .iter()
            .find(|a| a.is_named("import"))
            .unwrap();
        assert_eq!(import.lines, vec![1, 2, 3]);
    }

    #[test]
    fn error_continuation_with_no_preceding_attribute() {
        let input = "  accept ANY\n";
        let err = lex(input).unwrap_err();
        assert!(matches!(err, RpslError::Lex { line, .. } if line == 1));
    }

    #[test]
    fn error_missing_colon() {
        let input = "route 192.0.2.0/24\n";
        let err = lex(input).unwrap_err();
        assert!(matches!(err, RpslError::Lex { line, .. } if line == 1));
    }

    #[test]
    fn error_empty_name_before_colon() {
        let input = ": 192.0.2.0/24\n";
        let err = lex(input).unwrap_err();
        assert!(matches!(err, RpslError::Lex { line, .. } if line == 1));
    }

    #[test]
    fn empty_input_yields_no_objects() {
        let objs = lex("").unwrap();
        assert!(objs.is_empty());
    }

    #[test]
    fn is_named_is_case_insensitive() {
        let a = RawAttribute {
            name: "MNT-BY".to_string(),
            value: "MNT-TEST".to_string(),
            lines: vec![1],
        };
        assert!(a.is_named("mnt-by"));
        assert!(a.is_named("MNT-BY"));
        assert!(a.is_named("Mnt-By"));
        assert!(!a.is_named("mnt-byz"));
    }

    #[test]
    fn tokens_split_on_whitespace_and_comma() {
        let a = RawAttribute {
            name: "members".to_string(),
            value: "AS1, AS2 AS3".to_string(),
            lines: vec![1],
        };
        assert_eq!(a.tokens(), vec!["AS1", "AS2", "AS3"]);
    }
}