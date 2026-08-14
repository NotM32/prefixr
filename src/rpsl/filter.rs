//! RPSL filter grammar — RFC 2280 §6 / RFC 4012 §2.4.
//!
//! A *filter* is the right-hand side of an `import:`/`export:`/`mp-import:`/
//! `mp-export:` action's `accept`/`announce` clause, and also the value of a
//! `filter-set:`'s `filter:`/`mp-filter:` attribute. The grammar (RFC 2280
//! §6, slightly simplified) is:
//!
//! ```text
//! filter     ::= filter-factor (OP filter-factor)*
//!             | "ANY"
//! OP         ::= "AND" | "OR" | "AND NOT" | "EXCEPT" | "NOT"
//! filter-factor ::= filter-term
//!             | "(" filter ")"
//! filter-term::= route-set-name [range-op]
//!             | "{" prefix-set "}"
//!             | "ANY"
//!             | filter-set-name
//!             | as-set-name      // matches all routes originated by members
//! ```
//!
//! RFC 4012 §2.4 extends this with `ipv6` / multicast prefix literals and
//! with the `^` range operator on every prefix-bearing term. We capture all
//! of these in a single recursive-descent [`FilterParser`] producing a
//! small [`Filter`] AST.
//!
//! The parser is intentionally permissive about extra whitespace and
//! case-insensitive keywords (`and`/`AND`/`And` all work), but strict about
//! unknown tokens.

use serde::{Deserialize, Serialize};

use crate::rpsl::common::{ObjectName, PrefixRange, SetRef};
use crate::rpsl::error::{RpslError, RpslResult};

/// Abstract Syntax Tree for an RPSL filter expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum Filter {
    /// `ANY` — matches every route.
    Any,

    /// A bare route-set name, optionally with a `^` range operator applied
    /// to all prefixes the set expands to.
    RouteSet {
        /// The referenced route-set name (e.g. `RS-FOO`).
        name: SetRef,
        /// Optional `^+` / `^-` / `^n-m` suffix.
        range: Option<String>,
    },

    /// An explicit address prefix set literal: `{ 10.0.0.0/8, 192.0.2.0/24^+ }`.
    /// The braces are implied by this variant; each element is a
    /// [`PrefixRange`].
    AddressPrefixSet(Vec<PrefixRange>),

    /// A filter-set name reference (`fltr-foo`). When evaluated, the
    /// referenced filter-set's `filter:` value is substituted.
    FilterSetRef(SetRef),

    /// An AS-set reference — matches every route originated by any member
    /// of the named AS-set. RFC 2280 §6 allows `as-set-name` as a
    /// filter factor.
    AsSet(SetRef),

    /// A parenthesised sub-filter. Used both for grouping and for the
    /// comma-list form `( f1, f2, f3 )`, which is sugar for
    /// `f1 OR f2 OR f3` per RFC 2280 §6.
    Group(Vec<Filter>),

    /// `a AND b`
    And(Box<Filter>, Box<Filter>),

    /// `a OR b`
    Or(Box<Filter>, Box<Filter>),

    /// `a AND NOT b` (a distinct variant because it is a very common idiom
    /// and serialises differently from `And(a, Not(b))`).
    AndNot(Box<Filter>, Box<Filter>),

    /// `a EXCEPT b` — RFC 2280 §6: equivalent to `a AND NOT b`, but
    /// preserved verbatim for round-trip fidelity.
    Except(Box<Filter>, Box<Filter>),

    /// `NOT a`
    Not(Box<Filter>),
}

impl Filter {
    /// Parse a filter expression from a folded attribute value.
    pub fn parse(value: &str) -> RpslResult<Self> {
        let mut p = FilterParser::new(value);
        let f = p.parse_filter()?;
        p.expect_eof()?;
        Ok(f)
    }
}

impl std::fmt::Display for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        render_filter(f, self, 0)
    }
}

/// Recursively render a filter. `depth` tracks parenthesis nesting so we
/// can decide when parentheses are needed for unambiguous round-tripping.
fn render_filter(
    f: &mut std::fmt::Formatter<'_>,
    ftr: &Filter,
    depth: usize,
) -> std::fmt::Result {
    match ftr {
        Filter::Any => f.write_str("ANY"),
        Filter::RouteSet { name, range } => {
            if let Some(r) = range {
                write!(f, "{name}{r}")
            } else {
                write!(f, "{name}")
            }
        }
        Filter::AddressPrefixSet(items) => {
            f.write_str("{ ")?;
            for (i, p) in items.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{p}")?;
            }
            f.write_str(" }")
        }
        Filter::FilterSetRef(n) => write!(f, "{n}"),
        Filter::AsSet(n) => write!(f, "{n}"),
        Filter::Group(inner) => {
            if depth > 0 {
                f.write_str("(")?;
            }
            for (i, sub) in inner.iter().enumerate() {
                if i > 0 {
                    f.write_str(" OR ")?;
                }
                render_filter(f, sub, depth + 1)?;
            }
            if depth > 0 {
                f.write_str(")")?;
            }
            Ok(())
        }
        Filter::And(a, b) => {
            render_filter(f, a, depth + 1)?;
            f.write_str(" AND ")?;
            render_filter(f, b, depth + 1)
        }
        Filter::Or(a, b) => {
            render_filter(f, a, depth + 1)?;
            f.write_str(" OR ")?;
            render_filter(f, b, depth + 1)
        }
        Filter::AndNot(a, b) => {
            render_filter(f, a, depth + 1)?;
            f.write_str(" AND NOT ")?;
            render_filter(f, b, depth + 1)
        }
        Filter::Except(a, b) => {
            render_filter(f, a, depth + 1)?;
            f.write_str(" EXCEPT ")?;
            render_filter(f, b, depth + 1)
        }
        Filter::Not(a) => {
            f.write_str("NOT ")?;
            render_filter(f, a, depth + 1)
        }
    }
}

/// A tiny Pratt-style recursive-descent parser for the filter grammar.
///
/// The input is tokenised on the fly by scanning whitespace-separated
/// tokens; punctuation (`{`, `}`, `(`, `)`, `,`) is treated as its own
/// token even when not surrounded by whitespace.
pub struct FilterParser<'a> {
    /// Remaining input.
    input: &'a str,
}

impl<'a> FilterParser<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input }
    }

    /// Consume leading whitespace.
    fn skip_ws(&mut self) {
        self.input = self.input.trim_start();
    }

    /// Look at the next token without consuming it. Returns `None` at EOF.
    fn peek(&self) -> Option<&'a str> {
        let s = self.input.trim_start();
        if s.is_empty() {
            return None;
        }
        // Punctuation tokens are single chars.
        let first = s.chars().next().unwrap();
        if matches!(first, '{' | '}' | '(' | ')' | ',') {
            return s.get(0..first.len_utf8());
        }
        // Otherwise read until whitespace or punctuation.
        let end = s
            .find(|c: char| c.is_whitespace() || matches!(c, '{' | '}' | '(' | ')' | ','))
            .unwrap_or(s.len());
        Some(&s[..end])
    }

    /// Consume and return the next token.
    fn next_token(&mut self) -> Option<&'a str> {
        self.skip_ws();
        if self.input.is_empty() {
            return None;
        }
        let first = self.input.chars().next().unwrap();
        if matches!(first, '{' | '}' | '(' | ')' | ',') {
            let tok = &self.input[..first.len_utf8()];
            self.input = &self.input[first.len_utf8()..];
            return Some(tok);
        }
        let end = self
            .input
            .find(|c: char| c.is_whitespace() || matches!(c, '{' | '}' | '(' | ')' | ','))
            .unwrap_or(self.input.len());
        let tok = &self.input[..end];
        self.input = &self.input[end..];
        Some(tok)
    }

    /// Error if there is any non-whitespace input left.
    fn expect_eof(&mut self) -> RpslResult<()> {
        self.skip_ws();
        if !self.input.is_empty() {
            return Err(RpslError::parse(
                "filter",
                0,
                format!("trailing input: `{}`", self.input),
            ));
        }
        Ok(())
    }

    /// `filter ::= filter-term (AND|OR|EXCEPT|AND NOT) filter-term*`
    ///
    /// We parse with the conventional precedence:
    ///   `NOT` > `AND` / `AND NOT` > `OR` / `EXCEPT`
    /// which matches RFC 2280 §6's prose.
    pub fn parse_filter(&mut self) -> RpslResult<Filter> {
        let mut left = self.parse_or_term()?;
        loop {
            self.skip_ws();
            let Some(tok) = self.peek() else { break };
            let lower = tok.to_ascii_lowercase();
            match lower.as_str() {
                "or" => {
                    self.next_token();
                    let right = self.parse_or_term()?;
                    left = Filter::Or(Box::new(left), Box::new(right));
                }
                "except" => {
                    self.next_token();
                    let right = self.parse_or_term()?;
                    left = Filter::Except(Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }
        Ok(left)
    }

    /// `or-term ::= and-term ( "AND" | "AND NOT" ) and-term*`
    fn parse_or_term(&mut self) -> RpslResult<Filter> {
        let mut left = self.parse_not_term()?;
        loop {
            self.skip_ws();
            let Some(tok) = self.peek() else { break };
            if tok.eq_ignore_ascii_case("and") {
                self.next_token();
                // Check for "AND NOT".
                self.skip_ws();
                if let Some(next) = self.peek()
                    && next.eq_ignore_ascii_case("not") {
                        self.next_token();
                        let right = self.parse_not_term()?;
                        left = Filter::AndNot(Box::new(left), Box::new(right));
                        continue;
                    }
                let right = self.parse_not_term()?;
                left = Filter::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    /// `not-term ::= "NOT" not-term | factor`
    fn parse_not_term(&mut self) -> RpslResult<Filter> {
        self.skip_ws();
        if let Some(tok) = self.peek()
            && tok.eq_ignore_ascii_case("not") {
                self.next_token();
                let inner = self.parse_not_term()?;
                return Ok(Filter::Not(Box::new(inner)));
            }
        self.parse_factor()
    }

    /// `factor ::= "(" filter ("," filter)* ")"`
    ///           | "{" prefix-list "}"`
    ///           | "ANY"`
    ///           | name ["^" range]`
    fn parse_factor(&mut self) -> RpslResult<Filter> {
        self.skip_ws();
        let Some(tok) = self.next_token() else {
            return Err(RpslError::parse("filter", 0, "unexpected end of input"));
        };

        if tok == "(" {
            // Group: a comma-separated list of sub-filters. RFC 2280 §6
            // says the comma form is equivalent to OR.
            let mut items = Vec::new();
            self.skip_ws();
            if self.peek() == Some(")") {
                self.next_token();
                return Ok(Filter::Group(items));
            }
            loop {
                let sub = self.parse_filter()?;
                items.push(sub);
                self.skip_ws();
                match self.peek() {
                    Some(",") => {
                        self.next_token();
                    }
                    Some(")") => {
                        self.next_token();
                        break;
                    }
                    Some(other) => {
                        return Err(RpslError::parse(
                            "filter",
                            0,
                            format!("expected `,` or `)` in group, got `{other}`"),
                        ));
                    }
                    None => {
                        return Err(RpslError::parse(
                            "filter",
                            0,
                            "unterminated `(` group",
                        ));
                    }
                }
            }
            // A single-element group is just its inner filter.
            if items.len() == 1 {
                return Ok(items.into_iter().next().unwrap());
            }
            return Ok(Filter::Group(items));
        }

        if tok == "{" {
            let mut items = Vec::new();
            self.skip_ws();
            if self.peek() == Some("}") {
                self.next_token();
                return Ok(Filter::AddressPrefixSet(items));
            }
            loop {
                // A prefix-set element is everything up to the next `,` or
                // `}`, possibly containing a `^` range.
                self.skip_ws();
                let mut acc = String::new();
                while let Some(c) = self.peek() {
                    if c == "," || c == "}" {
                        break;
                    }
                    // Read a token and accumulate.
                    let t = self.next_token().unwrap();
                    if !acc.is_empty() {
                        acc.push(' ');
                    }
                    acc.push_str(t);
                }
                if acc.is_empty() {
                    return Err(RpslError::parse(
                        "filter",
                        0,
                        "expected prefix in `{}` set",
                    ));
                }
                items.push(PrefixRange::parse(&acc)?);
                self.skip_ws();
                match self.peek() {
                    Some(",") => {
                        self.next_token();
                    }
                    Some("}") => {
                        self.next_token();
                        break;
                    }
                    _ => {
                        return Err(RpslError::parse(
                            "filter",
                            0,
                            "unterminated `{}` set",
                        ));
                    }
                }
            }
            return Ok(Filter::AddressPrefixSet(items));
        }

        if tok.eq_ignore_ascii_case("ANY") {
            return Ok(Filter::Any);
        }

        // Otherwise this is a named reference: `RS-FOO`, `AS-FOO`,
        // `fltr-foo`, possibly followed by a `^range` suffix (only valid
        // for route-sets, but we accept it syntactically for any name and
        // let the semantic layer reject mismatches).
        let mut name = tok.to_string();
        // The `^` may be glued to the name with no whitespace.
        let (base, range) = if let Some(idx) = name.find('^') {
            let r = name[idx..].to_string();
            let b = name[..idx].to_string();
            (b, Some(r))
        } else {
            // Or it may appear as the next token.
            self.skip_ws();
            if let Some(next) = self.peek() {
                if next.starts_with('^') {
                    self.next_token();
                    (name.clone(), Some(next.to_string()))
                } else {
                    (name.clone(), None)
                }
            } else {
                (name.clone(), None)
            }
        };
        name = base;
        let parsed_name = ObjectName::parse(&name)?;

        // Classify the name by its conventional prefix. This is a hint
        // rather than a hard rule — RPSL does not strictly require the
        // `RS-`/`AS-`/`fltr-` prefixes, but in practice IRR databases use
        // them. We classify on prefix and fall back to `RouteSet` for
        // anything that looks like an IPv4/IPv6 prefix (contains `.` and
        // `/`).
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("as-") || lower.starts_with("as-") {
            return Ok(Filter::AsSet(parsed_name));
        }
        if lower.starts_with("fltr-") {
            return Ok(Filter::FilterSetRef(parsed_name));
        }
        // If it parses as an IP prefix, treat it as a single-element
        // AddressPrefixSet.
        if let Ok(pr) = PrefixRange::parse(&name) {
            return Ok(Filter::AddressPrefixSet(vec![pr]));
        }
        // Default: treat as a route-set reference.
        Ok(Filter::RouteSet {
            name: parsed_name,
            range,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpsl::common::IpPrefix;

    #[test]
    fn any_filter() {
        let f = Filter::parse("ANY").unwrap();
        assert_eq!(f, Filter::Any);
        assert_eq!(f.to_string(), "ANY");
    }

    #[test]
    fn address_prefix_set_single() {
        let f = Filter::parse("{ 192.0.2.0/24 }").unwrap();
        assert!(matches!(f, Filter::AddressPrefixSet(_)));
        assert_eq!(f.to_string(), "{ 192.0.2.0/24 }");
    }

    #[test]
    fn address_prefix_set_multiple_with_range() {
        let f = Filter::parse("{ 192.0.2.0/24^+, 10.0.0.0/8 }").unwrap();
        if let Filter::AddressPrefixSet(items) = f {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].range, Some(crate::rpsl::common::RangeOperator::MoreSpecifics));
            assert!(items[1].range.is_none());
        } else {
            panic!("expected AddressPrefixSet");
        }
    }

    #[test]
    fn route_set_with_range() {
        let f = Filter::parse("RS-FOO^+").unwrap();
        assert!(matches!(f, Filter::RouteSet { .. }));
        assert_eq!(f.to_string(), "RS-FOO^+");
    }

    #[test]
    fn as_set_filter() {
        let f = Filter::parse("AS-ANY").unwrap();
        assert!(matches!(f, Filter::AsSet(_)));
    }

    #[test]
    fn filter_set_ref() {
        let f = Filter::parse("fltr-foo").unwrap();
        assert!(matches!(f, Filter::FilterSetRef(_)));
    }

    #[test]
    fn and_combination() {
        let f = Filter::parse("AS-FOO AND NOT { 0.0.0.0/0 }").unwrap();
        assert!(matches!(f, Filter::AndNot(_, _)));
        assert_eq!(f.to_string(), "AS-FOO AND NOT { 0.0.0.0/0 }");
    }

    #[test]
    fn or_combination() {
        let f = Filter::parse("AS1 OR AS2").unwrap();
        assert!(matches!(f, Filter::Or(_, _)));
    }

    #[test]
    fn except_combination() {
        let f = Filter::parse("AS-FOO EXCEPT AS-BAR").unwrap();
        assert!(matches!(f, Filter::Except(_, _)));
    }

    #[test]
    fn not_combination() {
        let f = Filter::parse("NOT AS-ANY").unwrap();
        assert!(matches!(f, Filter::Not(_)));
        assert_eq!(f.to_string(), "NOT AS-ANY");
    }

    #[test]
    fn group_parens() {
        // `( AS1 OR AS2 )` — the inner `OR` is parsed as a single Or
        // filter, so the surrounding group is trivially unwrapped.
        let f = Filter::parse("( AS1 OR AS2 )").unwrap();
        assert!(matches!(f, Filter::Or(_, _)));
    }

    #[test]
    fn group_parens_explicit_two_items() {
        // `( AS1, AS2 )` — comma-separated, becomes a 2-element Group.
        let f = Filter::parse("( AS1, AS2 )").unwrap();
        if let Filter::Group(items) = f {
            assert_eq!(items.len(), 2);
        } else {
            panic!("expected Group");
        }
    }

    #[test]
    fn group_comma_list_is_or() {
        let f = Filter::parse("( AS1, AS2, AS3 )").unwrap();
        if let Filter::Group(items) = f {
            assert_eq!(items.len(), 3);
        } else {
            panic!("expected Group");
        }
    }

    #[test]
    fn complex_real_world_filter() {
        // Real-world example from an aut-num:
        //   AS-14061 AND NOT {0.0.0.0/0}
        let f = Filter::parse("AS-14061 AND NOT { 0.0.0.0/0 }").unwrap();
        assert!(matches!(f, Filter::AndNot(_, _)));
        assert_eq!(f.to_string(), "AS-14061 AND NOT { 0.0.0.0/0 }");
    }

    #[test]
    fn bare_prefix_is_address_set() {
        let f = Filter::parse("192.0.2.0/24").unwrap();
        if let Filter::AddressPrefixSet(items) = f {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].prefix, IpPrefix::parse("192.0.2.0/24").unwrap());
        } else {
            panic!("expected AddressPrefixSet");
        }
    }

    #[test]
    fn case_insensitive_keywords() {
        let f = Filter::parse("any").unwrap();
        assert_eq!(f, Filter::Any);
        let f = Filter::parse("AS-FOO and not { 0.0.0.0/0 }").unwrap();
        assert!(matches!(f, Filter::AndNot(_, _)));
    }

    #[test]
    fn trailing_input_rejected() {
        assert!(Filter::parse("ANY garbage").is_err());
    }

    #[test]
    fn unterminated_brace_set() {
        assert!(Filter::parse("{ 192.0.2.0/24").is_err());
    }

    #[test]
    fn unterminated_paren_group() {
        assert!(Filter::parse("( AS1 OR AS2").is_err());
    }
}