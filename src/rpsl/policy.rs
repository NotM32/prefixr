//! RPSL routing-policy expressions - RFC 2280 6.1 / RFC 4012 2.5.
//!
//! This module defines the AST and parser for the values of the
//! `import:`/`export:`/`mp-import:`/`mp-export:`/`default:`/`mp-default:`
//! attributes, and for the `peering:`/`mp-peering:` attributes of
//! `peering-set` objects.
//!
//! # Grammar (RFC 2280 6.1, slightly simplified)
//!
//! ```text
//! import       ::= "from" peering  ("action" action)*  "accept" filter
//! export       ::= "to"   peering  ("action" action)*  "announce" filter
//! default      ::= "to"   peering  ("action" action)*  "networks:" filter
//! peering      ::= as-expr ("at" router)* ("via" router)?
//! as-expr      ::= as-number | as-set-name | "(" as-expr "OR" as-expr ")"
//! action       ::= "pref"   "=" int
//!                | "med"    "=" int
//!                | "community" "add" community
//!                | "community" "remove" community
//!                | "community" "set"   community
//!                | ... (free-form, kept verbatim for unknown actions)
//! ```
//!
//! RFC 4012 section 2.5 introduces the `mp-*` variants which carry an explicit
//! `afi` (address-family) clause and use IPv6-capable peerings/prefixes.
//! We model those with the [`AddressFamily`]-tagged `Mp*` structs below.

use serde::{Deserialize, Serialize};

use crate::rpsl::common::{AddressFamily, AsNumber, IpAddress, ObjectName, SetRef};
use crate::rpsl::error::{RpslError, RpslResult};
use crate::rpsl::filter::Filter;

/// A peering expression — the `from`/`to` target of an import/export.
///
/// RFC 2280 §6.1:
/// ```text
/// peering ::= as-expr "at" router ["via" router]
///           | as-expr
/// ```
/// `as-expr` is either a single AS number, an AS-set name, or a
/// parenthesised OR-list of AS numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peering {
    /// The peer AS expression. `None` means the peering set's `peering:`
    /// attribute provided only router addresses (rare but legal).
    pub peer_as: Option<AsExpression>,
    /// Optional `at <router>` — the local router address at which the
    /// peering is observed.
    pub at_router: Option<IpAddress>,
    /// Optional `via <router>` — the remote router address through which
    /// the peering is established.
    pub via_router: Option<IpAddress>,
}

/// AS expression inside a peering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsExpression {
    /// A single AS number.
    As(AsNumber),
    /// An AS-set reference.
    AsSet(SetRef),
    /// `AS1 OR AS2 OR ...` — a list of alternatives.
    Or(Vec<AsExpression>),
}

/// A single `action` clause.
///
/// RPSL defines a fixed vocabulary of action keywords (`pref`, `med`,
/// `community`, `dpa`, `next-hop`, `cost`, ...). We model the common ones
/// explicitly and capture anything else as [`Action::Other`] verbatim,
/// which is what RFC 2280 6.1 allows (`<action>` is defined as
/// `action-name action-op action-val` with an open-ended name space).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// `pref = <int>` — the BGP `LOCAL_PREF` analogue.
    Pref(u32),
    /// `med = <int>` — the BGP `MULTI_EXIT_DISCRIMINATOR`.
    Med(u32),
    /// `community add <community-set>`.
    CommunityAdd(String),
    /// `community remove <community-set>`.
    CommunityRemove(String),
    /// `community set <community-set>`.
    CommunitySet(String),
    /// Any other action, captured verbatim (e.g. `dpa = 10`,
    /// `next-hop = 192.0.2.1`).
    Other(String),
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Pref(v) => write!(f, "pref = {v}"),
            Action::Med(v) => write!(f, "med = {v}"),
            Action::CommunityAdd(c) => write!(f, "community add {c}"),
            Action::CommunityRemove(c) => write!(f, "community remove {c}"),
            Action::CommunitySet(c) => write!(f, "community set {c}"),
            Action::Other(s) => f.write_str(s),
        }
    }
}

/// An `import:` policy line (RFC 2280 §6.1).
///
/// Serialized form:
/// ```text
/// from <peering> [action <a>; action <b>; ...] accept <filter>
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportPolicy {
    /// The `from <peering>` clause.
    pub peering: Peering,
    /// Zero or more `action ...` clauses, in source order.
    pub actions: Vec<Action>,
    /// The `accept <filter>` clause.
    pub filter: Filter,
}

/// An `export:` policy line (RFC 2280 §6.1).
///
/// Serialized form:
/// ```text
/// to <peering> [action ...] announce <filter>
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPolicy {
    /// The `to <peering>` clause.
    pub peering: Peering,
    /// Zero or more `action ...` clauses.
    pub actions: Vec<Action>,
    /// The `announce <filter>` clause.
    pub filter: Filter,
}

/// A `default:` policy line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultPolicy {
    /// The `to <peering>` clause.
    pub peering: Peering,
    /// Zero or more `action ...` clauses.
    pub actions: Vec<Action>,
    /// The `networks: <filter>` clause (RFC 2280 uses `networks:` but most
    /// IRR databases just put the filter here).
    pub filter: Filter,
}

/// An `mp-import:` policy line (RFC 4012 §2.5).
///
/// Differs from [`ImportPolicy`] by carrying an explicit [`AddressFamily`]
/// prefix: `afi <afi> from <peering> ... accept <filter>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpImportPolicy {
    /// The `afi <afi>` clause.
    pub afi: AddressFamily,
    /// Inner import policy.
    pub inner: ImportPolicy,
}

/// An `mp-export:` policy line (RFC 4012 §2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpExportPolicy {
    /// The `afi <afi>` clause.
    pub afi: AddressFamily,
    /// Inner export policy.
    pub inner: ExportPolicy,
}

/// An `mp-default:` policy line (RFC 4012 §2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpDefaultPolicy {
    /// The `afi <afi>` clause.
    pub afi: AddressFamily,
    /// Inner default policy.
    pub inner: DefaultPolicy,
}

/// Tagged union of all policy line kinds, used by the object layer to
/// store the heterogeneous `import:`/`export:`/`mp-import:`/...` lines of
/// an `aut-num` in a single ordered vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyLine {
    /// Plain `import:` line.
    Import(ImportPolicy),
    /// Plain `export:` line.
    Export(ExportPolicy),
    /// `default:` line.
    Default(DefaultPolicy),
    /// `mp-import:` line (RFC 4012).
    MpImport(MpImportPolicy),
    /// `mp-export:` line (RFC 4012).
    MpExport(MpExportPolicy),
    /// `mp-default:` line (RFC 4012).
    MpDefault(MpDefaultPolicy),
}

/// Parse an `import:` value.
pub fn parse_import(value: &str) -> RpslResult<ImportPolicy> {
    let mut p = PolicyParser::new(value);
    let pol = p.parse_import()?;
    p.expect_eof()?;
    Ok(pol)
}

/// Parse an `export:` value.
pub fn parse_export(value: &str) -> RpslResult<ExportPolicy> {
    let mut p = PolicyParser::new(value);
    let pol = p.parse_export()?;
    p.expect_eof()?;
    Ok(pol)
}

/// Parse a `default:` value.
pub fn parse_default(value: &str) -> RpslResult<DefaultPolicy> {
    let mut p = PolicyParser::new(value);
    let pol = p.parse_default()?;
    p.expect_eof()?;
    Ok(pol)
}

/// Parse an `mp-import:` value (RFC 4012 §2.5).
pub fn parse_mp_import(value: &str) -> RpslResult<MpImportPolicy> {
    let mut p = PolicyParser::new(value);
    let afi = p.parse_afi()?;
    p.expect_keyword("from")?;
    let inner = p.parse_import_body()?;
    p.expect_eof()?;
    Ok(MpImportPolicy { afi, inner })
}

/// Parse an `mp-export:` value (RFC 4012 §2.5).
pub fn parse_mp_export(value: &str) -> RpslResult<MpExportPolicy> {
    let mut p = PolicyParser::new(value);
    let afi = p.parse_afi()?;
    p.expect_keyword("to")?;
    let inner = p.parse_export_body()?;
    p.expect_eof()?;
    Ok(MpExportPolicy { afi, inner })
}

/// Parse an `mp-default:` value (RFC 4012 §2.5).
pub fn parse_mp_default(value: &str) -> RpslResult<MpDefaultPolicy> {
    let mut p = PolicyParser::new(value);
    let afi = p.parse_afi()?;
    p.expect_keyword("to")?;
    let inner = p.parse_default_body()?;
    p.expect_eof()?;
    Ok(MpDefaultPolicy { afi, inner })
}

/// Parse a `peering:` value (as found in `peering-set` objects).
pub fn parse_peering(value: &str) -> RpslResult<Peering> {
    let mut p = PolicyParser::new(value);
    let peering = p.parse_peering()?;
    p.expect_eof()?;
    Ok(peering)
}

// ----------------------------------------------------------------------
// Parser
// ----------------------------------------------------------------------

/// Recursive-descent parser for the policy grammar.
///
/// Tokenisation is the same whitespace/punctuation split as the filter
/// parser: identifiers and keywords are whitespace-delimited, while
/// `(`, `)`, `;`, `,`, `{`, `}` are single-character tokens.
pub struct PolicyParser<'a> {
    input: &'a str,
}

impl<'a> PolicyParser<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input }
    }

    fn skip_ws(&mut self) {
        self.input = self.input.trim_start();
    }

    fn peek(&self) -> Option<&'a str> {
        let s = self.input.trim_start();
        if s.is_empty() {
            return None;
        }
        let first = s.chars().next().unwrap();
        if matches!(first, '(' | ')' | ';' | ',' | '{' | '}') {
            return s.get(0..first.len_utf8());
        }
        let end = s
            .find(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | ';' | ',' | '{' | '}'))
            .unwrap_or(s.len());
        Some(&s[..end])
    }

    fn next_token(&mut self) -> Option<&'a str> {
        self.skip_ws();
        if self.input.is_empty() {
            return None;
        }
        let first = self.input.chars().next().unwrap();
        if matches!(first, '(' | ')' | ';' | ',' | '{' | '}') {
            let tok = &self.input[..first.len_utf8()];
            self.input = &self.input[first.len_utf8()..];
            return Some(tok);
        }
        let end = self
            .input
            .find(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | ';' | ',' | '{' | '}'))
            .unwrap_or(self.input.len());
        let tok = &self.input[..end];
        self.input = &self.input[end..];
        Some(tok)
    }

    fn expect_eof(&mut self) -> RpslResult<()> {
        self.skip_ws();
        if !self.input.is_empty() {
            return Err(RpslError::parse(
                "policy",
                0,
                format!("trailing input: `{}`", self.input),
            ));
        }
        Ok(())
    }

    /// Consume the next token and verify it equals `kw` (case-insensitive).
    fn expect_keyword(&mut self, kw: &str) -> RpslResult<()> {
        self.skip_ws();
        match self.next_token() {
            Some(t) if t.eq_ignore_ascii_case(kw) => Ok(()),
            other => Err(RpslError::parse(
                "policy",
                0,
                format!("expected `{kw}`, got {}", other.unwrap_or("EOF")),
            )),
        }
    }

    /// `afi <family>` — RFC 4012. The family may be `ipv4`, `ipv6`,
    /// `ipv4.unicast`, etc., optionally comma-separated for a list of
    /// families (we accept a single family and capture a comma-list as
    /// `Other`).
    fn parse_afi(&mut self) -> RpslResult<AddressFamily> {
        self.expect_keyword("afi")?;
        // Read a token that may include commas (e.g. `ipv4,ipv6`). We
        // capture the whole comma-list verbatim and pass to
        // AddressFamily::parse, which maps known forms and stores unknowns.
        self.skip_ws();
        let mut acc = String::new();
        while let Some(t) = self.peek() {
            if t.eq_ignore_ascii_case("from")
                || t.eq_ignore_ascii_case("to")
                || t.eq_ignore_ascii_case("accept")
                || t.eq_ignore_ascii_case("announce")
                || t == ";"
            {
                break;
            }
            let t = self.next_token().unwrap();
            if !acc.is_empty() && t != "," {
                acc.push(' ');
            }
            acc.push_str(t);
        }
        Ok(AddressFamily::parse(&acc))
    }

    /// `from <peering> [action ...]* accept <filter>`
    fn parse_import(&mut self) -> RpslResult<ImportPolicy> {
        self.expect_keyword("from")?;
        self.parse_import_body()
    }

    /// The body after `from` has been consumed.
    fn parse_import_body(&mut self) -> RpslResult<ImportPolicy> {
        let peering = self.parse_peering()?;
        let actions = self.parse_actions_until("accept")?;
        self.expect_keyword("accept")?;
        let filter = self.parse_filter_tail()?;
        Ok(ImportPolicy {
            peering,
            actions,
            filter,
        })
    }

    /// `to <peering> [action ...]* announce <filter>`
    fn parse_export(&mut self) -> RpslResult<ExportPolicy> {
        self.expect_keyword("to")?;
        self.parse_export_body()
    }

    fn parse_export_body(&mut self) -> RpslResult<ExportPolicy> {
        let peering = self.parse_peering()?;
        let actions = self.parse_actions_until("announce")?;
        self.expect_keyword("announce")?;
        let filter = self.parse_filter_tail()?;
        Ok(ExportPolicy {
            peering,
            actions,
            filter,
        })
    }

    /// `to <peering> [action ...]* networks: <filter>` (default).
    ///
    /// Many IRR databases omit the literal `networks:` keyword; we accept
    /// both forms.
    fn parse_default(&mut self) -> RpslResult<DefaultPolicy> {
        self.expect_keyword("to")?;
        self.parse_default_body()
    }

    fn parse_default_body(&mut self) -> RpslResult<DefaultPolicy> {
        let peering = self.parse_peering()?;
        // The terminator for the action list is `networks:` (or just
        // `networks`). We match case-insensitively on the prefix because
        // the `:` may be glued to the keyword.
        let actions = self.parse_actions_until_prefix("networks")?;
        // Optional `networks:` keyword. Match case-insensitively, with or
        // without the trailing `:`.
        self.skip_ws();
        if let Some(t) = self.peek()
            && t.to_ascii_lowercase().starts_with("networks")
        {
            self.next_token();
        }
        let filter = self.parse_filter_tail()?;
        Ok(DefaultPolicy {
            peering,
            actions,
            filter,
        })
    }

    /// `<as-expr> ["at" <router>] ["via" <router>]`
    fn parse_peering(&mut self) -> RpslResult<Peering> {
        let peer_as = Some(self.parse_as_expression()?);
        let mut at_router = None;
        let mut via_router = None;
        loop {
            self.skip_ws();
            match self.peek() {
                Some(t) if t.eq_ignore_ascii_case("at") => {
                    self.next_token();
                    let r = self.parse_router()?;
                    at_router = Some(r);
                }
                Some(t) if t.eq_ignore_ascii_case("via") => {
                    self.next_token();
                    let r = self.parse_router()?;
                    via_router = Some(r);
                }
                _ => break,
            }
        }
        Ok(Peering {
            peer_as,
            at_router,
            via_router,
        })
    }

    /// `as-number | as-set-name | "(" as-expr ("OR" as-expr)* ")"`
    fn parse_as_expression(&mut self) -> RpslResult<AsExpression> {
        self.skip_ws();
        if self.peek() == Some("(") {
            self.next_token();
            let mut items = Vec::new();
            loop {
                items.push(self.parse_as_expression()?);
                self.skip_ws();
                match self.peek() {
                    Some(t) if t.eq_ignore_ascii_case("or") => {
                        self.next_token();
                    }
                    Some(")") => {
                        self.next_token();
                        break;
                    }
                    Some(other) => {
                        return Err(RpslError::parse(
                            "peering",
                            0,
                            format!("expected `OR` or `)`, got `{other}`"),
                        ));
                    }
                    None => {
                        return Err(RpslError::parse(
                            "peering",
                            0,
                            "unterminated `(` in AS expression",
                        ));
                    }
                }
            }
            if items.len() == 1 {
                return Ok(items.into_iter().next().unwrap());
            }
            return Ok(AsExpression::Or(items));
        }
        let Some(tok) = self.next_token() else {
            return Err(RpslError::parse("peering", 0, "expected AS expression"));
        };
        // Try AS number first; if that fails, treat as an AS-set name.
        if let Ok(asn) = AsNumber::parse(tok) {
            return Ok(AsExpression::As(asn));
        }
        let name = ObjectName::parse(tok)?;
        Ok(AsExpression::AsSet(name))
    }

    /// A router address (an IP literal). RPSL also permits a DNS name here
    /// in some dialects; we accept any non-keyword token and try to parse
    /// it as an IP, falling back to a free-form name stored as an IP for
    /// round-trip purposes only if it isn't an IP.
    fn parse_router(&mut self) -> RpslResult<IpAddress> {
        self.skip_ws();
        let Some(tok) = self.next_token() else {
            return Err(RpslError::parse("peering", 0, "expected router address"));
        };
        IpAddress::parse(tok)
    }

    /// Like [`Self::parse_actions_until`] but matches the terminator by
    /// prefix (case-insensitive). Used for `networks:` where the `:` is
    /// glued to the keyword.
    fn parse_actions_until_prefix(&mut self, prefix: &str) -> RpslResult<Vec<Action>> {
        let mut actions = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None => break,
                Some(t) if t.to_ascii_lowercase().starts_with(prefix) => break,
                Some(t) if t.eq_ignore_ascii_case("action") => {
                    self.next_token();
                    loop {
                        let mut acc = String::new();
                        loop {
                            self.skip_ws();
                            match self.peek() {
                                None => break,
                                Some(";") => {
                                    self.next_token();
                                    break;
                                }
                                Some(t2) if t2.to_ascii_lowercase().starts_with(prefix) => break,
                                Some(t2) if t2.eq_ignore_ascii_case("action") => break,
                                _ => {}
                            }
                            let t = self.next_token().unwrap();
                            if !acc.is_empty() {
                                acc.push(' ');
                            }
                            acc.push_str(t);
                        }
                        if !acc.is_empty() {
                            actions.push(parse_single_action(&acc));
                        }
                        self.skip_ws();
                        match self.peek() {
                            Some(t) if t.to_ascii_lowercase().starts_with(prefix) => break,
                            Some(t) if t.eq_ignore_ascii_case("action") => {
                                self.next_token();
                                continue;
                            }
                            None => break,
                            Some(_) => continue,
                        }
                    }
                }
                _ => break,
            }
        }
        Ok(actions)
    }

    /// Consume zero or more `action <a>; <b>; ...` clauses until we hit
    /// `terminator`. The terminator itself is not consumed.
    ///
    /// RPSL syntax (RFC 2280 §6.1) allows two forms:
    /// * `action pref = 100; med = 50;` — one `action` keyword followed by
    ///   multiple `;`-separated assignments.
    /// * `action pref = 100; action med = 50;` — explicit `action` before
    ///   each assignment.
    ///
    /// Both are accepted.
    ///
    /// [`parse_actions_until`]: Self::parse_actions_until
    fn parse_actions_until(&mut self, terminator: &str) -> RpslResult<Vec<Action>> {
        let mut actions = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None => break,
                Some(t) if t.eq_ignore_ascii_case(terminator) => break,
                Some(t) if t.eq_ignore_ascii_case("action") => {
                    self.next_token();
                    // After `action`, read one or more `;`-separated
                    // assignments until we hit the terminator or EOF.
                    loop {
                        let mut acc = String::new();
                        loop {
                            self.skip_ws();
                            match self.peek() {
                                None => break,
                                Some(";") => {
                                    self.next_token();
                                    break;
                                }
                                Some(t2) if t2.eq_ignore_ascii_case(terminator) => break,
                                Some(t2) if t2.eq_ignore_ascii_case("action") => break,
                                _ => {}
                            }
                            let t = self.next_token().unwrap();
                            if !acc.is_empty() {
                                acc.push(' ');
                            }
                            acc.push_str(t);
                        }
                        if !acc.is_empty() {
                            actions.push(parse_single_action(&acc));
                        }
                        // After a `;`, check what follows: another
                        // assignment (no `action` keyword) or an explicit
                        // `action` keyword, or the terminator.
                        self.skip_ws();
                        match self.peek() {
                            Some(t) if t.eq_ignore_ascii_case(terminator) => break,
                            Some(t) if t.eq_ignore_ascii_case("action") => {
                                self.next_token();
                                continue;
                            }
                            None => break,
                            // Another `;`-separated assignment without
                            // an explicit `action` keyword — keep reading.
                            Some(_) => continue,
                        }
                    }
                }
                _ => break,
            }
        }
        Ok(actions)
    }

    /// Consume the rest of the input as a filter expression. We feed the
    /// remaining input to the [`Filter`] parser and then clear our own
    /// input so that [`Self::expect_eof`] succeeds.
    fn parse_filter_tail(&mut self) -> RpslResult<Filter> {
        self.skip_ws();
        let filter = Filter::parse(self.input)
            .map_err(|e| RpslError::parse("filter", 0, format!("invalid filter: {e}")))?;
        // The FilterParser consumed a private copy of the input; clear ours
        // so the outer `expect_eof` does not report trailing data.
        self.input = "";
        Ok(filter)
    }
}

/// Parse a single `action` body (everything between `action` and `;` or
/// the terminator) into an [`Action`]. Unknown actions fall back to
/// [`Action::Other`].
fn parse_single_action(s: &str) -> Action {
    let s = s.trim();
    let lower = s.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("pref") {
        let rest = rest.trim_start();
        if let Some(rest) = rest.strip_prefix('=')
            && let Ok(v) = rest.trim().parse::<u32>()
        {
            return Action::Pref(v);
        }
    }
    if let Some(rest) = lower.strip_prefix("med") {
        let rest = rest.trim_start();
        if let Some(rest) = rest.strip_prefix('=')
            && let Ok(v) = rest.trim().parse::<u32>()
        {
            return Action::Med(v);
        }
    }
    if let Some(rest) = lower.strip_prefix("community") {
        let rest = rest.trim_start();
        if let Some(rest) = rest.strip_prefix("add") {
            return Action::CommunityAdd(rest.trim().to_string());
        }
        if let Some(rest) = rest.strip_prefix("remove") {
            return Action::CommunityRemove(rest.trim().to_string());
        }
        if let Some(rest) = rest.strip_prefix("set") {
            return Action::CommunitySet(rest.trim().to_string());
        }
    }
    Action::Other(s.to_string())
}

impl std::fmt::Display for ImportPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "from {peering}", peering = self.peering)?;
        for a in &self.actions {
            write!(f, " action {a};")?;
        }
        write!(f, " accept {}", self.filter)
    }
}

impl std::fmt::Display for ExportPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "to {peering}", peering = self.peering)?;
        for a in &self.actions {
            write!(f, " action {a};")?;
        }
        write!(f, " announce {}", self.filter)
    }
}

impl std::fmt::Display for DefaultPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "to {peering}", peering = self.peering)?;
        for a in &self.actions {
            write!(f, " action {a};")?;
        }
        write!(f, " networks: {}", self.filter)
    }
}

impl std::fmt::Display for MpImportPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "afi {} {}", self.afi, self.inner)
    }
}

impl std::fmt::Display for MpExportPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "afi {} {}", self.afi, self.inner)
    }
}

impl std::fmt::Display for MpDefaultPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "afi {} {}", self.afi, self.inner)
    }
}

impl std::fmt::Display for Peering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(asn) = &self.peer_as {
            write!(f, "{asn}")?;
        }
        if let Some(r) = &self.at_router {
            write!(f, " at {r}")?;
        }
        if let Some(r) = &self.via_router {
            write!(f, " via {r}")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for AsExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsExpression::As(n) => write!(f, "{n}"),
            AsExpression::AsSet(n) => write!(f, "{n}"),
            AsExpression::Or(items) => {
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" OR ")?;
                    }
                    write!(f, "{it}")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpsl::common::{AsNumber, IpAddress};
    use std::net::Ipv4Addr;

    #[test]
    fn simple_import() {
        let p = parse_import("from AS1 accept ANY").unwrap();
        assert_eq!(p.peering.peer_as, Some(AsExpression::As(AsNumber(1))));
        assert!(p.actions.is_empty());
        assert_eq!(p.filter, Filter::Any);
        assert_eq!(p.to_string(), "from AS1 accept ANY");
    }

    #[test]
    fn import_with_action() {
        let p = parse_import("from AS1 action pref = 10; accept AS-FOO").unwrap();
        assert_eq!(p.actions, vec![Action::Pref(10)]);
        assert!(matches!(p.filter, Filter::AsSet(_)));
    }

    #[test]
    fn import_with_as_set_peering() {
        let p = parse_import("from AS-ANY accept ANY").unwrap();
        assert!(matches!(p.peering.peer_as, Some(AsExpression::AsSet(_))));
    }

    #[test]
    fn import_with_at_and_via() {
        let p = parse_import("from AS1 at 192.0.2.1 via 192.0.2.2 accept ANY").unwrap();
        assert_eq!(
            p.peering.at_router,
            Some(IpAddress::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            p.peering.via_router,
            Some(IpAddress::V4(Ipv4Addr::new(192, 0, 2, 2)))
        );
    }

    #[test]
    fn import_with_or_peering() {
        let p = parse_import("from ( AS1 OR AS2 ) accept ANY").unwrap();
        if let Some(AsExpression::Or(items)) = &p.peering.peer_as {
            assert_eq!(items.len(), 2);
        } else {
            panic!("expected Or peering");
        }
    }

    #[test]
    fn complex_import_from_real_world() {
        // Real-world-ish example with multiple actions and a NOT filter.
        let p = parse_import(
            "from AS64500 action pref = 100; med = 50; accept AS-FOO AND NOT { 0.0.0.0/0 }",
        )
        .unwrap();
        assert_eq!(p.actions.len(), 2);
        assert!(matches!(p.filter, Filter::AndNot(_, _)));
    }

    #[test]
    fn simple_export() {
        let p = parse_export("to AS1 announce AS-FOO").unwrap();
        assert_eq!(p.peering.peer_as, Some(AsExpression::As(AsNumber(1))));
        assert!(matches!(p.filter, Filter::AsSet(_)));
        assert_eq!(p.to_string(), "to AS1 announce AS-FOO");
    }

    #[test]
    fn simple_default() {
        let p = parse_default("to AS1 networks: AS-FOO").unwrap();
        assert_eq!(p.peering.peer_as, Some(AsExpression::As(AsNumber(1))));
        assert!(matches!(p.filter, Filter::AsSet(_)));
    }

    #[test]
    fn mp_import_ipv6() {
        let p = parse_mp_import("afi ipv6 from AS1 accept 2001:db8::/32").unwrap();
        assert_eq!(p.afi, AddressFamily::Ipv6);
        assert!(matches!(p.inner.filter, Filter::AddressPrefixSet(_)));
    }

    #[test]
    fn mp_export_ipv4() {
        let p = parse_mp_export("afi ipv4 to AS1 announce AS-FOO").unwrap();
        assert_eq!(p.afi, AddressFamily::Ipv4);
        assert!(matches!(p.inner.filter, Filter::AsSet(_)));
    }

    #[test]
    fn peering_attribute_value() {
        let p = parse_peering("AS1 at 192.0.2.1").unwrap();
        assert_eq!(p.peer_as, Some(AsExpression::As(AsNumber(1))));
        assert_eq!(
            p.at_router,
            Some(IpAddress::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
    }

    #[test]
    fn action_display_roundtrip() {
        assert_eq!(Action::Pref(10).to_string(), "pref = 10");
        assert_eq!(Action::Med(50).to_string(), "med = 50");
        assert_eq!(
            Action::CommunityAdd("123:456".to_string()).to_string(),
            "community add 123:456"
        );
    }

    #[test]
    fn unknown_action_captured() {
        let p = parse_import("from AS1 action dpa = 10; accept ANY").unwrap();
        assert_eq!(p.actions, vec![Action::Other("dpa = 10".to_string())]);
    }

    #[test]
    fn import_from_fixture() {
        // Matches the existing test fixture in the skeleton:
        //   import:         from AS-ANY   accept ANY
        let p = parse_import("from AS-ANY   accept ANY").unwrap();
        assert!(matches!(p.peering.peer_as, Some(AsExpression::AsSet(_))));
        assert_eq!(p.filter, Filter::Any);
    }

    #[test]
    fn export_from_fixture() {
        // export: to AS-ANY announce AS-14061 AND NOT {0.0.0.0/0}
        let p = parse_export("to AS-ANY announce AS-14061 AND NOT { 0.0.0.0/0 }").unwrap();
        assert!(matches!(p.peering.peer_as, Some(AsExpression::AsSet(_))));
        assert!(matches!(p.filter, Filter::AndNot(_, _)));
    }

    #[test]
    fn error_expected_from() {
        assert!(parse_import("AS1 accept ANY").is_err());
    }

    #[test]
    fn error_missing_accept() {
        assert!(parse_import("from AS1").is_err());
    }
}
