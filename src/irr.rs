use anyhow::{Context, Error, anyhow};
use reqwest::Client;
use serde_json::{Value, json};
use std::collections::HashSet;

const GRAPHQL_ENDPOINT: &str = "https://rr.ntt.net/graphql";

pub enum RPSLObjectClass {
    AutNum,
    AsSet,
    RouteSet,
}

impl TryFrom<String> for RPSLObjectClass {
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "aut-num" => Ok(Self::AutNum),
            "as-set" => Ok(Self::AsSet),
            "route-set" | "rpsl-route-set" | "rs-set" => Ok(Self::RouteSet),
            _ => Err("Invalid object-class"),
        }
    }

    type Error = &'static str;
}

/// Query RPSL object-type for the given object string
#[tracing::instrument()]
pub async fn query_object_type(irr_object: &str) -> anyhow::Result<RPSLObjectClass> {
    tracing::debug!("querying object class of {}", irr_object);
    let determine_gq = json!({
        "query": format!(r#"{{ rpslObjects(rpslPk: "{}") {{ objectClass }} }}"#, irr_object.to_uppercase())
    });
    let response: Value = post_graphql(determine_gq).await?;
    let objects = response["data"]["rpslObjects"]
        .as_array()
        .ok_or(anyhow!("No data in response"))?;

    if objects.is_empty() {
        return Err(anyhow!("No object found for {}", irr_object));
    }

    let object_class = objects[0]["objectClass"]
        .as_str()
        .ok_or(anyhow!("Missing objectClass"))?
        .to_lowercase();

    RPSLObjectClass::try_from(object_class).map_err(|_| anyhow!("invalid object class received"))
}

#[tracing::instrument()]
pub async fn query_prefixes(irr_object: &str, ipv6: bool) -> anyhow::Result<Vec<String>> {
    let object_class = query_object_type(irr_object).await?;

    // Step 2: Query prefixes based on type, with recursion handled by server queries
    let prefixes = match object_class {
        RPSLObjectClass::AutNum => {
            let stripped = irr_object
                .strip_prefix("AS")
                .or_else(|| irr_object.strip_prefix("as"))
                .ok_or(anyhow!("Invalid AS number"))?;
            let as_num: u32 = stripped.parse().context("Invalid AS number")?;
            let ip_version = if ipv6 { 6 } else { 4 };
            let gq = json!({
                "query": format!(r#"{{ asnPrefixes(asns: [{}], ipVersion: {}) {{ prefixes }} }}"#, as_num, ip_version)
            });
            let resp: Value = post_graphql(gq).await?;

            extract_prefixes(&resp["data"]["asnPrefixes"])?
        }
        RPSLObjectClass::AsSet => {
            let ip_version = if ipv6 { Some(6) } else { Some(4) };
            let ip_str = ip_version
                .map(|v| format!(", ipVersion: {}", v))
                .unwrap_or_default();
            let gq = json!({
                "query": format!(r#"{{ asSetPrefixes(setNames: ["{}"]{}) {{ prefixes }} }}"#, irr_object.to_uppercase(), ip_str)
            });
            let resp: Value = post_graphql(gq).await?;

            extract_prefixes(&resp["data"]["asSetPrefixes"])?
        }
        RPSLObjectClass::RouteSet => {
            // recursiveSetMembers handles recursion, returns flat members (prefixes)
            let gq = json!({
                "query": format!(r#"{{ recursiveSetMembers(setNames: ["{}"]) {{ members }} }}"#, irr_object.to_uppercase())
            });
            let resp: Value = post_graphql(gq).await?;

            let members = extract_prefixes(&resp["data"]["recursiveSetMembers"])?;

            // Filter by IP version (no server-side ipVersion for this query)
            members
                .into_iter()
                .filter(|p| ((ipv6 && p.contains(':')) || (!ipv6 && !p.contains(':'))))
                .collect()
        }
    };

    // Dedupe and sort
    let mut unique: HashSet<String> = prefixes.into_iter().collect();
    let mut sorted: Vec<String> = unique.drain().collect();
    sorted.sort();
    Ok(sorted)
}

/// Post graphql query payload to endpoint
async fn post_graphql(payload: Value) -> Result<Value, Error> {
    let client = Client::new();

    let resp = client
        .post(GRAPHQL_ENDPOINT)
        .json(&payload)
        .send()
        .await?
        .json::<Value>()
        .await?;

    if let Some(errors) = resp["errors"].as_array() {
        tracing::error!("errors: {}", errors[0]);
        return Err(anyhow!("GraphQL errors: {:?}", errors));
    }

    Ok(resp)
}

fn extract_prefixes(data: &Value) -> Result<Vec<String>, Error> {
    data.as_array()
        .ok_or(anyhow!("Invalid data"))?
        .first()
        .ok_or(anyhow!("No entries"))?["prefixes"]
        .as_array()
        .ok_or(anyhow!("Invalid prefixes"))?
        .iter()
        .map(|v| v.as_str().ok_or(anyhow!("not string")).map(str::to_string))
        .collect::<Result<Vec<_>, _>>()
}

/// Query the recursive members of an as-set, returning a deduplicated,
/// sorted list of AS numbers (e.g. `AS123`, `AS4567`).
///
/// Uses the `recursiveSetMembers` GraphQL query, which expands nested
/// as-set references server-side and returns a flat list of leaf AS
/// numbers. Empty member lists (from intermediate as-sets that only
/// reference other sets) are ignored.
#[tracing::instrument()]
pub async fn query_as_set_members(irr_object: &str) -> anyhow::Result<Vec<String>> {
    tracing::debug!("querying as-set members of {}", irr_object);
    let gq = json!({
        "query": format!(
            r#"{{ recursiveSetMembers(setNames: ["{}"]) {{ members }} }}"#,
            irr_object.to_uppercase()
        )
    });
    let resp: Value = post_graphql(gq).await?;

    let sets = resp["data"]["recursiveSetMembers"]
        .as_array()
        .ok_or(anyhow!("No data in response"))?;

    // Flatten all member lists into one, dedupe, and sort. Each element
    // is an as-set's resolved member list; we concatenate them.
    let mut all: HashSet<String> = HashSet::new();
    for set in sets {
        if let Some(members) = set["members"].as_array() {
            for m in members {
                if let Some(s) = m.as_str()
                    && !s.is_empty() {
                        all.insert(s.to_string());
                    }
            }
        }
    }

    let mut sorted: Vec<String> = all.into_iter().collect();
    // Sort numerically by the AS number (strip `AS` prefix) so that the
    // output is stable and human-friendly rather than lexicographic on
    // the `AS`-prefixed string.
    sorted.sort_by(|a, b| {
        let na = a
            .strip_prefix("AS")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let nb = b
            .strip_prefix("AS")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        na.cmp(&nb)
    });
    Ok(sorted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn determine_rpsl_object_types() {
        let asn = query_object_type("AS1299")
            .await
            .expect("failed to fetch object type");
        let as_set = query_object_type("AS-TEST")
            .await
            .expect("failed to fetch object type");
        let route_set = query_object_type("RS-TEST")
            .await
            .expect("failed to fetch object type");

        assert!(matches!(asn, RPSLObjectClass::AutNum));
        assert!(matches!(as_set, RPSLObjectClass::AsSet));
        assert!(matches!(route_set, RPSLObjectClass::RouteSet));
    }

    #[tokio::test]
    async fn query_as_set_members_returns_sorted_asns() {
        let members = query_as_set_members("AS-TEST")
            .await
            .expect("failed to fetch as-set members");
        // AS-TEST is a well-known public test as-set with at least one member.
        assert!(!members.is_empty());
        // Every member should start with `AS`.
        assert!(members.iter().all(|m| m.starts_with("AS")));
        // Members should be sorted numerically.
        let nums: Vec<u32> = members
            .iter()
            .map(|m| m.strip_prefix("AS").and_then(|s| s.parse().ok()).unwrap_or(0))
            .collect();
        let mut sorted_nums = nums.clone();
        sorted_nums.sort();
        assert_eq!(nums, sorted_nums);
    }
}
