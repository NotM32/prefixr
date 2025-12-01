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
pub async fn query_object_type(irr_object: &str) -> anyhow::Result<RPSLObjectClass> {
    let client = Client::new();

    tracing::debug!("querying object class of {}", irr_object);
    let determine_gq = json!({
        "query": format!(r#"{{ rpslObjects(rpslPk: "{}") {{ objectClass }} }}"#, irr_object.to_uppercase())
    });
    let response: Value = post_graphql(&client, determine_gq).await?;
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

pub async fn query_prefixes(irr_object: &str, ipv6: bool) -> anyhow::Result<Vec<String>> {
    let client = Client::new();

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
            let resp: Value = post_graphql(&client, gq).await?;
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
            let resp: Value = post_graphql(&client, gq).await?;
            extract_prefixes(&resp["data"]["asSetPrefixes"])?
        }
        RPSLObjectClass::RouteSet => {
            // recursiveSetMembers handles recursion, returns flat members (prefixes)
            let gq = json!({
                "query": format!(r#"{{ recursiveSetMembers(setNames: ["{}"]) {{ members }} }}"#, irr_object.to_uppercase())
            });
            let resp: Value = post_graphql(&client, gq).await?;
            let members = resp["data"]["recursiveSetMembers"]
                .as_array()
                .ok_or(anyhow!("No data"))?
                .get(0)
                .ok_or(anyhow!("No members"))?["members"]
                .as_array()
                .ok_or(anyhow!("Invalid members"))?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<String>>();
            // Filter by IP version (no server-side ipVersion for this query)
            members
                .into_iter()
                .filter(|p| {
                    if ipv6 {
                        p.contains(':')
                    } else {
                        !p.contains(':')
                    }
                })
                .collect()
        }
    };

    // Dedupe and sort
    let mut unique: HashSet<String> = prefixes.into_iter().collect();
    let mut sorted: Vec<String> = unique.drain().collect();
    sorted.sort();
    Ok(sorted)
}

async fn post_graphql(client: &Client, payload: Value) -> Result<Value, Error> {
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
        .get(0)
        .ok_or(anyhow!("No entries"))?["prefixes"]
        .as_array()
        .ok_or(anyhow!("Invalid prefixes"))?
        .iter()
        .map(|v| v.as_str().ok_or(anyhow!("not string")).map(str::to_string))
        .collect::<Result<Vec<_>, _>>()
}
