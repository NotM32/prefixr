use axum::{Router, extract::Path, http::StatusCode, response::IntoResponse, routing::get};
use serde::{Deserialize, Serialize};
use std::env;

#[cfg(feature = "lambda")]
use lambda_http::{Error, run};

mod format;
mod irr;
mod rpsl;

/// IP Version Enum
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum IPVersion {
    IPv4,
    IPv6,
}

/// URL Params for Prefix List generator
#[derive(Deserialize)]
struct PrefixListParams {
    ip_version: Option<IPVersion>,
    irr_object: String,
    min_length: Option<u8>,
}

impl Default for PrefixListParams {
    fn default() -> Self {
        Self {
            ip_version: Some(IPVersion::IPv4),
            irr_object: "".to_string(),
            min_length: None,
        }
    }
}

/// Route handler for /{ip_version?}/prefix-list/{irr_object}/{max_length?}
#[tracing::instrument]
async fn get_prefix_list(
    Path(PrefixListParams {
        ip_version,
        irr_object,
        min_length,
    }): Path<PrefixListParams>,
) -> impl IntoResponse {
    // Log request
    tracing::info!(
        "received params {} {}",
        irr_object,
        min_length.unwrap_or(250)
    );

    // Parse IP version
    match (&ip_version, min_length) {
        (Some(IPVersion::IPv4) | None, Some(min_length)) if min_length > 32 => {
            return (
                StatusCode::BAD_REQUEST,
                "min_length must not be greater than 32 for IPv4".to_string(),
            );
        }
        (Some(IPVersion::IPv6), Some(min_length)) if min_length > 128 => {
            return (
                StatusCode::BAD_REQUEST,
                "min_length must not be greater than 128 for IPv6".to_string(),
            );
        }
        (_, _) => {}
    }

    let ipv6 = matches!(ip_version, Some(IPVersion::IPv6));

    // Run Query
    match irr::query_prefixes(&irr_object, ipv6).await {
        Ok(prefixes) => {
            let prefix_list = format::format_as_prefix_list(&prefixes, min_length);

            (StatusCode::OK, prefix_list)
        }
        Err(_) => (StatusCode::BAD_REQUEST, "Bad request".to_string()),
    }
}

/// URL Params for Prefix List generator
#[derive(Deserialize)]
struct ASPathACLParams {
    irr_object: String,
}

/// Route handler for /as-path-acl/{irr_object}
///
/// Queries the IRR for the as-set's recursive members and formats the
/// result as an Arista eOS / Cisco-style AS-path access-list.
#[tracing::instrument]
async fn get_aspath_acl(
    Path(ASPathACLParams { irr_object }): Path<ASPathACLParams>,
) -> impl IntoResponse {
    match irr::query_object_type(irr_object.as_str()).await {
        Ok(irr::RPSLObjectClass::AsSet) => match irr::query_as_set_members(&irr_object).await {
            Ok(members) => {
                let acl = format::format_as_as_path_acl(&irr_object, &members);
                (StatusCode::OK, acl)
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error occurred while fetching members: {}", e),
            ),
        },
        Ok(_) => (
            StatusCode::NOT_ACCEPTABLE,
            format!(
                "irr_object must be of type as-set, value '{}' is not valid",
                irr_object
            ),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error occurred while fetching data: {}", e),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let app = Router::new()
        .route("/prefix-list/{irr_object}", get(get_prefix_list))
        .route(
            "/{ip_version}/prefix-list/{irr_object}",
            get(get_prefix_list),
        )
        .route(
            "/{ip_version}/prefix-list/{irr_object}/{min_length}",
            get(get_prefix_list),
        )
        .route("/as-path-acl/{irr_object}", get(get_aspath_acl));

    // Detect if running on Lambda via env var
    if env::var("AWS_LAMBDA_RUNTIME_API").is_ok() {
        // CloudWatch Logs
        lambda_http::tracing::init_default_subscriber();

        run(app).await
    } else {
        // construct a subscriber that prints formatted traces to stdout
        let subscriber = tracing_subscriber::FmtSubscriber::new();
        // use that subscriber to process traces emitted after this point
        tracing::subscriber::set_global_default(subscriber)?;

        // Local dev: Bind to port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;

        axum::serve(listener, app).await?;

        Ok(())
    }
}
