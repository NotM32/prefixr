use axum::{Router, extract::Path, http::StatusCode, response::IntoResponse, routing::get};
#[cfg(feature = "lambda")]
use lambda_http::{Error, run};
use serde::Deserialize;
use std::env;

mod format;
mod irr;

#[derive(Deserialize)]
struct PrefixListParams {
    ip_version: String,
    irr_object: String,
    min_length: Option<u8>,
}

impl Default for PrefixListParams {
    fn default() -> Self {
        Self {
            ip_version: "ipv4".to_string(),
            irr_object: "".to_string(),
            min_length: None,
        }
    }
}

async fn get_prefix_list(
    Path(PrefixListParams {
        ip_version,
        irr_object,
        min_length,
    }): Path<PrefixListParams>,
) -> impl IntoResponse {
    tracing::info!(
        "received params {} {} {}",
        ip_version,
        irr_object,
        min_length.unwrap_or(250)
    );
    // Parse IP version
    match (ip_version.as_str(), min_length) {
        ("ipv4", Some(min_length)) if min_length > 32 => {
            return (
                StatusCode::BAD_REQUEST,
                "min_length must not be greater than 32 for IPv4".to_string(),
            );
        }
        ("ipv6", Some(min_length)) if min_length > 128 => {
            return (
                StatusCode::BAD_REQUEST,
                "min_length must not be greater than 128 for IPv6".to_string(),
            );
        }
        ("ipv4" | "ipv6", _) => {}
        (_, _) => {
            return (
                StatusCode::BAD_REQUEST,
                "ip_version must be one of 'ipv4' or 'ipv6'".to_string(),
            );
        }
    }

    let ipv6 = ip_version == "ipv6";

    // Run Query
    match irr::query_prefixes(&irr_object, ipv6).await {
        Ok(prefixes) => {
            let prefix_list = format::format_as_prefix_list(&prefixes, min_length);

            (StatusCode::OK, prefix_list)
        }
        Err(_) => (StatusCode::BAD_REQUEST, "Bad request".to_string()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let app = Router::new()
        .route(
            "/{ip_version}/prefix-list/{irr_object}",
            get(get_prefix_list),
        )
        .route(
            "/{ip_version}/prefix-list/{irr_object}/{min_length}",
            get(get_prefix_list),
        );

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
