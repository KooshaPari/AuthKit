use std::{env, net::SocketAddr};

use axum::{routing::get, Router};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let bind_addr: SocketAddr =
        env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string()).parse()?;

    let app = Router::new().route("/health", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!(%bind_addr, "serving authvault example");
    axum::serve(listener, app).await?;

    Ok(())
}
