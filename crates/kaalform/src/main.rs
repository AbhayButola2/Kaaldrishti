//! Kaalform binary entrypoint.
//!
//! Starts the Kaalform MCP proxy gateway:
//! 1. Loads configuration from environment variables.
//! 2. Initialises the ManifestVerifier (Pillar 4) and ProvenanceFirewall (Pillar 5).
//! 3. Starts the Axum HTTP server on the configured listen address.
//! 4. Gracefully shuts down on Ctrl-C.
//!
//! ## Example Usage
//!
//! ```powershell
//! # Set required environment variables
//! $env:KAALFORM_UPSTREAM_MCP_URL = "http://localhost:9000"
//! $env:KAALFORM_KAALADRISHTI_ADDR = "127.0.0.1:9090"
//! $env:KAALFORM_DRIFT_THRESHOLD = "0.45"
//! $env:KAALFORM_REQUIRE_MANIFEST = "false"   # Set true for full Pillar 4 enforcement
//!
//! # Run Kaalform
//! cargo run --bin kaalform
//!
//! # The gateway is now listening on http://0.0.0.0:7070
//! ```
//!
//! ## Sending a Tool Call Through Kaalform
//!
//! ```bash
//! # Declare scope first
//! curl -X POST http://localhost:7070/mcp/v1/scope \
//!   -H "Content-Type: application/json" \
//!   -d '{"workflow_id":"wf-1","declared_scope":"Read customer database using sql_query"}'
//!
//! # Call a tool (proxied + gate-checked)
//! curl -X POST http://localhost:7070/mcp/v1/call \
//!   -H "Content-Type: application/json" \
//!   -H "X-Kaalform-Workflow-Id: wf-1" \
//!   -H "X-Kaalform-Principal-Id: alice@corp.internal" \
//!   -d '{"tool_id":"sql_query","arguments":{"query":"SELECT * FROM customers"}}'
//! ```

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use kaalform::config::Config;
use kaalform::gateway::{build_router, GatewayState};

#[tokio::main]
async fn main() {
    // Initialise structured JSON logging (same convention as Kaaladrishti engine).
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .with(fmt::layer().json())
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Kaalform agent execution firewall starting"
    );

    // Load configuration from environment variables.
    let config = Config::from_env().unwrap_or_else(|e| {
        eprintln!("kaalform: configuration error: {e}");
        std::process::exit(1);
    });

    info!(
        listen_addr = %config.listen_addr,
        upstream_mcp_url = %config.upstream_mcp_url,
        kaaladrishti_addr = %config.kaaladrishti_addr,
        drift_threshold = config.drift_threshold,
        require_manifest = config.require_manifest,
        "configuration loaded"
    );

    // Build shared gateway state.
    let state = GatewayState::new(config.clone()).unwrap_or_else(|e| {
        eprintln!("kaalform: failed to initialise gateway: {e}");
        std::process::exit(1);
    });
    let state = Arc::new(state);

    // Build the Axum router.
    let router = build_router(state);

    // Bind the listener.
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("kaalform: failed to bind {}: {e}", config.listen_addr);
            std::process::exit(1);
        });

    info!(
        addr = %config.listen_addr,
        "Kaalform gateway running. POST /mcp/v1/call to intercept tool calls."
    );
    info!(
        "Pillars active — Pillar 4 (manifest signing): {} | Pillar 5 (provenance firewall): enabled",
        if config.require_manifest { "enforcing" } else { "audit-only" }
    );

    // Serve with graceful shutdown on Ctrl-C.
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            signal::ctrl_c().await.ok();
            info!("kaalform: shutdown signal received");
        })
        .await
        .unwrap_or_else(|e| eprintln!("kaalform: server error: {e}"));

    info!("Kaalform gateway stopped.");
}
