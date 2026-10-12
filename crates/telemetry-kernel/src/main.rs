//! telemetry-kernel binary entrypoint.
//!
//! Reads configuration from environment variables, starts the synthetic telemetry
//! source, and runs the UDS transport loop until shutdown signal.

use std::env;

use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use telemetry_kernel::source::live_network::LiveNetworkSource;
use telemetry_kernel::source::synthetic::{SyntheticConfig, SyntheticTelemetrySource};
use telemetry_kernel::source::TelemetrySource;
use telemetry_kernel::transport::UdsTransport;

#[tokio::main]
async fn main() {
    // Initialize structured JSON logging.
    // RUST_LOG env controls the filter; default to "info".
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .with(fmt::layer().json())
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "telemetry-kernel starting"
    );

    // Load configuration from environment variables.
    // No hardcoded credentials or paths — all configurable.
    let socket_path = env::var("KAALADRISHTI_UDS_PATH")
        .unwrap_or_else(|_| "127.0.0.1:9090".to_string());

    let event_interval_ms: u64 = env::var("KAALADRISHTI_EVENT_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    let anomaly_probability: f64 = env::var("KAALADRISHTI_ANOMALY_PROB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.05);

    let max_events: Option<u64> = env::var("KAALADRISHTI_MAX_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok());

    info!(
        socket_path = %socket_path,
        event_interval_ms,
        anomaly_probability,
        "configuration loaded"
    );

    let source_type = env::var("KAALADRISHTI_SOURCE").unwrap_or_else(|_| "synthetic".to_string());
    let mut source: Box<dyn TelemetrySource> = if source_type == "live" {
        let device_name = env::var("KAALADRISHTI_LIVE_DEVICE").ok();
        info!("Using LiveNetworkSource (device: {:?})", device_name);
        Box::new(LiveNetworkSource::new("live-network-1".to_string(), device_name))
    } else {
        info!("Using SyntheticTelemetrySource");
        Box::new(SyntheticTelemetrySource::new(SyntheticConfig {
            event_interval_ms,
            anomaly_probability,
            source_id: "synthetic-telemetry-gen-1".to_string(),
            max_events,
        }))
    };

    if let Err(e) = source.start().await {
        error!(error = %e, "failed to start telemetry source");
        std::process::exit(1);
    }

    // Build the UDS transport.
    let mut transport = UdsTransport::new(socket_path);

    // Run the transport loop in a task, listen for Ctrl-C.
    let transport_task = tokio::spawn(async move {
        transport.run_loop(source.as_mut()).await
    });

    // Graceful shutdown on SIGINT/SIGTERM.
    tokio::select! {
        result = transport_task => {
            match result {
                Ok(Ok(())) => info!("transport loop exited cleanly"),
                Ok(Err(e)) => error!(error = %e, "transport loop error"),
                Err(e) => error!(error = %e, "transport task panicked"),
            }
        }
        _ = signal::ctrl_c() => {
            info!("received Ctrl-C; shutting down");
        }
    }

    info!("telemetry-kernel stopped");
}
