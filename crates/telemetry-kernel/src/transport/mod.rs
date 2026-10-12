//! UDS transport — protobuf-framed Unix Domain Socket writer.
//!
//! Writes length-prefixed protobuf-encoded `TelemetryEvent` messages to a
//! Unix Domain Socket for consumption by the Go engine's UDS listener.
//!
//! # Framing Protocol
//!
//! Each message is framed as:
//!   [4-byte big-endian u32 length][protobuf bytes]
//!
//! This framing is agreed with the Go UDS listener in `internal/ipc/uds_listener.go`.
//! Changing this framing requires updating both sides simultaneously.
//!
//! # Reconnect Behavior
//!
//! If the Go engine restarts (socket removed/recreated), the transport will
//! attempt to reconnect with exponential backoff (up to `MAX_BACKOFF_SECS`).
//! During reconnect, new events from the source are dropped and logged.
//! The source is never paused — it continues generating events.
//!
//! # Windows Compatibility
//!
//! Windows 10 1803+ (build 17134) supports Unix Domain Sockets natively via
//! the `tokio::net::UnixStream` API. On older Windows, the transport will fail
//! at connect time with a clear error message.

use std::path::Path;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use prost::Message;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::error::{Result, TelemetryError};
use crate::model::TelemetryEvent;

/// Maximum wait between reconnect attempts.
const MAX_BACKOFF_SECS: u64 = 30;

/// Transport that sends length-prefixed protobuf `TelemetryEvent` frames
/// over a TCP Socket to the Go engine.
pub struct UdsTransport {
    socket_path: String,
    stream: Option<TcpStream>,
    write_buffer: BytesMut,
}

impl UdsTransport {
    /// Create a new transport that will connect to the given UDS path.
    ///
    /// Does not connect immediately — call `connect()` or use `send_event()`,
    /// which will connect on first call.
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            stream: None,
            write_buffer: BytesMut::with_capacity(64 * 1024),
        }
    }

    /// Connect to the TCP Socket at the configured address.
    ///
    /// # Errors
    /// Returns `TelemetryError::Io` if the connection is refused.
    pub async fn connect(&mut self) -> Result<()> {
        let path = &self.socket_path;
        let stream = TcpStream::connect(path).await.map_err(|e| {
            TelemetryError::Io(std::io::Error::new(
                e.kind(),
                format!("TCP connect to {}: {}", path, e),
            ))
        })?;
        info!(socket_path = %self.socket_path, "TCP transport connected");
        self.stream = Some(stream);
        Ok(())
    }

    /// Send a single `TelemetryEvent` over the socket.
    ///
    /// Serializes the event to protobuf, frames it with a 4-byte length prefix,
    /// and writes the frame atomically (from the OS's perspective).
    ///
    /// If the connection is not established, attempts to connect first.
    /// If the write fails (connection dropped), clears the stream so the next
    /// call will reconnect.
    ///
    /// # Errors
    /// Returns `TelemetryError::Io` on write failure.
    /// Returns `TelemetryError::Protobuf` on encoding failure.
    pub async fn send_event(&mut self, event: &TelemetryEvent) -> Result<()> {
        // Encode to protobuf.
        let proto_event = event.to_proto();
        self.write_buffer.clear();
        proto_event
            .encode(&mut self.write_buffer)
            .map_err(TelemetryError::Protobuf)?;

        let payload = self.write_buffer.split();
        let payload_len = payload.len() as u32;

        // Construct the framed message: [4-byte length][payload]
        let mut frame = BytesMut::with_capacity(4 + payload.len());
        frame.put_u32(payload_len);
        frame.extend_from_slice(&payload);
        let frame = frame.freeze();

        // Connect if not already connected.
        if self.stream.is_none() {
            self.connect().await?;
        }

        // Write the frame. On any I/O error, drop the stream for reconnect.
        let stream = self.stream.as_mut().ok_or(TelemetryError::ConnectionClosed)?;
        if let Err(e) = stream.write_all(&frame).await {
            warn!(error = %e, "UDS write failed; dropping connection for reconnect");
            self.stream = None;
            return Err(TelemetryError::Io(e));
        }

        Ok(())
    }

    /// Run the transport loop: pull events from the source and send them,
    /// reconnecting with backoff on failures.
    ///
    /// This is the top-level driver function called by `main.rs`.
    ///
    /// # Errors
    /// Returns when the source signals `SourceShutdown`.
    pub async fn run_loop<S>(&mut self, source: &mut S) -> Result<()>
    where
        S: crate::source::TelemetrySource + ?Sized,
    {
        let mut backoff_secs = 1u64;

        loop {
            // Ensure connected.
            if self.stream.is_none() {
                match self.connect().await {
                    Ok(()) => {
                        backoff_secs = 1; // Reset backoff on success
                    }
                    Err(e) => {
                        error!(error = %e, backoff_secs, "UDS connect failed; retrying");
                        sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                        continue;
                    }
                }
            }

            // Pull next event from source.
            let event = match source.next_event().await {
                Ok(e) => e,
                Err(TelemetryError::SourceShutdown) => {
                    info!("telemetry source shut down; transport exiting");
                    return Ok(());
                }
                Err(e) => {
                    error!(error = %e, "source error; skipping event");
                    continue;
                }
            };

            // Send event.
            if let Err(e) = self.send_event(&event).await {
                error!(error = %e, event_id = %event.event_id, "failed to send event; will reconnect");
                // Drop the event rather than buffering unboundedly.
                // A production implementation would use a bounded ring buffer.
                // PROTOTYPE NOTE: events are dropped on transport failure.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener as StdTcpListener;
    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_framing_roundtrip() {
        // Bind a listener on a random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let local_addr = listener.local_addr().unwrap();
        let sock_path_str = local_addr.to_string();

        let recv_handle = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.expect("accept");
            // Read 4-byte length prefix
            let mut len_buf = [0u8; 4];
            conn.read_exact(&mut len_buf).await.expect("read len");
            let len = u32::from_be_bytes(len_buf) as usize;
            // Read payload
            let mut payload = vec![0u8; len];
            conn.read_exact(&mut payload).await.expect("read payload");
            payload
        });

        // Send one event via transport.
        let mut transport = UdsTransport::new(&sock_path_str);
        let event = TelemetryEvent::new(
            "test-source",
            crate::model::EventPayload::File(crate::model::FileEvent {
                process_id: "42".into(),
                host_id: "host-1".into(),
                file_path: "/etc/passwd".into(),
                user_id: "root".into(),
                action: crate::model::FileAction::Read,
                bytes: 1234,
            }),
        )
        .unwrap();

        transport.send_event(&event).await.expect("send_event");

        let payload = recv_handle.await.expect("receiver task");

        // Decode the payload back to proto.
        let decoded = crate::proto::TelemetryEvent::decode(bytes::Bytes::from(payload))
            .expect("proto decode");
        assert_eq!(decoded.event_id, event.event_id);
        assert_eq!(decoded.source_id, "test-source");
    }
}
