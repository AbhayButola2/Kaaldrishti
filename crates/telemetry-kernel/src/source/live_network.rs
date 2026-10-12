use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use crate::error::{Result, TelemetryError};
use crate::model::{EventPayload, NetworkDirection, NetworkEvent, TelemetryEvent};
use crate::source::TelemetrySource;

/// A live network telemetry source using `pcap` and `pnet`.
pub struct LiveNetworkSource {
    source_id: String,
    device_name: Option<String>,
    receiver: Option<mpsc::Receiver<TelemetryEvent>>,
    shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl LiveNetworkSource {
    pub fn new(source_id: String, device_name: Option<String>) -> Self {
        Self {
            source_id,
            device_name,
            receiver: None,
            shutdown_sender: None,
        }
    }
}

#[async_trait]
impl TelemetrySource for LiveNetworkSource {
    async fn start(&mut self) -> Result<()> {
        let (tx, rx) = mpsc::channel(1024);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        
        self.receiver = Some(rx);
        self.shutdown_sender = Some(shutdown_tx);

        let device_name = self.device_name.clone();
        let source_id = self.source_id.clone();

        info!("Starting LiveNetworkSource on device: {:?}", device_name);

        // Spawn a blocking thread for pcap since it blocks on packet read
        std::thread::spawn(move || {
            let device = if let Some(name) = device_name {
                match pcap::Device::list().unwrap_or_default().into_iter().find(|d| d.name == name) {
                    Some(d) => d,
                    None => {
                        error!("Specified device '{}' not found. Available devices:", name);
                        for dev in pcap::Device::list().unwrap_or_default() {
                            error!("- {} (Desc: {:?})", dev.name, dev.desc);
                        }
                        return;
                    }
                }
            } else {
                match pcap::Device::lookup() {
                    Ok(Some(d)) => d,
                    _ => {
                        error!("No default network device found.");
                        return;
                    }
                }
            };

            info!("Using device {} (Desc: {:?})", device.name, device.desc);

            let mut cap = match pcap::Capture::from_device(device)
                .expect("Failed to bind device")
                .promisc(true)
                .snaplen(65535)
                .timeout(500) // 500ms timeout so we can check for shutdown
                .open() 
            {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to open capture device: {}", e);
                    return;
                }
            };

            loop {
                // Check if shutdown was requested
                if shutdown_rx.try_recv().is_ok() {
                    info!("LiveNetworkSource capture thread shutting down.");
                    break;
                }

                match cap.next_packet() {
                    Ok(packet) => {
                        // Parse Ethernet
                        if let Some(eth) = EthernetPacket::new(packet.data) {
                            if eth.get_ethertype() == EtherTypes::Ipv4 {
                                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                                    let src_ip = ipv4.get_source().to_string();
                                    let dst_ip = ipv4.get_destination().to_string();
                                    
                                    let mut src_port = 0;
                                    let mut dst_port = 0;
                                    let mut protocol = String::new();

                                    match ipv4.get_next_level_protocol() {
                                        pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                                src_port = tcp.get_source() as i32;
                                                dst_port = tcp.get_destination() as i32;
                                                protocol = "TCP".to_string();
                                            }
                                        }
                                        pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                                src_port = udp.get_source() as i32;
                                                dst_port = udp.get_destination() as i32;
                                                protocol = "UDP".to_string();
                                            }
                                        }
                                        _ => {
                                            // Ignore other protocols for now
                                            continue;
                                        }
                                    }

                                    if !protocol.is_empty() {
                                        let network_event = NetworkEvent {
                                            process_id: "live-capture".to_string(),
                                            host_id: "local-machine".to_string(),
                                            src_ip,
                                            src_port,
                                            dst_ip,
                                            dst_port,
                                            protocol,
                                            direction: NetworkDirection::Outbound,
                                            bytes_sent: packet.header.len as i64,
                                            bytes_recv: 0,
                                        };

                                        if let Ok(event) = TelemetryEvent::new(
                                            &source_id,
                                            EventPayload::Network(network_event),
                                        ) {
                                            if tx.blocking_send(event).is_err() {
                                                // Receiver closed
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Timeout is expected, just loop again
                        continue;
                    }
                    Err(e) => {
                        error!("Packet capture error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn next_event(&mut self) -> Result<TelemetryEvent> {
        if let Some(rx) = self.receiver.as_mut() {
            match rx.recv().await {
                Some(event) => Ok(event),
                None => Err(TelemetryError::SourceShutdown),
            }
        } else {
            Err(TelemetryError::SourceShutdown)
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }
        Ok(())
    }

    fn source_id(&self) -> &str {
        &self.source_id
    }
}
