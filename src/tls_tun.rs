// Copyright 2020 Developers of the http-tunnel project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TUN-over-TLS (TCP) VPN module — single-connection with `tokio::io::split`.
//!
//! Uses one TLS connection per peer, split into independent read/write halves.
//! This allows TLS to process incoming records (e.g. NewSessionTicket) via the
//! read half while the write half sends tunnel data — preventing the TCP ACK
//! stall seen with separate connections.
//!
//! ## Protocol
//! - Framing: `[u16 big-endian length][IP packet bytes]`
//! - Length 0 = keepalive heartbeat (silently discarded by receiver)

use log::{error, info, warn};
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Maximum IP packet size we support.
const TUN_MTU: u16 = 1400;
/// Buffer size for reading from TUN device.
const BUF_SIZE: usize = TUN_MTU as usize + 4;
/// Keepalive interval to prevent NAT timeout.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Run the TUN-over-TLS server.
pub async fn run_tls_tun_server(
    bind: SocketAddr,
    cert_path: &str,
    key_path: &str,
    tun_addr: Ipv4Addr,
    tun_netmask: Ipv4Addr,
) -> io::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tls_acceptor = build_tls_acceptor(cert_path, key_path)?;

    let listener = TcpListener::bind(bind).await?;
    info!("TLS TUN server listening on {}", bind);

    // Create TUN device
    let mut config = tun2::Configuration::default();
    config
        .address(tun_addr)
        .netmask(tun_netmask)
        .mtu(TUN_MTU)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let tun = Arc::new(tun2::create_as_async(&config).map_err(|e| {
        error!("Failed to create TUN device: {}", e);
        io::Error::new(io::ErrorKind::Other, e.to_string())
    })?);
    info!("TUN device created with address {}/{}", tun_addr, tun_netmask);

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let tun = tun.clone();
        let _ = tcp_stream.set_nodelay(true);

        tokio::spawn(async move {
            // TLS handshake
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("TLS handshake failed from {}: {}", peer_addr, e);
                    return;
                }
            };

            info!("TLS connection from {}. Starting relay.", peer_addr);

            // Split into read/write halves
            let (reader, writer) = tokio::io::split(tls_stream);

            // Task 1: TLS→TUN (read from client, write to TUN)
            let tun_write = tun.clone();
            let peer_ip = peer_addr.ip();
            let read_task = tokio::spawn(async move {
                if let Err(e) = tls_to_tun(reader, tun_write).await {
                    warn!("Client→TUN relay stopped for {}: {}", peer_ip, e);
                }
            });

            // Task 2: TUN→TLS (read from TUN, write to client)
            let tun_read = tun.clone();
            let peer_ip2 = peer_addr.ip();
            let write_task = tokio::spawn(async move {
                if let Err(e) = tun_to_tls(tun_read, writer).await {
                    warn!("TUN→Client relay stopped for {}: {}", peer_ip2, e);
                }
            });

            tokio::select! {
                _ = read_task => {}
                _ = write_task => {}
            }
            info!("Relay ended for {}", peer_addr);
        });
    }
}

/// Run the TUN-over-TLS client with auto-reconnect.
pub async fn run_tls_tun_client(
    server_addr: SocketAddr,
    tun_name: &str,
    tun_addr: Ipv4Addr,
    tun_netmask: Ipv4Addr,
    insecure: bool,
) -> io::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Create TUN device once
    let mut config = tun2::Configuration::default();
    config
        .address(tun_addr)
        .netmask(tun_netmask)
        .mtu(TUN_MTU)
        .up();

    #[cfg(target_os = "linux")]
    {
        config.platform_config(|p| {
            p.ensure_root_privileges(true);
        });
        config.name(tun_name);
    }

    let tun = Arc::new(tun2::create_as_async(&config).map_err(|e| {
        error!("Failed to create TUN device '{}': {}", tun_name, e);
        io::Error::new(io::ErrorKind::Other, e.to_string())
    })?);
    info!("TUN device '{}' created with address {}/{}", tun_name, tun_addr, tun_netmask);

    // Build TLS connector
    let tls_connector = build_tls_connector(insecure)?;
    let server_name = rustls::pki_types::ServerName::IpAddress(
        std::net::IpAddr::from(server_addr.ip()).into(),
    );

    // Auto-reconnect loop
    loop {
        info!("Connecting to {}...", server_addr);

        let connect_result = async {
            let tcp = TcpStream::connect(server_addr).await?;
            tcp.set_nodelay(true)?;
            let tls_stream = tls_connector
                .connect(server_name.clone(), tcp)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
            info!("TLS connected to {}", server_addr);

            // Split into read/write halves
            let (reader, writer) = tokio::io::split(tls_stream);

            // Task 1: TUN→TLS (read from TUN, write to server)
            let tun_read = tun.clone();
            let send_task = tokio::spawn(async move {
                tun_to_tls(tun_read, writer).await
            });

            // Task 2: TLS→TUN (read from server, write to TUN)
            let tun_write = tun.clone();
            let recv_task = tokio::spawn(async move {
                tls_to_tun(reader, tun_write).await
            });

            // Wait for either direction to finish
            tokio::select! {
                r = send_task => {
                    if let Ok(Err(e)) = r {
                        warn!("TUN→TLS relay stopped: {}", e);
                    }
                }
                r = recv_task => {
                    if let Ok(Err(e)) = r {
                        warn!("TLS→TUN relay stopped: {}", e);
                    }
                }
            }
            Ok::<(), io::Error>(())
        }
        .await;

        if let Err(e) = connect_result {
            warn!("Connection failed: {}. Reconnecting in 5s...", e);
        } else {
            warn!("Connection closed. Reconnecting in 5s...");
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Relay: read framed packets from TUN, write to TLS stream.
/// Sends keepalive heartbeats during idle periods to prevent NAT timeout.
async fn tun_to_tls<W: AsyncWriteExt + Unpin>(
    tun: Arc<tun2::AsyncDevice>,
    mut writer: W,
) -> io::Result<()> {
    let mut frame_buf = vec![0u8; 2 + BUF_SIZE];
    let keepalive_frame: [u8; 2] = [0x00, 0x00]; // Zero-length = keepalive

    info!("tun_to_tls: relay started (keepalive every {}s)", KEEPALIVE_INTERVAL.as_secs());

    loop {
        tokio::select! {
            result = tun.recv(&mut frame_buf[2..]) => {
                let n = result?;
                if n == 0 {
                    continue;
                }

                info!("TUN→TLS: {} bytes (first: 0x{:02x})", n, frame_buf[2]);

                // Write length prefix + packet in one write
                let len = n as u16;
                frame_buf[..2].copy_from_slice(&len.to_be_bytes());
                writer.write_all(&frame_buf[..2 + n]).await?;
                writer.flush().await?;
            }
            _ = tokio::time::sleep(KEEPALIVE_INTERVAL) => {
                // Send keepalive heartbeat
                writer.write_all(&keepalive_frame).await?;
                writer.flush().await?;
                info!("TUN→TLS: keepalive sent");
            }
        }
    }
}

/// Relay: read framed packets from TLS stream, write to TUN.
/// Handles keepalive frames (length=0) by silently discarding them.
async fn tls_to_tun<R: AsyncReadExt + Unpin>(
    mut reader: R,
    tun: Arc<tun2::AsyncDevice>,
) -> io::Result<()> {
    let mut len_buf = [0u8; 2];
    let mut pkt_buf = vec![0u8; BUF_SIZE];

    info!("tls_to_tun: relay started, waiting for data...");

    loop {
        // Read length prefix
        reader.read_exact(&mut len_buf).await?;
        let pkt_len = u16::from_be_bytes(len_buf) as usize;

        // Keepalive frame (zero length) - just skip
        if pkt_len == 0 {
            continue;
        }

        if pkt_len > BUF_SIZE {
            error!("Invalid packet length: {}", pkt_len);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid packet length: {}", pkt_len),
            ));
        }

        // Read packet
        reader.read_exact(&mut pkt_buf[..pkt_len]).await?;
        info!("TLS→TUN: {} bytes (first: 0x{:02x})", pkt_len, pkt_buf[0]);

        // Write to TUN
        tun.send(&pkt_buf[..pkt_len]).await?;
    }
}

/// Build TLS acceptor for server.
fn build_tls_acceptor(cert_path: &str, key_path: &str) -> io::Result<TlsAcceptor> {
    let cert_file = File::open(cert_path).map_err(|e| {
        error!("Error opening certificate file {}: {}", cert_path, e);
        e
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|c| c.ok())
        .collect();

    let key_file = File::open(key_path).map_err(|e| {
        error!("Error opening key file {}: {}", key_path, e);
        e
    })?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| {
            error!("Error reading private key: {}", e);
            io::Error::new(io::ErrorKind::InvalidData, e)
        })?
        .ok_or_else(|| {
            error!("No private key found in {}", key_path);
            io::Error::new(io::ErrorKind::InvalidData, "No private key found")
        })?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            error!("TLS config error: {}", e);
            io::Error::new(io::ErrorKind::InvalidData, e)
        })?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build TLS connector for client.
fn build_tls_connector(insecure: bool) -> io::Result<TlsConnector> {
    let config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Insecure TLS verifier that accepts any certificate (for self-signed certs).
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
