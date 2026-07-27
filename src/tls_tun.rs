// Copyright 2020 Developers of the http-tunnel project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TUN-over-TLS (TCP) VPN module — dual-connection architecture.
//!
//! Uses **two TLS connections** for each tunnel: one for sending (TUN→TLS)
//! and one for receiving (TLS→TUN). This avoids the deadlock inherent in
//! single-connection bidirectional I/O with TLS (which requires splitting
//! the stream, and where write_all can block reads and vice versa).
//!
//! ## Protocol
//! 1. Client opens two TLS connections to the server
//! 2. First byte on each connection is the role marker:
//!    - `0x01` = SEND (client writes framed TUN packets, server reads)
//!    - `0x02` = RECV (server writes framed TUN packets, client reads)
//! 3. Server pairs connections by peer IP address
//! 4. Framing: [u16 big-endian length][IP packet bytes]

use log::{error, info, warn};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Role markers sent as the first byte on each connection.
const ROLE_SEND: u8 = 0x01; // Client→Server data direction
const ROLE_RECV: u8 = 0x02; // Server→Client data direction

/// Maximum IP packet size we support (standard MTU).
const TUN_MTU: u16 = 1400;
/// Buffer size for reading from TUN device.
const BUF_SIZE: usize = TUN_MTU as usize + 4;

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

    // Pending connections waiting for their partner
    // Key: peer IP, Value: (role, stream)
    type PendingMap = Arc<Mutex<HashMap<std::net::IpAddr, PendingConn>>>;

    struct PendingConn {
        send_stream: Option<tokio_rustls::server::TlsStream<TcpStream>>,
        recv_stream: Option<tokio_rustls::server::TlsStream<TcpStream>>,
    }

    let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let tun = tun.clone();
        let pending = pending.clone();
        let _ = tcp_stream.set_nodelay(true);

        tokio::spawn(async move {
            // TLS handshake
            let mut tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("TLS handshake failed from {}: {}", peer_addr, e);
                    return;
                }
            };

            // Read role marker
            let mut role_buf = [0u8; 1];
            if let Err(e) = tls_stream.read_exact(&mut role_buf).await {
                warn!("Failed to read role from {}: {}", peer_addr, e);
                return;
            }

            let role = role_buf[0];
            let peer_ip = peer_addr.ip();
            info!("TLS connection from {} with role 0x{:02x}", peer_addr, role);

            let mut map = pending.lock().await;
            let entry = map.entry(peer_ip).or_insert(PendingConn {
                send_stream: None,
                recv_stream: None,
            });

            match role {
                ROLE_SEND => entry.send_stream = Some(tls_stream),
                ROLE_RECV => entry.recv_stream = Some(tls_stream),
                _ => {
                    warn!("Unknown role 0x{:02x} from {}", role, peer_addr);
                    return;
                }
            }

            // Check if we have both connections
            if entry.send_stream.is_some() && entry.recv_stream.is_some() {
                let send_stream = entry.send_stream.take().unwrap();
                let recv_stream = entry.recv_stream.take().unwrap();
                map.remove(&peer_ip);
                drop(map); // Release lock before starting relay

                info!("Both connections paired for {}. Starting relay.", peer_ip);

                // Task 1: Client→Server (read from SEND TLS, write to TUN)
                let tun_write = tun.clone();
                let send_task = tokio::spawn(async move {
                    if let Err(e) = tls_to_tun(send_stream, tun_write).await {
                        warn!("Client→TUN relay stopped for {}: {}", peer_ip, e);
                    }
                });

                // Task 2: Server→Client (read from TUN, write to RECV TLS)
                let tun_read = tun.clone();
                let recv_task = tokio::spawn(async move {
                    if let Err(e) = tun_to_tls(tun_read, recv_stream).await {
                        warn!("TUN→Client relay stopped for {}: {}", peer_ip, e);
                    }
                });

                tokio::select! {
                    _ = send_task => {}
                    _ = recv_task => {}
                }
                info!("Relay ended for {}", peer_ip);
            } else {
                info!("Waiting for partner connection from {}", peer_ip);
                drop(map);
            }
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
        info!("Connecting two TLS channels to {}...", server_addr);

        let connect_result = async {
            // Connection 1: SEND (client writes TUN packets)
            let tcp1 = TcpStream::connect(server_addr).await?;
            tcp1.set_nodelay(true)?;
            let mut send_stream = tls_connector
                .connect(server_name.clone(), tcp1)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
            send_stream.write_all(&[ROLE_SEND]).await?;
            send_stream.flush().await?;
            info!("SEND channel connected");

            // Connection 2: RECV (client reads TUN packets)
            let tcp2 = TcpStream::connect(server_addr).await?;
            tcp2.set_nodelay(true)?;
            let mut recv_stream = tls_connector
                .connect(server_name.clone(), tcp2)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
            recv_stream.write_all(&[ROLE_RECV]).await?;
            recv_stream.flush().await?;
            info!("RECV channel connected");

            // Task 1: TUN → SEND TLS (client writes)
            let tun_read = tun.clone();
            let send_task = tokio::spawn(async move {
                tun_to_tls(tun_read, send_stream).await
            });

            // Task 2: RECV TLS → TUN (client reads)
            let tun_write = tun.clone();
            let recv_task = tokio::spawn(async move {
                tls_to_tun(recv_stream, tun_write).await
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
async fn tun_to_tls<W: AsyncWriteExt + Unpin>(
    tun: Arc<tun2::AsyncDevice>,
    mut writer: W,
) -> io::Result<()> {
    let mut frame_buf = vec![0u8; 2 + BUF_SIZE];

    info!("tun_to_tls: relay started");

    loop {
        let n = tun.recv(&mut frame_buf[2..]).await?;
        if n == 0 {
            continue;
        }

        // Write length prefix + packet in one write
        let len = n as u16;
        frame_buf[..2].copy_from_slice(&len.to_be_bytes());
        writer.write_all(&frame_buf[..2 + n]).await?;
        writer.flush().await?;
    }
}

/// Relay: read framed packets from TLS stream, write to TUN.
async fn tls_to_tun<R: AsyncReadExt + Unpin>(
    mut reader: R,
    tun: Arc<tun2::AsyncDevice>,
) -> io::Result<()> {
    let mut len_buf = [0u8; 2];
    let mut pkt_buf = vec![0u8; BUF_SIZE];

    info!("tls_to_tun: relay started");

    loop {
        // Read length prefix
        reader.read_exact(&mut len_buf).await?;
        let pkt_len = u16::from_be_bytes(len_buf) as usize;

        if pkt_len == 0 || pkt_len > BUF_SIZE {
            error!("Invalid packet length: {}", pkt_len);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid packet length: {}", pkt_len),
            ));
        }

        // Read packet
        reader.read_exact(&mut pkt_buf[..pkt_len]).await?;

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
