// Copyright 2020 Developers of the http-tunnel project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TUN-over-QUIC VPN module.
//!
//! Creates a TUN network interface and tunnels IP packets through a QUIC connection.
//! For the ISP this looks like regular HTTP/3 traffic (QUIC on UDP port 443).
//!
//! ## Server mode (`tun-server`)
//! - Creates TUN device (e.g. `quic0`) with given IP
//! - Listens for QUIC connections
//! - Relays IP packets between TUN and QUIC bi-stream
//! - Requires NAT/masquerade + ip_forward on the host
//!
//! ## Client mode (`tun-client`)
//! - Creates TUN device (e.g. `quic1`) with given IP
//! - Connects to QUIC server
//! - Relays IP packets between TUN and QUIC bi-stream
//! - Auto-reconnects on connection loss

use log::{error, info, warn};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::quic::build_quic_server_config;

/// Maximum IP packet size we support (standard MTU).
const TUN_MTU: u16 = 1400;
/// Buffer size for reading from TUN device.
const BUF_SIZE: usize = TUN_MTU as usize + 4; // extra room for TUN header on some platforms

/// Run the TUN-over-QUIC server.
///
/// 1. Creates a TUN device with the given address
/// 2. Accepts QUIC connections
/// 3. For each connection, relays IP packets between TUN and QUIC bi-stream
pub async fn run_tun_server(
    bind: SocketAddr,
    cert_path: &str,
    key_path: &str,
    tun_addr: Ipv4Addr,
    tun_netmask: Ipv4Addr,
) -> io::Result<()> {
    let server_config = build_quic_server_config(cert_path, key_path)?;

    let endpoint = quinn::Endpoint::server(server_config, bind).map_err(|e| {
        error!("Error creating QUIC endpoint on {}: {}", bind, e);
        io::Error::new(io::ErrorKind::AddrInUse, e)
    })?;

    info!("QUIC TUN server listening on {}", bind);

    // Create TUN device
    let mut config = tun2::Configuration::default();
    config
        .address(tun_addr)
        .netmask(tun_netmask)
        .mtu(TUN_MTU as u16)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let tun_dev = tun2::create_as_async(&config).map_err(|e| {
        error!("Error creating TUN device: {}", e);
        io::Error::new(io::ErrorKind::Other, e)
    })?;

    info!("TUN device created with address {}/{}", tun_addr, tun_netmask);

    // Split TUN into independent reader and writer
    let (tun_writer, tun_reader) = tun_dev.split().map_err(|e| {
        error!("Error splitting TUN device: {}", e);
        io::Error::new(io::ErrorKind::Other, e)
    })?;

    let tun_reader = Arc::new(tokio::sync::Mutex::new(tun_reader));
    let tun_writer = Arc::new(tokio::sync::Mutex::new(tun_writer));

    while let Some(incoming) = endpoint.accept().await {
        let reader = tun_reader.clone();
        let writer = tun_writer.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    info!(
                        "QUIC TUN connection from: {}",
                        connection.remote_address()
                    );
                    if let Err(e) = handle_tun_server_connection(connection, reader, writer).await {
                        error!("TUN connection error: {}", e);
                    }
                }
                Err(e) => {
                    error!("QUIC connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}

/// Run the TUN-over-QUIC client with auto-reconnect.
///
/// 1. Creates a TUN device with the given name and address
/// 2. Connects to the QUIC server
/// 3. Relays IP packets between TUN and QUIC bi-stream
/// 4. Reconnects automatically on connection loss
pub async fn run_tun_client(
    server_addr: SocketAddr,
    tun_name: &str,
    tun_addr: Ipv4Addr,
    tun_netmask: Ipv4Addr,
    insecure: bool,
) -> io::Result<()> {
    // Create TUN device
    let mut config = tun2::Configuration::default();
    config
        .tun_name(tun_name)
        .address(tun_addr)
        .netmask(tun_netmask)
        .mtu(TUN_MTU as u16)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let tun_dev = tun2::create_as_async(&config).map_err(|e| {
        error!("Error creating TUN device '{}': {}", tun_name, e);
        io::Error::new(io::ErrorKind::Other, e)
    })?;

    info!("TUN device '{}' created with address {}/{}", tun_name, tun_addr, tun_netmask);

    // Split TUN into independent reader and writer
    let (tun_writer, tun_reader) = tun_dev.split().map_err(|e| {
        error!("Error splitting TUN device: {}", e);
        io::Error::new(io::ErrorKind::Other, e)
    })?;

    let tun_reader = Arc::new(tokio::sync::Mutex::new(tun_reader));
    let tun_writer = Arc::new(tokio::sync::Mutex::new(tun_writer));

    // Client QUIC config
    let client_config = build_quic_client_config(insecure)?;

    loop {
        info!("Connecting to QUIC server at {}...", server_addr);

        let connect_result = async {
            let mut endpoint =
                quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().unwrap())
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            endpoint.set_default_client_config(client_config.clone());

            let connection = endpoint
                .connect(server_addr, "tunnel")
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

            info!("Connected to QUIC server {}", server_addr);

            handle_tun_client_connection(connection, tun_reader.clone(), tun_writer.clone()).await
        }
        .await;

        match connect_result {
            Ok(()) => {
                warn!("Connection closed gracefully, reconnecting...");
            }
            Err(e) => {
                error!("Connection error: {}, reconnecting in 5s...", e);
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Handle a single TUN-over-QUIC connection on the server side.
/// Accepts a bi-stream opened by the client and relays IP packets in both directions.
async fn handle_tun_server_connection(
    connection: quinn::Connection,
    tun_reader: Arc<tokio::sync::Mutex<tun2::DeviceReader>>,
    tun_writer: Arc<tokio::sync::Mutex<tun2::DeviceWriter>>,
) -> io::Result<()> {
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))?;

    info!("Bi-stream accepted, starting IP packet relay");

    relay_tun_quic(tun_reader, tun_writer, send, recv).await
}

/// Handle a single TUN-over-QUIC connection on the client side.
/// Opens a bi-stream to the server and relays IP packets in both directions.
async fn handle_tun_client_connection(
    connection: quinn::Connection,
    tun_reader: Arc<tokio::sync::Mutex<tun2::DeviceReader>>,
    tun_writer: Arc<tokio::sync::Mutex<tun2::DeviceWriter>>,
) -> io::Result<()> {
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))?;

    info!("Bi-stream opened, starting IP packet relay");

    relay_tun_quic(tun_reader, tun_writer, send, recv).await
}

/// Bidirectional relay between TUN device and QUIC bi-stream.
/// Uses separate reader/writer halves to avoid mutex contention.
async fn relay_tun_quic(
    tun_reader: Arc<tokio::sync::Mutex<tun2::DeviceReader>>,
    tun_writer: Arc<tokio::sync::Mutex<tun2::DeviceWriter>>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> io::Result<()> {
    let send_task = tokio::spawn(async move {
        tun_to_quic(tun_reader, send).await
    });

    let recv_task = tokio::spawn(async move {
        quic_to_tun(recv, tun_writer).await
    });

    // Wait for either direction to finish (connection closed/error)
    tokio::select! {
        r = send_task => {
            if let Ok(Err(e)) = r {
                warn!("TUN→QUIC relay stopped: {}", e);
            }
        }
        r = recv_task => {
            if let Ok(Err(e)) = r {
                warn!("QUIC→TUN relay stopped: {}", e);
            }
        }
    }

    Ok(())
}

/// Relay IP packets from TUN device to QUIC send stream.
/// Framing: [u16 big-endian length][IP packet bytes]
async fn tun_to_quic(
    tun_reader: Arc<tokio::sync::Mutex<tun2::DeviceReader>>,
    mut send: quinn::SendStream,
) -> io::Result<()> {
    let mut buf = vec![0u8; BUF_SIZE];

    loop {
        let n = {
            let mut reader = tun_reader.lock().await;
            reader.read(&mut buf).await?
        };

        if n == 0 {
            continue;
        }

        // Write length prefix + packet
        let len = n as u16;
        send.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        send.write_all(&buf[..n])
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
    }
}

/// Relay IP packets from QUIC recv stream to TUN device.
/// Reads framed packets: [u16 big-endian length][IP packet bytes]
async fn quic_to_tun(
    mut recv: quinn::RecvStream,
    tun_writer: Arc<tokio::sync::Mutex<tun2::DeviceWriter>>,
) -> io::Result<()> {
    let mut len_buf = [0u8; 2];
    let mut pkt_buf = vec![0u8; BUF_SIZE];

    loop {
        // Read length prefix
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;

        let pkt_len = u16::from_be_bytes(len_buf) as usize;

        if pkt_len == 0 || pkt_len > BUF_SIZE {
            error!("Invalid packet length: {}", pkt_len);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid packet length: {}", pkt_len),
            ));
        }

        // Read packet
        recv.read_exact(&mut pkt_buf[..pkt_len])
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;

        // Write to TUN
        let mut writer = tun_writer.lock().await;
        writer.write_all(&pkt_buf[..pkt_len]).await?;
    }
}

/// Build a QUIC client configuration.
/// If `insecure` is true, skip server certificate verification (for self-signed certs).
fn build_quic_client_config(insecure: bool) -> io::Result<quinn::ClientConfig> {
    let crypto = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
            error!("Error creating QUIC client config: {}", e);
            io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
        })?,
    ));

    Ok(client_config)
}

/// Certificate verifier that accepts any certificate (for self-signed certs).
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
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
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
