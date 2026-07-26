// Copyright 2020 Developers of the http-tunnel project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TUN-over-TLS (TCP) VPN module.
//!
//! Same architecture as `quic_tun` but over TCP/TLS instead of QUIC.
//! For the ISP this looks like regular HTTPS traffic (TLS on TCP port 443),
//! which cannot be blocked without breaking the web.
//!
//! ## Server mode (`tls-tun-server`)
//! - Creates TUN device with given IP
//! - Listens for TLS connections on TCP
//! - Relays IP packets between TUN and TLS stream
//! - Requires NAT/masquerade + ip_forward on the host
//!
//! ## Client mode (`tls-tun-client`)
//! - Creates TUN device with given IP
//! - Connects to TLS server via TCP
//! - Relays IP packets between TUN and TLS stream
//! - Auto-reconnects on connection loss

use log::{error, info, warn};
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
    let tls_acceptor = build_tls_acceptor(cert_path, key_path)?;
    let listener = TcpListener::bind(bind).await?;

    info!("TLS TUN server listening on {}", bind);

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

    let tun = Arc::new(tun_dev);
    info!("TUN device created with address {}/{}", tun_addr, tun_netmask);

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let tun = tun.clone();

        tokio::spawn(async move {
            info!("TLS TUN connection from: {}", peer_addr);

            // Set TCP_NODELAY for low latency
            let _ = tcp_stream.set_nodelay(true);

            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    info!("TLS handshake completed with {}", peer_addr);
                    if let Err(e) = relay_tun_tls(tun, tls_stream).await {
                        warn!("TLS TUN relay error from {}: {}", peer_addr, e);
                    }
                }
                Err(e) => {
                    error!("TLS handshake failed from {}: {}", peer_addr, e);
                }
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
    // Create TUN device once
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

    let tun = Arc::new(tun_dev);
    info!("TUN device '{}' created with address {}/{}", tun_name, tun_addr, tun_netmask);

    let tls_connector = build_tls_connector(insecure)?;

    loop {
        info!("Connecting to TLS server at {}...", server_addr);

        let connect_result = async {
            let tcp_stream = TcpStream::connect(server_addr).await?;
            let _ = tcp_stream.set_nodelay(true);

            let server_name = rustls::pki_types::ServerName::try_from("tunnel")
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

            let tls_stream = tls_connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

            info!("Connected to TLS server {}", server_addr);

            relay_tun_tls(tun.clone(), tls_stream).await
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

/// Bidirectional relay between TUN device and TLS stream.
async fn relay_tun_tls<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static>(
    tun: Arc<tun2::AsyncDevice>,
    tls_stream: S,
) -> io::Result<()> {
    let (read_half, write_half) = tokio::io::split(tls_stream);

    let tun_read = tun.clone();
    let tun_write = tun;

    let send_task = tokio::spawn(async move {
        tun_to_tls(tun_read, write_half).await
    });

    let recv_task = tokio::spawn(async move {
        tls_to_tun(read_half, tun_write).await
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

    Ok(())
}

/// Relay IP packets from TUN device to TLS write stream.
/// Framing: [u16 big-endian length][IP packet bytes]
async fn tun_to_tls<W: tokio::io::AsyncWrite + Unpin>(
    tun: Arc<tun2::AsyncDevice>,
    mut writer: W,
) -> io::Result<()> {
    let mut frame_buf = vec![0u8; 2 + BUF_SIZE];

    loop {
        let n = tun.recv(&mut frame_buf[2..]).await?;

        if n == 0 {
            continue;
        }

        // Write length prefix into frame buffer
        let len = n as u16;
        frame_buf[..2].copy_from_slice(&len.to_be_bytes());

        // Single atomic write: length prefix + packet data
        writer.write_all(&frame_buf[..2 + n]).await?;
        writer.flush().await?;
    }
}

/// Relay IP packets from TLS read stream to TUN device.
/// Reads framed packets: [u16 big-endian length][IP packet bytes]
async fn tls_to_tun<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    tun: Arc<tun2::AsyncDevice>,
) -> io::Result<()> {
    let mut len_buf = [0u8; 2];
    let mut pkt_buf = vec![0u8; BUF_SIZE];

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
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            error!("Error reading certificates: {}", e);
            io::Error::from(io::ErrorKind::InvalidData)
        })?;

    let key_file = File::open(key_path).map_err(|e| {
        error!("Error opening key file {}: {}", key_path, e);
        e
    })?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| {
            error!("Error reading private key: {}", e);
            io::Error::from(io::ErrorKind::InvalidData)
        })?
        .ok_or_else(|| {
            error!("No private key found in {}", key_path);
            io::Error::from(io::ErrorKind::InvalidData)
        })?;

    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            error!("Error building TLS config: {}", e);
            io::Error::new(io::ErrorKind::InvalidInput, e)
        })?;

    Ok(TlsAcceptor::from(Arc::new(rustls_config)))
}

/// Build TLS connector for client.
fn build_tls_connector(insecure: bool) -> io::Result<TlsConnector> {
    let config = if insecure {
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

    Ok(TlsConnector::from(Arc::new(config)))
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
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
