// Copyright 2020 Developers of the http-tunnel project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! QUIC transport support for http-tunnel.
//!
//! This module provides:
//! - [`QuicBiStream`]: an adapter that combines quinn's `SendStream` and `RecvStream`
//!   into a single type implementing `AsyncRead + AsyncWrite`, making it compatible
//!   with the existing tunnel infrastructure.
//! - [`build_quic_server_config`]: constructs a `quinn::ServerConfig` from PEM-encoded
//!   certificate and key files using rustls (TLS 1.3, as mandated by QUIC).

use log::error;
use quinn::crypto::rustls::QuicServerConfig;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

/// A bidirectional QUIC stream that implements both `AsyncRead` and `AsyncWrite`.
///
/// This is the bridge between quinn's split stream model (separate `SendStream`
/// and `RecvStream`) and the `AsyncRead + AsyncWrite` interface expected by
/// the tunnel and relay infrastructure.
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBiStream {
    /// Create a new `QuicBiStream` from a quinn bidirectional stream pair.
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf).map_err(|e| {
            io::Error::new(io::ErrorKind::ConnectionReset, e)
        })
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// Build a QUIC server configuration from PEM-encoded certificate and private key files.
///
/// QUIC mandates TLS 1.3, which is handled by rustls under the hood.
/// The certificate file should contain the full chain (end-entity + intermediates).
pub fn build_quic_server_config(
    cert_path: &str,
    key_path: &str,
) -> io::Result<quinn::ServerConfig> {
    // Read certificate chain
    let cert_file = File::open(cert_path).map_err(|e| {
        error!("Error opening certificate file {}: {}", cert_path, e);
        e
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            error!("Error reading certificates from {}: {}", cert_path, e);
            Error::from(ErrorKind::InvalidData)
        })?;

    if certs.is_empty() {
        error!("No certificates found in {}", cert_path);
        return Err(Error::from(ErrorKind::InvalidData));
    }

    // Read private key
    let key_file = File::open(key_path).map_err(|e| {
        error!("Error opening key file {}: {}", key_path, e);
        e
    })?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| {
            error!("Error reading private key from {}: {}", key_path, e);
            Error::from(ErrorKind::InvalidData)
        })?
        .ok_or_else(|| {
            error!("No private key found in {}", key_path);
            Error::from(ErrorKind::InvalidData)
        })?;

    // Build rustls server config for QUIC (TLS 1.3 only)
    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            error!("Error building TLS config: {}", e);
            Error::new(ErrorKind::InvalidInput, e)
        })?;

    let quic_server_config = QuicServerConfig::try_from(rustls_config).map_err(|e| {
        error!("Error creating QUIC server config: {}", e);
        Error::new(ErrorKind::InvalidInput, e.to_string())
    })?;

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    Ok(server_config)
}
