// Copyright 2020 Developers of the http-tunnel project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use log::{error, info, LevelFilter};
use rand::{thread_rng, Rng};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_native_tls::TlsAcceptor;

use crate::configuration::{ProxyConfiguration, ProxyMode};
use crate::http_tunnel_codec::{HttpTunnelCodec, HttpTunnelCodecBuilder, HttpTunnelTarget};
use crate::proxy_target::{SimpleCachingDnsResolver, SimpleTcpConnector, TargetConnector};
use crate::tunnel::{
    relay_connections, ConnectionTunnel, TunnelCtx, TunnelCtxBuilder, TunnelStats,
};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

mod configuration;
mod http_tunnel_codec;
mod proxy_target;
#[cfg(feature = "quic")]
mod quic;
mod relay;
mod tunnel;

type DnsResolver = SimpleCachingDnsResolver;

#[tokio::main]
async fn main() -> io::Result<()> {
    init_logger();

    let proxy_configuration =
        Arc::new(ProxyConfiguration::from_command_line().inspect_err(|_e| {
            println!("Failed to process parameters. See ./log/application.log for details");
        })?);

    info!("Starting listener on: {}", proxy_configuration.bind_address);

    let dns_resolver = SimpleCachingDnsResolver::new(
        proxy_configuration
            .tunnel_config
            .target_connection
            .dns_cache_ttl,
    );

    match proxy_configuration.mode.clone() {
        ProxyMode::Http => {
            serve_plain_text(proxy_configuration, dns_resolver).await?;
        }
        ProxyMode::Https(tls_identity) => {
            let acceptor = native_tls::TlsAcceptor::new(tls_identity).map_err(|e| {
                error!("Error setting up TLS {}", e);
                Error::from(ErrorKind::InvalidInput)
            })?;

            let tls_acceptor = TlsAcceptor::from(acceptor);

            serve_tls(proxy_configuration, tls_acceptor, dns_resolver).await?;
        }
        ProxyMode::Tcp(destination) => {
            serve_tcp(proxy_configuration, dns_resolver, destination).await?;
        }
        #[cfg(feature = "quic")]
        ProxyMode::Quic(quic_tls) => {
            serve_quic(proxy_configuration, quic_tls, dns_resolver).await?;
        }
    };

    info!("Proxy stopped");

    Ok(())
}

async fn start_listening_tcp(config: &ProxyConfiguration) -> Result<TcpListener, Error> {
    let bind_address = &config.bind_address;

    match TcpListener::bind(bind_address).await {
        Ok(s) => {
            info!("Serving requests on: {bind_address}");
            Ok(s)
        }
        Err(e) => {
            error!("Error binding TCP socket {bind_address}: {e}");
            Err(e)
        }
    }
}

async fn serve_tls(
    config: Arc<ProxyConfiguration>,
    tls_acceptor: TlsAcceptor,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    let listener = start_listening_tcp(&config).await?;

    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();

        match socket {
            Ok((stream, _)) => {
                stream.nodelay().unwrap_or_default();
                let stream_tls_acceptor = tls_acceptor.clone();
                let config = Arc::clone(&config);
                // handle accepted connections asynchronously
                tokio::spawn(async move {
                    handle_client_tls_connection(
                        config,
                        stream_tls_acceptor,
                        stream,
                        dns_resolver_ref,
                    )
                    .await
                });
            }
            Err(e) => error!("Failed TCP handshake {}", e),
        }
    }
}

async fn serve_plain_text(
    config: Arc<ProxyConfiguration>,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    let listener = start_listening_tcp(&config).await?;

    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();

        match socket {
            Ok((stream, _)) => {
                stream.nodelay().unwrap_or_default();
                let config = Arc::clone(&config);
                // handle accepted connections asynchronously
                tokio::spawn(async move { tunnel_stream(&config, stream, dns_resolver_ref).await });
            }
            Err(e) => error!("Failed TCP handshake {}", e),
        }
    }
}

async fn serve_tcp(
    config: Arc<ProxyConfiguration>,
    dns_resolver: DnsResolver,
    destination: String,
) -> io::Result<()> {
    let listener = start_listening_tcp(&config).await?;

    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();
        let destination_copy = destination.clone();

        match socket {
            Ok((stream, _)) => {
                let config = Arc::clone(&config);
                stream.nodelay().unwrap_or_default();
                // handle accepted connections asynchronously
                tokio::spawn(async move {
                    let ctx = TunnelCtxBuilder::default()
                        .id(thread_rng().gen::<u128>())
                        .build()
                        .expect("TunnelCtxBuilder failed");

                    let mut connector: SimpleTcpConnector<HttpTunnelTarget, DnsResolver> =
                        SimpleTcpConnector::new(
                            dns_resolver_ref,
                            config.tunnel_config.target_connection.connect_timeout,
                            ctx,
                        );

                    match connector
                        .connect(&HttpTunnelTarget {
                            target: destination_copy,
                            nugget: None,
                        })
                        .await
                    {
                        Ok(destination) => {
                            let stats = relay_connections(
                                stream,
                                destination,
                                ctx,
                                config.tunnel_config.client_connection.relay_policy.clone(),
                                config.tunnel_config.target_connection.relay_policy.clone(),
                            )
                            .await;

                            report_tunnel_metrics(ctx, stats);
                        }
                        Err(e) => error!("Failed to establish TCP upstream connection {:?}", e),
                    }
                });
            }
            Err(e) => error!("Failed TCP handshake {}", e),
        }
    }
}

async fn handle_client_tls_connection(
    config: Arc<ProxyConfiguration>,
    tls_acceptor: TlsAcceptor,
    stream: TcpStream,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    let timed_tls_handshake = timeout(
        config.tunnel_config.client_connection.initiation_timeout,
        tls_acceptor.accept(stream),
    )
    .await;

    if let Ok(tls_result) = timed_tls_handshake {
        match tls_result {
            Ok(downstream) => {
                tunnel_stream(&config, downstream, dns_resolver).await?;
            }
            Err(e) => {
                error!(
                    "Client opened a TCP connection but TLS handshake failed: {}.",
                    e
                );
            }
        }
    } else {
        error!(
            "Client opened TCP connection but didn't complete TLS handshake in time: {:?}.",
            config.tunnel_config.client_connection.initiation_timeout
        );
    }
    Ok(())
}

/// Tunnel via a client connection.
/// This method constructs `HttpTunnelCodec` and `SimpleTcpConnector`
/// to create an `HTTP` tunnel.
async fn tunnel_stream<C: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    config: &ProxyConfiguration,
    client: C,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    let ctx = TunnelCtxBuilder::default()
        .id(thread_rng().gen::<u128>())
        .build()
        .expect("TunnelCtxBuilder failed");

    // here it can be any codec.
    let codec: HttpTunnelCodec = HttpTunnelCodecBuilder::default()
        .tunnel_ctx(ctx)
        .enabled_targets(
            config
                .tunnel_config
                .target_connection
                .allowed_targets
                .clone(),
        )
        .build()
        .expect("HttpTunnelCodecBuilder failed");

    // any `TargetConnector` would do.
    let connector: SimpleTcpConnector<HttpTunnelTarget, DnsResolver> = SimpleTcpConnector::new(
        dns_resolver,
        config.tunnel_config.target_connection.connect_timeout,
        ctx,
    );

    let stats = ConnectionTunnel::new(codec, connector, client, config.tunnel_config.clone(), ctx)
        .start()
        .await;

    report_tunnel_metrics(ctx, stats);

    Ok(())
}

/// Serve QUIC connections.
/// Each QUIC connection can carry multiple bidirectional streams.
/// Each bidirectional stream is treated as an independent tunnel session.
#[cfg(feature = "quic")]
async fn serve_quic(
    config: Arc<ProxyConfiguration>,
    quic_tls: configuration::QuicTlsConfig,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    use std::net::SocketAddr;

    let server_config = quic::build_quic_server_config(&quic_tls.cert_path, &quic_tls.key_path)?;

    let bind_addr: SocketAddr = config.bind_address.parse().map_err(|e| {
        error!("Invalid bind address '{}': {}", config.bind_address, e);
        Error::from(ErrorKind::InvalidInput)
    })?;

    let endpoint = quinn::Endpoint::server(server_config, bind_addr).map_err(|e| {
        error!("Error creating QUIC endpoint on {}: {}", bind_addr, e);
        Error::from(ErrorKind::AddrInUse)
    })?;

    info!("QUIC endpoint listening on: {}", bind_addr);

    while let Some(incoming) = endpoint.accept().await {
        let config = Arc::clone(&config);
        let dns_resolver = dns_resolver.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    info!(
                        "QUIC connection established from: {}",
                        connection.remote_address()
                    );
                    handle_quic_connection(config, connection, dns_resolver).await;
                }
                Err(e) => {
                    error!("QUIC connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}

/// Handle a single QUIC connection by accepting bidirectional streams.
/// Each stream is tunneled independently via `tunnel_stream`.
#[cfg(feature = "quic")]
async fn handle_quic_connection(
    config: Arc<ProxyConfiguration>,
    connection: quinn::Connection,
    dns_resolver: DnsResolver,
) {
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let stream = quic::QuicBiStream::new(send, recv);
                let config = Arc::clone(&config);
                let dns_resolver = dns_resolver.clone();
                tokio::spawn(async move {
                    if let Err(e) = tunnel_stream(&config, stream, dns_resolver).await {
                        error!("QUIC tunnel stream error: {}", e);
                    }
                });
            }
            Err(e) => {
                // Connection closed or error — stop accepting streams
                match e {
                    quinn::ConnectionError::ApplicationClosed(_) => {
                        info!(
                            "QUIC connection closed by peer: {}",
                            connection.remote_address()
                        );
                    }
                    _ => {
                        error!(
                            "Error accepting QUIC bidirectional stream from {}: {}",
                            connection.remote_address(),
                            e
                        );
                    }
                }
                break;
            }
        }
    }
}

/// Placeholder for proper metrics emission.
/// Here we just write to a file without any aggregation.
fn report_tunnel_metrics(ctx: TunnelCtx, stats: io::Result<TunnelStats>) {
    match stats {
        Ok(s) => {
            info!(target: "metrics", "{}", serde_json::to_string(&s).expect("JSON serialization failed"));
        }
        Err(_) => error!("Failed to get stats for TID={}", ctx),
    }
}

fn init_logger() {
    let logger_configuration = "./config/log4rs.yaml";
    if let Err(e) = log4rs::init_file(logger_configuration, Default::default()) {
        println!(
            "Cannot initialize logger from {logger_configuration}, error=[{e}]. Logging to the console.");
        let config = Config::builder()
            .appender(
                Appender::builder()
                    .build("application", Box::new(ConsoleAppender::builder().build())),
            )
            .build(
                Root::builder()
                    .appender("application")
                    .build(LevelFilter::Info),
            )
            .unwrap();
        log4rs::init_config(config).expect("Bug: bad default config");
    }
}
