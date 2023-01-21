/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.

#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate serde_derive;

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
use tokio::io::{AsyncRead, AsyncWrite};

mod configuration;
mod http_tunnel_codec;
mod proxy_target;
mod relay;
mod tunnel;

type DnsResolver = SimpleCachingDnsResolver;

#[tokio::main]
async fn main() -> io::Result<()> {
    init_logger();

    let proxy_configuration = ProxyConfiguration::from_command_line().map_err(|e| {
        println!("Failed to process parameters. See ./log/application.log for details");
        e
    })?;

    info!("Starting listener on: {}", proxy_configuration.bind_address);

    let mut tcp_listener = TcpListener::bind(&proxy_configuration.bind_address)
        .await
        .map_err(|e| {
            error!(
                "Error binding address {}: {}",
                &proxy_configuration.bind_address, e
            );
            e
        })?;

    let dns_resolver = SimpleCachingDnsResolver::new(
        proxy_configuration
            .tunnel_config
            .target_connection
            .dns_cache_ttl,
    );

    match &proxy_configuration.mode {
        ProxyMode::Http => {
            serve_plain_text(proxy_configuration, &mut tcp_listener, dns_resolver).await?;
        }
        ProxyMode::Https(tls_identity) => {
            let acceptor = native_tls::TlsAcceptor::new(tls_identity.clone()).map_err(|e| {
                error!("Error setting up TLS {}", e);
                Error::from(ErrorKind::InvalidInput)
            })?;

            let tls_acceptor = TlsAcceptor::from(acceptor);

            serve_tls(
                proxy_configuration,
                &mut tcp_listener,
                tls_acceptor,
                dns_resolver,
            )
            .await?;
        }
        ProxyMode::Tcp(d) => {
            let destination = d.clone();
            serve_tcp(
                proxy_configuration,
                &mut tcp_listener,
                dns_resolver,
                destination,
            )
            .await?;
        }
    };

    info!("Proxy stopped");

    Ok(())
}

async fn serve_tls(
    config: ProxyConfiguration,
    listener: &mut TcpListener,
    tls_acceptor: TlsAcceptor,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    info!("Serving requests on: {}", config.bind_address);
    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();

        match socket {
            Ok((stream, _)) => {
                stream.nodelay().unwrap_or_default();
                let stream_tls_acceptor = tls_acceptor.clone();
                let config = config.clone();
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
    config: ProxyConfiguration,
    listener: &mut TcpListener,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    info!("Serving requests on: {}", config.bind_address);
    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();

        match socket {
            Ok((stream, _)) => {
                stream.nodelay().unwrap_or_default();
                let config = config.clone();
                // handle accepted connections asynchronously
                tokio::spawn(async move { tunnel_stream(&config, stream, dns_resolver_ref).await });
            }
            Err(e) => error!("Failed TCP handshake {}", e),
        }
    }
}

async fn serve_tcp(
    config: ProxyConfiguration,
    listener: &mut TcpListener,
    dns_resolver: DnsResolver,
    destination: String,
) -> io::Result<()> {
    info!("Serving requests on: {}", config.bind_address);
    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();
        let destination_copy = destination.clone();
        let config_copy = config.clone();

        match socket {
            Ok((stream, _)) => {
                let config = config.clone();
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
                                config_copy.tunnel_config.client_connection.relay_policy,
                                config_copy.tunnel_config.target_connection.relay_policy,
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
    config: ProxyConfiguration,
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
