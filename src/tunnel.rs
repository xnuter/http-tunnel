/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use log::{debug, error};
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::configuration::TunnelConfig;
use crate::relay::{Relay, RelayBuilder, RelayStats};
use crate::upstream::UpstreamConnector;
use core::fmt;
use futures::stream::SplitStream;
use std::fmt::Display;
use std::time::Duration;

#[derive(Eq, PartialEq, EnumIter, Debug, Copy, Clone, Serialize)]
pub enum EstablishTunnelResult {
    /// Successfully connected to upstream.  
    Ok,
    /// Malformed request
    BadRequest,
    /// Destination is not allowed
    Forbidden,
    /// Unsupported operation, however valid for the protocol.
    OperationNotAllowed,
    /// The client failed to send a tunnel request timely.
    RequestTimeout,
    /// Cannot connect to upstream.
    BadGateway,
    /// Connection attempt timed out.
    GatewayTimeout,
    /// Busy. Try again later. (not supported in this demo)
    TooManyRequests,
    /// Any other error. E.g. an abrupt I/O error.
    ServerError,
}

/// A connection tunnel.
///
/// # Parameters
/// * `<C>` - stream codec for initiating tunnel handshake.
///    It extracts the request message, which contains the
///    upstream destination, and, potentially policies. It also takes care of
///    encoding a response.
/// * `<D>` - downstream connection, or a connection from from client.
/// * `<U>` - upstream connector. It takes result produced by the codec and establishes a connection.
/// Once the upstream connection is established, it relays data until any connection is closed or an
/// error happened.
pub struct ConnectionTunnel<C, D, U> {
    tunnel_request_codec: Option<C>,
    tunnel_ctx: TunnelCtx,
    upstream_connector: U,
    downstream: Option<D>,
    tunnel_config: TunnelConfig,
}

#[async_trait]
pub trait TunnelDestination {
    type Addr;
    fn target_addr(&self) -> Self::Addr;
}

/// We need to be able to trace events in logs/metrics.
#[derive(Builder, Copy, Clone, Default, Serialize)]
pub struct TunnelCtx {
    /// We can easily extend it, if necessary. For now just a random u128.
    id: u128,
}

/// Statistics. No sensitive information.
#[derive(Serialize)]
pub struct TunnelStats {
    tunnel_ctx: TunnelCtx,
    result: EstablishTunnelResult,
    upstream_stats: Option<RelayStats>,
    downstream_stats: Option<RelayStats>,
}

impl<C, D, U> ConnectionTunnel<C, D, U>
where
    C: Decoder<Error = EstablishTunnelResult> + Encoder<EstablishTunnelResult>,
    C::Item: TunnelDestination + Sized + Display + Send + Sync,
    D: AsyncRead + AsyncWrite + Sized + Send + Unpin + 'static,
    U: UpstreamConnector<Destination = C::Item>,
{
    pub fn new(
        tunnel_request_codec: C,
        upstream_connector: U,
        downstream: D,
        tunnel_config: TunnelConfig,
        tunnel_ctx: TunnelCtx,
    ) -> Self {
        Self {
            tunnel_request_codec: Some(tunnel_request_codec),
            upstream_connector,
            tunnel_ctx,
            downstream: Some(downstream),
            tunnel_config,
        }
    }

    /// Once the client connected we wait for a tunnel establishment handshake.
    /// For instance, an `HTTP/1.1 CONNECT` for HTTP tunnels.
    ///
    /// During handshake we obtained the upstream destination, and if we were able to connect to it,
    /// a message indicating success is sent back to client (or an error response otherwise).
    ///
    /// At that point we start relaying data in full-duplex mode.
    ///
    /// # Note
    /// This method consumes `self` and thus can be called only once.
    pub async fn start(mut self) -> io::Result<TunnelStats> {
        let stream = self
            .downstream
            .take()
            .expect("downstream can be taken once");

        let tunnel_result = self
            .establish_tunnel(stream, self.tunnel_config.clone())
            .await;

        if let Err(error) = tunnel_result {
            return Ok(TunnelStats {
                tunnel_ctx: self.tunnel_ctx,
                result: error,
                upstream_stats: None,
                downstream_stats: None,
            });
        }

        let (downstream, upstream) = tunnel_result.unwrap();
        let (downstream_recv, downstream_send) = io::split(downstream);
        let (upstream_recv, upstream_send) = io::split(upstream);

        let downstream_relay: Relay = RelayBuilder::default()
            .name("Downstream")
            .tunnel_ctx(self.tunnel_ctx)
            .relay_policy(self.tunnel_config.client_connection.relay_policy)
            .build()
            .expect("RelayBuilder failed");

        let upstream_relay: Relay = RelayBuilder::default()
            .name("Upstream")
            .tunnel_ctx(self.tunnel_ctx)
            .relay_policy(self.tunnel_config.upstream_connection.relay_policy)
            .build()
            .expect("RelayBuilder failed");

        let downstream_task = tokio::spawn(async move {
            downstream_relay
                .relay_data(downstream_recv, upstream_send)
                .await
        });

        let upstream_task = tokio::spawn(async move {
            upstream_relay
                .relay_data(upstream_recv, downstream_send)
                .await
        });

        let upstream_stats = upstream_task.await??;
        let downstream_stats = downstream_task.await??;

        Ok(TunnelStats {
            tunnel_ctx: self.tunnel_ctx,
            result: EstablishTunnelResult::Ok,
            upstream_stats: Some(upstream_stats),
            downstream_stats: Some(downstream_stats),
        })
    }

    async fn establish_tunnel(
        &mut self,
        stream: D,
        configuration: TunnelConfig,
    ) -> Result<(D, U::Stream), EstablishTunnelResult> {
        debug!("Accepting HTTP tunnel request: CTX={}", self.tunnel_ctx);

        let (mut write, mut read) = self
            .tunnel_request_codec
            .take()
            .expect("establish_tunnel can be called only once")
            .framed(stream)
            .split();

        let (response, upstream) = self.process_tunnel_request(&configuration, &mut read).await;

        let response_sent = timeout(
            configuration.client_connection.initiation_timeout,
            write.send(response),
        )
        .await;

        if response_sent.is_ok() {
            match upstream {
                None => Err(response),
                Some(u) => {
                    // lets take the original stream to either relay data, or to drop it on error
                    let framed = write.reunite(read).expect("Uniting previously split parts");
                    let original_stream = framed.into_inner();

                    Ok((original_stream, u))
                }
            }
        } else {
            Err(EstablishTunnelResult::RequestTimeout)
        }
    }

    async fn process_tunnel_request(
        &mut self,
        configuration: &TunnelConfig,
        read: &mut SplitStream<Framed<D, C>>,
    ) -> (
        EstablishTunnelResult,
        Option<<U as UpstreamConnector>::Stream>,
    ) {
        let connect_request = timeout(
            configuration.client_connection.initiation_timeout,
            read.next(),
        )
        .await;

        let response;
        let mut upstream = None;

        if connect_request.is_err() {
            error!("Client established TLS connection but failed to send HTTP CONNECT request within {:?}, CTX={}",
                   configuration.client_connection.initiation_timeout,
                   self.tunnel_ctx);
            response = EstablishTunnelResult::RequestTimeout;
        } else if let Some(event) = connect_request.unwrap() {
            match event {
                Ok(destination) => {
                    response = match self
                        .connect_to_upstream(
                            destination,
                            configuration.upstream_connection.connect_timeout,
                        )
                        .await
                    {
                        Ok(u) => {
                            upstream = Some(u);
                            EstablishTunnelResult::Ok
                        }
                        Err(e) => e,
                    }
                }
                Err(e) => {
                    response = e;
                }
            }
        } else {
            response = EstablishTunnelResult::BadRequest;
        }

        (response, upstream)
    }

    async fn connect_to_upstream(
        &mut self,
        destination: U::Destination,
        connect_timeout: Duration,
    ) -> Result<U::Stream, EstablishTunnelResult> {
        debug!(
            "Establishing HTTP tunnel upstream connection: {}, CTX={}",
            destination, self.tunnel_ctx,
        );

        let timed_connection_result = timeout(
            connect_timeout,
            self.upstream_connector.connect(&destination),
        )
        .await;

        if timed_connection_result.is_err() {
            Err(EstablishTunnelResult::GatewayTimeout)
        } else {
            match timed_connection_result.unwrap() {
                Ok(tcp_stream) => Ok(tcp_stream),
                Err(e) => Err(EstablishTunnelResult::from(e)),
            }
        }
    }
}

impl fmt::Display for TunnelCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

#[cfg(test)]
mod test {
    extern crate tokio;

    use async_trait::async_trait;
    use std::time::Duration;

    use tokio::io;
    use tokio_test::io::Builder;
    use tokio_test::io::Mock;

    use crate::relay::RelayPolicy;

    use self::tokio::io::{Error, ErrorKind};
    use crate::configuration::{ClientConnectionConfig, TunnelConfig, UpstreamConnectionConfig};
    use crate::http_tunnel_codec::{
        HttpTunnelCodec, HttpTunnelCodecBuilder, HttpTunnelDestination,
    };
    use crate::tunnel::{
        ConnectionTunnel, EstablishTunnelResult, TunnelCtxBuilder, TunnelDestination,
    };
    use crate::upstream::UpstreamConnector;
    use rand::{thread_rng, Rng};
    use regex::Regex;

    #[tokio::test]
    async fn test_tunnel_ok() {
        let handshake_request = b"CONNECT foo.bar:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 200 OK\r\n\r\n";
        let tunneled_request = b"0: Some arbibrary request";
        let tunneled_response = b"1: Some arbibrary response";

        let downstream: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .read(tunneled_request)
            .write(tunneled_response)
            .build();

        let upstream: Mock = Builder::new()
            .write(tunneled_request)
            .read(tunneled_response)
            .build();

        let ctx = TunnelCtxBuilder::default()
            .id(thread_rng().gen::<u128>())
            .build()
            .expect("TunnelCtxBuilder failed");

        let codec: HttpTunnelCodec = HttpTunnelCodecBuilder::default()
            .tunnel_ctx(ctx)
            .enabled_destinations(Regex::new(r"foo\.bar:80").unwrap())
            .build()
            .expect("ConnectRequestCodecBuilder failed");

        let connector = MockUpstreamConnector {
            destination: "foo.bar:80".to_string(),
            mock: Some(upstream),
            delay: None,
            error: None,
        };

        let default_timeout = Duration::from_secs(5);
        let config = build_config(default_timeout);

        let result = ConnectionTunnel::new(codec, connector, downstream, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, EstablishTunnelResult::Ok);
        assert!(stats.upstream_stats.is_some());
        assert!(stats.downstream_stats.is_some());

        let upstream_stats = stats.upstream_stats.unwrap();
        let downstream_stats = stats.downstream_stats.unwrap();

        assert_eq!(downstream_stats.total_bytes, tunneled_request.len());
        assert_eq!(upstream_stats.total_bytes, tunneled_response.len());
    }

    #[tokio::test]
    async fn test_tunnel_request_timeout() {
        let handshake_request = b"CONNECT foo.bar:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 408 TIMEOUT\r\n\r\n";

        let downstream: Mock = Builder::new()
            .wait(Duration::from_secs(2))
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let ctx = TunnelCtxBuilder::default()
            .id(thread_rng().gen::<u128>())
            .build()
            .expect("TunnelCtxBuilder failed");

        let codec: HttpTunnelCodec = HttpTunnelCodecBuilder::default()
            .tunnel_ctx(ctx)
            .enabled_destinations(Regex::new(r"foo\.bar:80").unwrap())
            .build()
            .expect("ConnectRequestCodecBuilder failed");

        let connector = MockUpstreamConnector {
            destination: "foo.bar:80".to_string(),
            mock: None,
            delay: None,
            error: None,
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = ConnectionTunnel::new(codec, connector, downstream, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, EstablishTunnelResult::RequestTimeout);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_upstream_timeout() {
        let handshake_request = b"CONNECT foo.bar:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 504 GATEWAY_TIMEOUT\r\n\r\n";

        let downstream: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let upstream: Mock = Builder::new().build();

        let ctx = TunnelCtxBuilder::default()
            .id(thread_rng().gen::<u128>())
            .build()
            .expect("TunnelCtxBuilder failed");

        let codec: HttpTunnelCodec = HttpTunnelCodecBuilder::default()
            .tunnel_ctx(ctx)
            .enabled_destinations(Regex::new(r"foo\.bar:80").unwrap())
            .build()
            .expect("ConnectRequestCodecBuilder failed");

        let connector = MockUpstreamConnector {
            destination: "foo.bar:80".to_string(),
            mock: Some(upstream),
            delay: Some(Duration::from_secs(3)),
            error: None,
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = ConnectionTunnel::new(codec, connector, downstream, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, EstablishTunnelResult::GatewayTimeout);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_bad_destination() {
        let handshake_request = b"CONNECT disallowed.com:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 403 FORBIDDEN\r\n\r\n";

        let downstream: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let upstream: Mock = Builder::new().build();

        let ctx = TunnelCtxBuilder::default()
            .id(thread_rng().gen::<u128>())
            .build()
            .expect("TunnelCtxBuilder failed");

        let codec: HttpTunnelCodec = HttpTunnelCodecBuilder::default()
            .tunnel_ctx(ctx)
            .enabled_destinations(Regex::new(r"foo\.bar:80").unwrap())
            .build()
            .expect("ConnectRequestCodecBuilder failed");

        let connector = MockUpstreamConnector {
            destination: "foo.bar:80".to_string(),
            mock: Some(upstream),
            delay: None,
            error: None,
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = ConnectionTunnel::new(codec, connector, downstream, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, EstablishTunnelResult::Forbidden);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_bad_gateway() {
        let handshake_request = b"CONNECT foo.bar:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 502 BAD_GATEWAY\r\n\r\n";

        let downstream: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let _upstream: Mock = Builder::new().build();

        let ctx = TunnelCtxBuilder::default()
            .id(thread_rng().gen::<u128>())
            .build()
            .expect("TunnelCtxBuilder failed");

        let codec: HttpTunnelCodec = HttpTunnelCodecBuilder::default()
            .tunnel_ctx(ctx)
            .enabled_destinations(Regex::new(r"foo\.bar:80").unwrap())
            .build()
            .expect("ConnectRequestCodecBuilder failed");

        let connector = MockUpstreamConnector {
            destination: "foo.bar:80".to_string(),
            mock: None,
            delay: None,
            error: Some(ErrorKind::BrokenPipe),
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = ConnectionTunnel::new(codec, connector, downstream, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, EstablishTunnelResult::BadGateway);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    #[tokio::test]
    async fn test_tunnel_not_allowed() {
        let handshake_request = b"GET foo.bar:80 HTTP/1.1\r\n\r\n";
        let handshake_response = b"HTTP/1.1 405 NOT_ALLOWED\r\n\r\n";

        let downstream: Mock = Builder::new()
            .read(handshake_request)
            .write(handshake_response)
            .build();

        let _upstream: Mock = Builder::new().build();

        let ctx = TunnelCtxBuilder::default()
            .id(thread_rng().gen::<u128>())
            .build()
            .expect("TunnelCtxBuilder failed");

        let codec: HttpTunnelCodec = HttpTunnelCodecBuilder::default()
            .tunnel_ctx(ctx)
            .enabled_destinations(Regex::new(r"foo\.bar:80").unwrap())
            .build()
            .expect("ConnectRequestCodecBuilder failed");

        let connector = MockUpstreamConnector {
            destination: "foo.bar:80".to_string(),
            mock: None,
            delay: None,
            error: Some(ErrorKind::BrokenPipe),
        };

        let default_timeout = Duration::from_secs(1);
        let config = build_config(default_timeout);

        let result = ConnectionTunnel::new(codec, connector, downstream, config, ctx)
            .start()
            .await;

        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.result, EstablishTunnelResult::OperationNotAllowed);
        assert!(stats.upstream_stats.is_none());
        assert!(stats.downstream_stats.is_none());
    }

    fn build_config(default_timeout: Duration) -> TunnelConfig {
        let config = TunnelConfig {
            client_connection: ClientConnectionConfig {
                initiation_timeout: default_timeout,
                relay_policy: RelayPolicy {
                    idle_timeout: default_timeout,
                    min_rate_bpm: 0,
                    max_rate_bps: 120410065,
                },
            },
            upstream_connection: UpstreamConnectionConfig {
                dns_cache_ttl: default_timeout,
                allowed_destinations: Regex::new(r"foo\.bar:80").unwrap(),
                connect_timeout: default_timeout,
                relay_policy: RelayPolicy {
                    idle_timeout: default_timeout,
                    min_rate_bpm: 0,
                    max_rate_bps: 170310180,
                },
            },
        };
        config
    }

    struct MockUpstreamConnector {
        destination: String,
        mock: Option<Mock>,
        delay: Option<Duration>,
        error: Option<ErrorKind>,
    }

    #[async_trait]
    impl UpstreamConnector for MockUpstreamConnector {
        type Destination = HttpTunnelDestination;
        type Stream = Mock;

        async fn connect(&mut self, destination: &Self::Destination) -> io::Result<Self::Stream> {
            let target_addr = &destination.target_addr();
            assert_eq!(&self.destination, target_addr);

            if let Some(d) = self.delay {
                tokio::time::delay_for(d).await;
            }

            match self.error {
                None => Ok(self.mock.take().unwrap()),
                Some(e) => Err(Error::from(e)),
            }
        }
    }
}
