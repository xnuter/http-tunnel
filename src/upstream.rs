/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.
use crate::tunnel::{TunnelCtx, TunnelDestination};
use async_trait::async_trait;
use log::{debug, error, info};
use rand::prelude::thread_rng;
use rand::Rng;
use serde::export::PhantomData;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite, Error, ErrorKind};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio::time::Duration;

#[async_trait]
pub trait UpstreamConnector {
    type Destination: TunnelDestination + Send + Sync + Sized;
    type Stream: AsyncRead + AsyncWrite + Send + Sized + 'static;

    async fn connect(&mut self, destination: &Self::Destination) -> io::Result<Self::Stream>;
}

#[async_trait]
pub trait DnsResolver {
    async fn resolve(&mut self, destination: &str) -> io::Result<SocketAddr>;
}

#[derive(Clone, Builder)]
pub struct SimpleTcpConnector<D, R: DnsResolver> {
    connect_timeout: Duration,
    tunnel_ctx: TunnelCtx,
    dns_resolver: R,
    #[builder(setter(skip))]
    _phantom_destination: PhantomData<D>,
}

type CachedSocketAddrs = (Vec<SocketAddr>, u128);

/// Caching DNS resolution results to minimize DNS lookups.
/// The cache implementation is relaxed, it allows concurrent lookups of the same key,
/// without any guarantees which result is going to be cached.
///
/// Given it's used for DNS lookups this trade-off seems to be reasonable.
#[derive(Clone)]
pub struct SimpleCachingDnsResolver {
    // mostly reads, occasional writes
    cache: Arc<RwLock<HashMap<String, CachedSocketAddrs>>>,
    ttl: Duration,
    start_time: Instant,
}

#[async_trait]
impl<D, R> UpstreamConnector for SimpleTcpConnector<D, R>
where
    D: TunnelDestination<Addr = String> + Send + Sync + Sized,
    R: DnsResolver + Send + Sync + 'static,
{
    type Destination = D;
    type Stream = TcpStream;

    async fn connect(&mut self, destination: &Self::Destination) -> io::Result<Self::Stream> {
        let target_addr = &destination.target_addr();

        let addr = self.dns_resolver.resolve(target_addr).await?;

        if let Ok(tcp_stream) = timeout(self.connect_timeout, TcpStream::connect(addr)).await {
            Ok(tcp_stream?)
        } else {
            error!(
                "Timeout connecting to {}, {}, CTX={}",
                addr, target_addr, self.tunnel_ctx
            );
            Err(Error::from(ErrorKind::TimedOut))
        }
    }
}

#[async_trait]
impl DnsResolver for SimpleCachingDnsResolver {
    async fn resolve(&mut self, destination: &str) -> io::Result<SocketAddr> {
        match self.try_find(destination).await {
            Some(a) => Ok(a),
            _ => Ok(self.resolve_and_cache(destination).await?),
        }
    }
}

impl<D, R> SimpleTcpConnector<D, R>
where
    R: DnsResolver,
{
    pub fn new(dns_resolver: R, connect_timeout: Duration, tunnel_ctx: TunnelCtx) -> Self {
        Self {
            dns_resolver,
            connect_timeout,
            tunnel_ctx,
            _phantom_destination: PhantomData,
        }
    }
}

impl SimpleCachingDnsResolver {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            start_time: Instant::now(),
        }
    }

    fn pick(&self, addrs: &[SocketAddr]) -> SocketAddr {
        addrs[thread_rng().gen::<usize>() % addrs.len()]
    }

    async fn try_find(&mut self, destination: &str) -> Option<SocketAddr> {
        let map = self.cache.read().await;

        let addr = match map.get(destination) {
            None => None,
            Some((cached, expiration)) => {
                // expiration with gitter to avoid waves of expirations
                let expiration_gitter = *expiration + thread_rng().gen_range(0, 5_000);
                if Instant::now().duration_since(self.start_time).as_millis() < expiration_gitter {
                    Some(self.pick(cached))
                } else {
                    None
                }
            }
        };

        addr
    }

    async fn resolve_and_cache(&mut self, destination: &str) -> io::Result<SocketAddr> {
        let resolved = SimpleCachingDnsResolver::resolve(destination).await?;

        let mut map = self.cache.write().await;
        map.insert(
            destination.to_string(),
            (
                resolved.clone(),
                Instant::now().duration_since(self.start_time).as_millis() + self.ttl.as_millis(),
            ),
        );

        Ok(self.pick(&resolved))
    }

    async fn resolve(destination: &str) -> io::Result<Vec<SocketAddr>> {
        debug!("Resolving DNS {}", destination,);
        let resolved = Vec::from_iter(tokio::net::lookup_host(destination).await?);
        info!("Resolved DNS {} to {:?}", destination, resolved);

        if resolved.is_empty() {
            error!("Cannot resolve DNS {}", destination,);
            return Err(Error::from(ErrorKind::AddrNotAvailable));
        }

        Ok(resolved)
    }
}
