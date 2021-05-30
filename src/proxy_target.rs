/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.
use crate::tunnel::{TunnelCtx, TunnelTarget};
use async_trait::async_trait;
use log::{debug, error, info};
use rand::prelude::thread_rng;
use rand::Rng;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, Error, ErrorKind};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio::time::Duration;

#[async_trait]
pub trait TargetConnector {
    type Target: TunnelTarget + Send + Sync + Sized;
    type Stream: AsyncRead + AsyncWrite + Send + Sized + 'static;

    async fn connect(&mut self, target: &Self::Target) -> io::Result<Self::Stream>;
}

#[async_trait]
pub trait DnsResolver {
    async fn resolve(&mut self, target: &str) -> io::Result<SocketAddr>;
}

#[derive(Clone, Builder)]
pub struct SimpleTcpConnector<D, R: DnsResolver> {
    connect_timeout: Duration,
    tunnel_ctx: TunnelCtx,
    dns_resolver: R,
    #[builder(setter(skip))]
    _phantom_target: PhantomData<D>,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Nugget {
    data: Arc<Vec<u8>>,
}

type CachedSocketAddrs = (Vec<SocketAddr>, u128);

/// Caching DNS resolution to minimize DNS look-ups.
/// The cache has relaxed consistency, it allows concurrent DNS look-ups of the same key,
/// without any guarantees which result is going to be cached.
///
/// Given it's used for DNS look-ups this trade-off seems to be reasonable.
#[derive(Clone)]
pub struct SimpleCachingDnsResolver {
    // mostly reads, occasional writes
    cache: Arc<RwLock<HashMap<String, CachedSocketAddrs>>>,
    ttl: Duration,
    start_time: Instant,
}

#[async_trait]
impl<D, R> TargetConnector for SimpleTcpConnector<D, R>
where
    D: TunnelTarget<Addr = String> + Send + Sync + Sized,
    R: DnsResolver + Send + Sync + 'static,
{
    type Target = D;
    type Stream = TcpStream;

    async fn connect(&mut self, target: &Self::Target) -> io::Result<Self::Stream> {
        let target_addr = &target.target_addr();

        let addr = self.dns_resolver.resolve(target_addr).await?;

        if let Ok(tcp_stream) = timeout(self.connect_timeout, TcpStream::connect(addr)).await {
            let mut stream = tcp_stream?;
            stream.nodelay()?;
            if target.has_nugget() {
                if let Ok(written_successfully) = timeout(
                    self.connect_timeout,
                    stream.write_all(&target.nugget().data()),
                )
                .await
                {
                    written_successfully?;
                } else {
                    error!(
                        "Timeout sending nugget to {}, {}, CTX={}",
                        addr, target_addr, self.tunnel_ctx
                    );
                    return Err(Error::from(ErrorKind::TimedOut));
                }
            }
            Ok(stream)
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
    async fn resolve(&mut self, target: &str) -> io::Result<SocketAddr> {
        match self.try_find(target).await {
            Some(a) => Ok(a),
            _ => Ok(self.resolve_and_cache(target).await?),
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
            _phantom_target: PhantomData,
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

    async fn try_find(&mut self, target: &str) -> Option<SocketAddr> {
        let map = self.cache.read().await;

        let addr = match map.get(target) {
            None => None,
            Some((cached, expiration)) => {
                // expiration with jitter to avoid expiration "waves"
                let expiration_jitter = *expiration + thread_rng().gen_range(0..5_000);
                if Instant::now().duration_since(self.start_time).as_millis() < expiration_jitter {
                    Some(self.pick(cached))
                } else {
                    None
                }
            }
        };

        addr
    }

    async fn resolve_and_cache(&mut self, target: &str) -> io::Result<SocketAddr> {
        let resolved = SimpleCachingDnsResolver::resolve(target).await?;

        let mut map = self.cache.write().await;
        map.insert(
            target.to_string(),
            (
                resolved.clone(),
                Instant::now().duration_since(self.start_time).as_millis() + self.ttl.as_millis(),
            ),
        );

        Ok(self.pick(&resolved))
    }

    async fn resolve(target: &str) -> io::Result<Vec<SocketAddr>> {
        debug!("Resolving DNS {}", target,);
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
        info!("Resolved DNS {} to {:?}", target, resolved);

        if resolved.is_empty() {
            error!("Cannot resolve DNS {}", target,);
            return Err(Error::from(ErrorKind::AddrNotAvailable));
        }

        Ok(resolved)
    }
}

impl Nugget {
    pub fn new<T: Into<Vec<u8>>>(v: T) -> Self {
        Self {
            data: Arc::new(v.into()),
        }
    }

    pub fn data(&self) -> Arc<Vec<u8>> {
        self.data.clone()
    }
}
