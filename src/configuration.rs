/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.
use crate::relay::{RelayPolicy, NO_BANDWIDTH_LIMIT, NO_TIMEOUT};
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use derive_builder::Builder;
use log::{error, info};
use native_tls::Identity;
use regex::Regex;
use serde::Deserialize;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::time::Duration;
use tokio::io;

#[derive(Deserialize, Clone)]
pub struct ClientConnectionConfig {
    #[serde(with = "humantime_serde")]
    pub initiation_timeout: Duration,
    pub relay_policy: RelayPolicy,
}

#[derive(Deserialize, Clone)]
pub struct TargetConnectionConfig {
    #[serde(with = "humantime_serde")]
    pub dns_cache_ttl: Duration,
    #[serde(with = "serde_regex")]
    pub allowed_targets: Regex,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    pub relay_policy: RelayPolicy,
}

#[derive(Deserialize, Clone)]
pub struct TunnelConfig {
    pub client_connection: ClientConnectionConfig,
    pub target_connection: TargetConnectionConfig,
}

#[derive(Clone)]
pub enum ProxyMode {
    Http,
    Https(Identity),
    Tcp(String),
    #[cfg(feature = "quic")]
    Quic(QuicTlsConfig),
    #[cfg(feature = "tun-vpn")]
    TunServer(TunServerConfig),
    #[cfg(feature = "tun-vpn")]
    TunClient(TunClientConfig),
}

/// TLS configuration for QUIC transport.
/// QUIC mandates TLS 1.3, using PEM-encoded certificate and key files.
#[cfg(feature = "quic")]
#[derive(Clone)]
pub struct QuicTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// Configuration for TUN-over-QUIC VPN server.
#[cfg(feature = "tun-vpn")]
#[derive(Clone)]
pub struct TunServerConfig {
    pub cert_path: String,
    pub key_path: String,
    pub tun_addr: std::net::Ipv4Addr,
    pub tun_netmask: std::net::Ipv4Addr,
}

/// Configuration for TUN-over-QUIC VPN client.
#[cfg(feature = "tun-vpn")]
#[derive(Clone)]
pub struct TunClientConfig {
    pub server_addr: String,
    pub tun_name: String,
    pub tun_addr: std::net::Ipv4Addr,
    pub tun_netmask: std::net::Ipv4Addr,
    pub insecure: bool,
}

#[derive(Clone, Builder)]
pub struct ProxyConfiguration {
    pub mode: ProxyMode,
    pub bind_address: String,
    pub tunnel_config: TunnelConfig,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    /// Configuration file.
    #[clap(long)]
    config: Option<String>,
    /// Bind address, e.g. 0.0.0.0:8443.
    #[clap(long)]
    bind: String,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Http(HttpOptions),
    Https(HttpsOptions),
    Tcp(TcpOptions),
    #[cfg(feature = "quic")]
    Quic(QuicOptions),
    #[cfg(feature = "tun-vpn")]
    TunServer(TunServerOptions),
    #[cfg(feature = "tun-vpn")]
    TunClient(TunClientOptions),
}

#[derive(Args, Debug)]
#[clap(about = "Run the tunnel in HTTP mode", long_about = None)]
#[clap(author, version, long_about = None)]
#[clap(propagate_version = true)]
struct HttpOptions {}

#[derive(Args, Debug)]
#[clap(about = "Run the tunnel in HTTPS mode", long_about = None)]
#[clap(author, version, long_about = None)]
#[clap(propagate_version = true)]
struct HttpsOptions {
    /// pkcs12 filename.
    #[clap(long)]
    pk: String,
    /// Password for the pkcs12 file.
    #[clap(long)]
    password: String,
}

#[derive(Args, Debug)]
#[clap(about = "Run the tunnel in TCP proxy mode", long_about = None)]
#[clap(author, version, long_about = None)]
#[clap(propagate_version = true)]
struct TcpOptions {
    /// Destination address, e.g. 10.0.0.2:8443.
    #[clap(short, long)]
    destination: String,
}

#[cfg(feature = "quic")]
#[derive(Args, Debug)]
#[clap(about = "Run the tunnel in QUIC (HTTP/3) mode", long_about = None)]
#[clap(author, version, long_about = None)]
#[clap(propagate_version = true)]
struct QuicOptions {
    /// PEM-encoded certificate file (full chain).
    #[clap(long)]
    cert: String,
    /// PEM-encoded private key file.
    #[clap(long)]
    key: String,
}

#[cfg(feature = "tun-vpn")]
#[derive(Args, Debug)]
#[clap(about = "Run as TUN-over-QUIC VPN server", long_about = None)]
struct TunServerOptions {
    /// PEM-encoded certificate file.
    #[clap(long)]
    cert: String,
    /// PEM-encoded private key file.
    #[clap(long)]
    key: String,
    /// TUN device IP address (e.g. 10.9.0.1).
    #[clap(long, default_value = "10.9.0.1")]
    tun_addr: std::net::Ipv4Addr,
    /// TUN device netmask (e.g. 255.255.255.0).
    #[clap(long, default_value = "255.255.255.0")]
    tun_netmask: std::net::Ipv4Addr,
}

#[cfg(feature = "tun-vpn")]
#[derive(Args, Debug)]
#[clap(about = "Run as TUN-over-QUIC VPN client", long_about = None)]
struct TunClientOptions {
    /// QUIC server address (e.g. 98.82.60.69:443).
    #[clap(long)]
    server: String,
    /// TUN device name (e.g. quic1).
    #[clap(long, default_value = "quic1")]
    tun_name: String,
    /// TUN device IP address (e.g. 10.9.0.2).
    #[clap(long, default_value = "10.9.0.2")]
    tun_addr: std::net::Ipv4Addr,
    /// TUN device netmask (e.g. 255.255.255.0).
    #[clap(long, default_value = "255.255.255.0")]
    tun_netmask: std::net::Ipv4Addr,
    /// Skip TLS certificate verification (for self-signed certs).
    #[clap(long, default_value = "false")]
    insecure: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        // by default no restrictions
        Self {
            client_connection: ClientConnectionConfig {
                initiation_timeout: NO_TIMEOUT,
                relay_policy: RelayPolicy {
                    idle_timeout: NO_TIMEOUT,
                    min_rate_bpm: 0,
                    max_rate_bps: NO_BANDWIDTH_LIMIT,
                },
            },
            target_connection: TargetConnectionConfig {
                dns_cache_ttl: NO_TIMEOUT,
                allowed_targets: Regex::new(".*").expect("Bug: bad default regexp"),
                connect_timeout: NO_TIMEOUT,
                relay_policy: RelayPolicy {
                    idle_timeout: NO_TIMEOUT,
                    min_rate_bpm: 0,
                    max_rate_bps: NO_BANDWIDTH_LIMIT,
                },
            },
        }
    }
}

impl ProxyConfiguration {
    /// For this demo the app reads the key/certs from the disk.
    /// In production more secure approaches should be used (at least encryption with regularly
    /// rotated keys, storing sensitive data on RAM disk only, etc.)
    pub fn from_command_line() -> io::Result<ProxyConfiguration> {
        let cli: Cli = Cli::parse();

        let config = cli.config;
        let bind_address = cli.bind;

        let mode = match cli.command {
            Commands::Http(_) => {
                info!(
                    "Starting in HTTP mode: bind: {}, configuration: {:?}",
                    bind_address, config
                );
                ProxyMode::Http
            }
            Commands::Https(https) => {
                let pkcs12_file = https.pk.as_str();
                let password = https.password.as_str();

                let identity = ProxyConfiguration::tls_identity_from_file(pkcs12_file, password)?;
                info!(
                    "Starting in HTTPS mode: pkcs12: {}, password: {}, bind: {}, configuration: {:?}",
                    pkcs12_file,
                    !password.is_empty(),
                    bind_address,
                    config
                );
                ProxyMode::Https(identity)
            }
            Commands::Tcp(tcp) => {
                let destination = tcp.destination;
                info!(
                    "Starting in TCP mode: destination: {}, configuration: {:?}",
                    destination, config
                );
                ProxyMode::Tcp(destination)
            }
            #[cfg(feature = "quic")]
            Commands::Quic(quic) => {
                info!(
                    "Starting in QUIC mode: cert: {}, key: {}, bind: {}, configuration: {:?}",
                    quic.cert, quic.key, bind_address, config
                );
                ProxyMode::Quic(QuicTlsConfig {
                    cert_path: quic.cert,
                    key_path: quic.key,
                })
            }
            #[cfg(feature = "tun-vpn")]
            Commands::TunServer(opts) => {
                info!(
                    "Starting TUN VPN server: cert: {}, key: {}, tun: {}/{}, bind: {}",
                    opts.cert, opts.key, opts.tun_addr, opts.tun_netmask, bind_address
                );
                ProxyMode::TunServer(TunServerConfig {
                    cert_path: opts.cert,
                    key_path: opts.key,
                    tun_addr: opts.tun_addr,
                    tun_netmask: opts.tun_netmask,
                })
            }
            #[cfg(feature = "tun-vpn")]
            Commands::TunClient(opts) => {
                info!(
                    "Starting TUN VPN client: server: {}, tun: {} ({}/{}), insecure: {}",
                    opts.server, opts.tun_name, opts.tun_addr, opts.tun_netmask, opts.insecure
                );
                ProxyMode::TunClient(TunClientConfig {
                    server_addr: opts.server,
                    tun_name: opts.tun_name,
                    tun_addr: opts.tun_addr,
                    tun_netmask: opts.tun_netmask,
                    insecure: opts.insecure,
                })
            }
        };

        let tunnel_config = match config {
            None => TunnelConfig::default(),
            Some(config) => ProxyConfiguration::read_tunnel_config(config.as_str())?,
        };

        Ok(ProxyConfigurationBuilder::default()
            .bind_address(bind_address)
            .mode(mode)
            .tunnel_config(tunnel_config)
            .build()
            .expect("ProxyConfigurationBuilder failed"))
    }

    fn tls_identity_from_file(filename: &str, password: &str) -> io::Result<Identity> {
        let mut file = File::open(filename).map_err(|e| {
            error!("Error opening PKSC12 file {}: {}", filename, e);
            e
        })?;

        let mut identity = vec![];

        file.read_to_end(&mut identity).map_err(|e| {
            error!("Error reading file {}: {}", filename, e);
            e
        })?;

        Identity::from_pkcs12(&identity, password).map_err(|e| {
            error!("Cannot process PKCS12 file {}: {}", filename, e);
            Error::from(ErrorKind::InvalidInput)
        })
    }

    fn read_tunnel_config(filename: &str) -> io::Result<TunnelConfig> {
        let mut file = File::open(filename).map_err(|e| {
            error!("Error opening config file {}: {}", filename, e);
            e
        })?;

        let mut yaml = vec![];

        file.read_to_end(&mut yaml).map_err(|e| {
            error!("Error reading file {}: {}", filename, e);
            e
        })?;

        let result: TunnelConfig = serde_yml::from_slice(&yaml).map_err(|e| {
            error!("Error parsing yaml {}: {}", filename, e);
            Error::from(ErrorKind::InvalidInput)
        })?;

        Ok(result)
    }
}
