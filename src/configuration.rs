/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.
use crate::relay::{RelayPolicy, NO_BANDWIDTH_LIMIT, NO_TIMEOUT};
use clap::clap_app;
use log::{error, info};
use native_tls::Identity;
use regex::Regex;
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
}

#[derive(Clone, Builder)]
pub struct ProxyConfiguration {
    pub mode: ProxyMode,
    pub bind_address: String,
    pub tunnel_config: TunnelConfig,
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
        let matches = clap_app!(myapp =>
            (name: "Simple HTTP(S) Tunnel")
            (version: "0.1.0")
            (author: "Eugene Retunsky")
            (about: "A simple HTTP(S) tunnel")
            (@arg CONFIG: --config +takes_value "Configuration file")
            (@arg BIND: --bind +required +takes_value "Bind address, e.g. 0.0.0.0:8443")
            (@subcommand http =>
                (about: "Run the tunnel in HTTP mode")
                (version: "0.1.0")
            )
            (@subcommand https =>
                (about: "Run the tunnel in HTTPS mode")
                (version: "0.1.0")
                (@arg PKCS12: --pk +required +takes_value "pkcs12 filename")
                (@arg PASSWORD: --password +required  +takes_value "Password for the pkcs12 file")
            )
            (@subcommand tcp =>
                (about: "Run the tunnel in TCP proxy mode")
                (version: "0.1.0")
                (@arg DESTINATION: --destination -d +required +takes_value "Destination address, e.g. 10.0.0.2:8443")
            )
        )
        .get_matches();

        let config = matches.value_of("CONFIG");

        let bind_address = matches
            .value_of("BIND")
            .expect("misconfiguration for bind")
            .to_string();

        let mode = if matches.subcommand_matches("http").is_some() {
            info!(
                "Starting in HTTP mode: bind: {}, configuration: {:?}",
                bind_address, config
            );
            ProxyMode::Http
        } else if let Some(https) = matches.subcommand_matches("https") {
            let pkcs12_file = https
                .value_of("PKCS12")
                .expect("misconfiguration for pkcs12");
            let password = https
                .value_of("PASSWORD")
                .expect("misconfiguration for password");

            let identity = ProxyConfiguration::tls_identity_from_file(pkcs12_file, password)?;
            info!(
                "Starting in HTTPS mode: pkcs12: {}, password: {}, bind: {}, configuration: {:?}",
                pkcs12_file,
                !password.is_empty(),
                bind_address,
                config
            );
            ProxyMode::Https(identity)
        } else if let Some(tcp) = matches.subcommand_matches("tcp") {
            let destination = tcp
                .value_of("DESTINATION")
                .expect("misconfiguration for destination")
                .to_string();
            info!(
                "Starting in TCP mode: destination: {}, configuration: {:?}",
                destination, config
            );
            ProxyMode::Tcp(destination)
        } else {
            unreachable!("Only http, https and tcp commands are supported");
        };

        let tunnel_config = match config {
            None => TunnelConfig::default(),
            Some(config) => ProxyConfiguration::read_tunnel_config(config)?,
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

        let result: TunnelConfig = serde_yaml::from_slice(&yaml).map_err(|e| {
            error!("Error parsing yaml {}: {}", filename, e);
            Error::from(ErrorKind::InvalidInput)
        })?;

        Ok(result)
    }
}
