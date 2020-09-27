/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.
use crate::relay::RelayPolicy;
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
    HTTP,
    HTTPS(Identity),
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
        let no_limit = 1_000_000_000_000_u64;
        let default_timeout = Duration::from_secs(300);
        Self {
            client_connection: ClientConnectionConfig {
                initiation_timeout: default_timeout,
                relay_policy: RelayPolicy {
                    idle_timeout: default_timeout,
                    min_rate_bpm: 0,
                    max_rate_bps: no_limit,
                },
            },
            target_connection: TargetConnectionConfig {
                dns_cache_ttl: Default::default(),
                allowed_targets: Regex::new(".*").expect("Bug: bad default regexp"),
                connect_timeout: Default::default(),
                relay_policy: RelayPolicy {
                    idle_timeout: default_timeout,
                    min_rate_bpm: 0,
                    max_rate_bps: no_limit,
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
            ProxyMode::HTTP
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
            ProxyMode::HTTPS(identity)
        } else {
            unreachable!("Only http and https commands are supported");
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

        Identity::from_pkcs12(&identity, &password).map_err(|e| {
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
