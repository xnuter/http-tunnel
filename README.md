[![Crate](https://img.shields.io/crates/v/http-tunnel.svg)](https://crates.io/crates/http-tunnel)
![Clippy/Fmt](https://github.com/xnuter/http-tunnel/workflows/Clippy/Fmt/badge.svg)
![Tests](https://github.com/xnuter/http-tunnel/workflows/Tests/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/xnuter/http-tunnel/badge.svg?branch=main)](https://coveralls.io/github/xnuter/http-tunnel?branch=main)

### Overview

An implementation of [HTTP Tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel) in Rust, which can also function as a TCP proxy.

The core code is entirely abstract from the tunnel protocol or transport protocols.
It supports `HTTP`, `HTTPS`, and `QUIC` (HTTP/3) transports with minimal additional code.

*Please note*, this tunnel doesn't allow tunneling of plain text over HTTP tunnels (only HTTPS connections can be tunneled).
If you need this functionality you need to build the `http-tunnel` with the `plain_text` feature:

```bash
cargo build --release --features plain_text
```

To enable QUIC transport, build with the `quic` feature:

```bash
cargo build --release --features quic
```

The architecture is fully extensible — any transport satisfying `AsyncRead + AsyncWrite` can be plugged in.

You can check [benchmarks](https://github.com/xnuter/perf-gauge/wiki/Benchmarking-TCP-Proxies-written-in-different-languages:-C,-CPP,-Rust,-Golang,-Java,-Python).

[Read more](https://medium.com/@xnuter/writing-a-modern-http-s-tunnel-in-rust-56e70d898700) about the design.

### Quick overview of source files

* `configuration.rs` - contains configuration structures + a basic CLI
  * see `config/` with configuration files/TLS materials
* `http_tunnel_codec.rs` - a codec to process the initial HTTP request and encode a corresponding response.
* `proxy_target.rs` - an abstraction + basic TCP implementation to connect target servers.
  * contains a DNS resolver with a basic caching strategy (cache for a given `TTL`)
* `relay.rs` - relaying data from one stream to another, `tunnel = upstream_relay + downstream_relay`
  * also, contains basic `relay_policy`
* `tunnel.rs` - a tunnel. It's built from:
  * a tunnel handshake codec (e.g. `HttpTunnelCodec`)
  * a target connector
  * client connection as a stream
* `quic.rs` - QUIC transport adapter (behind `--features quic`)
  * `QuicBiStream` — combines quinn's `SendStream` + `RecvStream` into `AsyncRead + AsyncWrite`
  * `build_quic_server_config()` — loads PEM certificates for QUIC/TLS 1.3
* `main.rs` - application. May start `HTTP`, `HTTPS`, `TCP`, or `QUIC` tunnel (based on the command line parameters).
  * emits log to `logs/application.log` (`log/` contains the actual output of the app from the browser session)
  * metrics to `logs/metrics.log` - very basic, to demonstrate the concept.
          
### Run demo

Install via `cargo`:

```
cargo install http-tunnel
```

Now you can start it without any configuration:

```
$ http-tunnel --bind 0.0.0.0:8080 http
```

There are four modes.

* `HTTPS`:
```
$ http-tunnel --config ./config/config.yaml \
              --bind 0.0.0.0:8443 \
              https --pk "./config/domain.pfx" --password "6B9mZ*1hJ#xk"
```

* `HTTP`:
```
$ http-tunnel --config ./config/config-browser.yaml --bind 0.0.0.0:8080 http
```

* `TCP Proxy`:
```
$ http-tunnel --config ./config/config-browser.yaml --bind 0.0.0.0:8080 tcp --destination $REMOTE_HOST:$REMOTE_PORT
```

* `QUIC` (HTTP/3, requires `--features quic`):
```
$ http-tunnel --config ./config/config.yaml \
              --bind 0.0.0.0:8443 \
              quic --cert ./config/fullchain.pem --key ./config/privkey.pem
```

### Testing with a browser (HTTP)

In Firefox, you can set the HTTP proxy to `localhost:8080`. Make sure you run it with the right configuration:

https://support.mozilla.org/en-US/kb/connection-settings-firefox

(use HTTP Proxy and check "use this proxy for FTP and HTTPS")

```
$ ./target/release/http-tunnel --config ./config/config-browser.yaml --bind 0.0.0.0:8080 http
```

### Testing with cURL (HTTPS)

This proxy can be tested with `cURL`:

Add `simple.rust-http-tunnel.org'` to `/etc/hosts`:
```
$ echo '127.0.0.1       simple.rust-http-tunnel.org' | sudo tee -a /etc/hosts
```

Then try access-listed targets (see `./config/config.yaml`), e.g:

```
curl -vp --proxy https://simple.rust-http-tunnel.org:8443  --proxy-cacert ./config/domain.crt https://www.wikipedia.org
``` 

You can also play around with targets that are not allowed.

### Testing QUIC mode

First, generate a self-signed X.509v3 certificate (QUIC requires TLS 1.3 with v3 certs):

```bash
openssl req -x509 -newkey rsa:2048 \
    -keyout ./config/quic-domain.key -out ./config/quic-domain.crt \
    -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Start the QUIC tunnel:

```bash
cargo run --features quic -- \
    --config ./config/config.yaml \
    --bind 0.0.0.0:8443 \
    quic --cert ./config/quic-domain.crt --key ./config/quic-domain.key
```

You can test with any QUIC-capable HTTP client. For example, using `curl` with HTTP/3 support:

```bash
curl --http3 -vp --proxy-insecure \
    --proxy https://localhost:8443 \
    https://www.wikipedia.org
```

> **Note:** The existing `config/domain.crt` is X.509v1 and is not compatible with QUIC/rustls.
> Use the generated `quic-domain.crt`/`quic-domain.key` or your own v3 certificates.

### Privacy

The application cannot see the plaintext data.

The application doesn't log any information that may help identify clients (such as IP, auth tokens).
Only general information (events, errors, data sizes) is logged for monitoring purposes. 

#### DDoS protection

* `Slowloris` attack (opening tons of slow connections)
* Sending requests resulting in large responses

Some of them can be solved by introducing rate/age limits and inactivity timeouts.

### Build

Install `cargo` - [follow these instructions](https://doc.rust-lang.org/cargo/getting-started/installation.html)

On `Debian` to fix [OpenSSL build issue](https://docs.rs/openssl/0.10.30/openssl/):

```
sudo apt-get install pkg-config libssl-dev
```

### Installation

On MacOS:

```
curl https://sh.rustup.rs -sSf | sh
cargo install http-tunnel
http-tunnel --bind 0.0.0.0:8080 http
```

On Debian based Linux:

```
curl https://sh.rustup.rs -sSf | sh
sudo apt-get -y install gcc pkg-config libssl-dev
cargo install http-tunnel
http-tunnel --bind 0.0.0.0:8080 http
```
