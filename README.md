![Clippy/Fmt](https://github.com/xnuter/http-tunnel/workflows/Clippy/Fmt/badge.svg)
![Tests](https://github.com/xnuter/http-proxy/workflows/Tests/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/xnuter/http-tunnel/badge.svg?branch=initial-commit)](https://coveralls.io/github/xnuter/http-tunnel?branch=initial-commit)

### Overview

An implementation of [HTTP Tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel) in Rust.

The core code is entirely abstract from the tunnel protocol or transport protocols.
In this example, it supports both `HTTP` and `HTTPS` with minimal additional code. 

It can run over `QUIC+HTTP/3` or connect via another tunnel (as long as `AsyncRead + AsyncWrite` is satisfied for the implementation).

### Quick overview of source files

* `configuration.rs` - contains configuration structures + a basic CLI
  * see `config/` with configuration files/TLS materials
* `http-tunnel_codec.rs` - a codec to process the initial HTTP request and encode a corresponding response.
* `upstream.rs` - an abstraction + basic TCP implementation to connect upstream servers.
  * contains a DNS resolver with a basic caching strategy (cache for a given `TTL`)
* `relay.rs` - relaying data from one stream to another, `tunnel = upstream_relay + downstream_relay`
  * also, contains basic `relay_policy`
* `tunnel.rs` - a tunnel. It's built from:
  * a tunnel handshake codec (e.g. `HttpTunnelCodec`)
  * an upstream connector
  * downstream (client) connection as a stream
* `main.rs` - application. May start `HTTP` or `HTTPS` tunnel (based on the command line parameters).
  * emits log to `logs/application.log` (`log/` contains the actual output of the app from the browser session)
  * metrics to `logs/metrics.log` - very basic, to demonstrate the concept.`
          
### Run demo

There are two modes.

* `HTTPS`:
```
$ cargo fmt && cargo clippy && cargo test
$ cargo build --release
$ ./target/release/http-tunnel --config ./config/config.yaml --bind 0.0.0.0:8443 https --pk "./config/domain.pfx" --password "6B9mZ*1hJ#xk"
```

* `HTTP`:
```
$ cargo fmt && cargo clippy && cargo test 
$ cargo build --release
$ ./target/release/http-tunnel --config ./config/config-browser.yaml --bind 0.0.0.0:8080 http
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

Add `simple.rust-proxy.org'` to `/etc/hosts`:
```
$ echo '127.0.0.1       simple.rust-http-tunnel.org' | sudo tee -a /etc/hosts
```

Then try access-listed destinations (see `./config/config.yaml`), e.g:

```
curl -vp --proxy https://simple.rust-http-tunnel.org:8443  --proxy-cacert ./config/domain.crt https://www.wikipedia.org
``` 

You can also play around with destinations that are not allowed.

### Privacy

The application cannot see the plaintext data.

The application doesn't log any information that may help identify clients (such as IP, auth tokens).
Only general information (events, errors, data sizes) is logged for monitoring purposes. 

#### DDoS protection

* `Slowloris` attack (opening tons of slow connections)
* Sending requests resulting in large responses

Some of them can be solved by introducing rate/age limits and inactivity timeouts.
