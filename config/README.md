### PCKS12 generation

In case you want to generate your own TLS materials.
These self-signed certs are generated for `simple.rust-http-tunnel.org` domain.

Generate cert/pk:

```
openssl req \
       -newkey rsa:2048 -nodes -keyout domain.key \
       -x509 -days 365 -out domain.crt
```

Create a `pkcs12` file:

```
openssl pkcs12 \
       -inkey domain.key \
       -in domain.crt \
       -export -out domain.pfx
```
