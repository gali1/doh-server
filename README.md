# DoH Proxy with HTTP Authorization and Several Server Side Functions

This repo is a fork of `doh-proxy`. This forked version has the following functions in addition to ones of original version. **Use [`junkurihara/doh-auth-proxy`](https://github.com/junkurihara/doh-auth-proxy) to fully leverage the following functions.

- Proxy function of Oblivious DNS over HTTPS in addition to the target (server) function
- **Multiple hops of intermediate relays are enabled in addition to the standard ODoH protocol**, which is called *Mutualized Oblivious DNS over HTTPS* (MODoH).
- **Access control by HTTP Authorization header with bearer token at target and proxy endpoints independently.**
- Server-side blocking by query names (currently returns NXDOMAIN, and supports exact match, suffix match, and prefix match)
- server-side overriding query names with specific IP addresses
- (TODO:) configuration file
- (TODO:) logging

## Usage

```:text
USAGE:
    doh-proxy [FLAGS] [OPTIONS]

FLAGS:
    -O, --allow-odoh-post      Allow POST queries over ODoH even if they have been disabled for DoH
    -K, --disable-keepalive    Disable keepalive
    -P, --disable-post         Disable POST queries
    -h, --help                 Prints help information
    -V, --version              Prints version information

OPTIONS:
    -j, --client-ids-proxy <client_ids_proxy>
            Proxy allowed client ids of Id token, separated with comma like "id_a,id_b"

    -J, --client-ids-target <client_ids_target>
            Target allowed client ids of Id token, separated with comma like "id_a,id_b"

    -B, --domain-block-rule <domain_block>
            Domains block rule file path like "./domains_block.txt"

    -R, --domain-override-rule <domain_override>
            Domains override rule file path like "./domains_override.txt"

    -E, --err-ttl <err_ttl>                                            TTL for errors, in seconds [default: 2]
    -H, --hostname <hostname>
            Host name (not IP address) DoH clients will use to connect

    -l, --listen-address <listen_address>                              Address to listen to [default: 127.0.0.1:3000]
    -b, --local-bind-address <local_bind_address>                      Address to connect from
    -c, --max-clients <max_clients>
            Maximum number of simultaneous clients [default: 512]

    -C, --max-concurrent <max_concurrent>
            Maximum number of concurrent requests per client [default: 16]

    -X, --max-ttl <max_ttl>                                            Maximum TTL, in seconds [default: 604800]
    -T, --min-ttl <min_ttl>                                            Minimum TTL, in seconds [default: 10]
    -d, --odoh-allowed-proxy-ips <odoh_allowed_proxy_ips>
            Allowed ODoH proxies' IP addresses/DoH client addresses from which this node (as (O)DoH target and intermediate relay)
            can accept requests, separated with comma. If some ips are given, requests from them are accepted even if authorization
            header is missing. If none is given and no authorization is configured, it can accept anywhere.
    -D, --odoh-allowed-target-domains <odoh_allowed_target_domains>
            Allowed domains of ODoH target or MODoH intermediate relay to which this node (as ODoH proxy) can forward ODoH request,
            separated with comma. If none is given, it can forward anywhere.
    -q, --odoh-proxy-path <odoh_proxy_path>                            ODoH proxy URI path [default: /proxy]
    -p, --path <path>                                                  URI path [default: /dns-query]
    -g, --public-address <public_address>                              External IP address DoH clients will connect to
    -u, --server-address <server_address>                              Address to connect to [default: 9.9.9.9:53]
    -t, --timeout <timeout>                                            Timeout, in seconds [default: 10]
    -m, --token-issuer-proxy <token_issuer_proxy>
            Proxy allowed issuer of Id token specified as URL like "https://example.com/issue"

    -M, --token-issuer-target <token_issuer_target>
            Target allowed issuer of Id token specified as URL like "https://example.com/issue"

    -a, --validation-algorithm-proxy <validation_algorithm_proxy>      Proxy validation algorithm [default: ES256]
    -A, --validation-algorithm-target <validation_algorithm_target>    Target validation algorithm [default: ES256]
    -w, --validation-key-proxy <validation_key_proxy>
            Proxy validation key file path like "./public_key.pem"

    -W, --validation-key-target <validation_key_target>
            Target validation key file path like "./public_key.pem"
```

Below is the original README.md

---

# ![DoH server (and ODoH - Oblivious DoH server)](logo.png)

A fast and secure DoH (DNS-over-HTTPS) and ODoH (Oblivious DoH) server.

`doh-proxy` is written in Rust, and has been battle-tested in production since February 2018. It doesn't do DNS resolution on its own, but can sit in front of any DNS resolver in order to augment it with DoH support.

## Installation

### Option 1: precompiled binaries for Linux

Precompiled tarballs and Debian packages for Linux/x86_64 [can be downloaded here](https://github.com/jedisct1/doh-server/releases/latest).

### Option 2: from source code

This requires the [`rust`](https://rustup.rs) compiler to be installed.

* With built-in support for HTTPS (default):

```sh
cargo install doh-proxy
```

* Without built-in support for HTTPS:

```sh
cargo install doh-proxy --no-default-features
```

* With Oblivious DoH Proxy function (**for testing pupose**):

```sh
cargo install doh-proxy --features=doh-proxy
```

## Usage

```text
USAGE:
    doh-proxy [FLAGS] [OPTIONS]

FLAGS:
    -O, --allow-odoh-post      Allow POST queries over ODoH even if they have been disabled for DoH
    -K, --disable-keepalive    Disable keepalive
    -P, --disable-post         Disable POST queries
    -h, --help                 Prints help information
    -V, --version              Prints version information

OPTIONS:
    -E, --err-ttl <err_ttl>                          TTL for errors, in seconds [default: 2]
    -H, --hostname <hostname>                        Host name (not IP address) DoH clients will use to connect
    -l, --listen-address <listen_address>            Address to listen to [default: 127.0.0.1:3000]
    -b, --local-bind-address <local_bind_address>    Address to connect from
    -c, --max-clients <max_clients>                  Maximum number of simultaneous clients [default: 512]
    -C, --max-concurrent <max_concurrent>            Maximum number of concurrent requests per client [default: 16]
    -X, --max-ttl <max_ttl>                          Maximum TTL, in seconds [default: 604800]
    -T, --min-ttl <min_ttl>                          Minimum TTL, in seconds [default: 10]
    -q, --odoh-proxy-path <odoh_proxy_path>          ODoH proxy URI path [default: /proxy]
    -p, --path <path>                                URI path [default: /dns-query]
    -g, --public-address <public_address>            External IP address DoH clients will connect to
    -j, --public-port <public_port>                  External port DoH clients will connect to, if not 443
    -u, --server-address <server_address>            Address to connect to [default: 9.9.9.9:53]
    -t, --timeout <timeout>                          Timeout, in seconds [default: 10]
```

Example command-line:

```sh
doh-proxy -H 'doh.example.com' -u 127.0.0.1:53 -g 233.252.0.5
```

Here, `doh.example.com` is the host name (which should match a name included in the TLS certificate), `127.0.0.1:53` is the address of the DNS resolver, and `233.252.0.5` is the public IP address of the DoH server.

## HTTP/2 and HTTP/3 termination

The recommended way to use `doh-proxy` is to use a TLS termination proxy (such as [hitch](https://github.com/varnish/hitch) or [relayd](https://man.openbsd.org/relayd.8)), a CDN or a web server with proxying abilities as a front-end.

That way, the DoH service can be exposed as a virtual host, sharing the same IP addresses as existing websites.

If `doh-proxy` and the HTTP/2 (/ HTTP/3) front-end run on the same host, using the HTTP protocol to communicate between both is fine.

If both are on distinct networks, such as when using a CDN, `doh-proxy` can handle HTTPS requests, provided that it was compiled with the `tls` feature.

The certificates and private keys must be encoded in PEM/PKCS#8 format. They can be stored in the same file.

If you are using ECDSA certificates and ECDSA private keys start with `-----BEGIN EC PRIVATE KEY-----` and not `-----BEGIN PRIVATE KEY-----`, convert them to PKCS#8 with (in this example, `example.key` is the original file):

```sh
openssl pkcs8 -topk8 -nocrypt -in example.key -out example.pkcs8.pem
```

In order to enable built-in HTTPS support, add the `--tls-cert-path` option to specify the location of the certificates file, as well as the private keys file using `--tls-cert-key-path`.

Once HTTPS is enabled, HTTP connections will not be accepted.

A sample self-signed certificate [`localhost.pem`](https://github.com/jedisct1/doh-server/raw/master/localhost.pem) can be used for testing.
The file also includes the private key.

[`acme.sh`](https://github.com/acmesh-official/acme.sh) can be used to create and update TLS certificates using Let's Encrypt and other ACME-compliant providers. If you are using it to create ECDSA keys, see above for converting the secret key into PKCS#8.

The certificates path must be set to the full certificates chain (`fullchain.cer`) and the key path to the secret keys (the `.key` file):

```sh
doh-proxy -i /path/to/fullchain.cer -I /path/to/domain.key ...
```

Once started, `doh-proxy` automatically reloads the certificates as they change; there is no need to restart the server.

If clients are getting the `x509: certificate signed by unknown authority` error, double check that the certificate file is the full chain, not the other `.cer` file.

## Accepting both DNSCrypt and DoH connections on port 443

DNSCrypt is an alternative encrypted DNS protocol that is faster and more lightweight than DoH.

Both DNSCrypt and DoH connections can be accepted on the same TCP port using [Encrypted DNS Server](https://github.com/jedisct1/encrypted-dns-server).

Encrypted DNS Server forwards DoH queries to Nginx or `doh-proxy` when a TLS connection is detected, or directly responds to DNSCrypt queries.

It also provides DNS caching, server-side filtering, metrics, and TCP connection reuse in order to mitigate exhaustion attacks.

Unless the front-end is a CDN, an ideal setup is to use `doh-proxy` behind `Encrypted DNS Server`.

## Oblivious DoH (ODoH)

Oblivious DoH is similar to Anonymized DNSCrypt, but for DoH. It requires relays, but also upstream DoH servers that support the protocol.

This proxy supports ODoH termination out of the box.

However, ephemeral keys are currently only stored in memory. In a load-balanced configuration, sticky sessions must be used.

This also also provides ODoH relaying (Oblivious Proxy) of naive implementation, which is **for testing purposes only**. Please do not deploy the relaying function AS-IS. You need to carefully consider the performance and security issues when you deploy ODoH relays. Further, the relaying protocol is not fully fixed yet in the IETF draft.

As currently available ODoH relays only use `POST` queries, this proxy accepts and issues `POST` queries both in ODoH target and relay functions.
So, `POST` queries have been disabled for regular DoH queries, accepting them is required to be compatible with ODoH relays.

This can be achieved with the `--allow-odoh-post` command-line switch.

## Operational recommendations

* DoH can be easily detected and blocked using SNI inspection. As a mitigation, DoH endpoints should preferably share the same virtual host as existing, popular websites, rather than being on dedicated virtual hosts.
* When using DoH, DNS stamps should include a resolver IP address in order to remove a dependency on non-encrypted, non-authenticated, easy-to-block resolvers.
* Unlike DNSCrypt where users must explicitly trust a DNS server's public key, the security of DoH relies on traditional public Certificate Authorities. Additional root certificates (required by governments, security software, enterprise gateways) installed on a client immediately make DoH vulnerable to MITM. In order to prevent this, DNS stamps should include the hash of the parent certificate.
* TLS certificates are tied to host names. But domains expire, get reassigned and switch hands all the time. If a domain originally used for a DoH service gets a new, possibly malicious owner, clients still configured to use the service will blindly keep trusting it if the CA is the same. As a mitigation, the CA should sign an intermediate certificate (the only one present in the stamp), itself used to sign the name used by the DoH server. While commercial CAs offer this, Let's Encrypt currently doesn't.
* Make sure that the front-end supports at least HTTP/2 and TLS 1.3.
* Internal DoH servers still require TLS certificates. So, if you are planning to deploy an internal server, you need to set up an internal CA, or add self-signed certificates to every single client.

## Example usage with `encrypted-dns-server`

Add the following section to the configuration file:

```toml
[tls]
upstream_addr = "127.0.0.1:3000"
```

## Example usage with `nginx`

In an existing `server`, a `/dns-query` endpoint can be exposed that way:

```text
location /dns-query {
  proxy_pass http://127.0.0.1:3000;
}
```

This example assumes that the DoH proxy is listening locally to port `3000`.

HTTP caching can be added (see the `proxy_cache_path` and `proxy_cache` directives in the Nginx documentation), but be aware that a DoH server will quickly create a gigantic amount of files.

## DNS Stamp and certificate hashes

Use the online [DNS stamp calculator](https://dnscrypt.info/stamps/) to compute the stamp for your server.

Add it to the `[static]` section of [`dnscrypt-proxy`](https://github.com/DNSCrypt/dnscrypt-proxy) and check that everything works as expected.

Then, start `dnscrypt-proxy` with the `-show-certs` command-line flag to print the hashes for your certificate chain.

Here is an example output:

```text
[NOTICE] Advertised cert: [CN=dohtrial.att.net,O=AT&T Services\, Inc.,L=Dallas,ST=Texas,C=US] [f679e8451940f06141854dc94e1eb79fa5e04463c15b88f3b392da793c16c353]
[NOTICE] Advertised cert: [CN=DigiCert Global CA G2,O=DigiCert Inc,C=US] [f61e576877da9650294cccb5f96c75fcb71bda1bbc4646367c4ebeda89d7318f]
```

The first printed certificate is the certificate of the server itself. The next line is the one that signed that certificate. As you keep going down, you are getting closer to the certificate authority.

Unless you are using intermediate certificates, your safest option is probably to include the last printed hash certificate in your DNS stamp.

Go back to the online DNS stamp calculator, and copy&paste the hash (in this example: `f61e576877da9650294cccb5f96c75fcb71bda1bbc4646367c4ebeda89d7318f`).

If you are using Let's Encrypt, the last line is likely to be:

```text
Advertised cert: [CN=Let's Encrypt Authority R3,O=Let's Encrypt,C=US] [444ebd67bb83f8807b3921e938ac9178b882bd50aadb11231f044cf5f08df7ce]
```

There you have it. Your certificate hash is `444ebd67bb83f8807b3921e938ac9178b882bd50aadb11231f044cf5f08df7ce`.

This [Go code snippet](https://gist.github.com/d6cb41742a1ceb54d48cc286f3d5c5fa) can also compute the hash of certificates given a `.der` file.

### Common certificate hashes

* Let's Encrypt R3:
  * `444ebd67bb83f8807b3921e938ac9178b882bd50aadb11231f044cf5f08df7ce`
* Let's Encrypt E1:
  * `cc1060d39c8329b62b6fbc7d0d6df9309869b981e7e6392d5cd8fa408f4d80e6`

## Clients

`doh-proxy` can be used with [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) as a client.

`doh-proxy` is used in production for the `doh.crypto.sx` public DNS resolver and many others.

An extensive list of public DoH servers can be found here: [public encrypted DNS servers](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/public-resolvers.md).
