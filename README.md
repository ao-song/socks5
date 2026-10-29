# SOCKS5

A SOCKS5 server in Erlang/OTP implementing [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928) (SOCKS Protocol Version 5), [RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929) (Username/Password Authentication) and [RFC 1961](https://datatracker.ietf.org/doc/html/rfc1961) (GSS-API Authentication).

## Features

*   **CONNECT**, **BIND** and **UDP ASSOCIATE** with IPv4, IPv6 and domain-name addresses.
*   Listens on IPv4 and IPv6; domain names are resolved to both and tried in turn.
*   UDP relay through a dual-stack socket, so an IPv4 client can reach IPv6 targets and vice versa. Fragmented datagrams (FRAG ≠ 0) are dropped, as the RFC permits.
*   TCP half-close is relayed, so protocols that shut down one direction first keep working.
*   Authentication methods, offered in configurable preference order:
    *   `no_auth` (X'00')
    *   `gssapi` (X'01', RFC 1961) with Kerberos V5 via [kerlberos](https://github.com/arekinath/kerlberos), including per-message encapsulation of requests, replies, relayed TCP data and UDP datagrams.
    *   `username_password` (X'02', RFC 1929), constant-time password comparison.
*   Idle timeout for established relays.
*   Error replies for every failure class defined by the RFC, followed by closing the connection.

## Configuration

All settings live in `config/sys.config` under the `socks5` application:

| Key | Default | Meaning |
|-----|---------|---------|
| `socks5_port` | `1080` | Listening port |
| `socks5_ip` | all interfaces, IPv4 and IPv6 | Listen on one address only |
| `socks5_users` | `[]` | `{Username, Password}` pairs for RFC 1929 |
| `socks5_gssapi` | unset | `#{keytab => Path, levels => [0, 1, 2]}` for RFC 1961 |
| `socks5_auth_methods` | derived | Offered methods in preference order, e.g. `[gssapi, username_password, no_auth]` |
| `socks5_idle_timeout` | `600000` | Milliseconds without traffic before a relay is closed |

With no `socks5_auth_methods` the server offers `gssapi` if `socks5_gssapi` is set, else `username_password` if `socks5_users` is non-empty, else `no_auth`.

### GSS-API notes

*   The keytab must hold the key of the service principal clients ask for, normally `socks/<hostname>@REALM`.
*   Protection levels: 0 none (a de-facto extension used by curl and Dante), 1 integrity, 2 confidentiality. Level 3 (selective) is treated as 2. The server answers with the client's level if it is in `levels`, otherwise the highest allowed one.
*   The Kerberos mechanism in kerlberos always encrypts wrap tokens, so level 1 traffic is in practice protected like level 2.
*   NEC-style clients that send the protection level as a bare octet are supported.
*   The mechanism is pluggable: `#{mech => Module, mech_options => Map}` where `Module` implements kerlberos' `gss_mechanism` behaviour.

## Build, test, run

```
rebar3 eunit          # RFC 1928/1929/1961 protocol tests against a live server
rebar3 release && _build/default/rel/socks5/bin/socks5 foreground
curl --socks5-hostname localhost:1080 --proxy-user testuser:testpass http://example.com
docker compose up     # same, in a container
```

## Future

*   Client connection over TLS/DTLS.
