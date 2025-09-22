socks5
=====
A toy project that implements [rfc1928](https://datatracker.ietf.org/doc/html/rfc1928) (SOCKS5) and [rfc1929](https://datatracker.ietf.org/doc/html/rfc1929) (Username/Password Authentication).

Supported:
-----
1. `CONNECT` command for TCP proxying (IPv4, IPv6, Domain Names).
2. `BIND` command for accepting connections from a remote peer.
3. `UDP ASSOCIATE` command for UDP proxying.
4. Authentication Methods:
    - `NO AUTHENTICATION REQUIRED`
    - `USERNAME/PASSWORD`

Todo:
-----
- [ ] GSSAPI authentication (`GSSAPI`)
- [ ] Client connction over tls/dtls
