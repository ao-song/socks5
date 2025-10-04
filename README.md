# SOCKS5

This project is a robust, yet delightfully simple, implementation of the SOCKS5 protocol ([RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)) and its trusty sidekick, Username/Password Authentication ([RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929)).

## What it does (without the drama):
*   **TCP Proxying (`CONNECT`):** Connects your IPv4, IPv6, and domain-named traffic through a secure tunnel.
*   **Incoming Connections (`BIND`):** Allows remote peers to connect back to you.
*   **UDP Proxying (`UDP ASSOCIATE`):** For when your datagrams need a discreet detour.
*   **Authentication:** Supports both `NO AUTHENTICATION REQUIRED` (for the brave) and `USERNAME/PASSWORD` (for the slightly less brave).

## Future Enhancements (because we're always striving for more):
*   GSSAPI authentication (because who doesn't love a good Kerberos ticket?)
*   Client connection over TLS/DTLS (for that extra layer of digital armor)

Dive in, and let your network traffic flow with confidence (and a chuckle).😊
