socks5
=====

A socks5 proxy partially implemented in erlang, tested with firefox.

Build and Run
-----

On the terminal of proxy host run the commands below

    $ ./rebar3 release
    $ ./rebar3 shell

Config your browser or other socks5 client with the address of proxy and port 1080.

Here we go!

(There is a socks5 client implemented in test folder, just for your reference!)

Todo:
-----

- [ ] Code optimization
- [ ] UDP support
- [ ] GSSAPI must and username/password impl
- [ ] message encryption
- [ ] bind