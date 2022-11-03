socks5
=====

An experimental socks5 proxy implemented in erlang, tested with firefox.

Following [rfc1928](https://datatracker.ietf.org/doc/html/rfc1928) but not fully implemeted yet!


Refactor reminder:
-----
1. logger refactor later
2. add more logs
3. worker socket management
4. supervisor management revise
5. logger config
6. app config
7. containerize app

Want a try
-----

On the terminal of proxy host run the commands below

    $ ./rebar3 release
    $ ./rebar3 shell

Config your browser or other socks5 client with the address of proxy and port 1080.

Here we go!


Todo:
-----

- [ ] Code optimization
- [ ] UDP support
- [ ] GSSAPI must and username/password impl
- [ ] message encryption
- [ ] bind
