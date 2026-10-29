%% Exercises RFC 1928 commands, RFC 1929 auth and the RFC 1961 GSSAPI
%% framing (with a fake mechanism) against a server on ephemeral ports.
%% Run with: rebar3 eunit
-module(socks5_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LO, {127, 0, 0, 1}).
-define(LO6, {0, 0, 0, 0, 0, 0, 0, 1}).

socks5_test_() ->
    {setup, fun start/0, fun stop/1,
     fun({Port, Port6}) ->
             [{"CONNECT, request fed one byte at a time", fun() -> connect(Port) end},
              {"CONNECT by domain name, IPv6 fallback",   fun() -> connect_domain(Port) end},
              {"CONNECT over IPv6 to an IPv6 target",     fun() -> connect6(Port6) end},
              {"TCP half-close is relayed",               fun() -> half_close(Port) end},
              {"idle timeout closes the relay",           fun() -> idle(Port) end},
              {"username/password authentication",       fun() -> auth(Port) end},
              {"auth method preference order",            fun() -> methods(Port) end},
              {"error replies close the connection",     fun() -> errors(Port) end},
              {"BIND",                                    fun() -> bind(Port) end},
              {"UDP ASSOCIATE",                           fun() -> udp(Port) end},
              {"UDP ASSOCIATE over IPv6",                 fun() -> udp6(Port6) end},
              {"GSSAPI context establishment variants",  fun() -> gss_establish(Port) end},
              {"GSSAPI level 0: clear messages",          fun() -> gss_clear(Port) end},
              {"GSSAPI level 2: encapsulated CONNECT",    fun() -> gss_connect(Port) end},
              {"GSSAPI level 2: encapsulated UDP",        fun() -> gss_udp(Port) end}]
     end}.

start() ->
    application:set_env(socks5, socks5_port, 0),
    application:set_env(socks5, socks5_users, []),
    application:set_env(socks5, socks5_gssapi,
                        #{mech => socks5_test_mech, mech_options => #{keytab => fake}}),
    application:set_env(socks5, socks5_auth_methods, [no_auth]),
    {ok, _} = application:ensure_all_started(socks5),
    Ports = [{tuple_size(IP), P} || S <- sys:get_state(socks5_listener),
                                    {ok, {IP, P}} <- [inet:sockname(S)]],
    {proplists:get_value(4, Ports), proplists:get_value(8, Ports)}.

stop(_) ->
    application:stop(socks5).

%%% tests

connect(Port) ->
    Echo = tcp_echo(?LO),
    S = proxy(Port),
    send_bytewise(S, <<5, 1, 0>>),
    ?assertEqual(<<5, 0>>, recv(S, 2)),
    send_bytewise(S, <<5, 1, 0, 1, 127, 0, 0, 1, Echo:16>>),
    ?assertMatch({0, {?LO, _}}, reply(S)),
    ok = gen_tcp:send(S, <<"hello">>),
    ?assertEqual(<<"hello">>, recv(S, 5)).

connect_domain(Port) ->
    %% the echo listens on ::1 only: 127.0.0.1 is refused, ::1 is tried next
    Echo = tcp_echo(?LO6),
    {S, <<5, 0>>} = handshake(Port, [0]),
    ok = gen_tcp:send(S, <<5, 1, 0, 3, 9, "localhost", Echo:16>>),
    ?assertMatch({0, {?LO6, _}}, reply(S)),
    ok = gen_tcp:send(S, <<"hello">>),
    ?assertEqual(<<"hello">>, recv(S, 5)).

connect6(Port6) ->
    Echo = tcp_echo(?LO6),
    {ok, S} = gen_tcp:connect(?LO6, Port6, [binary, {active, false}]),
    ok = gen_tcp:send(S, <<5, 1, 0>>),
    ?assertEqual(<<5, 0>>, recv(S, 2)),
    ok = gen_tcp:send(S, <<5, 1, 0, 4, 0:112, 1:16, Echo:16>>),
    ?assertMatch({0, {?LO6, _}}, reply(S)),
    ok = gen_tcp:send(S, <<"hello">>),
    ?assertEqual(<<"hello">>, recv(S, 5)).

half_close(Port) ->
    %% target answers only after it has seen the client's FIN
    Target = tcp_server(?LO, [{exit_on_close, false}],
                        fun(T) -> {error, closed} = gen_tcp:recv(T, 0),
                                  ok = gen_tcp:send(T, <<"done">>) end),
    {S, <<5, 0>>} = handshake(Port, [0]),
    {0, _} = request(S, 1, ?LO, Target),
    ok = gen_tcp:shutdown(S, write),
    ?assertEqual(<<"done">>, recv(S, 4)),
    ?assertEqual({error, closed}, gen_tcp:recv(S, 0, 2000)).

idle(Port) ->
    application:set_env(socks5, socks5_idle_timeout, 200),
    try
        Echo = tcp_echo(?LO),
        {S, <<5, 0>>} = handshake(Port, [0]),
        {0, _} = request(S, 1, ?LO, Echo),
        ?assertEqual({error, closed}, gen_tcp:recv(S, 0, 2000))
    after
        application:unset_env(socks5, socks5_idle_timeout)
    end.

auth(Port) ->
    application:set_env(socks5, socks5_users, [{"user", "pass"}]),
    application:unset_env(socks5, socks5_auth_methods),
    try
        %% only "no auth" offered: no acceptable method, closed
        {S1, R1} = handshake(Port, [0]),
        ?assertEqual(<<5, 16#ff>>, R1),
        ?assertEqual({error, closed}, gen_tcp:recv(S1, 0, 2000)),
        %% wrong password: failure status, closed
        {S2, <<5, 2>>} = handshake(Port, [0, 2]),
        ok = gen_tcp:send(S2, <<1, 4, "user", 3, "bad">>),
        ?assertEqual(<<1, 1>>, recv(S2, 2)),
        ?assertEqual({error, closed}, gen_tcp:recv(S2, 0, 2000)),
        %% unknown user
        {S3, <<5, 2>>} = handshake(Port, [2]),
        ok = gen_tcp:send(S3, <<1, 5, "nobod", 4, "pass">>),
        ?assertEqual(<<1, 1>>, recv(S3, 2)),
        %% right password: success, then CONNECT works
        Echo = tcp_echo(?LO),
        {S4, <<5, 2>>} = handshake(Port, [2]),
        ok = gen_tcp:send(S4, <<1, 4, "user", 4, "pass">>),
        ?assertEqual(<<1, 0>>, recv(S4, 2)),
        ?assertMatch({0, _}, request(S4, 1, ?LO, Echo)),
        ok = gen_tcp:send(S4, <<"hi">>),
        ?assertEqual(<<"hi">>, recv(S4, 2))
    after
        application:set_env(socks5, socks5_users, []),
        application:set_env(socks5, socks5_auth_methods, [no_auth])
    end.

methods(Port) ->
    application:set_env(socks5, socks5_auth_methods, [username_password, gssapi, no_auth]),
    try
        {_, R1} = handshake(Port, [0, 1, 2]),
        ?assertEqual(<<5, 2>>, R1),
        {_, R2} = handshake(Port, [0, 1]),
        ?assertEqual(<<5, 1>>, R2),
        {_, R3} = handshake(Port, [0]),
        ?assertEqual(<<5, 0>>, R3),
        {_, R4} = handshake(Port, [16#80]),
        ?assertEqual(<<5, 16#ff>>, R4)
    after
        application:set_env(socks5, socks5_auth_methods, [no_auth])
    end.

errors(Port) ->
    {ok, L} = gen_tcp:listen(0, [{ip, ?LO}]),
    {ok, Closed} = inet:port(L),
    gen_tcp:close(L),
    %% connection refused
    {S1, <<5, 0>>} = handshake(Port, [0]),
    ?assertMatch({5, _}, request(S1, 1, ?LO, Closed)),
    ?assertEqual({error, closed}, gen_tcp:recv(S1, 0, 2000)),
    %% unresolvable name: host unreachable
    {S2, <<5, 0>>} = handshake(Port, [0]),
    ok = gen_tcp:send(S2, <<5, 1, 0, 3, 19, "nonexistent.invalid", 80:16>>),
    ?assertMatch({4, _}, reply(S2)),
    %% command not supported
    {S3, <<5, 0>>} = handshake(Port, [0]),
    ?assertMatch({7, _}, request(S3, 9, ?LO, 1)),
    ?assertEqual({error, closed}, gen_tcp:recv(S3, 0, 2000)),
    %% address type not supported
    {S4, <<5, 0>>} = handshake(Port, [0]),
    ok = gen_tcp:send(S4, <<5, 1, 0, 9, 0, 0, 0, 0, 0:16>>),
    ?assertMatch({8, _}, reply(S4)),
    ?assertEqual({error, closed}, gen_tcp:recv(S4, 0, 2000)),
    %% not SOCKS5
    S5 = proxy(Port),
    ok = gen_tcp:send(S5, <<4, 1, 0>>),
    ?assertEqual({error, closed}, gen_tcp:recv(S5, 0, 2000)).

bind(Port) ->
    {S, <<5, 0>>} = handshake(Port, [0]),
    {0, {BindIP, BindPort}} = request(S, 2, ?LO, 0),
    ?assertEqual(?LO, BindIP),
    {ok, Remote} = gen_tcp:connect(BindIP, BindPort, [binary, {active, false}]),
    {ok, {_, RemotePort}} = inet:sockname(Remote),
    ?assertEqual({0, {?LO, RemotePort}}, reply(S)),
    ok = gen_tcp:send(Remote, <<"from remote">>),
    ?assertEqual(<<"from remote">>, recv(S, 11)),
    ok = gen_tcp:send(S, <<"to remote">>),
    ?assertEqual(<<"to remote">>, recv(Remote, 9)),
    %% a peer other than DST.ADDR is refused
    {S2, <<5, 0>>} = handshake(Port, [0]),
    {0, {_, BindPort2}} = request(S2, 2, {10, 0, 0, 1}, 0),
    {ok, Remote2} = gen_tcp:connect(?LO, BindPort2, [binary, {active, false}]),
    ?assertMatch({2, _}, reply(S2)),
    ?assertEqual({error, closed}, gen_tcp:recv(Remote2, 0, 2000)).

udp(Port) ->
    Echo = udp_echo(?LO),
    Echo6 = udp_echo(?LO6),
    {S, <<5, 0>>} = handshake(Port, [0]),
    {0, {RelayIP, RelayPort}} = request(S, 3, {0, 0, 0, 0}, 0),
    ?assertEqual(?LO, RelayIP),
    {ok, C} = gen_udp:open(0, [binary, {active, false}, {ip, ?LO}]),
    Datagram = <<0, 0, 0, 1, 127, 0, 0, 1, Echo:16, "ping">>,
    ok = gen_udp:send(C, RelayIP, RelayPort, Datagram),
    ?assertEqual({ok, {RelayIP, RelayPort, Datagram}}, gen_udp:recv(C, 0, 2000)),
    %% an IPv6 target through the same association
    Datagram6 = <<0, 0, 0, 4, 0:112, 1:16, Echo6:16, "ping6">>,
    ok = gen_udp:send(C, RelayIP, RelayPort, Datagram6),
    ?assertEqual({ok, {RelayIP, RelayPort, Datagram6}}, gen_udp:recv(C, 0, 2000)),
    %% a domain-name target
    DatagramD = <<0, 0, 0, 3, 9, "localhost", Echo:16, "pingd">>,
    ok = gen_udp:send(C, RelayIP, RelayPort, DatagramD),
    ?assertEqual({ok, {RelayIP, RelayPort, <<0, 0, 0, 1, 127, 0, 0, 1, Echo:16, "pingd">>}},
                 gen_udp:recv(C, 0, 2000)),
    %% fragments are dropped
    ok = gen_udp:send(C, RelayIP, RelayPort, <<0, 0, 1, 1, 127, 0, 0, 1, Echo:16, "frag">>),
    ?assertEqual({error, timeout}, gen_udp:recv(C, 0, 300)),
    %% closing the TCP connection ends the association
    gen_tcp:close(S),
    timer:sleep(100),
    gen_udp:send(C, RelayIP, RelayPort, Datagram),
    ?assertMatch({error, _}, gen_udp:recv(C, 0, 300)).

udp6(Port6) ->
    Echo = udp_echo(?LO),
    {ok, S} = gen_tcp:connect(?LO6, Port6, [binary, {active, false}]),
    ok = gen_tcp:send(S, <<5, 1, 0>>),
    <<5, 0>> = recv(S, 2),
    ok = gen_tcp:send(S, <<5, 3, 0, 4, 0:128, 0:16>>),
    {0, {?LO6, RelayPort}} = reply(S),
    {ok, C} = gen_udp:open(0, [binary, {active, false}, inet6, {ip, ?LO6}]),
    Datagram = <<0, 0, 0, 1, 127, 0, 0, 1, Echo:16, "ping">>,
    ok = gen_udp:send(C, ?LO6, RelayPort, Datagram),
    ?assertEqual({ok, {?LO6, RelayPort, Datagram}}, gen_udp:recv(C, 0, 2000)).

gss_establish(Port) ->
    with_gssapi(fun() ->
        %% continue -> ok with final token
        {S1, <<5, 1>>} = handshake(Port, [1]),
        frame_send(S1, 1, <<"hello">>),
        ?assertEqual({1, <<"challenge">>}, frame_recv(S1)),
        frame_send(S1, 1, <<"response">>),
        ?assertEqual({1, <<"done">>}, frame_recv(S1)),
        %% complete without an output token: zero-length token
        {S2, <<5, 1>>} = handshake(Port, [1]),
        frame_send(S2, 1, <<"quick">>),
        ?assertEqual({1, <<>>}, frame_recv(S2)),
        %% complete with a final token right away
        {S3, <<5, 1>>} = handshake(Port, [1]),
        frame_send(S3, 1, <<"final">>),
        ?assertEqual({1, <<"done">>}, frame_recv(S3)),
        %% rejected: abort message, then closed
        {S4, <<5, 1>>} = handshake(Port, [1]),
        frame_send(S4, 1, <<"garbage">>),
        ?assertEqual(<<1, 16#ff>>, recv(S4, 2)),
        ?assertEqual({error, closed}, gen_tcp:recv(S4, 0, 2000)),
        %% level 3 (selective) is answered with 2, wrapped
        frame_send(S1, 2, <<"W", 3>>),
        ?assertEqual({2, <<"W", 2>>}, frame_recv(S1)),
        %% NEC-style bare level octet is answered bare
        frame_send(S2, 2, <<1>>),
        ?assertEqual({2, <<1>>}, frame_recv(S2))
    end).

gss_clear(Port) ->
    with_gssapi(fun() ->
        Echo = tcp_echo(?LO),
        S = gss_session(Port, 0),
        ?assertMatch({0, _}, request(S, 1, ?LO, Echo)),
        ok = gen_tcp:send(S, <<"plain">>),
        ?assertEqual(<<"plain">>, recv(S, 5))
    end).

gss_connect(Port) ->
    with_gssapi(fun() ->
        Echo = tcp_echo(?LO),
        S = gss_session(Port, 2),
        frame_send(S, 3, <<"W", 5, 1, 0, 1, 127, 0, 0, 1, Echo:16>>),
        {3, <<"W", 5, 0, 0, 1, _:4/binary, _:16>>} = frame_recv(S),
        %% a frame split across two segments, then two frames in one
        Frame = frame(3, <<"W", "hello">>),
        <<Half1:4/binary, Half2/binary>> = Frame,
        ok = gen_tcp:send(S, Half1),
        timer:sleep(50),
        ok = gen_tcp:send(S, Half2),
        ?assertEqual({3, <<"W", "hello">>}, frame_recv(S)),
        ok = gen_tcp:send(S, [frame(3, <<"W", "ab">>), frame(3, <<"W", "cd">>)]),
        ?assertEqual(<<"abcd">>, recv_frames(S, 4)),
        %% a bad token ends the connection
        frame_send(S, 3, <<"X", "bad">>),
        ?assertEqual({error, closed}, gen_tcp:recv(S, 0, 2000))
    end).

gss_udp(Port) ->
    with_gssapi(fun() ->
        Echo = udp_echo(?LO),
        S = gss_session(Port, 1),
        frame_send(S, 3, <<"W", 5, 3, 0, 1, 0, 0, 0, 0, 0:16>>),
        {3, <<"W", 5, 0, 0, 1, 127, 0, 0, 1, RelayPort:16>>} = frame_recv(S),
        {ok, C} = gen_udp:open(0, [binary, {active, false}, {ip, ?LO}]),
        Msg = <<0, 0, 0, 1, 127, 0, 0, 1, Echo:16, "ping">>,
        ok = gen_udp:send(C, ?LO, RelayPort, frame(3, <<"W", Msg/binary>>)),
        ?assertEqual({ok, {?LO, RelayPort, frame(3, <<"W", Msg/binary>>)}},
                     gen_udp:recv(C, 0, 2000)),
        %% unencapsulated or bad datagrams are dropped
        ok = gen_udp:send(C, ?LO, RelayPort, Msg),
        ?assertEqual({error, timeout}, gen_udp:recv(C, 0, 300))
    end).

%%% helpers

proxy(Port) ->
    {ok, S} = gen_tcp:connect(?LO, Port, [binary, {active, false}, {nodelay, true}]),
    S.

recv(_S, 0) ->
    <<>>;
recv(S, N) ->
    {ok, Bin} = gen_tcp:recv(S, N, 2000),
    Bin.

send_bytewise(S, Bin) ->
    [ok = gen_tcp:send(S, <<B>>) || <<B>> <= Bin].

handshake(Port, Methods) ->
    S = proxy(Port),
    ok = gen_tcp:send(S, <<5, (length(Methods)), (list_to_binary(Methods))/binary>>),
    {S, recv(S, 2)}.

request(S, Cmd, {A, B, C, D}, Port) ->
    ok = gen_tcp:send(S, <<5, Cmd, 0, 1, A, B, C, D, Port:16>>),
    reply(S).

reply(S) ->
    <<5, Rep, 0, ATyp>> = recv(S, 4),
    case ATyp of
        1 -> <<A, B, C, D, Port:16>> = recv(S, 6), {Rep, {{A, B, C, D}, Port}};
        4 -> <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16, Port:16>> = recv(S, 18),
             {Rep, {{A, B, C, D, E, F, G, H}, Port}}
    end.

with_gssapi(Fun) ->
    application:set_env(socks5, socks5_auth_methods, [gssapi]),
    try Fun()
    after application:set_env(socks5, socks5_auth_methods, [no_auth])
    end.

%% Authenticates with the fake mechanism and agrees on Level.
gss_session(Port, Level) ->
    {S, <<5, 1>>} = handshake(Port, [1]),
    frame_send(S, 1, <<"final">>),
    {1, <<"done">>} = frame_recv(S),
    frame_send(S, 2, <<"W", Level>>),
    {2, <<"W", Level>>} = frame_recv(S),
    S.

frame(Mtyp, Token) ->
    <<1, Mtyp, (byte_size(Token)):16, Token/binary>>.

frame_send(S, Mtyp, Token) ->
    ok = gen_tcp:send(S, frame(Mtyp, Token)).

frame_recv(S) ->
    <<1, Mtyp, Len:16>> = recv(S, 4),
    {Mtyp, recv(S, Len)}.

%% Collects encapsulated payload until N plaintext bytes have arrived.
recv_frames(S, N) ->
    recv_frames(S, N, <<>>).

recv_frames(_S, N, Acc) when byte_size(Acc) >= N ->
    Acc;
recv_frames(S, N, Acc) ->
    {3, <<"W", Payload/binary>>} = frame_recv(S),
    recv_frames(S, N, <<Acc/binary, Payload/binary>>).

tcp_echo(IP) ->
    tcp_server(IP, [], fun tcp_echo_loop/1).

tcp_server(IP, Opts, Handler) ->
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {ip, IP} | Opts]),
    spawn(fun() -> {ok, S} = gen_tcp:accept(L), Handler(S) end),
    {ok, Port} = inet:port(L),
    Port.

tcp_echo_loop(S) ->
    case gen_tcp:recv(S, 0) of
        {ok, Bin} -> ok = gen_tcp:send(S, Bin), tcp_echo_loop(S);
        _ -> ok
    end.

udp_echo(IP) ->
    Self = self(),
    spawn(fun() ->
                  {ok, U} = gen_udp:open(0, [binary, {ip, IP}]),
                  {ok, Port} = inet:port(U),
                  Self ! {udp_echo, Port},
                  udp_echo_loop(U)
          end),
    receive {udp_echo, Port} -> Port end.

udp_echo_loop(U) ->
    receive
        {udp, U, IP, Port, Bin} -> ok = gen_udp:send(U, IP, Port, Bin), udp_echo_loop(U)
    end.
