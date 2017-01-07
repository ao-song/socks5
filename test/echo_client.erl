-module(echo_client).
-export([start/0]).

-define(SERVERIP, "127.0.0.1").
-define(PORT, 8888).
-define(TCP_OPTIONS, [binary, 
                      {packet, 0}, 
                      {reuseaddr, true},
                      {keepalive, true}, 
                      {active, false}]).

start() ->
    {ok, Socket} = gen_tcp:connect(?SERVERIP, ?PORT, ?TCP_OPTIONS),
    send_loop(Socket, 5).

send_loop(_Socket, 0) ->
    ok;
send_loop(Socket, N) ->
    timer:sleep(1000),
    gen_tcp:send(Socket, <<"hello">>),
    case gen_tcp:recv(Socket, 0) of
        {ok, Data} ->
            io:format("client ~p~n", [Data]);
        _ -> ok
    end,
    send_loop(Socket, N-1).