-module(echo_server).
-export([start/0]).

-define(PORT, 8888).
-define(TCP_OPTIONS, [binary, 
                      {packet, 0}, 
                      {reuseaddr, true},
                      {keepalive, true}, 
                      {active, false}]).

start() ->
    {ok, ListenSocket} = gen_tcp:listen(?PORT, ?TCP_OPTIONS),
    accept_loop(ListenSocket).

accept_loop(ListenSocket) ->
    {ok, ClientSocket} = gen_tcp:accept(ListenSocket),
    Pid = spawn(echo_worker, echo, [ClientSocket]),
    io:format("spawn pid ~p~n", [Pid]),
    gen_tcp:controlling_process(ClientSocket, Pid),
    accept_loop(ListenSocket).
