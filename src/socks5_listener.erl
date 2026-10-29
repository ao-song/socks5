%%%-------------------------------------------------------------------
%%% @author Ao Song
%%% @copyright (C) 2019, Ao Song
%%% @doc Owns the listen sockets (IPv4 and IPv6 by default); a linked
%%% acceptor loop per socket hands every connection to a socks5_worker.
%%% @end
%%%-------------------------------------------------------------------
-module(socks5_listener).

-behaviour(gen_server).

-include("socks5.hrl").
-include_lib("kernel/include/logger.hrl").

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    Port = application:get_env(socks5, socks5_port, ?DEFAULT_PORT),
    Sockets = [S || {ok, S} <- [listen(IP, Port) || IP <- listen_addresses()]],
    case Sockets of
        [] ->
            {stop, {listen_failed, Port}};
        _ ->
            [spawn_link(fun() -> accept_loop(S) end) || S <- Sockets],
            {ok, Sockets}
    end.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

listen_addresses() ->
    case application:get_env(socks5, socks5_ip) of
        {ok, IP}  -> [IP];
        undefined -> [{0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}]
    end.

listen(IP, Port) ->
    Opts = [binary, {active, false}, {nodelay, true}, {reuseaddr, true},
            {backlog, 128}, {ip, IP} | v6only(IP)],
    case gen_tcp:listen(Port, Opts) of
        {ok, Socket} ->
            ?LOG_INFO("SOCKS5 server listening on ~s port ~p", [inet:ntoa(IP), Port]),
            {ok, Socket};
        {error, Reason} ->
            ?LOG_WARNING("Cannot listen on ~s port ~p: ~p", [inet:ntoa(IP), Port, Reason]),
            error
    end.

%% Separate IPv4 and IPv6 sockets, so both can bind the same port.
v6only({_, _, _, _}) -> [];
v6only(_)            -> [{ipv6_v6only, true}].

accept_loop(ListenSocket) ->
    case gen_tcp:accept(ListenSocket) of
        {ok, Socket} ->
            socks5_worker_sup:add_worker(Socket),
            accept_loop(ListenSocket);
        {error, closed} ->
            ok;
        {error, Reason} ->
            exit({accept, Reason})
    end.
