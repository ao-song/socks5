-module(socks5_listener).
-behaviour(gen_server).
-define(SERVER, ?MODULE).

-author("ao.song@outlook.com").

-include("socks5.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [?DEFAULT_PORT], []).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([Port]) ->
    case gen_tcp:listen(Port, ?SOCK_OPTIONS) of
        {ok, ListenSocket} ->            
            {ok, accept(#listener_state{listener = ListenSocket})};
        {error, Reason} ->
            ?LOG("Server: listen error, ~p~n.", [Reason]),
            {stop, Reason}
    end.

accept(#listener_state{listener = ListenSocket} = State) ->
    proc_lib:spawn(fun() -> accept_loop(ListenSocket) end),
    State.

accept_loop(ListenSocket) ->
    {ok, Socket} = gen_tcp:accept(ListenSocket),
    gen_server:cast(?SERVER, accepted),
    socks5_worker_sup:add_worker(Socket).


handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(accepted, State) ->
    {noreply, accept(State)};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #listener_state{listener = ListenSocket}) ->
    gen_tcp:close(ListenSocket),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

