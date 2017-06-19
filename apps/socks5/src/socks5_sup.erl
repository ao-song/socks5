%%%-------------------------------------------------------------------
%% @doc socks5 top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(socks5_sup).

-behaviour(supervisor).

-author("ao.song@outlook.com").

-include("socks5.hrl").

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

init([]) ->
    {ok, {{one_for_one, ?MAX_RESTART, ?MAX_TIME},
          [% socks listener
           ?CHILD(socks5_listener, worker, []),           
           % connection handler
           ?CHILD(socks5_worker_sup, supervisor, [])
          ]}}.

%%====================================================================
%% Internal functions
%%====================================================================

