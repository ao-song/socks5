-module(socks5_server_sup).

-behaviour(supervisor).

-include("socks5.hrl").

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{one_for_one, ?MAX_RESTART, ?MAX_TIME},
          [% socks listener
           ?CHILD(socks5_listener, worker, []),           
           % connection handler
           ?CHILD(socks5_worker_sup, supervisor, [])
          ]}}.

