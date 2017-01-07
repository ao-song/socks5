-module(socks5_client_sup).

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
          [?CHILD(socks5_client_worker, supervisor, [])]}}.

