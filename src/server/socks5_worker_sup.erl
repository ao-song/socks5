-module(socks5_worker_sup).

-behaviour(supervisor).

-author("ao.song@outlook.com").

-include("socks5.hrl").

%% API
-export([start_link/0,
	     add_worker/1]).

%% Supervisor callbacks
-export([init/1]).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

add_worker(Socket) ->
    {ok, Child} = supervisor:start_child(?MODULE, []),
    ok = gen_tcp:controlling_process(Socket, Child),
    socks5_worker:set_socket(Child, Socket).
    

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{simple_one_for_one, ?MAX_RESTART, ?MAX_TIME},
          [
           ?CHILD(socks5_worker, worker, [])
          ]}}.

