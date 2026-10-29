%%%-------------------------------------------------------------------
%% @doc socks5 top level supervisor.
%% @end
%%%-------------------------------------------------------------------
-module(socks5_sup).

-behaviour(supervisor).

-author("ao.song@outlook.com").

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% The worker supervisor starts first: the listener hands sockets to it.
init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 5, period => 60},
          [#{id => socks5_worker_sup,
             start => {socks5_worker_sup, start_link, []},
             type => supervisor},
           #{id => socks5_listener,
             start => {socks5_listener, start_link, []}}]}}.
