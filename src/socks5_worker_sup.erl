-module(socks5_worker_sup).

-behaviour(supervisor).

-author("ao.song@outlook.com").

-export([start_link/0, add_worker/1]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% Must be called by the socket owner.
add_worker(Socket) ->
    {ok, Child} = supervisor:start_child(?MODULE, []),
    ok = gen_tcp:controlling_process(Socket, Child),
    socks5_worker:set_socket(Child, Socket).

init([]) ->
    {ok, {#{strategy => simple_one_for_one, intensity => 5, period => 60},
          [#{id => socks5_worker,
             start => {socks5_worker, start_link, []},
             restart => temporary}]}}.
