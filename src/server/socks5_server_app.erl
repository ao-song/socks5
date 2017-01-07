-module(socks5_server_app).

-behaviour(application).

-author("ao.song@outlook.com").

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    socks5_server_sup:start_link().

stop(_State) ->
    ok.
