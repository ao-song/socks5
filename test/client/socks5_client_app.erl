-module(socks5_client_app).

-author("ao.song@outlook.com").

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    socks5_client_sup:start_link().

stop(_State) ->
    ok.
