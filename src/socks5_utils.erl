%%%-------------------------------------------------------------------
%%% @author Ao Song
%%% @copyright (C) 2022, Ao Song
%%% @doc
%%%
%%% @end
%%% Created : 2022-10-31 14:59:27.015480
%%%-------------------------------------------------------------------
-module(socks5_utils).

%% API
-export([get_config/0]).

%% Macro
-define(DEFAULT_CONF_FILE, "socks5.config").

%%%===================================================================
%%% API
%%%===================================================================

-spec get_config() -> {ok, map()} | {error, term()}.
get_config() ->
    ConfigFile =
    case os:getenv("SOCKS5_CONFIG") of
        false ->
            ?DEFAULT_CONF_FILE;
        [] ->
            ?DEFAULT_CONF_FILE;
        File ->
            File
    end,

    Config =
    case filelib:is_regular(ConfigFile) of
        true ->
            file:consult(ConfigFile);
        false ->
            {error, file_not_found}
    end,

    case Config of
        {ok, ConfigList} ->
            {ok, maps:from_list(ConfigList)};
        Error ->
            Error
    end.


%%%===================================================================
%%% Internal functions
%%%===================================================================
