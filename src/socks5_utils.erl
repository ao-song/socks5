%%%-------------------------------------------------------------------
%%% @author Ao Song
%%% @copyright (C) 2022, Ao Song
%%% @doc
%%%
%%% @end
%%% Created : 2022-10-31 14:59:27.015480
%%%-------------------------------------------------------------------
-module(socks5_utils).

-include_lib("kernel/include/logger.hrl").

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
                ?LOG_DEBUG("Socks5 config file is ~p", [ConfigFile]),
                file:consult(ConfigFile);
            false ->
                ?LOG_WARNING(
                    "Socks5 config file ~p not found!", [ConfigFile]),
                {error, file_not_found}
        end,

    case Config of
        {ok, ConfigList} ->
            ?LOG_DEBUG(
                "Socks5 config list is ~p", [ConfigList]),
            {ok, maps:from_list(ConfigList)};
        Error ->
            ?LOG_WARNING(
                "Socks5 config file read failed! ~p", [Error]),
            Error
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================
