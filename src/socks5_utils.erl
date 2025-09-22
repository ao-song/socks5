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
-include("socks5.hrl").

%% API
-export([
    get_config/0,
    get_user_credentials/0,
    format_address/2,
    reason_to_socks_error/1,
    parse_address/2
]).

%%%===================================================================
%%% API
%%%===================================================================

-spec get_config() -> {ok, map()} | {error, term()}.
get_config() ->
    case application:get_env(socks5, socks5_port) of
        {ok, Port} ->
            {ok, #{socks5_port => Port}};
        undefined ->
            ?LOG_WARNING("Socks5 port not configured in sys.config, using default."),
            {error, not_configured}
    end.

-spec get_user_credentials() -> {ok, map()} | {error, term()}.
get_user_credentials() ->
    case application:get_env(socks5, socks5_users) of
        {ok, Users} when is_list(Users) andalso length(Users) > 0 ->
            % For simplicity, we'll just take the first user for now.
            % A more robust implementation would iterate or look up by username.
            case hd(Users) of
                {Username, Password} when is_list(Username), is_list(Password) ->
                    {ok, #{username => Username, password => Password}};
                _ ->
                    ?LOG_ERROR("Malformed socks5_users configuration."),
                    {error, malformed_config}
            end;
        _ ->
            ?LOG_ERROR("Socks5 users not configured in sys.config."),
            {error, not_configured}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec format_address(inet:ip_address() | string(), inet:port_number()) ->
    {?ATYP_IPV4 | ?ATYP_IPV6 | ?DOMAINNAME, binary(), inet:port_number()}.
format_address({A,B,C,D}, Port) ->
    {?ATYP_IPV4, <<A,B,C,D>>, Port};
format_address({A,B,C,D,E,F,G,H}, Port) ->
    {?ATYP_IPV6, <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>, Port};
format_address(Domain, Port) when is_list(Domain) ->
    DomainBin = list_to_binary(Domain),
    {?DOMAINNAME, <<(byte_size(DomainBin)):?UBYTE, DomainBin/binary>>, Port}.

-spec reason_to_socks_error(term()) -> integer().
reason_to_socks_error(econnrefused) -> ?CONNECTION_REFUSED;
reason_to_socks_error(ehostunreach) -> ?HOST_UNREACHABLE;
reason_to_socks_error(enetunreach) -> ?NETWORK_UNREACHABLE;
reason_to_socks_error(etimedout) -> ?TTL_EXPIRED; % Using TTL_EXPIRED for timeout, could be more specific
reason_to_socks_error(_) -> ?GENERAL_SOCKS_SERVER_FAILURE.

-spec parse_address(integer(), binary()) ->
    {ok, {inet:ip_address() | string(), inet:port_number(), binary()}} | {error, term()}.
parse_address(?ATYP_IPV4, <<A:?UBYTE, B:?UBYTE, C:?UBYTE, D:?UBYTE, Port:?USHORT, Data/binary>>) ->
    {ok, {{A,B,C,D}, Port, Data}};
parse_address(?ATYP_IPV6, <<A:?USHORT, B:?USHORT, C:?USHORT, D:?USHORT,
                            E:?USHORT, F:?USHORT, G:?USHORT, H:?USHORT, Port:?USHORT, Data/binary>>) ->
    {ok, {{A,B,C,D,E,F,G,H}, Port, Data}};
parse_address(?DOMAINNAME, <<Len:?UBYTE, Domain:Len/binary, Port:?USHORT, Data/binary>>) ->
    {ok, {binary_to_list(Domain), Port, Data}};
parse_address(ATyp, _Rest) ->
    {error, {unsupported_address_type, ATyp}}.
