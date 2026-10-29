%%%-------------------------------------------------------------------
%%% @author Ao Song
%%% @copyright (C) 2022, Ao Song
%%% @doc Configuration access, address encoding/decoding and name
%%% resolution shared by the SOCKS5 worker.
%%% @end
%%%-------------------------------------------------------------------
-module(socks5_utils).

-include("socks5.hrl").

-export([auth_methods/0, users/0, gssapi/0, idle_timeout/0,
         check_password/2,
         encode_address/1, parse_address/2,
         resolve/1, connect/3, unmap/1, map6/1,
         reason_to_socks_error/1]).

-type address() :: inet:ip_address() | string().

%%%===================================================================
%%% Configuration
%%%===================================================================

%% Methods the server accepts, in preference order. Defaults to GSSAPI
%% when configured, username/password when users exist, else no auth.
-spec auth_methods() -> [no_auth | gssapi | username_password].
auth_methods() ->
    case application:get_env(socks5, socks5_auth_methods) of
        {ok, Methods} ->
            Methods;
        undefined ->
            [gssapi || gssapi() =/= undefined] ++
                case users() of
                    [] -> [no_auth];
                    _  -> [username_password]
                end
    end.

-spec users() -> [{unicode:chardata(), unicode:chardata()}].
users() ->
    application:get_env(socks5, socks5_users, []).

-spec gssapi() -> map() | undefined.
gssapi() ->
    application:get_env(socks5, socks5_gssapi, undefined).

-spec idle_timeout() -> timeout().
idle_timeout() ->
    application:get_env(socks5, socks5_idle_timeout, ?DEFAULT_IDLE_TIMEOUT).

%% Constant-time comparison; an unknown user is compared against an
%% empty password so timing does not reveal which names exist.
-spec check_password(unicode:chardata(), unicode:chardata()) -> boolean().
check_password(User, Pass) ->
    UserBin = unicode:characters_to_binary(User),
    {Found, Expected} =
        case [P || {U, P} <- users(), unicode:characters_to_binary(U) =:= UserBin] of
            [P | _] -> {true, P};
            []      -> {false, <<>>}
        end,
    Hash = fun(X) -> crypto:hash(sha256, unicode:characters_to_binary(X)) end,
    crypto:hash_equals(Hash(Pass), Hash(Expected)) andalso Found.

%%%===================================================================
%%% Addresses
%%%===================================================================

%% ATYP + BND.ADDR + BND.PORT
-spec encode_address({inet:ip_address(), inet:port_number()}) -> binary().
encode_address({{A, B, C, D}, Port}) ->
    <<?ATYP_IPV4, A, B, C, D, Port:?USHORT>>;
encode_address({{A, B, C, D, E, F, G, H}, Port}) ->
    <<?ATYP_IPV6, A:?USHORT, B:?USHORT, C:?USHORT, D:?USHORT,
      E:?USHORT, F:?USHORT, G:?USHORT, H:?USHORT, Port:?USHORT>>.

%% DST.ADDR + DST.PORT (+ trailing data) for a given ATYP
-spec parse_address(byte(), binary()) ->
          {ok, {address(), inet:port_number(), binary()}} | error.
parse_address(?ATYP_IPV4, <<A, B, C, D, Port:?USHORT, Rest/binary>>) ->
    {ok, {{A, B, C, D}, Port, Rest}};
parse_address(?ATYP_IPV6, <<A:?USHORT, B:?USHORT, C:?USHORT, D:?USHORT,
                            E:?USHORT, F:?USHORT, G:?USHORT, H:?USHORT,
                            Port:?USHORT, Rest/binary>>) ->
    {ok, {{A, B, C, D, E, F, G, H}, Port, Rest}};
parse_address(?DOMAINNAME, <<Len, Domain:Len/binary, Port:?USHORT, Rest/binary>>) ->
    {ok, {binary_to_list(Domain), Port, Rest}};
parse_address(_ATyp, _Bin) ->
    error.

%% Every address of a host, IPv4 before IPv6.
-spec resolve(address()) -> {ok, [inet:ip_address()]} | {error, nxdomain}.
resolve(IP) when is_tuple(IP) ->
    {ok, [IP]};
resolve(Host) ->
    case [IP || Family <- [inet, inet6],
                {ok, IPs} <- [inet:getaddrs(Host, Family)],
                IP <- IPs] of
        []  -> {error, nxdomain};
        IPs -> {ok, IPs}
    end.

%% TCP connect, trying each resolved address in turn.
-spec connect(address(), inet:port_number(), [gen_tcp:connect_option()]) ->
          {ok, gen_tcp:socket()} | {error, term()}.
connect(Host, Port, Opts) ->
    case resolve(Host) of
        {ok, IPs}      -> connect_each(IPs, Port, Opts, nxdomain);
        {error, _} = E -> E
    end.

connect_each([], _Port, _Opts, LastError) ->
    {error, LastError};
connect_each([IP | Rest], Port, Opts, _LastError) ->
    case gen_tcp:connect(IP, Port, Opts, ?TIMEOUT) of
        {ok, Socket}    -> {ok, Socket};
        {error, Reason} -> connect_each(Rest, Port, Opts, Reason)
    end.

%% IPv4-mapped IPv6 address (seen on dual-stack sockets) to plain IPv4.
-spec unmap(inet:ip_address()) -> inet:ip_address().
unmap({0, 0, 0, 0, 0, 16#ffff, AB, CD}) ->
    {AB bsr 8, AB band 16#ff, CD bsr 8, CD band 16#ff};
unmap(IP) ->
    IP.

%% Plain IPv4 to IPv4-mapped IPv6, for sending through a dual-stack socket.
-spec map6(inet:ip_address()) -> inet:ip6_address().
map6({A, B, C, D}) ->
    {0, 0, 0, 0, 0, 16#ffff, (A bsl 8) bor B, (C bsl 8) bor D};
map6(IP) ->
    IP.

-spec reason_to_socks_error(term()) -> byte().
reason_to_socks_error(econnrefused) -> ?CONNECTION_REFUSED;
reason_to_socks_error(ehostunreach) -> ?HOST_UNREACHABLE;
reason_to_socks_error(nxdomain)     -> ?HOST_UNREACHABLE;
reason_to_socks_error(enetunreach)  -> ?NETWORK_UNREACHABLE;
reason_to_socks_error(eafnosupport) -> ?NETWORK_UNREACHABLE;
reason_to_socks_error(eacces)       -> ?CONNECTION_NOT_ALLOWED;
reason_to_socks_error(etimedout)    -> ?TTL_EXPIRED;
reason_to_socks_error(timeout)      -> ?TTL_EXPIRED;
reason_to_socks_error(_)            -> ?GENERAL_SOCKS_SERVER_FAILURE.
