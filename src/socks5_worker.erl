%%%-------------------------------------------------------------------
%%% @author Ao Song
%%% @copyright (C) 2019, Ao Song
%%% @doc One SOCKS5 client connection (RFC 1928, RFC 1929, RFC 1961).
%%%
%%% The handshake states read exact-length protocol fields with a
%%% passive gen_tcp:recv/3, so TCP segment boundaries never matter.
%%% Once the request has been served the sockets switch to
%%% {active, once} and the relay states forward traffic. With GSSAPI
%%% at protection level 1 or 2, everything after authentication is
%%% encapsulated through socks5_gssapi.
%%% @end
%%%-------------------------------------------------------------------
-module(socks5_worker).

-behaviour(gen_statem).

-include("socks5.hrl").
-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0, set_socket/2]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3]).

%% states
-export(['WAIT_FOR_SOCKET'/3,
         'AUTH_METHOD_NEG'/3,
         'AUTH_CLIENT'/3,
         'SETUP_CONNECTION'/3,
         'BIND_WAIT_FOR_CONNECTION'/3,
         'UDP_RELAY'/3,
         'CONNECTED'/3]).

-define(HANDLE_COMMON,
        ?FUNCTION_NAME(T, C, D) -> handle_common(T, C, D)).
-define(RUN, {next_event, internal, run}).
-define(ACTIVE_ONCE, [{active, once}]).
-define(TARGET_OPTS, [binary, {active, false}, {nodelay, true}]).

-record(state,
        {socket,         % client TCP socket
         method,         % selected auth method
         gss,            % socks5_gssapi:ctx() when messages are encapsulated
         buf = <<>>,     % client bytes not yet forming a whole GSSAPI frame
         target,         % remote TCP socket (CONNECT / BIND)
         closed,         % CONNECTED: the socket whose read side is already closed
         expect,         % BIND: DST.ADDR the client expects the peer from
         udp,            % UDP relay socket
         udp_family,     % inet6 (dual-stack) | inet
         client_udp,     % {IP, Port | undefined}: where client datagrams come from
         idle}).         % idle timeout for the relay states

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_statem:start_link(?MODULE, [], []).

set_socket(Child, Socket) when is_pid(Child), is_port(Socket) ->
    gen_statem:cast(Child, {socket_ready, Socket}).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

callback_mode() ->
    state_functions.

init([]) ->
    {ok, 'WAIT_FOR_SOCKET', #state{idle = socks5_utils:idle_timeout()}}.

%% Sockets close with the process; only the GSS context needs cleanup.
terminate(_Reason, _State, #state{gss = Gss}) ->
    socks5_gssapi:delete(Gss).

%%%===================================================================
%%% States
%%%===================================================================

'WAIT_FOR_SOCKET'(cast, {socket_ready, Socket}, Data) ->
    {next_state, 'AUTH_METHOD_NEG', Data#state{socket = Socket}, ?RUN};
?HANDLE_COMMON.

%% RFC 1928 section 3
'AUTH_METHOD_NEG'(internal, run, Data) ->
    handshake(fun negotiate/1, Data);
?HANDLE_COMMON.

%% RFC 1929 / RFC 1961
'AUTH_CLIENT'(internal, run, Data) ->
    handshake(fun authenticate/1, Data);
?HANDLE_COMMON.

%% RFC 1928 section 4
'SETUP_CONNECTION'(internal, run, Data) ->
    handshake(fun request/1, Data);
?HANDLE_COMMON.

%% Second BIND reply: the peer connected (or the accept failed).
'BIND_WAIT_FOR_CONNECTION'(info, {bind_accepted, {ok, Target}},
                           #state{expect = Expect} = Data) ->
    {ok, {PeerIP, _} = Peer} = inet:peername(Target),
    case peer_allowed(PeerIP, Expect) of
        true ->
            connected(Target, reply(?SUCCEEDED, Peer, Data));
        false ->
            ?LOG_WARNING("BIND: rejected peer ~p, expected ~p", [PeerIP, Expect]),
            reply(?CONNECTION_NOT_ALLOWED, Data),
            stop
    end;
'BIND_WAIT_FOR_CONNECTION'(info, {bind_accepted, {error, Reason}}, Data) ->
    reply(socks5_utils:reason_to_socks_error(Reason), Data),
    stop;
?HANDLE_COMMON.

%% RFC 1928 section 7. Datagrams from the client's endpoint go out,
%% anything else is a remote reply that gets wrapped and sent back.
%% The association lives as long as the client's TCP connection.
'UDP_RELAY'(info, {udp, Udp, IP0, Port, Packet},
            #state{udp = Udp, client_udp = Client} = Data) ->
    inet:setopts(Udp, ?ACTIVE_ONCE),
    IP = socks5_utils:unmap(IP0),
    Data1 = case Client of
                {IP, CPort} when CPort =:= Port; CPort =:= undefined ->
                    relay_out(Packet, Data#state{client_udp = {IP, Port}});
                {_, CPort} when is_integer(CPort) ->
                    relay_in({IP, Port}, Packet, Data);
                _ ->
                    Data   % remote traffic before the client spoke: dropped
            end,
    {keep_state, Data1, idle(Data1)};
?HANDLE_COMMON.

'CONNECTED'(info, {tcp, Socket, Bytes},
            #state{socket = Socket, gss = undefined, target = Target} = Data) ->
    forward(Target, Bytes, Socket, Data);
'CONNECTED'(info, {tcp, Socket, Bytes},
            #state{socket = Socket, gss = Gss, buf = Buf, target = Target} = Data) ->
    case socks5_gssapi:unwrap_stream(<<Buf/binary, Bytes/binary>>, Gss) of
        {ok, Plain, Rest, Gss1} ->
            forward(Target, Plain, Socket, Data#state{gss = Gss1, buf = Rest});
        {error, Reason} ->
            ?LOG_WARNING("GSSAPI: bad client data: ~p", [Reason]),
            stop
    end;
'CONNECTED'(info, {tcp, Target, Bytes}, #state{target = Target} = Data) ->
    case send_to_client(Bytes, Data) of
        {ok, Data1} ->
            inet:setopts(Target, ?ACTIVE_ONCE),
            {keep_state, Data1, idle(Data1)};
        {error, _} ->
            stop
    end;
%% Half-close: pass the FIN on and keep relaying the other direction.
'CONNECTED'(info, {tcp_closed, From}, #state{closed = undefined} = Data) ->
    gen_tcp:shutdown(other(From, Data), write),
    {keep_state, Data#state{closed = From}, idle(Data)};
'CONNECTED'(info, {tcp_closed, _}, _Data) ->
    stop;
?HANDLE_COMMON.

handle_common(info, {tcp_closed, _}, _Data) ->
    stop;
handle_common(info, {tcp_error, _, _}, _Data) ->
    stop;
handle_common({timeout, idle}, idle, _Data) ->
    ?LOG_INFO("Idle timeout, closing"),
    stop;
handle_common(info, {tcp, Socket, _}, _Data) ->
    %% Client data while waiting for BIND / during UDP: not part of the
    %% protocol, ignored.
    inet:setopts(Socket, ?ACTIVE_ONCE),
    keep_state_and_data;
handle_common(Type, Event, _Data) ->
    ?LOG_WARNING("Unexpected event ~p:~p", [Type, Event]),
    keep_state_and_data.

%%%===================================================================
%%% Handshake phases. Each reads from the socket with recv/2, which
%%% throws {socks5, Reason} on error; handshake/2 turns that into a
%%% clean stop.
%%%===================================================================

handshake(Phase, Data) ->
    try Phase(Data)
    catch throw:{socks5, Reason} ->
            ?LOG_INFO("Connection closed: ~p", [Reason]),
            {stop, normal, Data}
    end.

negotiate(#state{socket = Socket} = Data) ->
    case recv(Socket, 2) of
        <<?SOCKS_VERSION, NMethods>> when NMethods > 0 ->
            Method = select_method(binary_to_list(recv(Socket, NMethods))),
            gen_tcp:send(Socket, <<?SOCKS_VERSION, Method>>),
            case Method of
                ?NO_ACCEPTABLE_METHODS ->
                    throw({socks5, no_acceptable_methods});
                ?NO_AUTHENTICATION_REQUIRED ->
                    {next_state, 'SETUP_CONNECTION', Data#state{method = Method}, ?RUN};
                _ ->
                    {next_state, 'AUTH_CLIENT', Data#state{method = Method}, ?RUN}
            end;
        _ ->
            throw({socks5, bad_version})
    end.

%% First configured method (in preference order) that the client offers.
select_method(Offered) ->
    Codes = [method_code(M) || M <- socks5_utils:auth_methods()],
    case [C || C <- Codes, lists:member(C, Offered)] of
        [Code | _] -> Code;
        []         -> ?NO_ACCEPTABLE_METHODS
    end.

method_code(no_auth)           -> ?NO_AUTHENTICATION_REQUIRED;
method_code(gssapi)            -> ?GSSAPI;
method_code(username_password) -> ?USERNAME_PASSWORD.

authenticate(#state{method = ?USERNAME_PASSWORD, socket = Socket} = Data) ->
    case recv(Socket, 2) of
        <<?AUTH_VERSION, ULen>> ->
            <<User:ULen/binary, PLen>> = recv(Socket, ULen + 1),
            Pass = recv(Socket, PLen),
            case socks5_utils:check_password(User, Pass) of
                true ->
                    gen_tcp:send(Socket, <<?AUTH_VERSION, ?AUTH_SUCCESS>>),
                    {next_state, 'SETUP_CONNECTION', Data, ?RUN};
                false ->
                    gen_tcp:send(Socket, <<?AUTH_VERSION, ?AUTH_FAILURE>>),
                    throw({socks5, {auth_failed, User}})
            end;
        _ ->
            throw({socks5, bad_auth_version})
    end;
authenticate(#state{method = ?GSSAPI, socket = Socket} = Data) ->
    Config = case socks5_utils:gssapi() of
                 undefined -> #{};
                 Map       -> Map
             end,
    case socks5_gssapi:negotiate(Socket, Config) of
        {ok, clear}     -> {next_state, 'SETUP_CONNECTION', Data, ?RUN};
        {ok, Gss}       -> {next_state, 'SETUP_CONNECTION', Data#state{gss = Gss}, ?RUN};
        {error, Reason} -> throw({socks5, {gssapi, Reason}})
    end.

request(#state{socket = Socket, gss = undefined} = Data) ->
    case recv(Socket, 4) of
        <<?SOCKS_VERSION, Cmd, ?RSV, ATyp>> ->
            {Addr, Port} = recv_address(ATyp, Data),
            command(Cmd, Addr, Port, Data);
        _ ->
            throw({socks5, bad_request})
    end;
request(#state{socket = Socket, gss = Gss} = Data) ->
    case socks5_gssapi:recv_message(Socket, Gss) of
        {ok, <<?SOCKS_VERSION, Cmd, ?RSV, ATyp, Rest/binary>>, Gss1} ->
            Data1 = Data#state{gss = Gss1},
            case socks5_utils:parse_address(ATyp, Rest) of
                {ok, {Addr, Port, <<>>}} ->
                    command(Cmd, Addr, Port, Data1);
                _ ->
                    reply(?ATYP_NOT_SUPPORTED, Data1),
                    throw({socks5, {atyp_not_supported, ATyp}})
            end;
        {ok, _Other, _} ->
            throw({socks5, bad_request});
        {error, Reason} ->
            throw({socks5, {gssapi, Reason}})
    end.

recv_address(ATyp, #state{socket = Socket} = Data) ->
    Bin = case ATyp of
              ?ATYP_IPV4 ->
                  recv(Socket, 6);
              ?ATYP_IPV6 ->
                  recv(Socket, 18);
              ?DOMAINNAME ->
                  <<Len>> = recv(Socket, 1),
                  <<Len, (recv(Socket, Len + 2))/binary>>;
              _ ->
                  reply(?ATYP_NOT_SUPPORTED, Data),
                  throw({socks5, {atyp_not_supported, ATyp}})
          end,
    {ok, {Addr, Port, <<>>}} = socks5_utils:parse_address(ATyp, Bin),
    {Addr, Port}.

command(?CONNECT, Addr, Port, Data) ->
    case socks5_utils:connect(Addr, Port, ?TARGET_OPTS) of
        {ok, Target} ->
            {ok, Bound} = inet:sockname(Target),
            connected(Target, reply(?SUCCEEDED, Bound, Data));
        {error, Reason} ->
            fail(Reason, Data)
    end;
command(?BIND, Addr, _Port, #state{socket = Socket} = Data) ->
    %% Listen on the address the client reached us on, so the reported
    %% BND.ADDR is reachable by the peer. One shot: accept in a helper
    %% process so the client socket keeps being watched meanwhile.
    Opts = [binary, {active, false}, {ip, local_ip(Socket)}, {backlog, 1}],
    case gen_tcp:listen(0, Opts) of
        {ok, Listen} ->
            {ok, Bound} = inet:sockname(Listen),
            Data1 = reply(?SUCCEEDED, Bound, Data),
            Self = self(),
            spawn_link(fun() ->
                               Result = gen_tcp:accept(Listen, ?TIMEOUT),
                               gen_tcp:close(Listen),
                               case Result of
                                   {ok, T} -> ok = gen_tcp:controlling_process(T, Self);
                                   _ -> ok
                               end,
                               Self ! {bind_accepted, Result}
                       end),
            inet:setopts(Socket, ?ACTIVE_ONCE),
            {next_state, 'BIND_WAIT_FOR_CONNECTION', Data1#state{expect = Addr}};
        {error, Reason} ->
            fail(Reason, Data)
    end;
command(?UDP_ASSOCIATE, Addr, Port, #state{socket = Socket} = Data) ->
    case open_udp() of
        {ok, Udp, Family} ->
            {ok, UdpPort} = inet:port(Udp),
            Data1 = reply(?SUCCEEDED, {local_ip(Socket), UdpPort}, Data),
            inet:setopts(Socket, ?ACTIVE_ONCE),
            Data2 = Data1#state{udp = Udp, udp_family = Family,
                                client_udp = client_udp(Socket, Addr, Port)},
            {next_state, 'UDP_RELAY', Data2, idle(Data2)};
        {error, Reason} ->
            fail(Reason, Data)
    end;
command(Cmd, _Addr, _Port, Data) ->
    reply(?CMD_NOT_SUPPORTED, Data),
    throw({socks5, {cmd_not_supported, Cmd}}).

fail(Reason, Data) ->
    reply(socks5_utils:reason_to_socks_error(Reason), Data),
    throw({socks5, Reason}).

%% Both sockets active; exit_on_close off so a half-closed socket can
%% still carry the other direction.
connected(Target, #state{socket = Socket} = Data) ->
    Opts = [{active, once}, {exit_on_close, false}],
    inet:setopts(Socket, Opts),
    inet:setopts(Target, Opts),
    {next_state, 'CONNECTED', Data#state{target = Target}, idle(Data)}.

%% A dual-stack socket relays to IPv4 and IPv6 targets alike; plain
%% IPv4 is the fallback on hosts without IPv6.
open_udp() ->
    case gen_udp:open(0, [binary, {active, once}, inet6, {ipv6_v6only, false}]) of
        {ok, Udp} ->
            {ok, Udp, inet6};
        {error, _} ->
            case gen_udp:open(0, [binary, {active, once}]) of
                {ok, Udp} -> {ok, Udp, inet};
                Error     -> Error
            end
    end.

%%%===================================================================
%%% Relay helpers
%%%===================================================================

forward(To, Plain, From, Data) ->
    case gen_tcp:send(To, Plain) of
        ok ->
            inet:setopts(From, ?ACTIVE_ONCE),
            {keep_state, Data, idle(Data)};
        {error, _} ->
            stop
    end.

%% Client -> remote datagram: de-encapsulate, strip the request header,
%% resolve and send. Fragments (FRAG =/= 0) and malformed ones are dropped.
relay_out(Packet, #state{gss = undefined} = Data) ->
    send_out(Packet, Data),
    Data;
relay_out(Packet, #state{gss = Gss} = Data) ->
    case socks5_gssapi:unwrap(Packet, Gss) of
        {ok, Plain, Gss1} ->
            send_out(Plain, Data),
            Data#state{gss = Gss1};
        {error, Reason, Gss1} ->
            ?LOG_WARNING("GSSAPI: dropped client datagram: ~p", [Reason]),
            Data#state{gss = Gss1}
    end.

send_out(<<?RSV:?USHORT, 0, ATyp, Rest/binary>>, #state{udp = Udp, udp_family = Family}) ->
    case socks5_utils:parse_address(ATyp, Rest) of
        {ok, {Addr, Port, Payload}} ->
            case udp_target(Addr, Family) of
                {ok, IP} -> gen_udp:send(Udp, IP, Port, Payload);
                error    -> ok
            end;
        error ->
            ok
    end;
send_out(_Packet, _Data) ->
    ok.

udp_target(Addr, Family) ->
    case socks5_utils:resolve(Addr) of
        {ok, IPs} ->
            case [IP || IP <- IPs, Family =:= inet6 orelse tuple_size(IP) =:= 4] of
                [IP | _] when Family =:= inet6 -> {ok, socks5_utils:map6(IP)};
                [IP | _]                       -> {ok, IP};
                []                             -> error
            end;
        {error, _} ->
            error
    end.

%% Remote -> client datagram: prepend the header carrying the remote's
%% address, encapsulate if needed.
relay_in(Remote, Payload, #state{udp = Udp, udp_family = Family,
                                 client_udp = {ClientIP, ClientPort}} = Data) ->
    Header = socks5_utils:encode_address(Remote),
    Msg = <<?RSV:?USHORT, 0, Header/binary, Payload/binary>>,
    {Datagram, Data1} = encapsulate(Msg, Data),
    IP = case Family of
             inet6 -> socks5_utils:map6(ClientIP);
             inet  -> ClientIP
         end,
    gen_udp:send(Udp, IP, ClientPort, Datagram),
    Data1.

%% The endpoint the client said it will send from; unknown parts are
%% taken from the TCP peer (IP) or learned from the first datagram (port).
client_udp(Socket, Addr, Port) ->
    {ok, {PeerIP, _}} = inet:peername(Socket),
    IP = case socks5_utils:resolve(Addr) of
             {ok, [Given | _]} ->
                 case unspecified(Given) of
                     true  -> PeerIP;
                     false -> Given
                 end;
             {error, _} ->
                 PeerIP
         end,
    {IP, case Port of 0 -> undefined; _ -> Port end}.

peer_allowed(PeerIP, Expect) when is_tuple(Expect) ->
    Expect =:= PeerIP orelse unspecified(Expect);
peer_allowed(_PeerIP, _Domain) ->
    true.

unspecified(IP) ->
    lists:all(fun(X) -> X =:= 0 end, tuple_to_list(IP)).

other(Socket, #state{socket = Socket, target = Target}) -> Target;
other(_Target, #state{socket = Socket})                 -> Socket.

idle(#state{idle = Idle}) ->
    {{timeout, idle}, Idle, idle}.

%%%===================================================================
%%% Socket helpers
%%%===================================================================

reply(Rep, Data) ->
    reply(Rep, {{0, 0, 0, 0}, 0}, Data).

reply(Rep, Bound, Data) ->
    Addr = socks5_utils:encode_address(Bound),
    {_, Data1} = send_to_client(<<?SOCKS_VERSION, Rep, ?RSV, Addr/binary>>, Data),
    Data1.

send_to_client(Msg, #state{socket = Socket} = Data) ->
    {Bytes, Data1} = encapsulate(Msg, Data),
    {gen_tcp:send(Socket, Bytes), Data1}.

encapsulate(Msg, #state{gss = undefined} = Data) ->
    {Msg, Data};
encapsulate(Msg, #state{gss = Gss} = Data) ->
    {Frames, Gss1} = socks5_gssapi:wrap(Msg, Gss),
    {Frames, Data#state{gss = Gss1}}.

recv(_Socket, 0) ->
    <<>>;
recv(Socket, Len) ->
    case gen_tcp:recv(Socket, Len, ?TIMEOUT) of
        {ok, Bin}       -> Bin;
        {error, Reason} -> throw({socks5, {recv, Reason}})
    end.

local_ip(Socket) ->
    {ok, {IP, _}} = inet:sockname(Socket),
    IP.
