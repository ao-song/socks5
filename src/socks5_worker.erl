%%%-------------------------------------------------------------------
%%% @author Ao Song
%%% @copyright (C) 2019, Ao Song
%%% @doc
%%%
%%% @end
%%% Created : 2019-11-13 14:39:38.009820
%%%-------------------------------------------------------------------
-module(socks5_worker).

-behaviour(gen_statem).

-include("socks5.hrl").

-include_lib("kernel/include/logger.hrl").

%% API
-export([start_link/0,
         set_socket/2]).

%% gen_statem callbacks
-export([callback_mode/0,
         init/1,
         format_status/1,
         terminate/3,
         code_change/4]).

%% states
-export(['WAIT_FOR_SOCKET'/3,
         'AUTH_METHOD_NEG'/3,
         'AUTH_CLIENT'/3,
         'SETUP_CONNECTION'/3,
         'BIND_WAIT_FOR_CONNECTION'/3,
         'UDP_RELAY'/3,
         'CONNECTED'/3]).

%% Macro
-define(SERVER, ?MODULE).
-define(SOCK_SERVER_OPTIONS,
        [{active, once},
         binary,
         {packet, 0},
         {nodelay, true},
         {reuseaddr, true}]).

-define(HANDLE_COMMON,
        ?FUNCTION_NAME(T, C, D) -> handle_common(T, C, D)).

%% Record
-record(state,
        {
         socket,
         auth_method,
         authed_client = false,
         connect = false,
         bind_socket,
         udp_socket,
         target_socket
        }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_statem process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_statem:start_link({local, ?SERVER}, ?MODULE, [], []).

set_socket(Child, Socket) when is_pid(Child), is_port(Socket) ->
    gen_statem:cast(Child, {socket_ready, Socket}).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Define the callback_mode() for this callback module.
%%
%% @spec callback_mode() -> state_functions |
%%                          handle_event_function |
%%                          [state_functions, state_enter] |
%%                          [handle_event_function, state_enter]
%% @end
%%--------------------------------------------------------------------
callback_mode() ->
    state_functions.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_statem is started using gen_statem:start/[3,4] or
%% gen_statem:start_link/[3,4], this function is called by the new
%% process to initialize.
%%
%% @spec init(Args) -> {ok, State, Data} |
%%                     {ok, State, Data, Actions} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    process_flag(trap_exit, true),
    {ok, 'WAIT_FOR_SOCKET', #state{}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Called (1) whenever sys:get_status/1,2 is called by gen_statem or
%% (2) when gen_statem terminates abnormally.
%% This callback is optional.
%%
%% @spec format_status([PDict, State, Data]) -> Status
%% @end
%%--------------------------------------------------------------------
format_status([_PDict, State, Data]) ->
    [{data, [{"State", {State, Data}}]}].

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name.  If callback_mode is statefunctions, one of these
%% functions is called when gen_statem receives and event from
%% call/2, cast/2, or as a normal process message.
%%
%% @spec state_name(Event, OldState, Data) ->
%%                   {next_state, NextState, NewData} |
%%                   {next_state, NextState, NewData, Actions} |
%%                   {keep_state, NewData} |
%%                   {keep_state, NewData, Actions} |
%%                   keep_state_and_data |
%%                   {keep_state_and_data, Actions} |
%%                   {repeat_state, NewData} |
%%                   {repeat_state, NewData, Actions} |
%%                   repeat_state_and_data |
%%                   {repeat_state_and_data, Actions} |
%%                   stop |
%%                   {stop, Reason} |
%%                   {stop, Reason, NewData} |
%%                   {stop_and_reply, Reason, Replies} |
%%                   {stop_and_reply, Reason, Replies, NewData}
%% @end
%%--------------------------------------------------------------------
'WAIT_FOR_SOCKET'(cast, {socket_ready, Socket}, _State) ->
    inet:setopts(Socket, ?SOCK_SERVER_OPTIONS),
    {next_state, 'AUTH_METHOD_NEG', #state{socket = Socket}};
'WAIT_FOR_SOCKET'(_EventType, Other, State) ->
    ?LOG_WARNING("State: 'WAIT_FOR_SOCKET'. "
                 "Unexpected message: ~p", [Other]),
    {next_state, 'WAIT_FOR_SOCKET', State}.

%% receive the method negotiation request
'AUTH_METHOD_NEG'(info, {tcp, Socket, <<?SOCKS_VERSION:?UBYTE,
                                        MethodsNum:?UBYTE,
                                        Methods:(MethodsNum*8)/binary>>},
                #state{socket = Socket,
                       auth_method = undefined} = State) ->
    reset_socket(Socket),
    Method = get_method(get_supported_methods(),
                        get_methods(Methods, MethodsNum)),
    handle_request(auth_negotiation, {Socket, Method}, State),
    case Method of
        ?NO_ACCEPTABLE_METHODS ->
            ?LOG_INFO("No acceptable auth methods from client, "
                      "close the connection."),
            {stop, normal, State};
        ?NO_AUTHENTICATION_REQUIRED ->
            ?LOG_INFO("No authentication required, proceed to connection setup."),
            {next_state, 'SETUP_CONNECTION',
             State#state{auth_method = Method, authed_client = true}};
        _ ->
            ?LOG_INFO("Selected authentication method: ~p, waiting for client auth data.",
                      [Method]),
            {next_state, 'AUTH_CLIENT',
             State#state{auth_method = Method}}
    end;
'AUTH_METHOD_NEG'(info, {tcp, Socket, Data}, _State) ->
    reset_socket(Socket),
    ?LOG_WARNING("Data ~p arrived in incorrect state! "
                 "This message will be ignored", [Data]),
    keep_state_and_data;
?HANDLE_COMMON.

'AUTH_CLIENT'(info, {tcp, Socket, <<1:?UBYTE,
                                    ULen:?UBYTE,
                                    Username:ULen/binary,
                                    PLen:?UBYTE,
                                    Password:PLen/binary>>},
              #state{auth_method = ?USERNAME_PASSWORD} = State) ->
    reset_socket(Socket),
    case validate_credentials(binary_to_list(Username), binary_to_list(Password)) of
        true ->
            ?LOG_INFO("Client authenticated successfully."),
            gen_tcp:send(Socket, <<1:?UBYTE, ?SUCCEEDED:?UBYTE>>),
            {next_state, 'SETUP_CONNECTION',
             State#state{authed_client = true}};
        false ->
            ?LOG_ERROR("Client authentication failed: Invalid username or password."),
            gen_tcp:send(Socket, <<1:?UBYTE, 1:?UBYTE>>), % Version 1, status 1 (failure)
            {stop, normal, State}
    end;
'AUTH_CLIENT'(info, {tcp, Socket, _AuthData},
              #state{auth_method = AuthMethod} = State) ->
    reset_socket(Socket),
    ?LOG_ERROR("Unsupported authentication method (~p) or malformed "
               "authentication data. Close the connection!", [AuthMethod]),
    gen_tcp:send(Socket, <<1:?UBYTE, 1:?UBYTE>>),
    {stop, normal, State};
?HANDLE_COMMON.

'SETUP_CONNECTION'(info, {tcp, Socket, <<?SOCKS_VERSION:?UBYTE,
                                         Command:?UBYTE,
                                         ?RSV:?UBYTE,
                                         ATyp:?UBYTE,
                                         Rest/binary>>},
                   #state{socket = Socket,
                          authed_client = true} = State) ->
    reset_socket(Socket),
    case Command of
        ?CONNECT ->
            handle_connect_command(Socket, ATyp, Rest, State);
        ?BIND ->
            handle_bind_command(Socket, ATyp, Rest, State);
        ?UDP_ASSOCIATE ->
            handle_udp_associate_command(Socket, ATyp, Rest, State);
        _ ->
            ?LOG_ERROR("Unsupported SOCKS5 command: ~p", [Command]),
            gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE,
                                   ?CMD_NOT_SUPPORTED:?UBYTE,
                                   ?RSV:?UBYTE,
                                   0:?UINT,
                                   0:?USHORT>>),
            {stop, normal, State}
    end;
?HANDLE_COMMON.

'BIND_WAIT_FOR_CONNECTION'(info, {tcp, BindSocket, _Data},
                           #state{socket = ClientSocket,
                                  bind_socket = BindSocket} = State) ->
    reset_socket(BindSocket),
    case gen_tcp:accept(BindSocket) of
        {ok, TargetSocket} ->
            {ok, {Addr, Port}} = inet:peername(TargetSocket),
            {Atyp, BndAddr, BndPort} = socks5_utils:format_address(Addr, Port),
            gen_tcp:send(ClientSocket, <<?SOCKS_VERSION:?UBYTE,
                                           ?SUCCEEDED:?UBYTE,
                                           ?RSV:?UBYTE,
                                           Atyp:?UBYTE,
                                           BndAddr/binary,
                                           BndPort:?USHORT>>),
            inet:setopts(TargetSocket, ?SOCK_SERVER_OPTIONS),
            {next_state, 'CONNECTED',
             State#state{connect = true,
                         authed_client = true,
                         target_socket = TargetSocket}};
        {error, Reason} ->
            ?LOG_ERROR("Bind accept error: ~p", [Reason]),
            gen_tcp:send(ClientSocket, <<?SOCKS_VERSION:?UBYTE,
                                           ?GENERAL_SOCKS_SERVER_FAILURE:?UBYTE,
                                           ?RSV:?UBYTE,
                                           0:?UINT,
                                           0:?USHORT>>),
            {stop, normal, State}
    end;
?HANDLE_COMMON.

'UDP_RELAY'(info, {udp, UdpSocket, _ClientIP, _ClientPort,
                   <<?RSV:?USHORT, Frag:?UBYTE, ATyp:?UBYTE, Rest/binary>>},
            #state{udp_socket = UdpSocket}) ->
    % Only fragment 0 is supported
    case Frag of
        0 ->
            case socks5_utils:parse_address(ATyp, Rest) of
                {ok, {TargetAddr, TargetPort, Data}} ->
                    gen_udp:send(UdpSocket, TargetAddr, TargetPort, Data),
                    keep_state_and_data;
                {error, Reason} ->
                    ?LOG_ERROR("Failed to parse UDP address: ~p", [Reason]),
                    keep_state_and_data
            end;
        _ ->
            ?LOG_ERROR("UDP fragmentation is not supported (Frag: ~p)", [Frag]),
            keep_state_and_data
    end;
'UDP_RELAY'(info, {udp_passive, UdpSocket}, _State) ->
    % This means the UDP socket was set to passive, we need to set it active again
    inet:setopts(UdpSocket, [{active, once}]),
    keep_state_and_data;
'UDP_RELAY'(info, {tcp_closed, Socket}, #state{socket = Socket} = State) ->
    ?LOG_INFO("Client TCP connection closed during UDP relay. Terminating UDP relay."),
    {stop, normal, State};
?HANDLE_COMMON.


'CONNECTED'(info, {tcp, CSocket, Data},
            #state{socket = CSocket,
                   target_socket = TSocket} = State) ->
    reset_socket(CSocket),
    gen_tcp:send(TSocket, Data),
    {next_state, 'CONNECTED', State};
'CONNECTED'(info, {tcp, TSocket, Data},
            #state{socket = CSocket} = State) ->
    reset_socket(TSocket),
    gen_tcp:send(CSocket, Data),
    {next_state, 'CONNECTED', State};
'CONNECTED'(_EventType, timeout, State) ->
    ?LOG_ERROR("Client connection timeout."),
    {stop, normal, State};
?HANDLE_COMMON.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handle comment events for all states.
%%
%% @end
%%--------------------------------------------------------------------

handle_common(_EventType, {tcp_closed, Socket},
              #state{socket=Socket} = State) ->
    ?LOG_INFO("Client disconnected."),
    {stop, normal, State};
handle_common(_EventType, {tcp_closed, Socket},
              #state{target_socket=Socket} = State) ->
    ?LOG_INFO("Server disconnected."),
    {stop, normal, State};
handle_common({call, From}, _Msg, _Data) ->
    {keep_state_and_data, [{reply, From, ok}]};
handle_common(EventType, Event, _Data) ->
    ?LOG_ERROR("Unexpected event: ~p:~p", [EventType, Event]),
    keep_state_and_data.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_statem when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_statem terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State, Data) -> Ignored
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _StateName,
          #state{socket=Socket,
                 bind_socket=BindSocket,
                 udp_socket=UdpSocket,
                 target_socket=TarSocket}) ->
    ok = close_socket_if_defined(Socket),
    ok = close_socket_if_defined(BindSocket),
    ok = close_socket_if_defined(UdpSocket),
    ok = close_socket_if_defined(TarSocket),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, OldState, OldData, Extra) ->
%%                   {ok, NewState, NewData} |
%%                   Reason
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

handle_request(connect, {Socket, DstAddr, DstPort}, State) ->
    case gen_tcp:connect(DstAddr, DstPort, ?SOCK_SERVER_OPTIONS) of
        {ok, DstSocket} ->
            {ok, {Addr, Port}} = inet:sockname(DstSocket),
            {Atyp, BndAddr, BndPort} = socks5_utils:format_address(Addr, Port),
            gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE,
                                   ?SUCCEEDED:?UBYTE,
                                   ?RSV:?UBYTE,
                                   Atyp:?UBYTE,
                                   BndAddr/binary,
                                   BndPort:?USHORT>>),
            {next_state, 'CONNECTED',
             State#state{connect = true, target_socket = DstSocket}};
        {error, Reason} ->
            handle_connect_error(Socket, Reason),
            {stop, normal, State}
    end;
handle_request(auth_negotiation, {Socket, Method}, _State) ->
    ok = gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE, Method:?UBYTE>>),
    {ok, Method};
handle_request(bind, {ClientSocket, _BindAddr, _BindPort}, State) ->
    % For BIND, the client specifies the address/port it expects the SOCKS server to bind to.
    % However, for simplicity, we'll let the OS choose a port and report it back.
    % A more complete implementation would try to bind to the requested address/port.
    case gen_tcp:listen(0, ?SOCK_SERVER_OPTIONS) of % Listen on any available port
        {ok, ListenSocket} ->
            {ok, {BindAddr, BindPort}} = inet:sockname(ListenSocket),
            {Atyp, BndAddr, BndPort} = socks5_utils:format_address(BindAddr, BindPort),
            gen_tcp:send(ClientSocket, <<?SOCKS_VERSION:?UBYTE,
                                           ?SUCCEEDED:?UBYTE,
                                           ?RSV:?UBYTE,
                                           Atyp:?UBYTE,
                                           BndAddr/binary,
                                           BndPort:?USHORT>>),
            inet:setopts(ListenSocket, [{active, once}]), % Wait for the incoming connection
            {next_state, 'BIND_WAIT_FOR_CONNECTION', State#state{bind_socket = ListenSocket}};
        {error, Reason} ->
            ?LOG_ERROR("Bind listen error: ~p", [Reason]),
            ErrorReply = socks5_utils:reason_to_socks_error(Reason),
            gen_tcp:send(ClientSocket, <<?SOCKS_VERSION:?UBYTE,
                                           ErrorReply:?UBYTE,
                                           ?RSV:?UBYTE,
                                           ?ATYP_IPV4, 0:32, 0:16>>),
            {stop, normal, State}
    end.

handle_connect_command(Socket, ?ATYP_IPV4, <<A:?UBYTE, B:?UBYTE, C:?UBYTE, D:?UBYTE, DstPort:?USHORT>>, State) ->
    handle_request(connect, {Socket, {A,B,C,D}, DstPort}, State);
handle_connect_command(Socket, ?ATYP_IPV6, <<A:?USHORT, B:?USHORT, C:?USHORT, D:?USHORT,
                                             E:?USHORT, F:?USHORT, G:?USHORT, H:?USHORT,
                                             DstPort:?USHORT>>, State) ->
    handle_request(connect, {Socket, {A,B,C,D,E,F,G,H}, DstPort}, State);
handle_connect_command(Socket, ?DOMAINNAME, <<Len:?UBYTE, Hostname:Len/binary, DstPort:?USHORT>>, State) ->
    handle_request(connect, {Socket, binary_to_list(Hostname), DstPort}, State);
handle_connect_command(Socket, ATyp, _Rest, State) ->
    ?LOG_ERROR("Unsupported ATYP for CONNECT command: ~p", [ATyp]),
    gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE, ?ATYP_NOT_SUPPORTED:?UBYTE, ?RSV:?UBYTE, 0:?UINT, 0:?USHORT>>),
    {next_state, 'SETUP_CONNECTION', State}.

handle_connect_error(Socket, Reason) ->
    ?LOG_ERROR("Connect to target host error: ~p", [Reason]),
    ErrorReply = socks5_utils:reason_to_socks_error(Reason),
    gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE,
                           ErrorReply:?UBYTE,
                           ?RSV:?UBYTE,
                           ?ATYP_IPV4, 0:32, 0:16>>),
    ok.

handle_bind_command(Socket, ?ATYP_IPV4, <<A:?UBYTE, B:?UBYTE, C:?UBYTE, D:?UBYTE, DstPort:?USHORT>>, State) ->
    handle_request(bind, {Socket, {A,B,C,D}, DstPort}, State);
handle_bind_command(Socket, ?ATYP_IPV6, <<A:?USHORT, B:?USHORT, C:?USHORT, D:?USHORT,
                                          E:?USHORT, F:?USHORT, G:?USHORT, H:?USHORT,
                                          DstPort:?USHORT>>, State) ->
    handle_request(bind, {Socket, {A,B,C,D,E,F,G,H}, DstPort}, State);
handle_bind_command(Socket, ?DOMAINNAME, <<Len:?UBYTE, Hostname:Len/binary, DstPort:?USHORT>>, State) ->
    handle_request(bind, {Socket, binary_to_list(Hostname), DstPort}, State);
handle_bind_command(Socket, ATyp, _Rest, State) ->
    ?LOG_ERROR("Unsupported ATYP for BIND command: ~p", [ATyp]),
    gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE,
                           ?ATYP_NOT_SUPPORTED:?UBYTE,
                           ?RSV:?UBYTE,
                           ?ATYP_IPV4, 0:32, 0:16>>),
    {next_state, 'SETUP_CONNECTION', State}.

handle_udp_associate_command(Socket, _ATyp, _Rest, State) ->
    % The client provides a desired BND.ADDR and BND.PORT, but the server
    % typically assigns its own UDP port and reports it back.
    % The ATyp and Rest here are for the desired address, which we'll ignore for now.
    case gen_udp:open(0, [{active, once}, binary]) of % Open on any available port
        {ok, UdpSocket} ->
            {ok, {BoundIP, BoundPort}} = inet:sockname(UdpSocket),
            {Atyp, BndAddr, _BndPort} = socks5_utils:format_address(BoundIP, BoundPort),
            gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE,
                                   ?SUCCEEDED:?UBYTE,
                                   ?RSV:?UBYTE,
                                   Atyp:?UBYTE,
                                   BndAddr/binary,
                                   BoundPort:?USHORT>>),
            {next_state, 'UDP_RELAY', State#state{udp_socket = UdpSocket}};
        {error, Reason} ->
            ?LOG_ERROR("UDP associate error: ~p", [Reason]),
            ErrorReply = socks5_utils:reason_to_socks_error(Reason),
            gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE,
                                   ErrorReply:?UBYTE,
                                   ?RSV:?UBYTE,
                                   ?ATYP_IPV4, 0:32, 0:16>>),
            {stop, normal, State}
    end.

close_socket_if_defined(undefined) -> ok;
close_socket_if_defined(Socket) when is_port(Socket) ->
    socket:close(Socket).

reset_socket(Socket) ->
    inet:setopts(Socket, [{active, once}]).

get_methods(Methods, MethodsNum) ->
    get_methods(Methods, MethodsNum, []).

get_methods(_Methods, 0, MethodList) ->
    MethodList;
get_methods(<<Method:?UBYTE, MethodsLeft>>, MethodsNum, MethodList) ->
    get_methods(MethodsLeft, MethodsNum-1, [Method | MethodList]).


get_supported_methods() ->
    [?USERNAME_PASSWORD, ?NO_AUTHENTICATION_REQUIRED].

get_method(_SupportedMethods, []) ->
    ?NO_ACCEPTABLE_METHODS;
get_method([], _MethodList) ->
    ?NO_ACCEPTABLE_METHODS;
get_method([M | SupportedMethods], MethodList) ->
    case lists:member(M, MethodList) of
        true ->
            M;
        false ->
            get_method(SupportedMethods, MethodList)
    end.

validate_credentials(Username, Password) ->
    case socks5_utils:get_user_credentials() of
        {ok, #{username := ExpectedUsername, password := ExpectedPassword}} ->
            Username == ExpectedUsername andalso Password == ExpectedPassword;
        _ ->
            ?LOG_ERROR("No user credentials configured, authentication will always fail."),
            false
    end.
