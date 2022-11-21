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
         format_status/2,
         terminate/3,
         code_change/4]).

%% states
-export(['WAIT_FOR_SOCKET'/3,
         'AUTH_METHOD_NEG'/3,
         'AUTH_CLIENT'/3,
         'SETUP_CONNECTION'/3,
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
%% @spec format_status(Opt, [PDict, State, Data]) -> Status
%% @end
%%--------------------------------------------------------------------
format_status(_Opt, [_PDict, State, Data]) ->
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
    handle_request(auth_negotiation, {Socket, Method}),
    case Method of
        ?NO_ACCEPTABLE_METHODS ->
            ?LOG_INFO("No acceptable auth methods from client, "
                      "close the connection."),
            {stop, normal, State};
        _ ->
            {next_state, 'AUTH_CLIENT',
             State#state{auth_method = Method}}
    end;
'AUTH_METHOD_NEG'(info, {tcp, Socket, Data}, _State) ->
    reset_socket(Socket),
    ?LOG_WARNING("Data ~p arrived in incorrect state! "
                 "This message will be ignored", [Data]),
    keep_state_and_data;
?HANDLE_COMMON.

%% TODO: GSSAPI must be supported,
%%       Username/Password should be supported.
'AUTH_CLIENT'(info, {tcp, Socket, AuthData},
              #state{auth_method = AuthMethod} = State) ->
    reset_socket(Socket),
    case auth_client(AuthData, AuthMethod) of
        ok ->
            {next_state, 'SETUP_CONNECTION',
             State#state{authed_client = true}};
        {error, Reason} ->
            ?LOG_ERROR("Client authentication failed, "
                       "close the connection! ~p", [Reason]),
            {stop, normal, State}
    end;
?HANDLE_COMMON.

'SETUP_CONNECTION'(info, {tcp, Socket, <<?SOCKS_VERSION:?UBYTE,
                                         ?CONNECT:?UBYTE,
                                         ?RSV:?UBYTE,
                                         ?DOMAINNAME:?UBYTE,
                                         Len:?UBYTE,
                                         Hostname:Len/binary,
                                         DstPort:?USHORT>>},
                   #state{socket = Socket,
                          authed_client = true} = State) ->
    reset_socket(Socket),
    case handle_request(connect,
                        {Socket, binary_to_list(Hostname),
                        DstPort}) of
        {ok, DstSocket} ->
            {next_state, 'CONNECTED',
             State#state{connect = true,
                         target_socket = DstSocket}};
        {error, _Reason} ->
            {next_state, 'SETUP_CONNECTION', State}
    end;
'SETUP_CONNECTION'(info,
                   {tcp, Socket, <<?SOCKS_VERSION:?UBYTE,
                                   ?CONNECT:?UBYTE,
                                   ?RSV:?UBYTE,
                                   ?ATYP_IPV4:?UBYTE,
                                   A:?UBYTE, B:?UBYTE, C:?UBYTE, D:?UBYTE,
                                   DstPort:?USHORT>>},
                   #state{socket = Socket,
                          authed_client = true} = State) ->
    reset_socket(Socket),
    case handle_request(connect, {Socket, {A,B,C,D}, DstPort}) of
        {ok, DstSocket} ->
            {next_state,
             'CONNECTED',
             State#state{connect = true,
                         target_socket = DstSocket}};
        {error, _Reason} ->
            {next_state, 'SETUP_CONNECTION', State}
    end;
'SETUP_CONNECTION'(info,
                   {tcp, Socket, <<?SOCKS_VERSION:?UBYTE,
                                   ?CONNECT:?UBYTE,
                                   ?RSV:?UBYTE,
                                   ?ATYP_IPV6:?UBYTE,
                                   A:?USHORT, B:?USHORT, C:?USHORT, D:?USHORT,
                                   E:?USHORT, F:?USHORT, G:?USHORT, H:?USHORT,
                                   DstPort:?USHORT>>},
                   #state{socket = Socket,
                          authed_client = true} = State) ->
    reset_socket(Socket),
    case handle_request(connect, {Socket, {A,B,C,D,E,F,G,H}, DstPort}) of
        {ok, DstSocket} ->
            {next_state,
             'CONNECTED',
             State#state{connect = true,
                         target_socket = DstSocket}};
        {error, _Reason} ->
            {next_state, 'SETUP_CONNECTION', State}
    end;
?HANDLE_COMMON.


'CONNECTED'(info, {tcp, CSocket, Data},
                #state{socket = CSocket,
                       target_socket = TSocket} = State) ->
    reset_socket(CSocket),
    gen_tcp:send(TSocket, Data),
    {next_state, 'CONNECTED', State};
'CONNECTED'(info, {tcp, TSocket, Data},
            #state{socket=CSocket} = State) ->
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
                 target_socket=TarSocket}) ->
    case {Socket, TarSocket} of
        {undefined, undefined} -> ok;
        {Socket, undefined} ->
            gen_tcp:close(Socket);
        {undefined, TarSocket} ->
            gen_tcp:close(TarSocket);
        {_S, _TS} ->
            gen_tcp:close(Socket),
            gen_tcp:close(TarSocket)
    end,
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
handle_request(auth_negotiation, {Socket, Method}) ->
    ok = gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE, Method:?UBYTE>>),
    {ok, Method};
handle_request(connect, {Socket, DstAddr, DstPort}) ->
    case gen_tcp:connect(DstAddr, DstPort, ?SOCK_SERVER_OPTIONS) of
        {ok, DstSocket} ->
            gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE,
                                   ?SUCCEEDED:?UBYTE,
                                   ?RSV:?UBYTE,
                                   ?ATYP_IPV4:?UBYTE,
                                   0:?UINT,
                                   0:?USHORT>>),
            {ok, DstSocket};
        {error, Reason} ->
            ?LOG_ERROR("Connect to target host error: ~p", [Reason]),
            gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE,
                                   ?GENERAL_SOCKS_SERVER_FAILURE:?UBYTE,
                                   ?RSV:?UBYTE,
                                   0:?UINT,
                                   0:?USHORT>>),
            {error, Reason}
    end.

reset_socket(Socket) ->
    inet:setopts(Socket, [{active, once}]).

get_methods(Methods, MethodsNum) ->
    get_methods(Methods, MethodsNum, []).

get_methods(_Methods, 0, MethodList) ->
    MethodList;
get_methods(<<Method:?UBYTE, MethodsLeft>>, MethodsNum, MethodList) ->
    get_methods(MethodsLeft, MethodsNum-1, [Method | MethodList]).


get_supported_methods() ->
    [?GSSAPI, ?USERNAME_PASSWORD, ?NO_AUTHENTICATION_REQUIRED].

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

auth_client(_AuthData, _AuthMethod) ->
    ok.