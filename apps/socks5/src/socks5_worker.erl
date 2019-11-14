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

%% API
-export([start_link/0,
         set_socket/2]).

%% gen_statem callbacks
-export([callback_mode/0,
         init/1,
         format_status/2,
         handle_event/4,
         terminate/3,
         code_change/4]).

%% states
-export(['WAIT_FOR_SOCKET'/3,
         'WAIT_FOR_AUTH'/3,
         'WAIT_FOR_CONNECT'/3,
         'WAIT_FOR_DATA'/3]).

%% Macro
-define(SERVER, ?MODULE).
-define(LOG(A1), io:format(A1)).
-define(LOG(A1, A2), io:format(A1, A2)).
-define(SOCK_SERVER_OPTIONS,
        [{active, once},
         binary,
         {packet, 0},
         {nodelay, true},
         {reuseaddr, true}]).

-define(MAX_RESTART, 5).
-define(MAX_TIME, 60).
-define(DEFAULT_PORT, 1080).

-define(TIMEOUT, 60000).

-define(SOCKS_VERSION, 16#05).
-define(RSV, 16#00).

-define(NMETHODS, 1).

%% Authentication methods
%% X'03'~X'7F' IANA assigned
%% X'80'~X'FE' reserved for private methods
-define(NO_AUTHENTICATION_REQUIRED, 16#00).
-define(GSSAPI,                     16#01).
-define(USERNAME_PASSWORD,          16#02).
-define(NO_ACCEPTABLE_METHODS,      16#ff).

-define(CONNECT, 16#01).
-define(BIND, 16#02).
-define(UDP_ASSOCIATE, 16#03).

-define(ATYP_IPV4, 16#01).
-define(DOMAINNAME, 16#03).
-define(ATYP_IPV6, 16#04).

-define(SUCCEEDED, 16#00).
-define(GENERAL_SOCKS_SERVER_FAILURE, 16#01).
-define(CONNECTION_NOT_ALLOWED, 16#02).
-define(NETWORK_UNREACHABLE, 16#03).
-define(HOST_UNREACHABLE, 16#04).
-define(CONNECTION_REFUSED, 16#05).
-define(TTL_EXPIRED, 16#06).
-define(CMD_NOT_SUPPORTED, 16#07).
-define(ATYP_NOT_SUPPORTED, 16#08).

-define(UBYTE, 8/unsigned-integer).
-define(USHORT, 16/unsigned-integer).
-define(UINT, 32/unsigned-integer).

%% Record
-record(worker_state,
        {
         socket,
         auth_method,
         authed_client = false,
         connect = false,
         bind = false,
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
    {ok, 'WAIT_FOR_SOCKET', #worker_state{}}.

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
'WAIT_FOR_SOCKET'(_EventType, {socket_ready, Socket}, _State) ->
    inet:setopts(Socket, ?SOCK_SERVER_OPTIONS),
    {next_state, 'WAIT_FOR_AUTH', #worker_state{socket = Socket}};
'WAIT_FOR_SOCKET'(_EventType, Other, State) ->
    ?LOG("State: 'WAIT_FOR_SOCKET'. Unexpected message: ~p~n", [Other]),
    {next_state, 'WAIT_FOR_SOCKET', State}.    

%% receive the method negotiation request
'WAIT_FOR_AUTH'(_EventType, {bin, <<?SOCKS_VERSION:?UBYTE,
                                    ?NMETHODS:?UBYTE,
                                    ?NO_AUTHENTICATION_REQUIRED:?UBYTE>>},
                #worker_state{socket = Socket,
                              auth_method = undefined} = State) ->
    {ok, Method} = handle_request(auth_method_negotiation,
                                  {Socket, ?NO_AUTHENTICATION_REQUIRED}),
    {next_state, 'WAIT_FOR_CONNECT',
     State#worker_state{auth_method = Method, authed_client = true}}.

'WAIT_FOR_CONNECT'(_EventType, {bin, <<?SOCKS_VERSION:?UBYTE,
                                       ?CONNECT:?UBYTE, 
                                       ?RSV:?UBYTE, 
                                       ?DOMAINNAME:?UBYTE, 
                                       Len:?UBYTE,
                                       Hostname:Len/binary,
                                       DstPort:?USHORT>>},
                   #worker_state{socket = Socket, 
                                 authed_client = true} = State) ->
    case handle_request(connect,
                        {Socket, binary_to_list(Hostname),
                        DstPort}) of
        {ok, DstSocket} ->
            {next_state, 
             'WAIT_FOR_DATA', 
             State#worker_state{connect = true,
                                target_socket = DstSocket}};
        {error, _Reason} ->
            {next_state, 'WAIT_FOR_CONNECT', State}
    end;  
'WAIT_FOR_CONNECT'(_EventType,
                   {bin, <<?SOCKS_VERSION:?UBYTE, 
                           ?CONNECT:?UBYTE,
                           ?RSV:?UBYTE,
                           ?ATYP_IPV4:?UBYTE,
                           A:?UBYTE, B:?UBYTE, C:?UBYTE, D:?UBYTE,
                           DstPort:?USHORT>>}, 
                   #worker_state{socket = Socket, 
                                 authed_client = true} = State) ->
    case handle_request(connect, {Socket, {A,B,C,D}, DstPort}) of
        {ok, DstSocket} ->
            {next_state, 
             'WAIT_FOR_DATA', 
             State#worker_state{connect = true,
                                target_socket = DstSocket}};
        {error, _Reason} ->
            {next_state, 'WAIT_FOR_CONNECT', State}
    end;    
'WAIT_FOR_CONNECT'(_EventType, 
                   {bin, <<?SOCKS_VERSION:?UBYTE, 
                           ?CONNECT:?UBYTE, 
                           ?RSV:?UBYTE, 
                           ?ATYP_IPV6:?UBYTE, 
                           A:?USHORT, B:?USHORT, C:?USHORT, D:?USHORT,
                           E:?USHORT, F:?USHORT, G:?USHORT, H:?USHORT,
                           DstPort:?USHORT>>},
                   #worker_state{socket = Socket,
                                 authed_client = true} = State) ->
    case handle_request(connect, {Socket, {A,B,C,D,E,F,G,H}, DstPort}) of
        {ok, DstSocket} ->
            {next_state, 
             'WAIT_FOR_DATA', 
             State#worker_state{connect = true,
                                target_socket = DstSocket}};
        {error, _Reason} ->
            {next_state, 'WAIT_FOR_CONNECT', State}
    end.


'WAIT_FOR_DATA'(_EventType, {toS, Data},
                #worker_state{target_socket=Socket} = State) ->
    gen_tcp:send(Socket, Data),
    {next_state, 'WAIT_FOR_DATA', State};
'WAIT_FOR_DATA'(_EventType, {toC, Data},
                #worker_state{socket=Socket} = State) ->
    gen_tcp:send(Socket, Data),
    {next_state, 'WAIT_FOR_DATA', State};
'WAIT_FOR_DATA'(_EventType, timeout, State) ->
    ?LOG("Client connection timeout. ~n"),
    {stop, normal, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% If callback_mode is handle_event_function, then whenever a
%% gen_statem receives an event from call/2, cast/2, or as a normal
%% process message, this function is called.
%%
%% @spec handle_event(Event, StateName, State) ->
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
handle_event(EventType, {socket_ready, Socket},
             'WAIT_FOR_SOCKET' = StateName, State) ->
    ?SERVER:StateName(EventType, {socket_ready, Socket}, State);
handle_event(EventType, {tcp, Socket, Data},
            'WAIT_FOR_AUTH' = StateName, State) ->
    reset_socket(Socket),
    ?SERVER:StateName(EventType, {bin, Data}, State);
handle_event(EventType, {tcp, Socket, Data},
             'WAIT_FOR_CONNECT' = StateName, State) ->
    reset_socket(Socket),
    ?SERVER:StateName(EventType, {bin, Data}, State);    
handle_event(EventType, {tcp, Socket, Data},
             'WAIT_FOR_DATA' = StateName,
             #worker_state{socket=Socket} = State) ->
    reset_socket(Socket),
    ?SERVER:StateName(EventType, {toS, Data}, State);
handle_event(EventType, {tcp, Socket, Data},
             'WAIT_FOR_DATA'=StateName, 
             #worker_state{target_socket=Socket} = State) ->
    reset_socket(Socket),
    ?SERVER:StateName(EventType, {toC, Data}, State);
handle_event(_EventType, {tcp_closed, Socket}, _StateName,
            #worker_state{socket=Socket} = State) ->
    ?LOG("Client disconnected. ~n"),
    {stop, normal, State};
handle_event(_EventType, {tcp_closed, Socket}, _StateName,
            #worker_state{target_socket=Socket} = State) ->
    ?LOG("Server disconnected. ~n"),
    {stop, normal, State};
handle_event(_EventType, _Info, StateName, State) ->
    {noreply, StateName, State};
handle_event({call, From}, _Msg, State, Data) ->
    {next_state, State, Data, [{reply, From, ok}]}.

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
          #worker_state{socket=Socket,
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
handle_request(auth_method_negotiation, 
               {Socket, ?NO_AUTHENTICATION_REQUIRED}) ->
    ok = gen_tcp:send(Socket,
                      <<?SOCKS_VERSION:?UBYTE,
                        ?NO_AUTHENTICATION_REQUIRED:?UBYTE>>),
    {ok, ?NO_AUTHENTICATION_REQUIRED};
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
            ?LOG("Connect to target host error: ~p~n", [Reason]),
            gen_tcp:send(Socket, <<?SOCKS_VERSION:?UBYTE,
                                   ?GENERAL_SOCKS_SERVER_FAILURE:?UBYTE,
                                   ?RSV:?UBYTE,
                                   0:?UINT,
                                   0:?USHORT>>),
            {error, Reason}
    end.

reset_socket(Socket) ->
    inet:setopts(Socket, [{active, once}]).