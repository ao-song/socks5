-module(socks5_worker).
-behaviour(gen_fsm).
-define(SERVER, ?MODULE).

-author("ao.song@outlook.com").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0,
         set_socket/2]).

%% ------------------------------------------------------------------
%% gen_fsm Function Exports
%% ------------------------------------------------------------------

-export([init/1, state_name/2, state_name/3, handle_event/3,
         handle_sync_event/4, handle_info/3, terminate/3,
         code_change/4]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link() ->
    gen_fsm:start_link({local, ?SERVER}, ?MODULE, [], []).

set_socket(Child, Socket) when is_pid(Child), is_port(Socket) ->
    gen_fsm:send_event(Child, {socket_ready, Socket}).

%% ------------------------------------------------------------------
%% gen_fsm Function Definitions
%% ------------------------------------------------------------------

init(_Args) ->
    process_flag(trap_exit, true),
    {ok, 'WAIT_FOR_SOCKET', #worker_state{}}.

%% state
'WAIT_FOR_SOCKET'({socket_ready, Socket}, _State) when is_port(Socket) ->
    inet:setopts(Socket, ?SOCK_SERVER_OPTIONS),
    {next_state, 'WAIT_FOR_DATA', #worker_state{socket = Socket}}, ?TIMEOUT};
'WAIT_FOR_SOCKET'(Other, State) ->
    ?LOG("State: 'WAIT_FOR_SOCKET'. Unexpected message: ~p\n", [Other]),
    {next_state, 'WAIT_FOR_SOCKET', State}.    

%% receive the method negotiation request
'WAIT_FOR_DATA'({bin, <<?SOCKS_VERSION:8, 
                        ?NMETHODS:8, 
                        ?NO_AUTHENTICATION_REQUIRED:8>>}, 
                #worker_state{socket = Socket,
                              auth_method = undefined} = State) ->
    {ok, Method} = handle_request(auth_method_negotiation, 
                                  {Socket, ?NO_AUTHENTICATION_REQUIRED}),
    {next_state, 'WAIT_FOR_DATA', State#worker_state{auth_method = Method,
                                                     authed_client = true}};
'WAIT_FOR_DATA'({bin, <<?SOCKS_VERSION:8, 
                        ?CONNECT:8, 
                        ?RSV:8, 
                        ?ATYP_IPV4:8, 
                        A:8, B:8, C:8, D:8, 
                        DstPort:16>>}, 
                #worker_state{socket = Socket, 
                              authed_client = true} = State) ->
    case handle_request(connect, {Socket, {A,B,C,D}, DstPort}) of
        {ok, DstSocket} ->
            {next_state, 
             'WAIT_FOR_DATA', 
             State#worker_state{connect = true,
                                target_socket = DstSocket}};
        {error, Reason} ->
            {next_state, 'WAIT_FOR_DATA', State}
    end;
'WAIT_FOR_DATA'({bin, <<?SOCKS_VERSION:8, 
                        ?CONNECT:8, 
                        ?RSV:8, 
                        ?ATYP_IPV6:8, 
                        A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16,
                        DstPort:16>>}, 
                #worker_state{socket = Socket,
                              authed_client = true} = State) ->
    case handle_request(connect, {Socket, {A,B,C,D,E,F,G,H}, DstPort}) of
        {ok, DstSocket} ->
            {next_state, 
             'WAIT_FOR_DATA', 
             State#worker_state{connect = true,
                                target_socket = DstSocket}};
        {error, Reason} ->
            {next_state, 'WAIT_FOR_DATA', State}
    end;
'WAIT_FOR_DATA'(timeout, State) ->
     ?LOG("Client connection timeout. ~n"),
     {stop, normal, State};
'WAIT_FOR_DATA'(Data, State) ->
     ?LOG("Ignore data: ~p~n", [Data]),
     {next_state, 'WAIT_FOR_DATA', State}.

handle_event(Event, StateName, State) ->
    {stop, {StateName, undefined_event, Event}, State}.

handle_sync_event(Event, _From, StateName, State) ->
    {stop, {StateName, undefined_event, Event}, State}.

handle_info({tcp, Socket, Data}, StateName, 
            #worker_state{socket=Socket} = State) ->
    inet:setopts(Socket, [{active, once}]),
    ?SERVER:StateName({bin, Data}, State);
handle_info({tcp_closed, Socket}, _StateName,
            #worker_state{socket=Socket} = State) ->
    ?LOG("Client disconnected. ~n"),
    {stop, normal, State};
handle_info(_Info, StateName, State) ->
    {noreply, StateName, State}.

terminate(_Reason, _StateName, #worker_state{socket=Socket}) ->
    ok = gen_tcp:close(Socket),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

handle_request(auth_method_negotiation, 
               {Socket, ?NO_AUTHENTICATION_REQUIRED}) ->
    ok = gen_tcp:send(Socket, 
                      <<
                        ?SOCKS_VERSION:8, 
                        ?NO_AUTHENTICATION_REQUIRED:8
                      >>),
    {ok, ?NO_AUTHENTICATION_REQUIRED};
handle_request(connect, {Socket, DstAddr, DstPort}) ->
    case gen_tcp:connect(DstAddr, DstPort, ?SOCK_OPTIONS) of
        {ok, DstSocket} ->
            gen_tcp:send(Socket, <<?SOCKS_VERSION:8, 
                                   ?SUCCEEDED:8, 
                                   ?RSV:8, 
                                   ?ATYP_IPV4:8, 
                                   0:32,
                                   0:16>>),
            {ok, DstSocket};
        {error, Reason} ->
            ?LOG("Connect to target host error: ~p~n", [Reason]),
            gen_tcp:send(Socket, <<?SOCKS_VERSION:8,
                                   ?GENERAL_SOCKS_SERVER_FAILURE:8,
                                   ?RSV:8,
                                   0:32,
                                   0:16>>),
            {error, Reason}
    end.
