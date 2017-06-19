-module(socks5_client_worker).
-behaviour(gen_server).

-author("ao.song@outlook.com").

-define(SERVER, ?MODULE).

-include("socks5.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([connect/2]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [{SrvIP, SrvPort}], []).

connect(DstHost, DstPort) ->
    case inet:parse_address(DstHost) of
        {ok, IPAdress} ->
            gen_server:call(?SERVER, {connect, IPAdress, DstPort});
        {error, einval} ->
            ?LOG("Client: Invalid address!~n."),
            {error, invalid_address}
    end.

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([{SrvIP, SrvPort}]) ->
    case gen_tcp:connect(SrvIP, SrvPort, ?SOCK_OPTIONS) of
      {ok, Socket} ->
          method_negotiation(Socket, #client_state{socket = Socket});
      {error, Reason} ->
          ?LOG("Client: Socks server connect error, ~p~n.", [Reason]),
          {stop, Reason}
    end.

handle_call({connect, {A, B, C, D}, DstPort}, 
            _From, 
            #client_state{socket = Socket} = State) ->
    ConnectReq = <<?SOCKS_VERSION:8, 
                   ?CONNECT:8, 
                   ?RSV:8, 
                   ?ATYP_IPV4:8, 
                   A:8, B:8, C:8, D:8, 
                   DstPort:16>>,
    gen_tcp:send(Socket, ConnectReq),
    handle_connect_reply(Socket, State);

handle_call({connect, {A, B, C, D, E, F, G, H}, DstPort},
            _From,
            #client_state{socket = Socket} = State) ->
    ConnectReq = <<?SOCKS_VERSION:8, 
                   ?CONNECT:8, 
                   ?RSV:8, 
                   ?ATYP_IPV6:8, 
                   A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16,
                   DstPort:16>>,
    gen_tcp:send(Socket, ConnectReq),
    handle_connect_reply(Socket, State);

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #client_state{socket = Socket} = State) ->
    ok = gen_tcp:close(Socket),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

method_negotiation(Socket, ClientState) ->
    gen_tcp:send(Socket, <<?SOCKS_VERSION:8, 
                           ?NMETHODS:8, 
                           ?NO_AUTHENTICATION_REQUIRED:8>>),
    case gen_tcp:recv(Socket, 0) of
        {ok, <<?SOCKS_VERSION:8, Method:8>>} -> 
            authentication_req(Socket, Method, ClientState);
        {error, Reason} ->
            ?LOG("Client: Socks server negotiation reply error, ~p~n.", 
                 [Reason]),
            {stop, Reason}
    end.

%% todo: introduce auth protocols
authentication_req(Socket, Method, ClientState) ->
    {ok, ClientState#client_state{method = Method}}.

handle_connect_reply(Socket, State) ->
    case gen_tcp:recv(Socket, 0) of
        {ok, 
         <<?SOCKS_VERSION:8, 
           ?SUCCEEDED:8, 
           ?RSV:8, 
           ATYP:8, 
           Bound/binary>>} ->
            update_connect_state(ATYP, Bound, State);
        {ok,
         <<?SOCKS_VERSION:8,
           ConnError:8,
           ?RSV:8,
           _Other/binary>>} ->
            {reply, {error, ConnError}, State};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end.


update_connect_state(?ATYP_IPV4, <<A:8, B:8, C:8, D:8, Port:16>>, State) ->
    {reply, 
     ok, 
     State#client_state{bound_addr = {A, B, C, D},
                        bound_port = Port}};
update_connect_state(?ATYP_IPV6, 
                     <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16, 
                       Port:16>>, 
                     State) ->
    {reply,
     ok,
     State#client_state{bound_addr = {A, B, C, D, E, F, G, H},
                        bound_port = Port}}.