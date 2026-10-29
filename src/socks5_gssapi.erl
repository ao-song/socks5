%%%-------------------------------------------------------------------
%%% @author Ao Song
%%% @copyright (C) 2025, Ao Song
%%% @doc GSS-API authentication for SOCKS5 (RFC 1961).
%%%
%%% The GSS-API mechanism is a module implementing kerlberos'
%%% `gss_mechanism' behaviour; `gss_krb5' (Kerberos V5) is the default.
%%% After the context is established and a protection level agreed,
%%% every SOCKS message and UDP datagram travels as
%%% VER(1) | MTYP(3) | LEN(2) | gss_wrap(message).
%%% @end
%%%-------------------------------------------------------------------
-module(socks5_gssapi).

-include("socks5.hrl").
-include_lib("kernel/include/logger.hrl").

-export([negotiate/2, recv_message/2, wrap/2, unwrap/2, unwrap_stream/2,
         delete/1]).

-export_type([ctx/0]).

-define(VER,        16#01).
-define(MTYP_AUTH,  16#01).
-define(MTYP_LEVEL, 16#02).
-define(MTYP_DATA,  16#03).
-define(MTYP_ABORT, 16#ff).

%% Largest plaintext per wrap token: LEN is 16 bit and the token adds
%% a few dozen bytes of header, checksum and padding.
-define(CHUNK, 65000).

%% GSS_KRB5_NT_PRINCIPAL_NAME, for logging the authenticated principal.
-define(KRB5_NAME_OID, {1, 2, 840, 113554, 1, 2, 2, 1}).

-record(ctx, {mech  :: module(),
              state :: term()}).

-opaque ctx() :: #ctx{}.

%%%===================================================================
%%% Context establishment and protection level (RFC 1961 sections 3, 4)
%%%===================================================================

%% Runs the subnegotiation on a passive socket. Returns `clear' when
%% protection level 0 was agreed (later messages are not encapsulated).
-spec negotiate(gen_tcp:socket(), map()) -> {ok, ctx() | clear} | {error, term()}.
negotiate(Socket, Config) ->
    Mech = maps:get(mech, Config, gss_krb5),
    try
        Token = recv_frame(Socket, ?MTYP_AUTH),
        State = establish(Socket, Mech, Mech:accept(Token, mech_options(Mech, Config))),
        Ctx = #ctx{mech = Mech, state = State},
        ?LOG_INFO("GSSAPI: authenticated ~s", [peer(Ctx)]),
        protection_level(Socket, Ctx, Config)
    catch
        throw:{abort, Reason} ->
            gen_tcp:send(Socket, <<?VER, ?MTYP_ABORT>>),
            {error, Reason};
        throw:{closed, Reason} ->
            {error, Reason}
    end.

establish(Socket, Mech, {continue, Token, State}) ->
    send_frame(Socket, ?MTYP_AUTH, Token),
    establish(Socket, Mech, Mech:continue(recv_frame(Socket, ?MTYP_AUTH), State));
establish(Socket, _Mech, {ok, Token, State}) ->
    send_frame(Socket, ?MTYP_AUTH, Token),
    State;
establish(Socket, _Mech, {ok, State}) ->
    %% Context complete with no output token: a zero-length token tells
    %% the client we are ready (section 3.6).
    send_frame(Socket, ?MTYP_AUTH, <<>>),
    State;
establish(_Socket, _Mech, {error, Reason}) ->
    throw({abort, Reason});
establish(_Socket, _Mech, {error, Reason, _State}) ->
    throw({abort, Reason}).

%% The client sends its required level wrapped (or, NEC style, as a
%% bare octet); we answer with the level we agree to, the same way.
protection_level(Socket, #ctx{mech = Mech} = Ctx, Config) ->
    {Requested, Ctx1, Bare} =
        case recv_frame(Socket, ?MTYP_LEVEL) of
            <<Level>> ->
                {Level, Ctx, true};
            Token ->
                case unwrap_token(Token, Ctx) of
                    {ok, <<Level>>, C} -> {Level, C, false};
                    _                  -> throw({abort, bad_level_token})
                end
        end,
    Agreed = choose_level(Requested, Config),
    Ctx2 = case Bare of
               true ->
                   send_frame(Socket, ?MTYP_LEVEL, <<Agreed>>),
                   Ctx1;
               false ->
                   {ok, Reply, State} = Mech:wrap(<<Agreed>>, Ctx1#ctx.state),
                   send_frame(Socket, ?MTYP_LEVEL, Reply),
                   Ctx1#ctx{state = State}
           end,
    ?LOG_INFO("GSSAPI: protection level ~p requested, ~p agreed", [Requested, Agreed]),
    case Agreed of
        0 -> {ok, clear};
        _ -> {ok, Ctx2}
    end.

%% Levels: 0 none (de-facto extension used by curl, Dante), 1 integrity,
%% 2 confidentiality, 3 selective (treated as 2: we always wrap).
choose_level(Requested, Config) ->
    Allowed = maps:get(levels, Config, [0, 1, 2]),
    Wanted = min(Requested, 2),
    case lists:member(Wanted, Allowed) of
        true  -> Wanted;
        false -> lists:max(Allowed)
    end.

mech_options(Mech, Config) ->
    Base = #{mutual_auth => true, chan_bindings => <<0:128>>},
    Opts = maps:merge(Base, maps:get(mech_options, Config, #{})),
    case {maps:find(keytab, Config), Mech} of
        {{ok, Path}, _} ->
            case krb_mit_keytab:file(Path) of
                {ok, KeyTab}    -> Opts#{keytab => KeyTab};
                {error, Reason} -> throw({abort, {keytab, Path, Reason}})
            end;
        {error, gss_krb5} ->
            throw({abort, no_keytab_configured});
        {error, _} ->
            Opts
    end.

peer(#ctx{mech = Mech, state = State}) ->
    try
        {ok, Name} = Mech:peer_name(State),
        case Mech:translate_name(Name, ?KRB5_NAME_OID) of
            {ok, Display} -> Display;
            _             -> io_lib:format("~p", [Name])
        end
    catch
        _:_ -> "unknown principal"
    end.

%%%===================================================================
%%% Per-message protection (RFC 1961 section 5)
%%%===================================================================

%% Reads one encapsulated message from a passive socket.
-spec recv_message(gen_tcp:socket(), ctx()) -> {ok, binary(), ctx()} | {error, term()}.
recv_message(Socket, Ctx) ->
    try unwrap_token(recv_frame(Socket, ?MTYP_DATA), Ctx) of
        {ok, Msg, Ctx1}    -> {ok, Msg, Ctx1};
        {error, Reason, _} -> {error, Reason}
    catch
        throw:{_, Reason} -> {error, Reason}
    end.

%% Encapsulates a message as one or more frames (iolist).
-spec wrap(binary(), ctx()) -> {iolist(), ctx()}.
wrap(<<>>, Ctx) ->
    {[], Ctx};
wrap(Msg, #ctx{mech = Mech, state = State} = Ctx) ->
    {Chunk, Rest} = case Msg of
                        <<C:?CHUNK/binary, R/binary>> -> {C, R};
                        _                            -> {Msg, <<>>}
                    end,
    {ok, Token, State1} = Mech:wrap(Chunk, State),
    {Frames, Ctx1} = wrap(Rest, Ctx#ctx{state = State1}),
    {[frame(?MTYP_DATA, Token) | Frames], Ctx1}.

%% De-encapsulates exactly one frame (a UDP datagram).
-spec unwrap(binary(), ctx()) -> {ok, binary(), ctx()} | {error, term(), ctx()}.
unwrap(<<?VER, ?MTYP_DATA, Len:?USHORT, Token:Len/binary>>, Ctx) ->
    unwrap_token(Token, Ctx);
unwrap(_Datagram, Ctx) ->
    {error, bad_frame, Ctx}.

%% De-encapsulates every complete frame in a TCP stream buffer and
%% returns the plaintext plus the unconsumed tail.
-spec unwrap_stream(binary(), ctx()) ->
          {ok, iolist(), binary(), ctx()} | {error, term()}.
unwrap_stream(Buf, Ctx) ->
    unwrap_stream(Buf, Ctx, []).

unwrap_stream(<<?VER, ?MTYP_DATA, Len:?USHORT, Rest/binary>> = Buf, Ctx, Acc) ->
    case Rest of
        <<Token:Len/binary, More/binary>> ->
            case unwrap_token(Token, Ctx) of
                {ok, Msg, Ctx1}    -> unwrap_stream(More, Ctx1, [Msg | Acc]);
                {error, Reason, _} -> {error, Reason}
            end;
        _ ->
            {ok, lists:reverse(Acc), Buf, Ctx}
    end;
unwrap_stream(Buf, Ctx, Acc) when byte_size(Buf) < 4 ->
    {ok, lists:reverse(Acc), Buf, Ctx};
unwrap_stream(_Buf, _Ctx, _Acc) ->
    {error, bad_frame}.

unwrap_token(Token, #ctx{mech = Mech, state = State} = Ctx) ->
    case Mech:unwrap(Token, State) of
        {ok, Msg, State1}        -> {ok, Msg, Ctx#ctx{state = State1}};
        {error, Reason, State1}  -> {error, Reason, Ctx#ctx{state = State1}};
        {error, Reason}          -> {error, Reason, Ctx}
    end.

%% Section 6: contexts are deleted locally, no token is exchanged.
-spec delete(ctx() | clear | undefined) -> ok.
delete(#ctx{mech = Mech, state = State}) ->
    catch Mech:delete(State),
    ok;
delete(_) ->
    ok.

%%%===================================================================
%%% Framing
%%%===================================================================

frame(Mtyp, Token) ->
    <<?VER, Mtyp, (byte_size(Token)):?USHORT, Token/binary>>.

send_frame(Socket, Mtyp, Token) ->
    gen_tcp:send(Socket, frame(Mtyp, Token)).

recv_frame(Socket, Mtyp) ->
    case gen_tcp:recv(Socket, 4, ?TIMEOUT) of
        {ok, <<?VER, Mtyp, Len:?USHORT>>} -> recv_bytes(Socket, Len);
        {ok, Other}                       -> throw({abort, {bad_frame, Other}});
        {error, Reason}                   -> throw({closed, Reason})
    end.

recv_bytes(_Socket, 0) ->
    <<>>;
recv_bytes(Socket, Len) ->
    case gen_tcp:recv(Socket, Len, ?TIMEOUT) of
        {ok, Bin}       -> Bin;
        {error, Reason} -> throw({closed, Reason})
    end.
