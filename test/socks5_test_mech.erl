%% A fake GSS-API mechanism (kerlberos gss_mechanism callbacks) used to
%% exercise the RFC 1961 framing without a KDC: tokens are plain text
%% and wrapping prefixes "W".
-module(socks5_test_mech).

-export([accept/2, continue/2, wrap/2, unwrap/2, delete/1,
         peer_name/1, translate_name/2]).

accept(<<"hello">>, #{keytab := fake, mutual_auth := true}) ->
    {continue, <<"challenge">>, established};
accept(<<"quick">>, _Opts) ->
    {ok, established};                     % complete, no output token
accept(<<"final">>, _Opts) ->
    {ok, <<"done">>, established};         % complete with a last token
accept(_Token, _Opts) ->
    {error, defective_token}.

continue(<<"response">>, established) ->
    {ok, <<"done">>, established};
continue(_Token, _State) ->
    {error, defective_token}.

wrap(Msg, State) ->
    {ok, <<"W", Msg/binary>>, State}.

unwrap(<<"W", Msg/binary>>, State) ->
    {ok, Msg, State};
unwrap(_Token, State) ->
    {error, bad_mic, State}.

delete(_State) ->
    ok.

peer_name(_State) ->
    {ok, tester}.

translate_name(tester, _Oid) ->
    {ok, "tester@EXAMPLE.COM"}.
