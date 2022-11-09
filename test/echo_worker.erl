-module(echo_worker).
-export([echo/1]).

echo(ClientSocket) ->
    case gen_tcp:recv(ClientSocket, 0) of
        {ok, <<"hello">>} ->
            gen_tcp:send(ClientSocket, <<"got it!">>),
            echo(ClientSocket);
        {error, closed} ->
            ok
    end.