FROM erlang:25-alpine AS builder

WORKDIR /app

# Install rebar3
RUN wget https://github.com/erlang/rebar3/releases/download/3.22.1/rebar3 && \
    chmod +x rebar3

COPY . .

# Unlock dependencies so they can be fetched, then build the release
RUN ./rebar3 unlock --all
RUN ./rebar3 as prod release

CMD ["bin/socks5", "foreground"]
