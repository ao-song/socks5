# Stage 1: Build the release
FROM erlang:25-alpine AS builder

WORKDIR /app

# Install rebar3
RUN wget https://github.com/erlang/rebar3/releases/download/3.22.1/rebar3 && \
    chmod +x rebar3

COPY . .

# Unlock dependencies so they can be fetched, then build the release
RUN ./rebar3 unlock
RUN ./rebar3 as prod release

# Stage 2: Create the final, minimal image
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/_build/prod/rel/socks5 .

CMD ["bin/socks5", "foreground"]
