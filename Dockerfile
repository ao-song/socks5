# Stage 1: Build the application
FROM erlang:28-alpine AS builder

WORKDIR /app

# Install rebar3
RUN wget https://github.com/erlang/rebar3/releases/download/3.25.1/rebar3 && \
    chmod +x rebar3

COPY . .

RUN ./rebar3 as prod release

# Stage 2: Create the final runtime image
FROM erlang:28-alpine

WORKDIR /app

# Copy the built release from the builder stage
COPY --from=builder /app/_build/prod/rel/socks5 .

CMD ["bin/socks5", "foreground"]
