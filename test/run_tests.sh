#!/bin/bash

# Ensure rebar3 is available
if ! command -v rebar3 &> /dev/null
then
    echo "rebar3 not found. Attempting to download and make executable..."
    curl -LO https://s3.amazonaws.com/rebar3/rebar3
    chmod +x rebar3
    if [ $? -ne 0 ]; then
        echo "Failed to download or make rebar3 executable. Exiting."
        exit 1
    fi
    REBAR3_CMD="./rebar3"
else
    REBAR3_CMD="rebar3"
fi

echo "Building the SOCKS5 application..."
$REBAR3_CMD compile

if [ $? -ne 0 ]; then
    echo "Build failed. Exiting."
    exit 1
fi

echo "Starting the SOCKS5 application in the background..."
# Build the release
$REBAR3_CMD release

if [ $? -ne 0 ]; then
    echo "Release build failed. Exiting."
    exit 1
fi

# Find the release directory, usually _build/default/rel/socks5/bin/socks5
RELEASE_DIR="_build/default/rel/socks5"
if [ ! -d "$RELEASE_DIR" ]; then
    echo "Release directory not found: $RELEASE_DIR. Exiting."
    exit 1
fi

# Start the application
$RELEASE_DIR/bin/socks5 daemon &
SOCKS5_PID=$!
echo "SOCKS5 application started with PID: $SOCKS5_PID"

# Give it a moment to start up
sleep 5

echo "Checking if SOCKS5 is listening on port 1080..."
ss -tlnp | grep ":1080"
if [ $? -ne 0 ]; then
    echo "SOCKS5 application not listening on port 1080. Tests failed."
    kill $SOCKS5_PID
    exit 1
fi
echo "SOCKS5 is listening on port 1080."

echo "Testing SOCKS5 proxy with curl..."
# Use a known public endpoint for testing
CURL_TEST_URL="http://example.com"
CURL_OUTPUT=$(curl --socks5-hostname localhost:1080 $CURL_TEST_URL 2>&1)

if echo "$CURL_OUTPUT" | grep -q "Example Domain"; then
    echo "Curl test successful! Received expected content from $CURL_TEST_URL."
    echo "Curl output: $CURL_OUTPUT"
else
    echo "Curl test failed. Unexpected output or connection issue."
    echo "Curl output: $CURL_OUTPUT"
    kill $SOCKS5_PID
    exit 1
fi

echo "Stopping SOCKS5 application..."
kill $SOCKS5_PID
wait $SOCKS5_PID 2>/dev/null # Wait for the process to terminate

echo "All tests passed successfully!"
