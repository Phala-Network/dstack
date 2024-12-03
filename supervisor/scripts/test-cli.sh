#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m' # No Color
RED='\033[0;31m'

info() {
    printf "${GREEN}$1${NC}\n"
}

error() {
    printf "${RED}$1${NC}\n"
}

assert_eq() {
    local actual="$1"
    local expected="$2"
    local message="$3"
    local assert_ok=n
    if diff <(echo "$actual") <(echo "$expected") >/dev/null; then
        assert_ok=y
    fi
    if [ $assert_ok == "n" ]; then
        error "Assertion failed: $message"
        error "Expected : $expected"
        error "Got      : $actual"
        exit 1
    fi
}

CLI="cargo run -p supervisor-client --features cli -- --base-url unix:$1"

info "Testing Supervisor CLI commands..."

# Deploy a new process
info "Testing Deploy command"
RES=$(${CLI} deploy --id test-process --command sleep --arg 1000)
assert_eq "$RES" '{"data":null}' "Deploy should return empty object"

# Get info for specific process
info "Testing Info command"
RES=$(${CLI} info test-process)
assert_eq "$(echo "$RES" | jq -r .data.config.id)" "test-process" "Info should return object with id"
assert_eq "$(echo "$RES" | jq -r .data.config.command)" "sleep" "Info should return correct command"
assert_eq "$(echo "$RES" | jq -r .data.config.args[0])" "1000" "Info should return correct args"
assert_eq "$(echo "$RES" | jq -r .data.state.status)" "running" "Info should show running status"
assert_eq "$(echo "$RES" | jq -r .data.state.started)" "true" "Info should show started as true"

# Start the process (should fail as it's already running)
info "Testing Start command"
RES=$(${CLI} start test-process)
assert_eq "$RES" '{"error":"Process is already running"}' "Start should return error"

# Stop the process
info "Testing Stop command"
RES=$(${CLI} stop test-process)
assert_eq "$RES" '{"data":null}' "Stop should return empty object"

# Get info again to see the stopped state
info "Testing Info command after stop"
RES=$(${CLI} info test-process)
assert_eq "$(echo "$RES" | jq -r .data.state.status)" "stopped" "Info should show stopped status"
assert_eq "$(echo "$RES" | jq -r .data.state.started)" "false" "Info should show started as false"

# Remove the process
info "Testing Remove command"
RES=$(${CLI} remove test-process)
assert_eq "$RES" '{"data":null}' "Remove should return empty object"

# Can not start a removed process
info "Testing Start command after remove"
RES=$(${CLI} start test-process)
assert_eq "$RES" '{"error":"Process not found"}' "Start should return error"

# Test list command
info "Testing List command"
RES=$(${CLI} list)
echo "$RES"
assert_eq "$(echo "$RES" | jq -r .data)" "[]" "List should return empty array"

# Test ping command
info "Testing Ping command"
RES=$(${CLI} ping)
assert_eq "$RES" '{"data":"pong"}' "Ping should return empty object"

info "CLI testing completed!" 