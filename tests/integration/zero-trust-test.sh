#!/bin/bash
set -e

# Zero Trust Architecture Integration Test
# This script tests the integration between PostgreSQL and the zero trust authentication service

# Configuration
TEST_DIR="$(dirname "$0")"
LOG_FILE="${TEST_DIR}/zero-trust-test.log"
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-db_dev}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-postgres}"
AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-http://localhost:8080}"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Log function
log() {
    echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check required tools
command -v curl >/dev/null 2>&1 || error_exit "curl is required but not installed"
command -v jq >/dev/null 2>&1 || error_exit "jq is required but not installed"
command -v psql >/dev/null 2>&1 || error_exit "psql is required but not installed"

log "Starting Zero Trust Architecture Integration Test"

# Test 1: Register a test user
log "Test 1: Register a test user"
USER_ID=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c "
    SELECT auth.register_user('zero_trust_test_user', 'zero_trust_test@example.com', 'test_password', 'user');
")
USER_ID=$(echo "$USER_ID" | tr -d '[:space:]')

if [ -z "$USER_ID" ]; then
    error_exit "Failed to register test user"
fi

log "Successfully registered test user with ID: $USER_ID"

# Test 2: Authenticate the test user
log "Test 2: Authenticate the test user"
AUTH_RESULT=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c "
    SELECT row_to_json(t) FROM (
        SELECT * FROM auth.authenticate_user('zero_trust_test_user', 'test_password', '127.0.0.1', 'Test User Agent')
    ) t;
")

if [ -z "$AUTH_RESULT" ]; then
    error_exit "Failed to authenticate test user"
fi

# Extract JWT token and session ID
JWT_TOKEN=$(echo "$AUTH_RESULT" | jq -r '.jwt_token')
SESSION_ID=$(echo "$AUTH_RESULT" | jq -r '.session_id')

if [ -z "$JWT_TOKEN" ] || [ "$JWT_TOKEN" = "null" ]; then
    error_exit "Failed to get JWT token"
fi

if [ -z "$SESSION_ID" ] || [ "$SESSION_ID" = "null" ]; then
    error_exit "Failed to get session ID"
fi

log "Successfully authenticated test user and got JWT token"

# Test 3: Verify the JWT token with the auth service
log "Test 3: Verify the JWT token with the auth service"
VERIFY_RESULT=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$JWT_TOKEN\"}" \
    "${AUTH_SERVICE_URL}/api/auth/verify")

if [ -z "$VERIFY_RESULT" ]; then
    error_exit "Failed to verify JWT token with auth service"
fi

VERIFY_STATUS=$(echo "$VERIFY_RESULT" | jq -r '.valid')

if [ "$VERIFY_STATUS" != "true" ]; then
    error_exit "JWT token verification failed: $VERIFY_RESULT"
fi

log "Successfully verified JWT token with auth service"

# Test 4: Test session validation in PostgreSQL
log "Test 4: Test session validation in PostgreSQL"
SESSION_RESULT=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c "
    SELECT row_to_json(t) FROM (
        SELECT * FROM auth.validate_session('$JWT_TOKEN', '127.0.0.1')
    ) t;
")

if [ -z "$SESSION_RESULT" ]; then
    error_exit "Failed to validate session in PostgreSQL"
fi

SESSION_VALID=$(echo "$SESSION_RESULT" | jq -r '.valid')

if [ "$SESSION_VALID" != "true" ]; then
    error_exit "Session validation failed in PostgreSQL: $SESSION_RESULT"
fi

log "Successfully validated session in PostgreSQL"

# Test 5: Revoke the session in PostgreSQL
log "Test 5: Revoke the session in PostgreSQL"
REVOKE_RESULT=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c "
    SELECT auth.revoke_session('$SESSION_ID', 'Test revocation');
")

if [ -z "$REVOKE_RESULT" ]; then
    error_exit "Failed to revoke session in PostgreSQL"
fi

REVOKE_SUCCESS=$(echo "$REVOKE_RESULT" | tr -d '[:space:]')

if [ "$REVOKE_SUCCESS" != "t" ]; then
    error_exit "Session revocation failed in PostgreSQL: $REVOKE_RESULT"
fi

log "Successfully revoked session in PostgreSQL"

# Test 6: Verify the session is revoked in PostgreSQL
log "Test 6: Verify the session is revoked in PostgreSQL"
SESSION_RESULT=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c "
    SELECT row_to_json(t) FROM (
        SELECT * FROM auth.validate_session('$JWT_TOKEN', '127.0.0.1')
    ) t;
")

if [ -z "$SESSION_RESULT" ]; then
    error_exit "Failed to validate revoked session in PostgreSQL"
fi

SESSION_VALID=$(echo "$SESSION_RESULT" | jq -r '.valid')

if [ "$SESSION_VALID" = "true" ]; then
    error_exit "Revoked session is still valid in PostgreSQL: $SESSION_RESULT"
fi

log "Successfully verified session is revoked in PostgreSQL"

# Test 7: Verify the session is revoked in the auth service
log "Test 7: Verify the session is revoked in the auth service"
VERIFY_RESULT=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$JWT_TOKEN\"}" \
    "${AUTH_SERVICE_URL}/api/auth/verify")

if [ -z "$VERIFY_RESULT" ]; then
    error_exit "Failed to verify revoked JWT token with auth service"
fi

VERIFY_STATUS=$(echo "$VERIFY_RESULT" | jq -r '.valid')

if [ "$VERIFY_STATUS" = "true" ]; then
    error_exit "Revoked JWT token is still valid in auth service: $VERIFY_RESULT"
fi

log "Successfully verified session is revoked in auth service"

# Test 8: Test the auth service connector
log "Test 8: Test the auth service connector"
CONNECTOR_RESULT=$(python3 ../../scripts/security/auth_service_connector.py --once)

if [ $? -ne 0 ]; then
    error_exit "Auth service connector failed: $CONNECTOR_RESULT"
fi

log "Successfully ran auth service connector"

# Clean up
log "Cleaning up test data"
psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    DELETE FROM auth.active_sessions WHERE user_id = '$USER_ID';
    DELETE FROM auth.users WHERE user_id = '$USER_ID';
"

log "Zero Trust Architecture Integration Test completed successfully"
exit 0
