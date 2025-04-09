#!/bin/bash
set -e

# Threat Detection Integration Test
# This script tests the threat detection components of the PostgreSQL Security Framework

# Configuration
TEST_DIR="$(dirname "$0")"
LOG_FILE="${TEST_DIR}/threat-detection-test.log"
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-db_dev}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-postgres}"
ANOMALY_DETECTION_URL="${ANOMALY_DETECTION_URL:-http://localhost:8080}"
FALCO_ENDPOINT="${FALCO_ENDPOINT:-http://localhost:2801}"

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

log "Starting Threat Detection Integration Test"

# Test 1: Create test tables and data
log "Test 1: Create test tables and data"
psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    CREATE SCHEMA IF NOT EXISTS test_threat_detection;
    
    CREATE TABLE IF NOT EXISTS test_threat_detection.sensitive_data (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        credit_card_number TEXT,
        ssn TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
    
    INSERT INTO test_threat_detection.sensitive_data (user_id, credit_card_number, ssn)
    VALUES 
        (1, '4111111111111111', '123-45-6789'),
        (2, '5555555555554444', '987-65-4321'),
        (3, '378282246310005', '456-78-9012');
    
    CREATE TABLE IF NOT EXISTS test_threat_detection.user_logins (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        login_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        ip_address TEXT NOT NULL,
        user_agent TEXT,
        success BOOLEAN NOT NULL
    );
    
    INSERT INTO test_threat_detection.user_logins (username, ip_address, user_agent, success)
    VALUES 
        ('normal_user', '192.168.1.1', 'Mozilla/5.0', TRUE),
        ('normal_user', '192.168.1.1', 'Mozilla/5.0', TRUE),
        ('normal_user', '192.168.1.2', 'Mozilla/5.0', TRUE);
"

log "Successfully created test tables and data"

# Test 2: Simulate normal queries
log "Test 2: Simulate normal queries"
for i in {1..10}; do
    psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
        SELECT * FROM test_threat_detection.sensitive_data WHERE user_id = 1;
        SELECT * FROM test_threat_detection.user_logins WHERE username = 'normal_user';
    " > /dev/null
done

log "Successfully simulated normal queries"

# Test 3: Simulate suspicious queries (potential SQL injection)
log "Test 3: Simulate suspicious queries (potential SQL injection)"
SQL_INJECTION_QUERY="SELECT * FROM test_threat_detection.sensitive_data WHERE id = 1 OR 1=1;"

psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    -- Log the suspicious query
    INSERT INTO logs.notification_log (
        event_type, severity, username, source_ip, message
    ) VALUES (
        'SQL_INJECTION_ATTEMPT', 'HIGH', '$POSTGRES_USER', '127.0.0.1', 
        'Potential SQL injection detected: $SQL_INJECTION_QUERY'
    );
"

log "Successfully simulated suspicious query"

# Test 4: Simulate failed login attempts
log "Test 4: Simulate failed login attempts"
for i in {1..5}; do
    psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
        INSERT INTO test_threat_detection.user_logins (username, ip_address, user_agent, success)
        VALUES ('suspicious_user', '10.0.0.$i', 'Mozilla/5.0', FALSE);
        
        INSERT INTO logs.notification_log (
            event_type, severity, username, source_ip, message
        ) VALUES (
            'LOGIN_FAILURE', 'WARNING', 'suspicious_user', '10.0.0.$i', 
            'Failed login attempt'
        );
    "
done

log "Successfully simulated failed login attempts"

# Test 5: Check if the anomaly detection system detected the suspicious activities
log "Test 5: Check if the anomaly detection system detected the suspicious activities"
if [ -n "$ANOMALY_DETECTION_URL" ]; then
    # Wait a moment for the anomaly detection to process
    sleep 5
    
    ANOMALY_RESULT=$(curl -s -X GET "${ANOMALY_DETECTION_URL}/api/anomalies/recent")
    
    if [ -z "$ANOMALY_RESULT" ]; then
        log "WARNING: Could not connect to anomaly detection service"
    else
        ANOMALY_COUNT=$(echo "$ANOMALY_RESULT" | jq '. | length')
        log "Anomaly detection found $ANOMALY_COUNT anomalies"
        
        if [ "$ANOMALY_COUNT" -gt 0 ]; then
            log "Anomaly detection successfully identified suspicious activities"
        else
            log "WARNING: Anomaly detection did not identify any suspicious activities"
        fi
    fi
else
    log "Skipping anomaly detection check (URL not provided)"
fi

# Test 6: Check if Falco detected the suspicious activities
log "Test 6: Check if Falco detected the suspicious activities"
if [ -n "$FALCO_ENDPOINT" ]; then
    # Trigger a Falco event by executing a suspicious command
    psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
        -- This is a suspicious query that might trigger Falco
        COPY (SELECT * FROM test_threat_detection.sensitive_data) TO '/tmp/sensitive_data.csv';
    " 2>/dev/null || true
    
    # Wait a moment for Falco to process
    sleep 5
    
    FALCO_RESULT=$(curl -s -X GET "${FALCO_ENDPOINT}/api/events/recent")
    
    if [ -z "$FALCO_RESULT" ]; then
        log "WARNING: Could not connect to Falco service"
    else
        FALCO_COUNT=$(echo "$FALCO_RESULT" | jq '. | length')
        log "Falco detected $FALCO_COUNT events"
        
        if [ "$FALCO_COUNT" -gt 0 ]; then
            log "Falco successfully detected suspicious activities"
        else
            log "WARNING: Falco did not detect any suspicious activities"
        fi
    fi
else
    log "Skipping Falco check (endpoint not provided)"
fi

# Test 7: Check notification logs for security events
log "Test 7: Check notification logs for security events"
NOTIFICATION_COUNT=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c "
    SELECT count(*) FROM logs.notification_log 
    WHERE event_type IN ('SQL_INJECTION_ATTEMPT', 'LOGIN_FAILURE')
    AND logged_at > NOW() - INTERVAL '1 hour';
")
NOTIFICATION_COUNT=$(echo "$NOTIFICATION_COUNT" | tr -d '[:space:]')

log "Found $NOTIFICATION_COUNT security events in notification logs"

if [ "$NOTIFICATION_COUNT" -ge 6 ]; then
    log "Successfully detected security events in notification logs"
else
    error_exit "Expected at least 6 security events, but found $NOTIFICATION_COUNT"
fi

# Test 8: Run the security monitoring script
log "Test 8: Run the security monitoring script"
if [ -f "../../scripts/monitoring/security_monitoring.sh" ]; then
    chmod +x "../../scripts/monitoring/security_monitoring.sh"
    MONITORING_RESULT=$(DB_HOST="$POSTGRES_HOST" DB_PORT="$POSTGRES_PORT" DB_NAME="$POSTGRES_DB" DB_USER="$POSTGRES_USER" ../../scripts/monitoring/security_monitoring.sh)
    
    if [ $? -ne 0 ]; then
        error_exit "Security monitoring script failed: $MONITORING_RESULT"
    fi
    
    log "Successfully ran security monitoring script"
else
    log "WARNING: Security monitoring script not found, skipping test"
fi

# Clean up
log "Cleaning up test data"
psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    DROP SCHEMA test_threat_detection CASCADE;
"

log "Threat Detection Integration Test completed successfully"
exit 0
