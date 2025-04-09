#!/bin/bash
set -e

# Script to run security monitoring queries and send results to monitoring systems
# This script integrates the standalone query scripts into a cohesive monitoring solution

# Configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-db_dev}"
DB_USER="${DB_USER:-postgres}"
PROMETHEUS_PUSHGATEWAY="${PROMETHEUS_PUSHGATEWAY:-http://localhost:9091}"
LOG_DIR="${LOG_DIR:-/var/log/postgres-security}"
ALERT_THRESHOLD="${ALERT_THRESHOLD:-5}"

# Ensure log directory exists
mkdir -p "${LOG_DIR}"

# Log function
log() {
    echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $1" | tee -a "${LOG_DIR}/security_monitoring.log"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check required tools
command -v psql >/dev/null 2>&1 || error_exit "psql is required but not installed"
command -v curl >/dev/null 2>&1 || error_exit "curl is required but not installed"
command -v jq >/dev/null 2>&1 || error_exit "jq is required but not installed"

log "Starting security monitoring..."

# Run log management queries
log "Running log management queries..."
LOG_QUERY_RESULT=$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -f ../queries/log_management_queries.sql 2>&1)
if [ $? -ne 0 ]; then
    error_exit "Failed to run log management queries: ${LOG_QUERY_RESULT}"
fi
log "Log management queries completed successfully"

# Run notification log queries
log "Running notification log queries..."
NOTIFICATION_QUERY_RESULT=$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -f ../queries/view_notification_logs.sql 2>&1)
if [ $? -ne 0 ]; then
    error_exit "Failed to run notification log queries: ${NOTIFICATION_QUERY_RESULT}"
fi
log "Notification log queries completed successfully"

# Check for security events
log "Checking for security events..."
SECURITY_EVENTS=$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -c "
    SELECT count(*) 
    FROM logs.notification_log 
    WHERE event_type IN ('PERMISSION_DENIED', 'LOGIN_FAILURE', 'SQL_INJECTION_ATTEMPT') 
    AND logged_at > NOW() - INTERVAL '1 hour'
")
SECURITY_EVENTS=$(echo "${SECURITY_EVENTS}" | tr -d '[:space:]')

log "Found ${SECURITY_EVENTS} security events in the last hour"

# Export metrics to Prometheus
if [ -n "${PROMETHEUS_PUSHGATEWAY}" ]; then
    log "Exporting metrics to Prometheus..."
    
    # Create metrics payload
    cat <<EOF > /tmp/security_metrics.txt
# HELP postgres_security_events Number of security events in the last hour
# TYPE postgres_security_events gauge
postgres_security_events ${SECURITY_EVENTS}
EOF

    # Push metrics to Prometheus
    curl -s --data-binary @/tmp/security_metrics.txt "${PROMETHEUS_PUSHGATEWAY}/metrics/job/postgres_security/instance/${DB_HOST}" || log "WARNING: Failed to push metrics to Prometheus"
    
    # Clean up
    rm -f /tmp/security_metrics.txt
    
    log "Metrics exported successfully"
fi

# Check if we need to trigger alerts
if [ "${SECURITY_EVENTS}" -ge "${ALERT_THRESHOLD}" ]; then
    log "ALERT: Security event threshold exceeded (${SECURITY_EVENTS} >= ${ALERT_THRESHOLD})"
    
    # Get details of security events
    SECURITY_EVENT_DETAILS=$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -c "
        SELECT json_agg(row_to_json(t)) 
        FROM (
            SELECT event_type, severity, username, source_ip, message, logged_at
            FROM logs.notification_log 
            WHERE event_type IN ('PERMISSION_DENIED', 'LOGIN_FAILURE', 'SQL_INJECTION_ATTEMPT') 
            AND logged_at > NOW() - INTERVAL '1 hour'
            ORDER BY logged_at DESC
        ) t
    ")
    
    # Write details to log
    echo "${SECURITY_EVENT_DETAILS}" | jq . > "${LOG_DIR}/security_events_$(date +%Y%m%d_%H%M%S).json"
    
    # Here you would integrate with your alerting system (Slack, Email, PagerDuty, etc.)
    # For example:
    # curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"Security alert: ${SECURITY_EVENTS} security events detected in the last hour\"}" "${SLACK_WEBHOOK_URL}"
fi

log "Security monitoring completed successfully"
exit 0
