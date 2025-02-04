#!/usr/bin/env bash

# PostgreSQL pgTAP Test Runner with HTML Reports & Slack Notifications

set -e  # Exit immediately if a command exits with a non-zero status
set -o pipefail  # Ensures pipeline errors are not masked

# Load environment variables from .env if available
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Default database credentials
DB_NAME=${DB_NAME:-db_dev}
DB_USER=${DB_USER:-myuser}
DB_HOST=${DB_HOST:-localhost}
TEST_DIR="test/pgTAP"
PARALLEL_MODE=false
REPORT_FILE="pgTAP_test_report.html"
SLACK_WEBHOOK_URL="your-slack-webhook-url"
FAILED_TESTS=()

# Parse script arguments
if [[ "$1" == "--parallel" ]]; then
    PARALLEL_MODE=true
elif [[ "$1" == "--sequential" ]]; then
    PARALLEL_MODE=false
fi

# Ensure pg_prove is installed
if ! command -v pg_prove &> /dev/null; then
    echo "pg_prove is not installed. Please install it before running tests."
    exit 1
fi

# Start the test execution timer
start_time=$(date +%s)

echo "Running pgTAP tests against database: $DB_NAME ($DB_HOST)"
echo "-----------------------------------------------------------"

# Run tests and save results in HTML format
if [ "$PARALLEL_MODE" = true ]; then
    echo "Running tests in PARALLEL mode..."
    pg_prove -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" --ext .sql --html --output "$REPORT_FILE" "$TEST_DIR"/*.sql || FAILED_TESTS+=("pgTAP Failed")
else
    echo "Running tests in SEQUENTIAL mode..."
    for FILE in "$TEST_DIR"/*.sql; do
        echo "Running: $FILE..."
        if ! pg_prove -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" "$FILE"; then
            FAILED_TESTS+=("$FILE")
        fi
    done
fi

# Calculate execution time
end_time=$(date +%s)
execution_time=$((end_time - start_time))

echo "-----------------------------------------------------------"
echo "All tests completed in ${execution_time}s"
echo "Test report saved to: $REPORT_FILE"

# Send results to Slack
send_slack_notification() {
    curl -X POST -H 'Content-type: application/json' --data "{
        \"text\": \"PostgreSQL Test Summary:\n\nExecution Time: ${execution_time}s\n\nTest Report: $REPORT_FILE\",
        \"attachments\": [
            {\"text\": \"Test Status: $(if [ ${#FAILED_TESTS[@]} -ne 0 ]; then echo '❌ Some tests failed'; else echo '✅ All tests passed!'; fi)\"}
        ]
    }" $SLACK_WEBHOOK_URL
}

send_slack_notification

# Handle failed tests
if [ ${#FAILED_TESTS[@]} -ne 0 ]; then
    echo "${#FAILED_TESTS[@]} tests failed:"
    for test in "${FAILED_TESTS[@]}"; do
        echo "   - $test"
    done
    exit 1  # Fail the script if any test failed
fi

echo "All tests passed successfully!"
exit 0
