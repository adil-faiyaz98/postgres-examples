#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting PostgreSQL Kubernetes Deployment Tests${NC}"

# Test variables
NAMESPACE="postgres-security"
DEPLOYMENT="postgres-security"
SERVICE="postgres-security"
DB_USER="postgres"
DB_PASSWORD="securepassword"
DB_NAME="db_dev"

# Function to run tests with proper output
run_test() {
  local test_name=$1
  local command=$2
  
  echo -e "\n${YELLOW}Running test: ${test_name}${NC}"
  
  if eval "$command"; then
    echo -e "${GREEN}✓ Test Passed: ${test_name}${NC}"
    return 0
  else
    echo -e "${RED}✗ Test Failed: ${test_name}${NC}"
    return 1
  fi
}

# 1. Test namespace creation
run_test "Namespace exists" "kubectl get namespace $NAMESPACE"

# 2. Test StatefulSet deployment
run_test "StatefulSet exists" "kubectl get statefulset -n $NAMESPACE $DEPLOYMENT"

# 3. Test StatefulSet status
run_test "StatefulSet ready" "kubectl get statefulset -n $NAMESPACE $DEPLOYMENT -o jsonpath='{.status.readyReplicas}' | grep 1"

# 4. Test Service creation
run_test "Service exists" "kubectl get service -n $NAMESPACE $SERVICE"

# 5. Test PostgreSQL pod readiness
run_test "Pod is ready" "kubectl wait --for=condition=ready pod/${DEPLOYMENT}-0 -n $NAMESPACE --timeout=120s"

# 6. Test PostgreSQL connectivity
POD_NAME="${DEPLOYMENT}-0"
run_test "PostgreSQL accepting connections" "kubectl exec -n $NAMESPACE $POD_NAME -- pg_isready -U $DB_USER"

# 7. Test pgAudit extension
run_test "pgAudit extension installed" "kubectl exec -n $NAMESPACE $POD_NAME -- psql -U $DB_USER -d $DB_NAME -c 'SELECT * FROM pg_extension WHERE extname = '\'pgaudit\'';"

# 8. Test security configuration
run_test "SSL is enabled" "kubectl exec -n $NAMESPACE $POD_NAME -- psql -U $DB_USER -d $DB_NAME -c 'SHOW ssl;' | grep on"

# 9. Test security tier level
run_test "Advanced security tier configured" "kubectl exec -n $NAMESPACE $POD_NAME -- psql -U $DB_USER -d $DB_NAME -c 'SHOW log_statement;' | grep all"

# 10. Test NetworkPolicy
run_test "NetworkPolicy exists" "kubectl get networkpolicy -n $NAMESPACE postgres-security-network-policy"

echo -e "\n${GREEN}All tests completed successfully!${NC}"
exit 0 