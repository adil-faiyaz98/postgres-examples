#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

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

# Create test results directory
RESULTS_DIR="test_results"
mkdir -p $RESULTS_DIR

echo -e "${YELLOW}Starting Comprehensive Test Suite${NC}"

# 1. Unit Tests (pgTAP)
echo -e "\n${YELLOW}Running Unit Tests${NC}"
run_test "pgTAP Tests" "./test/pgTAP/run-all-tests.sh --parallel > $RESULTS_DIR/unit_tests.log 2>&1"

# 2. Integration Tests
echo -e "\n${YELLOW}Running Integration Tests${NC}"
run_test "Integration Tests" "./test/integration/integration_test.sh > $RESULTS_DIR/integration_tests.log 2>&1"

# 3. Kubernetes Deployment Tests
echo -e "\n${YELLOW}Running Kubernetes Tests${NC}"
run_test "Kubernetes Deployment Tests" "./test/kubernetes/postgres-deployment-test.sh > $RESULTS_DIR/k8s_tests.log 2>&1"

# 4. Infrastructure Tests (Terratest)
echo -e "\n${YELLOW}Running Infrastructure Tests${NC}"
run_test "Terratest" "cd test/terratest && go test -v ./... > ../../$RESULTS_DIR/terratest.log 2>&1"

# 5. Performance Tests
echo -e "\n${YELLOW}Running Performance Tests${NC}"
run_test "Performance Tests" "./test/performance/benchmark_security_tiers.sh > $RESULTS_DIR/performance_tests.log 2>&1"

# 6. Security Tests
echo -e "\n${YELLOW}Running Security Tests${NC}"
run_test "Basic Security Tier Tests" "./test/security/test_basic_tier.sh > $RESULTS_DIR/security_basic.log 2>&1"
run_test "Standard Security Tier Tests" "./test/security/test_standard_tier.sh > $RESULTS_DIR/security_standard.log 2>&1"
run_test "Advanced Security Tier Tests" "./test/security/test_advanced_tier.sh > $RESULTS_DIR/security_advanced.log 2>&1"

# 7. Monitoring Tests
echo -e "\n${YELLOW}Running Monitoring Stack Tests${NC}"
run_test "Prometheus Tests" "./test/monitoring/test_prometheus.sh > $RESULTS_DIR/prometheus_tests.log 2>&1"
run_test "Grafana Tests" "./test/monitoring/test_grafana.sh > $RESULTS_DIR/grafana_tests.log 2>&1"
run_test "Metrics Tests" "./test/monitoring/test_metrics.sh > $RESULTS_DIR/metrics_tests.log 2>&1"

# Generate Test Report
echo -e "\n${YELLOW}Generating Test Report${NC}"
cat << EOF > $RESULTS_DIR/test_report.md
# Test Execution Report
Date: $(date)

## Test Results Summary
- Unit Tests: $(grep -q "Test Passed" $RESULTS_DIR/unit_tests.log && echo "✓ Passed" || echo "✗ Failed")
- Integration Tests: $(grep -q "Test Passed" $RESULTS_DIR/integration_tests.log && echo "✓ Passed" || echo "✗ Failed")
- Kubernetes Tests: $(grep -q "Test Passed" $RESULTS_DIR/k8s_tests.log && echo "✓ Passed" || echo "✗ Failed")
- Infrastructure Tests: $(grep -q "PASS" $RESULTS_DIR/terratest.log && echo "✓ Passed" || echo "✗ Failed")
- Performance Tests: $(grep -q "Test Passed" $RESULTS_DIR/performance_tests.log && echo "✓ Passed" || echo "✗ Failed")
- Security Tests:
  - Basic Tier: $(grep -q "Test Passed" $RESULTS_DIR/security_basic.log && echo "✓ Passed" || echo "✗ Failed")
  - Standard Tier: $(grep -q "Test Passed" $RESULTS_DIR/security_standard.log && echo "✓ Passed" || echo "✗ Failed")
  - Advanced Tier: $(grep -q "Test Passed" $RESULTS_DIR/security_advanced.log && echo "✓ Passed" || echo "✗ Failed")
- Monitoring Tests:
  - Prometheus: $(grep -q "Test Passed" $RESULTS_DIR/prometheus_tests.log && echo "✓ Passed" || echo "✗ Failed")
  - Grafana: $(grep -q "Test Passed" $RESULTS_DIR/grafana_tests.log && echo "✓ Passed" || echo "✗ Failed")
  - Metrics: $(grep -q "Test Passed" $RESULTS_DIR/metrics_tests.log && echo "✓ Passed" || echo "✗ Failed")

## Detailed Test Logs
See individual log files in the $RESULTS_DIR directory for detailed test output.
EOF

echo -e "${GREEN}Test execution complete! Check $RESULTS_DIR/test_report.md for results.${NC}"
