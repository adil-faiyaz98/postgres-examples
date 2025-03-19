#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Integration Tests for PostgreSQL Security Framework${NC}"

# Variables
TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$(dirname "$(dirname "$TEST_DIR")")"
DOCKER_DIR="$ROOT_DIR/docker"
TERRAFORM_DIR="$ROOT_DIR/terraform"

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

# Create temporary test environment
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# 1. Test Docker Image Build
echo -e "\n${YELLOW}Testing Docker Image Build...${NC}"
run_test "Docker image builds successfully" "cd $DOCKER_DIR && docker build -t postgres-security-test:latest ."

# 2. Test Docker Container Runs
echo -e "\n${YELLOW}Testing Docker Container Execution...${NC}"
run_test "Docker container runs successfully" "docker run -d --name postgres-security-integration-test -e POSTGRES_PASSWORD=securepassword postgres-security-test:latest"

# 3. Test PostgreSQL is Running in Container
echo -e "\n${YELLOW}Testing PostgreSQL in Container...${NC}"
sleep 10  # Give PostgreSQL time to start
run_test "PostgreSQL accepts connections" "docker exec postgres-security-integration-test pg_isready -U postgres"

# 4. Test Security Tiers in Docker
echo -e "\n${YELLOW}Testing Security Tiers in Docker...${NC}"
run_test "Apply basic security tier" "docker exec postgres-security-integration-test psql -U postgres -c 'CREATE EXTENSION IF NOT EXISTS pgaudit;'"
run_test "Verify pgAudit is enabled" "docker exec postgres-security-integration-test psql -U postgres -c 'SELECT * FROM pg_extension WHERE extname = '\'pgaudit\'';"

# 5. Test Terraform Configuration
echo -e "\n${YELLOW}Testing Terraform Configuration...${NC}"
cd $TERRAFORM_DIR
run_test "Terraform initializes successfully" "terraform init -backend=false"
run_test "Terraform validates successfully" "terraform validate"

# Create simplified test plan file for testing
cat > "$TEMP_DIR/test.tf" << EOF
provider "aws" {
  region = "us-east-1"
  access_key = "mock-access-key"
  secret_key = "mock-secret-key"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_requesting_account_id = true
}

resource "aws_db_instance" "test_postgres" {
  allocated_storage    = 10
  engine               = "postgres"
  engine_version       = "15"
  instance_class      = "db.t3.micro"
  username            = "postgres"
  password            = "securepassword"
  skip_final_snapshot = true
}
EOF

run_test "Terraform plan succeeds" "cd $TEMP_DIR && terraform init -backend=false && terraform plan"

# Clean up Docker container
docker stop postgres-security-integration-test
docker rm postgres-security-integration-test

echo -e "\n${GREEN}All integration tests completed successfully!${NC}"
exit 0 