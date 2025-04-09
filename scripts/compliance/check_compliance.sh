#!/bin/bash
set -e

# Script to check compliance with various security standards
# Usage: ./check_compliance.sh --standard=pci-dss|hipaa|gdpr|soc2

# Parse arguments
STANDARD=""
for arg in "$@"; do
  case $arg in
    --standard=*)
      STANDARD="${arg#*=}"
      shift
      ;;
    *)
      echo "Unknown argument: $arg"
      exit 1
      ;;
  esac
done

if [ -z "$STANDARD" ]; then
  echo "Error: Standard not specified. Use --standard=pci-dss|hipaa|gdpr|soc2"
  exit 1
fi

# Set colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to check if a file exists
check_file_exists() {
  if [ -f "$1" ]; then
    echo -e "${GREEN}✓${NC} File exists: $1"
    return 0
  else
    echo -e "${RED}✗${NC} File missing: $1"
    return 1
  fi
}

# Function to check if a pattern exists in a file
check_pattern_in_file() {
  if grep -q "$2" "$1"; then
    echo -e "${GREEN}✓${NC} Pattern found in $1: $2"
    return 0
  else
    echo -e "${RED}✗${NC} Pattern not found in $1: $2"
    return 1
  fi
}

# Function to check if a Kubernetes resource exists
check_k8s_resource() {
  resource_type=$1
  resource_name=$2
  file_pattern=$3
  
  if find kubernetes -name "$file_pattern" | grep -q .; then
    echo -e "${GREEN}✓${NC} Kubernetes $resource_type '$resource_name' found"
    return 0
  else
    echo -e "${RED}✗${NC} Kubernetes $resource_type '$resource_name' not found"
    return 1
  fi
}

# Common checks for all standards
common_checks() {
  echo "Running common compliance checks..."
  
  # Check for encryption configuration
  check_pattern_in_file "config/postgres.conf" "ssl = on"
  check_pattern_in_file "config/postgres.conf" "password_encryption = 'scram-sha-256'"
  
  # Check for audit logging
  check_pattern_in_file "config/postgres.conf" "logging_collector = on"
  check_pattern_in_file "config/postgres.conf" "log_connections = on"
  
  # Check for network security
  check_pattern_in_file "config/pg_hba.conf" "scram-sha-256"
  check_pattern_in_file "kubernetes/network-policy.yaml" "NetworkPolicy"
  
  # Check for backup configuration
  check_file_exists "config/pgbackrest.conf.j2"
  check_pattern_in_file "config/pgbackrest.conf.j2" "cipher-type"
  
  # Check for security scanning in CI/CD
  check_file_exists ".github/workflows/security_scanning.yml"
  
  # Check for Pod Security Standards
  check_file_exists "kubernetes/pod-security-standards.yaml"
  
  # Check for secure Docker configuration
  check_file_exists "docker/Dockerfile"
  check_pattern_in_file "docker/Dockerfile" "HEALTHCHECK"
}

# PCI-DSS specific checks
pci_dss_checks() {
  echo "Running PCI-DSS compliance checks..."
  
  # Requirement 2: Do not use vendor-supplied defaults
  check_pattern_in_file "config/pg_hba.conf" "reject"
  
  # Requirement 3: Protect stored cardholder data
  check_pattern_in_file "scripts/security/column_encryption.sql" "pgcrypto"
  
  # Requirement 6: Develop and maintain secure systems
  check_file_exists ".github/workflows/secure-cicd.yml"
  
  # Requirement 7: Restrict access to cardholder data
  check_pattern_in_file "scripts/security/row_level_security.sql" "CREATE POLICY"
  
  # Requirement 8: Identify and authenticate access
  check_pattern_in_file "config/pg_hba.conf" "scram-sha-256"
  
  # Requirement 10: Track and monitor access
  check_pattern_in_file "config/postgres.conf" "pgaudit"
  
  # Requirement 11: Regularly test security systems
  check_file_exists "test/pgTAP/04-security_test.sql"
}

# HIPAA specific checks
hipaa_checks() {
  echo "Running HIPAA compliance checks..."
  
  # Access Controls
  check_pattern_in_file "scripts/security/role_based_access.sql" "CREATE ROLE"
  
  # Audit Controls
  check_pattern_in_file "config/postgres.conf" "pgaudit"
  
  # Integrity Controls
  check_pattern_in_file "config/postgres.conf" "data-checksums"
  
  # Transmission Security
  check_pattern_in_file "config/postgres.conf" "ssl = on"
  
  # Backup and Recovery
  check_file_exists "scripts/backup/encrypt-backup.sh"
  
  # Risk Analysis
  check_file_exists "docs/threat_model.md"
}

# GDPR specific checks
gdpr_checks() {
  echo "Running GDPR compliance checks..."
  
  # Data Protection by Design
  check_file_exists "security_tiers/advanced/setup.sql"
  
  # Right to Erasure
  check_file_exists "scripts/compliance/gdpr_data_erasure.sql"
  
  # Data Minimization
  check_file_exists "scripts/compliance/gdpr_data_minimization.sql"
  
  # Consent Management
  check_file_exists "scripts/compliance/gdpr_consent_tracking.sql"
  
  # Data Breach Notification
  check_file_exists "scripts/compliance/gdpr_breach_notification.sql"
  
  # Cross-border Data Transfers
  check_file_exists "docs/gdpr_data_transfers.md"
}

# SOC2 specific checks
soc2_checks() {
  echo "Running SOC2 compliance checks..."
  
  # Security
  check_file_exists "security_tiers/README.md"
  
  # Availability
  check_k8s_resource "StatefulSet" "postgres" "*statefulset.yaml"
  
  # Processing Integrity
  check_pattern_in_file "config/postgres.conf" "data-checksums"
  
  # Confidentiality
  check_pattern_in_file "config/postgres.conf" "ssl = on"
  
  # Privacy
  check_file_exists "scripts/compliance/data_classification.sql"
}

# Run checks based on the specified standard
echo "Checking compliance with $STANDARD standard..."
common_checks

case $STANDARD in
  pci-dss)
    pci_dss_checks
    ;;
  hipaa)
    hipaa_checks
    ;;
  gdpr)
    gdpr_checks
    ;;
  soc2)
    soc2_checks
    ;;
  *)
    echo "Error: Unknown standard: $STANDARD"
    exit 1
    ;;
esac

echo "Compliance check for $STANDARD completed."
exit 0
