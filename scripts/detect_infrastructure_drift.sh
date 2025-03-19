#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Running Infrastructure Drift Detection${NC}"

# Variables
TERRAFORM_DIR="terraform"
TF_PLAN_FILE="drift_detection.tfplan"
DRIFT_REPORT="drift_report.txt"

# Check if terraform is installed
if ! command -v terraform &> /dev/null; then
    echo -e "${RED}Error: terraform is not installed${NC}"
    exit 1
fi

# Function to check Kubernetes configuration drift
check_k8s_drift() {
    echo -e "\n${YELLOW}Checking Kubernetes configuration drift...${NC}"
    
    # Use kubectl to detect drift in manifests
    for resource_type in namespace configmap service statefulset networkpolicy; do
        echo -e "${YELLOW}Checking $resource_type resources...${NC}"
        kubectl get $resource_type -n postgres-security -o json > current_state.json
        
        # Here we would compare with the desired state from our manifests
        # For this example, we're just checking if resources exist
        if [ "$resource_type" == "namespace" ]; then
            if grep -q "postgres-security" current_state.json; then
                echo -e "${GREEN}✓ Namespace postgres-security exists as expected${NC}"
            else
                echo -e "${RED}✗ Namespace postgres-security does not exist${NC}"
                echo "Namespace drift detected: postgres-security not found" >> $DRIFT_REPORT
            fi
        elif [ "$resource_type" == "statefulset" ]; then
            if grep -q "postgres-security" current_state.json; then
                echo -e "${GREEN}✓ StatefulSet postgres-security exists as expected${NC}"
                
                # Check replicas to detect potential drift
                CURRENT_REPLICAS=$(kubectl get statefulset postgres-security -n postgres-security -o jsonpath='{.spec.replicas}')
                if [ "$CURRENT_REPLICAS" == "1" ]; then
                    echo -e "${GREEN}✓ StatefulSet replicas match expected (1)${NC}"
                else
                    echo -e "${RED}✗ StatefulSet replicas mismatch. Expected: 1, Got: $CURRENT_REPLICAS${NC}"
                    echo "StatefulSet drift detected: replica count mismatch" >> $DRIFT_REPORT
                fi
            else
                echo -e "${RED}✗ StatefulSet postgres-security does not exist${NC}"
                echo "StatefulSet drift detected: postgres-security not found" >> $DRIFT_REPORT
            fi
        fi
    done
    
    rm -f current_state.json
}

# Function to check Terraform infrastructure drift
check_terraform_drift() {
    echo -e "\n${YELLOW}Checking Terraform infrastructure drift...${NC}"
    
    # Navigate to Terraform directory
    cd $TERRAFORM_DIR
    
    # Initialize Terraform
    echo -e "${YELLOW}Initializing Terraform...${NC}"
    terraform init -no-color
    
    # Check for drift
    echo -e "${YELLOW}Running Terraform plan to detect drift...${NC}"
    terraform plan -detailed-exitcode -out=$TF_PLAN_FILE -no-color > /dev/null 2>&1
    EXITCODE=$?
    
    # Check the exit code
    # 0 = Succeeded with empty diff (no changes)
    # 1 = Error
    # 2 = Succeeded with non-empty diff (changes present)
    if [ $EXITCODE -eq 0 ]; then
        echo -e "${GREEN}No infrastructure drift detected${NC}"
    elif [ $EXITCODE -eq 1 ]; then
        echo -e "${RED}Error running Terraform plan${NC}"
        echo "Error running Terraform plan to detect drift" >> ../$DRIFT_REPORT
    elif [ $EXITCODE -eq 2 ]; then
        echo -e "${RED}Infrastructure drift detected!${NC}"
        echo "Terraform infrastructure drift detected" >> ../$DRIFT_REPORT
        
        # Show the drift details
        terraform show -no-color $TF_PLAN_FILE > drift_details.txt
        echo -e "${YELLOW}Drift details saved to drift_details.txt${NC}"
        echo -e "${YELLOW}Summary of changes:${NC}"
        grep -A 3 -E '(^[[:space:]]*~|^[[:space:]]*-|^[[:space:]]*\+)' drift_details.txt
        
        # Append drift details to report
        echo -e "\nDrift Details:" >> ../$DRIFT_REPORT
        grep -A 3 -E '(^[[:space:]]*~|^[[:space:]]*-|^[[:space:]]*\+)' drift_details.txt >> ../$DRIFT_REPORT
    fi
    
    # Clean up
    rm -f $TF_PLAN_FILE drift_details.txt
    cd ..
}

# Create a new drift report
echo "Infrastructure Drift Report - $(date)" > $DRIFT_REPORT
echo "=========================================" >> $DRIFT_REPORT

# Run Terraform drift detection
check_terraform_drift

# Run Kubernetes drift detection
check_k8s_drift

# Check if any drift was detected
if [ $(grep -c "drift detected" $DRIFT_REPORT) -gt 0 ]; then
    echo -e "\n${RED}Infrastructure drift detected!${NC}"
    echo -e "${YELLOW}See $DRIFT_REPORT for details${NC}"
    exit 1
else
    echo -e "\n${GREEN}No infrastructure drift detected.${NC}"
    echo "No drift detected" >> $DRIFT_REPORT
    exit 0
fi 