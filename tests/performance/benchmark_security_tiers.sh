#!/bin/bash
# Performance benchmark to compare security tiers

# Set database connection parameters
DB_USER=${POSTGRES_USER:-admin}
DB_PASS=${POSTGRES_PASSWORD:-securepassword}
DB_HOST=${POSTGRES_HOST:-localhost}
DB_PORT=${POSTGRES_PORT:-5432}
DB_NAME=${POSTGRES_DB:-db_dev}
PGPASSWORD=$DB_PASS

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Ensure pgbench is installed
if ! command -v pgbench &> /dev/null; then
    echo -e "${RED}pgbench is not installed. Please install PostgreSQL client tools.${NC}"
    exit 1
fi

# Create results directory
RESULTS_DIR="performance_results"
mkdir -p $RESULTS_DIR

# Timestamp for this run
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SUMMARY_FILE="$RESULTS_DIR/security_benchmark_summary_$TIMESTAMP.md"

# Create summary file header
cat > $SUMMARY_FILE << EOF
# PostgreSQL Security Tiers Performance Benchmark
Date: $(date)

This benchmark measures the performance impact of different security tiers.

## Test Environment
- PostgreSQL Version: $(psql -h $DB_HOST -p $DB_PORT -U $DB_USER -t -c "SELECT version();" | tr -d '\n')
- Host: $DB_HOST
- Database: $DB_NAME

## Benchmark Configuration
- Clients: 10
- Transactions per client: 1000
- Scale factor: 10 (pgbench default tables with this scale)

## Results Summary

EOF

echo -e "${BLUE}Starting PostgreSQL Security Tiers Performance Benchmark${NC}"
echo -e "${BLUE}===================================================${NC}"

# Function to run benchmark with specific configuration
run_benchmark() {
    local tier=$1
    local config_file=$2
    local result_file="$RESULTS_DIR/${tier}_results_$TIMESTAMP.txt"
    
    echo -e "${YELLOW}Running benchmark for $tier tier...${NC}"
    
    # Reset database
    echo "Recreating pgbench tables..."
    pgbench -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -i -s 10 --quiet
    
    # Apply security configuration
    if [ -n "$config_file" ] && [ -f "$config_file" ]; then
        echo "Applying $tier security configuration..."
        psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f $config_file
    fi
    
    # Run the benchmark
    echo "Running pgbench..."
    pgbench -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c 10 -t 1000 -P 10 > $result_file
    
    # Extract TPS (transactions per second)
    TPS=$(grep "tps" $result_file | tail -n1 | awk '{print $3}' | sed 's/tps=//')
    LATENCY=$(grep "latency" $result_file | awk '{print $4}')
    
    # Output results
    echo -e "${GREEN}$tier tier results: $TPS tps, $LATENCY ms average latency${NC}"
    
    # Add to summary
    cat >> $SUMMARY_FILE << EOF
### $tier Tier
- Transactions per second: $TPS
- Average latency: $LATENCY ms
- [Detailed Results](./${tier}_results_$TIMESTAMP.txt)

EOF

    # Return TPS for comparison
    echo $TPS
}

# Baseline without security
echo -e "${BLUE}Running baseline (no security)...${NC}"
BASELINE_TPS=$(run_benchmark "Baseline" "")

# Basic security tier
BASIC_TPS=$(run_benchmark "Basic" "../security_tiers/basic/setup.sql")

# Standard security tier
STANDARD_TPS=$(run_benchmark "Standard" "../security_tiers/standard/setup.sql")

# Advanced security tier
ADVANCED_TPS=$(run_benchmark "Advanced" "../security_tiers/advanced/setup.sql")

# Calculate performance impact
BASIC_IMPACT=$(awk "BEGIN {printf \"%.2f\", (($BASELINE_TPS - $BASIC_TPS) / $BASELINE_TPS * 100)}")
STANDARD_IMPACT=$(awk "BEGIN {printf \"%.2f\", (($BASELINE_TPS - $STANDARD_TPS) / $BASELINE_TPS * 100)}")
ADVANCED_IMPACT=$(awk "BEGIN {printf \"%.2f\", (($BASELINE_TPS - $ADVANCED_TPS) / $BASELINE_TPS * 100)}")

# Add impact summary
cat >> $SUMMARY_FILE << EOF
## Performance Impact

| Security Tier | TPS | Impact (% decrease) |
|---------------|-----|---------------------|
| Baseline | $BASELINE_TPS | 0% |
| Basic | $BASIC_TPS | $BASIC_IMPACT% |
| Standard | $STANDARD_TPS | $STANDARD_IMPACT% |
| Advanced | $ADVANCED_TPS | $ADVANCED_IMPACT% |

## Recommendations

Based on the performance metrics:

- **Basic Tier**: Suitable for all production environments with minimal performance impact
- **Standard Tier**: Recommended for applications with sensitive data where security is important
- **Advanced Tier**: For high-security environments where security requirements outweigh performance considerations

## Charts

For visual representation, import the detailed results into a visualization tool.
EOF

echo -e "${BLUE}Benchmark complete!${NC}"
echo -e "${GREEN}Results saved to $SUMMARY_FILE${NC}"
echo ""
echo -e "${YELLOW}Performance Impact Summary:${NC}"
echo -e "Basic tier impact: ${RED}$BASIC_IMPACT%${NC} decrease in throughput"
echo -e "Standard tier impact: ${RED}$STANDARD_IMPACT%${NC} decrease in throughput"
echo -e "Advanced tier impact: ${RED}$ADVANCED_IMPACT%${NC} decrease in throughput" 