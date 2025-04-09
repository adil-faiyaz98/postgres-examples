#!/bin/bash
set -e

# Script to generate a comprehensive compliance report
# This script runs all compliance checks and generates a PDF report

# Create output directory
REPORT_DIR="compliance-reports"
mkdir -p "$REPORT_DIR"

# Set report filename with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/compliance_report_$TIMESTAMP.md"
PDF_REPORT="compliance-report.pdf"

# Function to run a compliance check and capture output
run_compliance_check() {
  standard=$1
  echo "Running compliance check for $standard..."
  output=$(./scripts/compliance/check_compliance.sh --standard="$standard")
  
  # Count passes and failures
  passes=$(echo "$output" | grep -c "✓" || true)
  failures=$(echo "$output" | grep -c "✗" || true)
  total=$((passes + failures))
  percentage=$((passes * 100 / total))
  
  # Add to report
  echo "## $standard Compliance" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "Compliance Score: $percentage% ($passes/$total)" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "### Detailed Results" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo "$output" >> "$REPORT_FILE"
  echo '```' >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  
  # Return the percentage for overall calculation
  echo "$percentage"
}

# Create report header
cat > "$REPORT_FILE" << EOF
# PostgreSQL Security Framework Compliance Report

**Generated:** $(date)

**Repository:** postgres-examples

This report provides a comprehensive assessment of the repository's compliance with various security standards and frameworks.

## Executive Summary

EOF

# Run all compliance checks
pci_score=$(run_compliance_check "pci-dss")
hipaa_score=$(run_compliance_check "hipaa")
gdpr_score=$(run_compliance_check "gdpr")
soc2_score=$(run_compliance_check "soc2")

# Calculate overall compliance score
overall_score=$(( (pci_score + hipaa_score + gdpr_score + soc2_score) / 4 ))

# Add executive summary
cat >> "$REPORT_FILE" << EOF
The PostgreSQL Security Framework demonstrates an overall compliance score of **$overall_score%** across all evaluated standards.

| Standard | Compliance Score |
|----------|-----------------|
| PCI-DSS  | $pci_score% |
| HIPAA    | $hipaa_score% |
| GDPR     | $gdpr_score% |
| SOC2     | $soc2_score% |

## Recommendations

EOF

# Add recommendations based on compliance scores
if [ "$pci_score" -lt 100 ]; then
  echo "- **PCI-DSS**: Improve compliance by addressing the failed checks above." >> "$REPORT_FILE"
fi

if [ "$hipaa_score" -lt 100 ]; then
  echo "- **HIPAA**: Enhance protected health information security by fixing the identified issues." >> "$REPORT_FILE"
fi

if [ "$gdpr_score" -lt 100 ]; then
  echo "- **GDPR**: Address data protection requirements by implementing the missing controls." >> "$REPORT_FILE"
fi

if [ "$soc2_score" -lt 100 ]; then
  echo "- **SOC2**: Strengthen trust services criteria compliance by resolving the gaps identified." >> "$REPORT_FILE"
fi

# Add appendix with security tiers information
cat >> "$REPORT_FILE" << EOF

## Appendix A: Security Tiers

The PostgreSQL Security Framework implements a tiered approach to security:

1. **Basic Tier**: Essential security controls for development and testing environments
2. **Standard Tier**: Comprehensive security controls for production environments
3. **Advanced Tier**: Enhanced security controls for high-security environments

Each tier builds upon the previous one, providing incremental security improvements while balancing performance considerations.

## Appendix B: Compliance Mapping

| Security Control | PCI-DSS | HIPAA | GDPR | SOC2 |
|------------------|---------|-------|------|------|
| Strong Authentication | ✓ | ✓ | ✓ | ✓ |
| Encryption at Rest | ✓ | ✓ | ✓ | ✓ |
| Encryption in Transit | ✓ | ✓ | ✓ | ✓ |
| Audit Logging | ✓ | ✓ | ✓ | ✓ |
| Access Controls | ✓ | ✓ | ✓ | ✓ |
| Network Security | ✓ | ✓ | ✓ | ✓ |
| Backup Encryption | ✓ | ✓ | ✓ | ✓ |
| Vulnerability Management | ✓ | ✓ | ✓ | ✓ |
| Secure Configuration | ✓ | ✓ | ✓ | ✓ |
| Monitoring and Alerting | ✓ | ✓ | ✓ | ✓ |

EOF

# Convert markdown to PDF
echo "Converting report to PDF..."
if command -v pandoc > /dev/null && command -v wkhtmltopdf > /dev/null; then
  pandoc "$REPORT_FILE" -o "$PDF_REPORT" --pdf-engine=wkhtmltopdf
  echo "PDF report generated: $PDF_REPORT"
else
  echo "Warning: pandoc or wkhtmltopdf not installed. Skipping PDF generation."
  echo "Markdown report generated: $REPORT_FILE"
  # Copy the markdown file to the expected PDF location for CI/CD
  cp "$REPORT_FILE" "$PDF_REPORT"
fi

echo "Compliance report generation completed."
exit 0
