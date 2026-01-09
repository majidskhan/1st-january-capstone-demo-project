#!/bin/bash
# Directory containing Terraform files
TERRAFORM_CODE_DIR="./"

# File to save Checkov scan output
CHECKOV_OUTPUT_FILE="checkov_output.json"

# Run Checkov scan and save output to file (CLI format)
checkov -d "$TERRAFORM_CODE_DIR" -o cli > "$CHECKOV_OUTPUT_FILE"

# If Checkov fails, still save the output and exit successfully
if [ $? -ne 0 ]; then
  exit 0
fi

# Parse Checkov output for critical and high severity vulnerabilities
critical_issues=$(jq '.results.failed_checks | map(select(.severity == "CRITICAL")) | length' "$CHECKOV_OUTPUT_FILE")
high_issues=$(jq '.results.failed_checks | map(select(.severity == "HIGH")) | length' "$CHECKOV_OUTPUT_FILE")

# Save summary to a separate local file
SUMMARY_FILE="checkov_summary.txt"
echo "Critical Issues: $critical_issues" > "$SUMMARY_FILE"
echo "High Issues: $high_issues" >> "$SUMMARY_FILE"
echo "Full Checkov output saved in $CHECKOV_OUTPUT_FILE" >> "$SUMMARY_FILE"

# Exit script successfully
exit 0
