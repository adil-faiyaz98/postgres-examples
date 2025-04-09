#!/bin/bash
set -e

# Script to clean up redundant and irrelevant files
# This script removes backup files, temporary files, and consolidates duplicates

echo "Starting cleanup process..."

# Remove backup and temporary files
echo "Removing backup and temporary files..."
find . -type f \( -name "*.bak" -o -name "*.tmp" -o -name "*.log" \) -delete

# Remove files with "backup" or "old" in the name
echo "Removing backup and old files..."
find . -type f \( -name "*backup*" -o -name "*old*" \) -delete

# Consolidate duplicate files
echo "Checking for duplicate files..."

# Function to check if two files are identical
files_are_identical() {
  cmp -s "$1" "$2"
  return $?
}

# Function to consolidate duplicate files
consolidate_duplicates() {
  base_name=$1
  echo "Checking duplicates for: $base_name"
  
  # Find all files with the given name
  files=$(find . -name "$base_name" | sort)
  file_count=$(echo "$files" | wc -l)
  
  if [ "$file_count" -le 1 ]; then
    echo "No duplicates found for $base_name"
    return
  fi
  
  echo "Found $file_count files named $base_name"
  
  # Get the first file as the reference
  reference_file=$(echo "$files" | head -n 1)
  echo "Using $reference_file as reference"
  
  # Check each other file against the reference
  for file in $files; do
    if [ "$file" != "$reference_file" ]; then
      if files_are_identical "$reference_file" "$file"; then
        echo "Removing duplicate: $file"
        rm "$file"
      else
        echo "Files differ, keeping both: $reference_file and $file"
      fi
    fi
  done
}

# List of common duplicate files to check
duplicate_files=(
  "partition_maintenance.sql"
  "zero_knowledge_proof_verification.sql"
  "adaptive_security_policies.sql"
  "aws_security_hub_integration.sql"
  "siem_integration.sql"
  "configmap.yaml"
  "setup.sql"
)

# Consolidate each duplicate file
for file in "${duplicate_files[@]}"; do
  consolidate_duplicates "$file"
done

# Special handling for README.md files
echo "Handling README.md files..."
readmes=$(find . -name "README.md" | sort)
for readme in $readmes; do
  dir=$(dirname "$readme")
  if [ "$dir" != "." ] && [ "$dir" != "./docs" ]; then
    echo "Moving content from $readme to main README.md"
    echo -e "\n## $(basename "$dir") Documentation\n" >> ./README.md
    cat "$readme" >> ./README.md
    echo "Removing $readme"
    rm "$readme"
  fi
done

# Remove empty directories
echo "Removing empty directories..."
find . -type d -empty -delete

echo "Cleanup completed successfully."
exit 0
