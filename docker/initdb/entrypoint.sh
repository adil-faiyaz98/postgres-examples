#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status
set -o pipefail  # Ensures pipeline errors are not masked
shopt -s nullglob  # Prevents errors if no `.sql` files are found

echo "Running PostgreSQL initialization scripts..."

# Ensure PostgreSQL is ready before executing scripts
until pg_isready -h "$POSTGRES_HOST" -p 5432 -U "$POSTGRES_USER"; do
  echo "Waiting for PostgreSQL to be ready..."
  sleep 2
done

echo "PostgreSQL is ready! Executing initialization scripts..."

# Loop through and execute all initialization scripts
for f in /docker-entrypoint-initdb.d/*.sql; do
    echo "Running: $f..."
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$f" || {
        echo "Error executing $f. Stopping execution."
        exit 1
    }
done

echo "PostgreSQL Initialization Completed Successfully!"
