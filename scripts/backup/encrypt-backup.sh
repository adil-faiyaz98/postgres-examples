#!/bin/bash
set -e

# Script to create and encrypt PostgreSQL backups
# This script creates a backup using pgBackRest and adds an additional layer of encryption

# Configuration
BACKUP_DIR="/var/lib/pgbackrest/backup"
ENCRYPTED_BACKUP_DIR="/var/lib/pgbackrest/encrypted"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="postgres_backup_${TIMESTAMP}"
LOG_FILE="/var/log/pgbackrest/encrypt-backup-${TIMESTAMP}.log"
KMS_KEY_ID="${KMS_KEY_ID:-alias/postgres-backup-key}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Ensure directories exist
mkdir -p "${ENCRYPTED_BACKUP_DIR}"
mkdir -p "$(dirname "${LOG_FILE}")"

# Log function
log() {
    echo "[$(date +%Y-%m-%d\ %H:%M:%S)] $1" | tee -a "${LOG_FILE}"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check for required tools
command -v pgbackrest >/dev/null 2>&1 || error_exit "pgbackrest is required but not installed"
command -v aws >/dev/null 2>&1 || error_exit "AWS CLI is required but not installed"
command -v openssl >/dev/null 2>&1 || error_exit "OpenSSL is required but not installed"

# Create backup using pgBackRest
log "Starting pgBackRest backup..."
pgbackrest --stanza=db_dev backup --type=full || error_exit "pgBackRest backup failed"
log "pgBackRest backup completed successfully"

# Generate a secure random key for OpenSSL encryption
log "Generating encryption key..."
ENCRYPTION_KEY=$(openssl rand -base64 32)

# Encrypt the key with AWS KMS
log "Encrypting key with AWS KMS..."
ENCRYPTED_KEY=$(aws kms encrypt \
    --key-id "${KMS_KEY_ID}" \
    --plaintext "${ENCRYPTION_KEY}" \
    --output text \
    --query CiphertextBlob \
    --region "${AWS_REGION}") || error_exit "KMS encryption failed"

# Find the latest backup
LATEST_BACKUP=$(find "${BACKUP_DIR}" -type d -name "*.backup" | sort -r | head -n 1)
if [ -z "${LATEST_BACKUP}" ]; then
    error_exit "No backup found in ${BACKUP_DIR}"
fi

# Create a tar archive of the backup
log "Creating tar archive of backup..."
tar -czf "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.tar.gz" -C "$(dirname "${LATEST_BACKUP}")" "$(basename "${LATEST_BACKUP}")" || error_exit "Failed to create tar archive"

# Encrypt the backup with OpenSSL using the generated key
log "Encrypting backup with OpenSSL..."
openssl enc -aes-256-cbc -salt -in "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.tar.gz" \
    -out "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.tar.gz.enc" \
    -pass "pass:${ENCRYPTION_KEY}" || error_exit "OpenSSL encryption failed"

# Remove the unencrypted tar file
rm "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

# Store the encrypted key alongside the backup
echo "${ENCRYPTED_KEY}" > "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.key.enc"

# Calculate and store checksums
log "Calculating checksums..."
sha256sum "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.tar.gz.enc" > "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.sha256"
sha256sum "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.key.enc" >> "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.sha256"

# Upload to S3 if configured
if [ -n "${S3_BUCKET}" ]; then
    log "Uploading encrypted backup to S3..."
    aws s3 cp "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.tar.gz.enc" "s3://${S3_BUCKET}/backups/${BACKUP_NAME}.tar.gz.enc" \
        --sse aws:kms \
        --sse-kms-key-id "${KMS_KEY_ID}" \
        --region "${AWS_REGION}" || error_exit "Failed to upload backup to S3"
    
    aws s3 cp "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.key.enc" "s3://${S3_BUCKET}/backups/${BACKUP_NAME}.key.enc" \
        --sse aws:kms \
        --sse-kms-key-id "${KMS_KEY_ID}" \
        --region "${AWS_REGION}" || error_exit "Failed to upload key to S3"
    
    aws s3 cp "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.sha256" "s3://${S3_BUCKET}/backups/${BACKUP_NAME}.sha256" \
        --sse aws:kms \
        --sse-kms-key-id "${KMS_KEY_ID}" \
        --region "${AWS_REGION}" || error_exit "Failed to upload checksums to S3"
    
    log "Upload to S3 completed successfully"
fi

log "Backup encryption completed successfully: ${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.tar.gz.enc"
log "To restore this backup, you will need both the encrypted backup file and the encrypted key file"
log "The key file must be decrypted using AWS KMS before it can be used to decrypt the backup"

exit 0
