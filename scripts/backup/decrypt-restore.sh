#!/bin/bash
set -e

# Script to decrypt and restore PostgreSQL backups
# This script decrypts a backup created by encrypt-backup.sh and restores it using pgBackRest

# Configuration
ENCRYPTED_BACKUP_DIR="/var/lib/pgbackrest/encrypted"
RESTORE_DIR="/var/lib/pgbackrest/restore"
LOG_FILE="/var/log/pgbackrest/decrypt-restore-$(date +%Y%m%d_%H%M%S).log"
KMS_KEY_ID="${KMS_KEY_ID:-alias/postgres-backup-key}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Ensure directories exist
mkdir -p "${RESTORE_DIR}"
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

# Check for required arguments
if [ $# -lt 1 ]; then
    error_exit "Usage: $0 <backup_name> [s3_bucket]"
fi

BACKUP_NAME="$1"
S3_BUCKET="$2"

# If S3 bucket is provided, download the backup files
if [ -n "${S3_BUCKET}" ]; then
    log "Downloading encrypted backup from S3..."
    aws s3 cp "s3://${S3_BUCKET}/backups/${BACKUP_NAME}.tar.gz.enc" "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.tar.gz.enc" \
        --region "${AWS_REGION}" || error_exit "Failed to download backup from S3"
    
    aws s3 cp "s3://${S3_BUCKET}/backups/${BACKUP_NAME}.key.enc" "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.key.enc" \
        --region "${AWS_REGION}" || error_exit "Failed to download key from S3"
    
    aws s3 cp "s3://${S3_BUCKET}/backups/${BACKUP_NAME}.sha256" "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.sha256" \
        --region "${AWS_REGION}" || error_exit "Failed to download checksums from S3"
    
    log "Download from S3 completed successfully"
fi

# Verify checksums
log "Verifying checksums..."
cd "${ENCRYPTED_BACKUP_DIR}"
sha256sum -c "${BACKUP_NAME}.sha256" || error_exit "Checksum verification failed"

# Decrypt the encryption key using AWS KMS
log "Decrypting key with AWS KMS..."
ENCRYPTED_KEY=$(cat "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.key.enc")
DECRYPTED_KEY=$(aws kms decrypt \
    --ciphertext-blob fileb://<(echo "${ENCRYPTED_KEY}" | base64 -d) \
    --output text \
    --query Plaintext \
    --region "${AWS_REGION}") || error_exit "KMS decryption failed"

# Decrypt the backup with OpenSSL using the decrypted key
log "Decrypting backup with OpenSSL..."
openssl enc -d -aes-256-cbc -in "${ENCRYPTED_BACKUP_DIR}/${BACKUP_NAME}.tar.gz.enc" \
    -out "${RESTORE_DIR}/${BACKUP_NAME}.tar.gz" \
    -pass "pass:$(echo "${DECRYPTED_KEY}" | base64 -d)" || error_exit "OpenSSL decryption failed"

# Extract the backup
log "Extracting backup..."
mkdir -p "${RESTORE_DIR}/extract"
tar -xzf "${RESTORE_DIR}/${BACKUP_NAME}.tar.gz" -C "${RESTORE_DIR}/extract" || error_exit "Failed to extract backup"

# Find the extracted backup directory
BACKUP_DIR=$(find "${RESTORE_DIR}/extract" -type d -name "*.backup" | head -n 1)
if [ -z "${BACKUP_DIR}" ]; then
    error_exit "No backup found in extracted archive"
fi

# Copy the backup to the pgBackRest backup directory
log "Copying backup to pgBackRest directory..."
cp -r "${BACKUP_DIR}" "/var/lib/pgbackrest/backup/" || error_exit "Failed to copy backup"

# Restore the backup using pgBackRest
log "Restoring backup using pgBackRest..."
pgbackrest --stanza=db_dev --delta restore || error_exit "pgBackRest restore failed"

log "Backup restoration completed successfully"
log "Cleaning up temporary files..."

# Clean up
rm -rf "${RESTORE_DIR}/${BACKUP_NAME}.tar.gz"
rm -rf "${RESTORE_DIR}/extract"

log "Restore process completed successfully"

exit 0
