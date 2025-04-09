#!/bin/bash
set -e

# Script to generate strong SSL certificates for PostgreSQL
# This script creates a Certificate Authority (CA) and server certificates

# Configuration
CERT_DIR="/etc/certs"
DAYS_VALID=3650  # 10 years for CA, adjust as needed
SERVER_DAYS_VALID=365  # 1 year for server cert
KEY_SIZE=4096
COUNTRY="US"
STATE="California"
LOCALITY="San Francisco"
ORGANIZATION="PostgreSQL Security Framework"
ORGANIZATIONAL_UNIT="Database Security"
CA_CN="PostgreSQL-Security-CA"
SERVER_CN="postgres.example.com"  # Change to your actual server hostname
SERVER_ALT_NAMES="DNS:postgres.example.com,DNS:postgres,IP:127.0.0.1"  # Add your actual DNS names and IPs

# Ensure certificate directory exists
mkdir -p "${CERT_DIR}"
chmod 700 "${CERT_DIR}"

# Generate CA private key
openssl genrsa -out "${CERT_DIR}/ca.key" "${KEY_SIZE}"
chmod 400 "${CERT_DIR}/ca.key"

# Generate CA certificate
openssl req -new -x509 -days "${DAYS_VALID}" -key "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/OU=${ORGANIZATIONAL_UNIT}/CN=${CA_CN}"

# Generate server private key
openssl genrsa -out "${CERT_DIR}/server.key" "${KEY_SIZE}"
chmod 400 "${CERT_DIR}/server.key"

# Create OpenSSL config for SAN
cat > "${CERT_DIR}/openssl.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = ${COUNTRY}
ST = ${STATE}
L = ${LOCALITY}
O = ${ORGANIZATION}
OU = ${ORGANIZATIONAL_UNIT}
CN = ${SERVER_CN}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
$(echo "${SERVER_ALT_NAMES}" | sed 's/,/\n/g')
EOF

# Generate server CSR
openssl req -new -key "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.csr" \
    -config "${CERT_DIR}/openssl.cnf"

# Sign server certificate with CA
openssl x509 -req -days "${SERVER_DAYS_VALID}" \
    -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/server.crt" \
    -extensions v3_req \
    -extfile "${CERT_DIR}/openssl.cnf"

# Create client certificate for authentication (optional)
openssl genrsa -out "${CERT_DIR}/client.key" "${KEY_SIZE}"
chmod 400 "${CERT_DIR}/client.key"

openssl req -new -key "${CERT_DIR}/client.key" -out "${CERT_DIR}/client.csr" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/OU=Client/CN=postgres-client"

openssl x509 -req -days "${SERVER_DAYS_VALID}" \
    -in "${CERT_DIR}/client.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/client.crt"

# Create combined client certificate for PostgreSQL client authentication
cat "${CERT_DIR}/client.crt" "${CERT_DIR}/client.key" > "${CERT_DIR}/postgresql.crt"
chmod 600 "${CERT_DIR}/postgresql.crt"

# Verify certificates
echo "Verifying server certificate..."
openssl verify -CAfile "${CERT_DIR}/ca.crt" "${CERT_DIR}/server.crt"

echo "Verifying client certificate..."
openssl verify -CAfile "${CERT_DIR}/ca.crt" "${CERT_DIR}/client.crt"

# Clean up temporary files
rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/client.csr" "${CERT_DIR}/openssl.cnf"

echo "SSL certificates generated successfully in ${CERT_DIR}"
echo "CA certificate: ${CERT_DIR}/ca.crt"
echo "Server certificate: ${CERT_DIR}/server.crt"
echo "Server private key: ${CERT_DIR}/server.key"
echo "Client certificate: ${CERT_DIR}/client.crt"
echo "Client private key: ${CERT_DIR}/client.key"
echo "Combined client certificate: ${CERT_DIR}/postgresql.crt"

# Instructions for PostgreSQL configuration
echo ""
echo "To configure PostgreSQL to use these certificates:"
echo "1. Ensure the following settings are in postgresql.conf:"
echo "   ssl = on"
echo "   ssl_cert_file = '${CERT_DIR}/server.crt'"
echo "   ssl_key_file = '${CERT_DIR}/server.key'"
echo "   ssl_ca_file = '${CERT_DIR}/ca.crt'"
echo ""
echo "2. To require client certificate authentication, add the following to pg_hba.conf:"
echo "   hostssl all all 0.0.0.0/0 cert clientcert=verify-full"
echo ""
echo "3. Distribute the CA certificate (${CERT_DIR}/ca.crt) to clients"
echo "   and the client certificate/key (${CERT_DIR}/postgresql.crt) to authorized clients"

exit 0
