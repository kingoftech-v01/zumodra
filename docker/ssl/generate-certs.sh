#!/bin/bash
# =============================================================================
# SSL Certificate Generation Script for Zumodra
# =============================================================================
# Generates self-signed certificates for development and DH parameters
# For production, use Let's Encrypt or a commercial CA
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
DOMAIN="${DOMAIN:-localhost}"
DAYS_VALID=365

# Create certs directory
mkdir -p "${CERTS_DIR}"

echo "==================================================================="
echo "Generating SSL certificates for Zumodra"
echo "==================================================================="

# Generate DH parameters (4096-bit for TLS 1.3)
echo "[1/4] Generating DH parameters (this may take a few minutes)..."
if [ ! -f "${SCRIPT_DIR}/dhparam.pem" ]; then
    openssl dhparam -out "${SCRIPT_DIR}/dhparam.pem" 4096
    echo "      DH parameters generated."
else
    echo "      DH parameters already exist, skipping."
fi

# Generate private key
echo "[2/4] Generating private key..."
openssl genrsa -out "${CERTS_DIR}/privkey.pem" 4096

# Generate certificate signing request (CSR)
echo "[3/4] Generating certificate signing request..."
openssl req -new -key "${CERTS_DIR}/privkey.pem" \
    -out "${CERTS_DIR}/csr.pem" \
    -subj "/C=CA/ST=Quebec/L=Montreal/O=Zumodra/OU=DevOps/CN=${DOMAIN}"

# Generate self-signed certificate
echo "[4/4] Generating self-signed certificate..."
openssl x509 -req -days ${DAYS_VALID} \
    -in "${CERTS_DIR}/csr.pem" \
    -signkey "${CERTS_DIR}/privkey.pem" \
    -out "${CERTS_DIR}/fullchain.pem" \
    -extfile <(printf "subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN},DNS:localhost,IP:127.0.0.1")

# Create chain file (same as fullchain for self-signed)
cp "${CERTS_DIR}/fullchain.pem" "${CERTS_DIR}/chain.pem"

# Set permissions
chmod 600 "${CERTS_DIR}/privkey.pem"
chmod 644 "${CERTS_DIR}/fullchain.pem"
chmod 644 "${CERTS_DIR}/chain.pem"
chmod 644 "${SCRIPT_DIR}/dhparam.pem"

echo "==================================================================="
echo "SSL certificates generated successfully!"
echo "==================================================================="
echo "Files created:"
echo "  - ${CERTS_DIR}/privkey.pem    (private key)"
echo "  - ${CERTS_DIR}/fullchain.pem  (certificate)"
echo "  - ${CERTS_DIR}/chain.pem      (certificate chain)"
echo "  - ${SCRIPT_DIR}/dhparam.pem   (DH parameters)"
echo ""
echo "For production, replace these with Let's Encrypt certificates:"
echo "  certbot certonly --webroot -w /var/www/certbot -d ${DOMAIN}"
echo "==================================================================="
