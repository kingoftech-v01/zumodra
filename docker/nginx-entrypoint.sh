#!/bin/sh
# =============================================================================
# Nginx Entrypoint Script
# =============================================================================
# Generates self-signed SSL certificates if they don't exist
# For production, mount Let's Encrypt certificates instead
# =============================================================================

set -e

SSL_DIR="/etc/nginx/ssl"
DOMAIN="${DOMAIN:-localhost}"
DAYS_VALID=365

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[NGINX]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[NGINX]${NC} $1"
}

# Check if certificates exist
if [ ! -f "${SSL_DIR}/fullchain.pem" ] || [ ! -f "${SSL_DIR}/privkey.pem" ]; then
    log_warn "SSL certificates not found. Generating self-signed certificates..."

    # Create SSL directory if it doesn't exist
    mkdir -p "${SSL_DIR}"

    # Generate private key
    log_info "Generating private key..."
    openssl genrsa -out "${SSL_DIR}/privkey.pem" 2048

    # Generate self-signed certificate
    log_info "Generating self-signed certificate for ${DOMAIN}..."
    openssl req -new -x509 -days ${DAYS_VALID} \
        -key "${SSL_DIR}/privkey.pem" \
        -out "${SSL_DIR}/fullchain.pem" \
        -subj "/C=CA/ST=Quebec/L=Montreal/O=Zumodra/OU=Development/CN=${DOMAIN}" \
        -addext "subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN},DNS:localhost,IP:127.0.0.1"

    # Create chain file (same as fullchain for self-signed)
    cp "${SSL_DIR}/fullchain.pem" "${SSL_DIR}/chain.pem"

    # Set permissions
    chmod 600 "${SSL_DIR}/privkey.pem"
    chmod 644 "${SSL_DIR}/fullchain.pem"
    chmod 644 "${SSL_DIR}/chain.pem"

    log_info "Self-signed certificates generated successfully!"
    log_warn "For production, use Let's Encrypt or a commercial CA"
else
    log_info "SSL certificates found."
fi

# Generate DH parameters if not present
if [ ! -f "${SSL_DIR}/dhparam.pem" ]; then
    log_info "Generating DH parameters (2048-bit for faster startup)..."
    openssl dhparam -out "${SSL_DIR}/dhparam.pem" 2048
    chmod 644 "${SSL_DIR}/dhparam.pem"
    log_info "DH parameters generated."
fi

# Validate nginx configuration
log_info "Testing nginx configuration..."
nginx -t

log_info "Starting nginx..."
exec nginx -g "daemon off;"
