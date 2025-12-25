#!/bin/bash

# SSL/TLS Certificate Setup Script using Certbot (Let's Encrypt)
# This script automates the setup of SSL certificates for Zumodra

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Zumodra SSL Certificate Setup ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (use sudo)${NC}"
    exit 1
fi

# Prompt for domain and email
read -p "Enter your domain name (e.g., zumodra.com): " DOMAIN
read -p "Enter your admin email: " ADMIN_EMAIL

echo -e "${YELLOW}Installing Certbot...${NC}"

# Install Certbot (Ubuntu/Debian)
apt-get update
apt-get install -y certbot python3-certbot-nginx

echo -e "${YELLOW}Requesting SSL certificate for $DOMAIN...${NC}"

# Stop Nginx temporarily
systemctl stop nginx

# Get certificate (standalone mode)
certbot certonly --standalone \
    -d $DOMAIN \
    -d www.$DOMAIN \
    --email $ADMIN_EMAIL \
    --agree-tos \
    --no-eff-email \
    --keep-until-expiring

# Or if Nginx is running, use webroot:
# certbot certonly --webroot \
#     -w /var/www/certbot \
#     -d $DOMAIN \
#     -d www.$DOMAIN \
#     --email $ADMIN_EMAIL \
#     --agree-tos

echo -e "${GREEN}Certificate obtained successfully!${NC}"

# Update Nginx configuration
NGINX_CONF="/etc/nginx/sites-available/zumodra"

echo -e "${YELLOW}Updating Nginx configuration...${NC}"

# Backup existing config
cp $NGINX_CONF ${NGINX_CONF}.backup

# Update domain name in Nginx config
sed -i "s/server_name _;/server_name $DOMAIN www.$DOMAIN;/" $NGINX_CONF
sed -i "s/# server_name your-domain.com;/server_name $DOMAIN www.$DOMAIN;/" $NGINX_CONF

# Update SSL certificate paths
sed -i "s|/etc/letsencrypt/live/your-domain.com/|/etc/letsencrypt/live/$DOMAIN/|g" $NGINX_CONF

# Uncomment HTTPS server block
sed -i 's/# server {/server {/g' $NGINX_CONF
sed -i 's/#     /    /g' $NGINX_CONF
sed -i 's/# }/}/g' $NGINX_CONF

# Uncomment redirect to HTTPS
sed -i 's/# return 301 https/return 301 https/g' $NGINX_CONF

# Test Nginx configuration
nginx -t

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Nginx configuration is valid${NC}"

    # Reload Nginx
    systemctl start nginx
    systemctl reload nginx

    echo -e "${GREEN}Nginx reloaded successfully${NC}"
else
    echo -e "${RED}Nginx configuration error! Restoring backup...${NC}"
    cp ${NGINX_CONF}.backup $NGINX_CONF
    systemctl start nginx
    exit 1
fi

# Set up auto-renewal
echo -e "${YELLOW}Setting up automatic certificate renewal...${NC}"

# Test renewal
certbot renew --dry-run

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Certificate renewal test passed${NC}"

    # Add cron job for auto-renewal (runs twice daily)
    (crontab -l 2>/dev/null; echo "0 */12 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'") | crontab -

    echo -e "${GREEN}Auto-renewal cron job added${NC}"
else
    echo -e "${RED}Certificate renewal test failed${NC}"
fi

# Update Django settings
echo -e "${YELLOW}Updating Django .env file...${NC}"

# Add SSL settings to .env
cat >> /path/to/zumodra/.env << EOF

# SSL Configuration (added by setup_ssl.sh)
DOMAIN=$DOMAIN
ADMIN_EMAIL=$ADMIN_EMAIL
SSL_CERTIFICATE=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
SSL_CERTIFICATE_KEY=/etc/letsencrypt/live/$DOMAIN/privkey.pem
EOF

echo -e "${GREEN}=== SSL Setup Complete! ===${NC}"
echo -e "${GREEN}Your site is now secured with HTTPS${NC}"
echo -e "${YELLOW}Certificate will auto-renew before expiration${NC}"
echo ""
echo -e "Next steps:"
echo -e "1. Update your .env file: DEBUG=False"
echo -e "2. Restart your Django application"
echo -e "3. Test your site at: https://$DOMAIN"
echo ""
echo -e "${YELLOW}Certificate information:${NC}"
certbot certificates

echo -e "\n${GREEN}Done!${NC}"
