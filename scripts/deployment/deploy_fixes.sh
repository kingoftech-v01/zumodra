#!/bin/bash
# Deployment script for namespace fix and TenantProfile migration
# Run this on your production server

set -e  # Exit on error

echo "=========================================="
echo "Deploying Namespace Fix + TenantProfile Migration"
echo "=========================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Step 1: Pull latest code
echo -e "\n${YELLOW}[1/7]${NC} Pulling latest code from GitHub..."
git fetch origin
git pull origin restore-freelanhub-template

# Step 2: Verify the namespace fix is in place
echo -e "\n${YELLOW}[2/7]${NC} Verifying namespace fix in zumodra/urls.py..."
if grep -q "include('core.urls_frontend', namespace='frontend')" zumodra/urls.py; then
    echo -e "${GREEN}✓${NC} Namespace fix verified!"
else
    echo -e "${RED}✗${NC} Namespace fix NOT found! Checking deployment..."
    cat zumodra/urls.py | grep -A 2 -B 2 "core.urls_frontend"
    exit 1
fi

# Step 3: Clear Python cache
echo -e "\n${YELLOW}[3/7]${NC} Clearing Python cache files..."
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
echo -e "${GREEN}✓${NC} Cache cleared"

# Step 4: Run PUBLIC schema migrations (for PublicProfile, ProfileFieldSync)
echo -e "\n${YELLOW}[4/7]${NC} Running PUBLIC schema migrations..."
docker compose exec web python manage.py migrate_schemas --shared

# Step 5: Run TENANT schema migrations (for TenantProfile)
echo -e "\n${YELLOW}[5/7]${NC} Running TENANT schema migrations..."
docker compose exec web python manage.py migrate_schemas --tenant

# Step 6: Rebuild and restart the web container
echo -e "\n${YELLOW}[6/7]${NC} Rebuilding and restarting web container..."
docker compose up -d --force-recreate --no-deps --build web

# Wait for container to be ready
echo "Waiting for container to start..."
sleep 5

# Step 7: Verify the deployment
echo -e "\n${YELLOW}[7/7]${NC} Verifying deployment..."

# Check if container is running
if docker compose ps web | grep -q "Up"; then
    echo -e "${GREEN}✓${NC} Container is running"
else
    echo -e "${RED}✗${NC} Container failed to start!"
    docker compose logs web --tail=50
    exit 1
fi

# Test namespace resolution in Django shell
echo "Testing namespace resolution..."
docker compose exec web python manage.py shell <<EOF
from django.urls import get_resolver
resolver = get_resolver()
if 'frontend' in resolver.namespace_dict:
    print("✓ Frontend namespace is registered!")
    exit(0)
else:
    print("✗ Frontend namespace NOT registered!")
    exit(1)
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Namespace resolution test passed!"
else
    echo -e "${RED}✗${NC} Namespace resolution test failed!"
    exit 1
fi

# Check TenantProfile table exists
echo "Checking TenantProfile table..."
docker compose exec web python manage.py shell <<EOF
from django.db import connection
from tenants.models import Tenant

# Check in one tenant schema
tenant = Tenant.objects.exclude(schema_name='public').first()
if tenant:
    connection.set_schema(tenant.schema_name)
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = %s
                AND table_name = 'accounts_tenantprofile'
            );
        """, [tenant.schema_name])
        exists = cursor.fetchone()[0]
        if exists:
            print(f"✓ TenantProfile table exists in {tenant.schema_name}!")
            exit(0)
        else:
            print(f"✗ TenantProfile table NOT found in {tenant.schema_name}!")
            exit(1)
else:
    print("No tenants found to check")
    exit(1)
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} TenantProfile table exists!"
else
    echo -e "${RED}✗${NC} TenantProfile table missing!"
    exit 1
fi

echo ""
echo "=========================================="
echo -e "${GREEN}DEPLOYMENT SUCCESSFUL!${NC}"
echo "=========================================="
echo ""
echo "What was deployed:"
echo "  1. Frontend namespace fix (namespace='frontend')"
echo "  2. TenantProfile migration (accounts.0003_tenantprofile)"
echo "  3. Updated bootstrap commands for dual-profile"
echo ""
echo "Next steps:"
echo "  - Test the website at https://zumodra.rhematek-solutions.com/"
echo "  - Create demo tenants: docker compose exec web python manage.py bootstrap_demo_tenants"
echo "  - Backfill profiles: docker compose exec web python manage.py create_tenant_profiles"
echo ""
echo "To view logs:"
echo "  docker compose logs -f web"
echo ""
