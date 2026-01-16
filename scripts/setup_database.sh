#!/bin/bash
# Database Setup Script for Zumodra Platform
# Run this after Docker containers are up and running

set -e  # Exit on error

echo "================================================"
echo "Zumodra Database Setup Script"
echo "================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Docker containers are running
echo "Step 1: Checking Docker containers..."
if ! docker ps | grep -q "zumodra-db"; then
    echo -e "${RED}Error: Database container is not running${NC}"
    echo "Please start Docker containers first:"
    echo "  docker compose up -d"
    exit 1
fi
echo -e "${GREEN}✓ Database container is running${NC}"
echo ""

# Wait for PostgreSQL to be ready
echo "Step 2: Waiting for PostgreSQL to be ready..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec zumodra-db-1 pg_isready -U postgres > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PostgreSQL is ready${NC}"
        break
    fi
    attempt=$((attempt + 1))
    echo "  Waiting... ($attempt/$max_attempts)"
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}Error: PostgreSQL did not become ready in time${NC}"
    exit 1
fi
echo ""

# Test database connection from Django
echo "Step 3: Testing database connection..."
if python manage.py check --database default > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Django can connect to database${NC}"
else
    echo -e "${RED}Error: Django cannot connect to database${NC}"
    echo "Check your DATABASE_URL in .env file"
    exit 1
fi
echo ""

# Run shared schema migrations
echo "Step 4: Running shared schema migrations..."
echo "  This creates tables in the PUBLIC schema (shared across all tenants)"
if python manage.py migrate_schemas --shared; then
    echo -e "${GREEN}✓ Shared schema migrations complete${NC}"
else
    echo -e "${RED}Error: Shared schema migrations failed${NC}"
    exit 1
fi
echo ""

# Check if any tenants exist
echo "Step 5: Checking for existing tenants..."
tenant_count=$(python manage.py shell -c "from tenants.models import Client; print(Client.objects.count())" 2>/dev/null || echo "0")
echo "  Found $tenant_count tenant(s)"
echo ""

# Run tenant schema migrations (if tenants exist)
if [ "$tenant_count" -gt "0" ]; then
    echo "Step 6: Running tenant schema migrations..."
    echo "  This creates tables in each tenant's schema"
    if python manage.py migrate_schemas --tenant; then
        echo -e "${GREEN}✓ Tenant schema migrations complete${NC}"
    else
        echo -e "${YELLOW}⚠ Warning: Some tenant migrations may have failed${NC}"
        echo "  You may need to fix migrations manually"
    fi
else
    echo "Step 6: Skipping tenant migrations (no tenants exist yet)"
    echo -e "${YELLOW}  Note: Create a tenant first, then run:${NC}"
    echo "    python manage.py migrate_schemas --tenant"
fi
echo ""

# Verify migrations
echo "Step 7: Verifying migrations..."
if python manage.py showmigrations --plan | grep -q "\[ \]"; then
    echo -e "${YELLOW}⚠ Warning: Some migrations are not applied${NC}"
    python manage.py showmigrations | grep "\[ \]" | head -10
else
    echo -e "${GREEN}✓ All migrations are applied${NC}"
fi
echo ""

# Create superuser (interactive)
echo "Step 8: Create superuser account"
echo "  You'll be prompted for email and password"
echo ""
if python manage.py createsuperuser; then
    echo -e "${GREEN}✓ Superuser created successfully${NC}"
else
    echo -e "${YELLOW}⚠ Superuser creation skipped or failed${NC}"
fi
echo ""

# Collect static files
echo "Step 9: Collecting static files..."
if python manage.py collectstatic --no-input; then
    echo -e "${GREEN}✓ Static files collected${NC}"
else
    echo -e "${YELLOW}⚠ Warning: Static files collection had issues${NC}"
fi
echo ""

# Run system checks
echo "Step 10: Running Django system checks..."
if python manage.py check --deploy; then
    echo -e "${GREEN}✓ All system checks passed${NC}"
else
    echo -e "${YELLOW}⚠ Warning: Some system checks failed${NC}"
    echo "  Review the warnings above"
fi
echo ""

# Summary
echo "================================================"
echo "Database Setup Complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo "  1. Start development server:"
echo "     python manage.py runserver"
echo ""
echo "  2. Access Django admin:"
echo "     http://localhost:8002/admin/"
echo ""
echo "  3. Create a tenant (if needed):"
echo "     python manage.py bootstrap_demo_tenant"
echo ""
echo "  4. Run tests:"
echo "     pytest"
echo ""
