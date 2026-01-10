#!/bin/bash
# Quick deployment verification script
# Run this on the server to verify all files are present and correct

echo "=== ZUMODRA DEPLOYMENT VERIFICATION ==="
echo ""

# Check Git status
echo "[1/6] Checking Git status..."
CURRENT_COMMIT=$(git rev-parse --short HEAD)
echo "Current commit: $CURRENT_COMMIT"

if [ "$CURRENT_COMMIT" = "26c9bb8" ] || git log --oneline -5 | grep -q "26c9bb8"; then
    echo "✓ Latest commit found (26c9bb8)"
else
    echo "✗ WARNING: Latest commit (26c9bb8) not found!"
    echo "  Run: git pull origin main"
fi
echo ""

# Check critical files exist
echo "[2/6] Checking critical files..."
FILES=(
    "tenants/decorators.py"
    "templates/components/tenant_type_switcher.html"
    "templates/components/verification_badges.html"
    "templates/components/hiring_context_selector.html"
    "templates/components/company_only_wrapper_start.html"
    "templates/components/company_only_wrapper_end.html"
    "templates/components/company_only_check.html"
    "docs/api/tenant_types.md"
    "docs/verification.md"
    "docs/components.md"
)

ALL_FILES_EXIST=true
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file"
    else
        echo "✗ MISSING: $file"
        ALL_FILES_EXIST=false
    fi
done

if [ "$ALL_FILES_EXIST" = true ]; then
    echo "✓ All critical files present"
else
    echo "✗ Some files missing - run: git pull origin main"
fi
echo ""

# Check imports in tenants/views.py
echo "[3/6] Checking tenants/views.py imports..."
if grep -q "from rest_framework.decorators import action, api_view, permission_classes" tenants/views.py; then
    echo "✓ tenants/views.py has correct imports"
else
    echo "✗ tenants/views.py missing api_view import"
    echo "  This will cause: NameError: name 'api_view' is not defined"
fi
echo ""

# Check imports in accounts/views.py
echo "[4/6] Checking accounts/views.py imports..."
if grep -q "from rest_framework.decorators import action, api_view, permission_classes" accounts/views.py; then
    echo "✓ accounts/views.py has correct imports"
else
    echo "✗ accounts/views.py missing api_view import"
fi
echo ""

# Check URL configurations
echo "[5/6] Checking URL configurations..."
if grep -q "path('verify/kyc/', views.submit_kyc_verification" accounts/urls.py; then
    echo "✓ accounts/urls.py has verification routes"
else
    echo "✗ accounts/urls.py missing verification routes"
fi

if grep -q "path('verify/ein/', views.submit_ein_verification" tenants/urls.py; then
    echo "✓ tenants/urls.py has EIN verification routes"
else
    echo "✗ tenants/urls.py missing EIN verification routes"
fi
echo ""

# Check decorators file
echo "[6/6] Checking decorators..."
if [ -f "tenants/decorators.py" ]; then
    if grep -q "def require_tenant_type" tenants/decorators.py; then
        echo "✓ tenants/decorators.py has require_tenant_type decorator"
    else
        echo "✗ tenants/decorators.py missing require_tenant_type"
    fi
else
    echo "✗ tenants/decorators.py file not found"
fi
echo ""

echo "=== SUMMARY ==="
if [ "$CURRENT_COMMIT" = "26c9bb8" ] && [ "$ALL_FILES_EXIST" = true ]; then
    echo "✓ Deployment looks good!"
    echo ""
    echo "Next steps:"
    echo "1. Restart the application:"
    echo "   docker-compose restart web"
    echo "   # OR"
    echo "   sudo systemctl restart gunicorn"
    echo ""
    echo "2. Check logs for errors:"
    echo "   docker-compose logs -f web"
    echo "   # OR"
    echo "   tail -f /var/log/gunicorn/error.log"
else
    echo "✗ Issues detected!"
    echo ""
    echo "Required actions:"
    echo "1. Pull latest code:"
    echo "   git pull origin main"
    echo ""
    echo "2. Rebuild containers (if using Docker):"
    echo "   docker-compose down"
    echo "   docker-compose build --no-cache web"
    echo "   docker-compose up -d"
    echo ""
    echo "3. Run migrations:"
    echo "   docker-compose exec web python manage.py migrate_schemas --shared"
    echo "   docker-compose exec web python manage.py migrate_schemas --tenant"
fi
