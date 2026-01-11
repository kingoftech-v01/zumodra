#!/bin/bash
# Script to create initial migrations for apps that are missing them
# This should be run inside the Docker container where Django and all dependencies are available

set -e

echo "Creating initial migrations for apps missing them..."

# Check if tenants app has migrations
if [ ! -f "tenants/migrations/0001_initial.py" ]; then
    echo "Creating tenants app initial migration..."
    python manage.py makemigrations tenants
else
    echo "✓ tenants app already has migrations"
fi

# Check if custom_account_u app has migrations
if [ ! -f "custom_account_u/migrations/0001_initial.py" ]; then
    echo "Creating custom_account_u app initial migration..."
    python manage.py makemigrations custom_account_u
else
    echo "✓ custom_account_u app already has migrations"
fi

# Check if accounts app has migrations
if [ ! -f "accounts/migrations/0001_initial.py" ]; then
    echo "Creating accounts app initial migration..."
    python manage.py makemigrations accounts
else
    echo "✓ accounts app already has migrations"
fi

echo "✅ All required initial migrations created!"
echo ""
echo "Next steps:"
echo "1. Exit the container"
echo "2. Commit the new migration files:"
echo "   git add */migrations/*.py"
echo "   git commit -m 'feat: add initial migrations for core apps'"
echo "   git push origin main"
echo "3. Restart the container to apply migrations"
