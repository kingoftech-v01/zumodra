#!/bin/bash

# Fix Migration Permissions Script
# This script fixes permission issues with migration files in Docker

echo "==================================="
echo "Fixing Migration Permissions"
echo "==================================="

# Stop containers
echo "Stopping containers..."
docker compose down

# Remove the problematic migration file if it exists
echo "Cleaning up migration files..."
rm -f tenants/migrations/0001_initial.py
rm -f accounts/migrations/0001_initial.py
rm -f custom_account_u/migrations/0001_initial.py

# Ensure migrations directories exist with correct permissions
echo "Creating migrations directories..."
mkdir -p tenants/migrations
mkdir -p accounts/migrations
mkdir -p custom_account_u/migrations

# Create __init__.py files
touch tenants/migrations/__init__.py
touch accounts/migrations/__init__.py
touch custom_account_u/migrations/__init__.py

# Rebuild containers with proper permissions
echo "Rebuilding containers..."
docker compose build --no-cache web

# Start containers
echo "Starting containers..."
docker compose up -d

# Wait for services to be ready
echo "Waiting for services to initialize..."
sleep 10

# Watch logs
echo "Watching logs (Ctrl+C to exit)..."
docker compose logs -f web

