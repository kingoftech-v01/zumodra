#!/bin/bash

# Direct Rate Limiting Test Execution Script

set -e

echo "=========================================="
echo "Rate Limiting Comprehensive Test Suite"
echo "=========================================="

cd "$(dirname "$0")/.."

# Check Docker
echo "[1/4] Checking Docker services..."
if ! docker ps > /dev/null 2>&1; then
    echo "Docker not running. Starting Docker..."
    docker compose up -d
    sleep 20
else
    echo "Docker is running"
fi

# Verify services
echo "[2/4] Verifying services..."
docker compose ps

# Run tests
echo "[3/4] Running rate limiting tests..."
python -m pytest tests_comprehensive/test_rate_limiting.py -v --tb=short --color=yes || true

# Generate report
echo "[4/4] Tests complete. Check reports in tests_comprehensive/reports/"
ls -lh tests_comprehensive/reports/ || mkdir -p tests_comprehensive/reports

echo "=========================================="
echo "Test Execution Complete"
echo "=========================================="
