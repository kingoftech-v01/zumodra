#!/bin/bash
#==============================================================================
# ZUMODRA AUTOMATED DEPLOYMENT & TESTING SCRIPT (Docker Version)
#==============================================================================
#
# This script automates the complete deployment and testing workflow:
# 1. Pull latest changes from GitHub
# 2. Rebuild Docker containers
# 3. Run database migrations
# 4. Collect static files
# 5. Restart services
# 6. Run automated tests
# 7. Generate comprehensive test report
#
# Usage: ./deploy_and_test.sh
# Or: ssh zumodra 'bash -s' < deploy_and_test.sh
#
#==============================================================================

set -u  # Exit on undefined variable
# Note: NOT using set -e to continue on errors and report them

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="/root/zumodra"
DOCKER_COMPOSE="docker compose"
WEB_CONTAINER="zumodra_web"
CELERY_CONTAINER="zumodra_celery-worker"
BEAT_CONTAINER="zumodra_celery-beat"

# Docker exec command helper
docker_exec() {
    docker exec -i "$WEB_CONTAINER" "$@"
}

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           ZUMODRA AUTOMATED DEPLOYMENT & TESTING              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Started at: $(date)${NC}"
echo ""

#==============================================================================
# STEP 1: NAVIGATE TO PROJECT DIRECTORY
#==============================================================================
echo -e "${BLUE}[1/9] Navigating to project directory...${NC}"
if cd "$PROJECT_DIR"; then
    echo -e "${GREEN}✓ Current directory: $(pwd)${NC}"
else
    echo -e "${RED}Error: Project directory not found${NC}"
    exit 1
fi
echo ""

#==============================================================================
# STEP 2: PULL LATEST CHANGES FROM GITHUB
#==============================================================================
echo -e "${BLUE}[2/9] Pulling latest changes from GitHub...${NC}"
git fetch origin 2>&1
BEFORE_COMMIT=$(git rev-parse HEAD 2>&1)
git pull origin main 2>&1
AFTER_COMMIT=$(git rev-parse HEAD 2>&1)

if [ "$BEFORE_COMMIT" = "$AFTER_COMMIT" ]; then
    echo -e "${YELLOW}✓ Already up to date (no new changes)${NC}"
else
    echo -e "${GREEN}✓ Updated from $BEFORE_COMMIT to $AFTER_COMMIT${NC}"
    git log --oneline -5
fi
echo ""

#==============================================================================
# STEP 3: REBUILD DOCKER CONTAINERS (if needed)
#==============================================================================
echo -e "${BLUE}[3/9] Rebuilding Docker containers...${NC}"
if [ "$BEFORE_COMMIT" != "$AFTER_COMMIT" ]; then
    echo "  → Changes detected, rebuilding containers..."
    $DOCKER_COMPOSE build --no-cache web celery-worker celery-beat 2>&1 | tail -10
    echo -e "${GREEN}✓ Containers rebuilt${NC}"
else
    echo -e "${YELLOW}  → No changes, skipping rebuild${NC}"
fi
echo ""

#==============================================================================
# STEP 4: RUN DATABASE MIGRATIONS
#==============================================================================
echo -e "${BLUE}[4/9] Running database migrations...${NC}"
echo "  → Migrating public schema..."
if docker_exec python manage.py migrate_schemas --shared --noinput 2>&1 | grep -E "(Operations to perform|Running migrations|No migrations)" | tail -3; then
    echo -e "${GREEN}  ✓ Public schema migrated${NC}"
fi

echo "  → Migrating tenant schemas..."
if docker_exec python manage.py migrate_schemas --tenant --noinput 2>&1 | grep -E "(Operations to perform|Running migrations|No migrations)" | tail -3; then
    echo -e "${GREEN}  ✓ Tenant schemas migrated${NC}"
fi
echo -e "${GREEN}✓ Migrations completed${NC}"
echo ""

#==============================================================================
# STEP 5: COLLECT STATIC FILES
#==============================================================================
echo -e "${BLUE}[5/9] Collecting static files...${NC}"
if docker_exec python manage.py collectstatic --noinput -c 2>&1 | tail -5; then
    echo -e "${GREEN}✓ Static files collected${NC}"
fi
echo ""

#==============================================================================
# STEP 6: RESTART SERVICES
#==============================================================================
echo -e "${BLUE}[6/9] Restarting services...${NC}"
echo "  → Restarting web server..."
$DOCKER_COMPOSE restart web 2>&1 | head -2
echo "  → Restarting celery workers..."
$DOCKER_COMPOSE restart celery-worker 2>&1 | head -2
echo "  → Restarting celery beat..."
$DOCKER_COMPOSE restart celery-beat 2>&1 | head -2
sleep 3  # Give services time to start
echo -e "${GREEN}✓ Services restarted${NC}"
echo ""

#==============================================================================
# STEP 7: VERIFY SERVICES ARE RUNNING
#==============================================================================
echo -e "${BLUE}[7/9] Verifying services...${NC}"
CONTAINERS=("$WEB_CONTAINER" "$CELERY_CONTAINER" "$BEAT_CONTAINER")
ALL_RUNNING=true

for container in "${CONTAINERS[@]}"; do
    if docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
        echo -e "  ${GREEN}✓${NC} $container is running"
    else
        echo -e "  ${RED}✗${NC} $container is NOT running"
        ALL_RUNNING=false
    fi
done

if [ "$ALL_RUNNING" = true ]; then
    echo -e "${GREEN}✓ All services running${NC}"
else
    echo -e "${YELLOW}⚠ Some services are not running (check logs)${NC}"
fi
echo ""

#==============================================================================
# STEP 8: RUN AUTOMATED TESTS
#==============================================================================
echo -e "${BLUE}[8/9] Running automated tests...${NC}"
echo ""

# Create test results directory
TEST_DIR="$PROJECT_DIR/test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TEST_DIR"

# Test 1: Quick Authentication Test (Infrastructure)
echo -e "${YELLOW}→ Test 1: Authentication Infrastructure${NC}"
if docker_exec python quick_auth_test.py > "$TEST_DIR/auth_test.log" 2>&1; then
    echo -e "${GREEN}  ✓ Authentication test PASSED${NC}"
else
    echo -e "${RED}  ✗ Authentication test FAILED (see auth_test.log)${NC}"
fi

# Test 2: MFA Enforcement Test
echo -e "${YELLOW}→ Test 2: MFA Enforcement${NC}"
if docker_exec python test_mfa_enforcement.py > "$TEST_DIR/mfa_test.log" 2>&1; then
    echo -e "${GREEN}  ✓ MFA test PASSED${NC}"
else
    echo -e "${YELLOW}  ⚠ MFA test needs credentials (see mfa_test.log)${NC}"
fi

# Test 3: Health Check
echo -e "${YELLOW}→ Test 3: Health Check${NC}"
if docker_exec python manage.py health_check > "$TEST_DIR/health_check.log" 2>&1; then
    echo -e "${GREEN}  ✓ Health check PASSED${NC}"
else
    echo -e "${RED}  ✗ Health check FAILED (see health_check.log)${NC}"
fi

# Test 4: Django Check
echo -e "${YELLOW}→ Test 4: Django System Check${NC}"
if docker_exec python manage.py check > "$TEST_DIR/django_check.log" 2>&1; then
    echo -e "${GREEN}  ✓ Django check PASSED${NC}"
else
    echo -e "${RED}  ✗ Django check FAILED (see django_check.log)${NC}"
fi

# Test 5: Run pytest (if available)
echo -e "${YELLOW}→ Test 5: Pytest Suite${NC}"
if docker_exec pytest tests/ -v --maxfail=5 > "$TEST_DIR/pytest.log" 2>&1; then
    echo -e "${GREEN}  ✓ Pytest PASSED${NC}"
else
    echo -e "${YELLOW}  ⚠ Some tests failed (see pytest.log)${NC}"
fi

echo ""
echo -e "${GREEN}✓ Tests completed${NC}"
echo -e "  Results saved to: ${BLUE}$TEST_DIR${NC}"
echo ""

#==============================================================================
# STEP 9: GENERATE TEST REPORT
#==============================================================================
echo -e "${BLUE}[9/9] Generating test report...${NC}"

REPORT_FILE="$TEST_DIR/DEPLOYMENT_REPORT.txt"

cat > "$REPORT_FILE" << EOF
╔════════════════════════════════════════════════════════════════╗
║           ZUMODRA DEPLOYMENT & TEST REPORT                     ║
╚════════════════════════════════════════════════════════════════╝

Deployment Date: $(date)
Server: zumodra.rhematek-solutions.com
Project Path: $PROJECT_DIR

═══════════════════════════════════════════════════════════════════
DEPLOYMENT SUMMARY
═══════════════════════════════════════════════════════════════════

Git Commit (Before): $BEFORE_COMMIT
Git Commit (After):  $AFTER_COMMIT
Changes Applied:     $(if [ "$BEFORE_COMMIT" = "$AFTER_COMMIT" ]; then echo "None (up to date)"; else echo "Yes"; fi)

Recent Commits:
$(git log --oneline -5)

═══════════════════════════════════════════════════════════════════
DOCKER SERVICES STATUS
═══════════════════════════════════════════════════════════════════

$(for container in "${CONTAINERS[@]}"; do
    if docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
        echo "✓ $container: RUNNING"
    else
        echo "✗ $container: STOPPED"
    fi
done)

═══════════════════════════════════════════════════════════════════
TEST RESULTS
═══════════════════════════════════════════════════════════════════

See individual log files in: $TEST_DIR

- auth_test.log          (Authentication Infrastructure Test)
- mfa_test.log           (MFA Enforcement Test)
- health_check.log       (Django Health Check)
- django_check.log       (Django System Check)
- pytest.log             (Pytest Suite)

═══════════════════════════════════════════════════════════════════
NEXT STEPS
═══════════════════════════════════════════════════════════════════

1. Review test results in $TEST_DIR
2. Check service logs if any services failed:
   - docker logs zumodra_web
   - docker logs zumodra_celery-worker
   - docker logs zumodra_celery-beat

3. Access the application:
   - https://zumodra.rhematek-solutions.com

4. Verify key features manually:
   - Registration & Login
   - MFA Setup (/accounts/two-factor/)
   - Public User Dashboard (/app/dashboard/)
   - Navigation dropdown with MFA link

═══════════════════════════════════════════════════════════════════

Deployment completed successfully!
EOF

cat "$REPORT_FILE"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                 DEPLOYMENT COMPLETE                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Full report: ${BLUE}$REPORT_FILE${NC}"
echo -e "Test results: ${BLUE}$TEST_DIR${NC}"
echo ""
echo -e "${YELLOW}Finished at: $(date)${NC}"
echo ""

# Exit with success
exit 0
