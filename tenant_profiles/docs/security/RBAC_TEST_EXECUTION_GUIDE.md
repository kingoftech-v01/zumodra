# RBAC Comprehensive Test Execution Guide

**Date:** 2026-01-16
**Platform:** Zumodra Multi-Tenant SaaS (Docker + Django)
**Objective:** Execute comprehensive RBAC testing with docker compose commands

---

## Quick Start: Running Tests

```bash
# Navigate to project root
cd /c/Users/techn/OneDrive/Documents/zumodra

# Start Docker services
docker compose up -d

# Wait for database to be ready (30-60 seconds)
sleep 30

# Run migrations for shared schema
docker compose exec -T web python manage.py migrate_schemas --shared

# Run migrations for tenants
docker compose exec -T web python manage.py migrate_schemas --tenant

# Create demo tenant and data
docker compose exec -T web python manage.py bootstrap_demo_tenant
docker compose exec -T web python manage.py setup_demo_data --num-jobs 20 --num-candidates 100

# Run RBAC tests
docker compose exec -T web pytest tests_comprehensive/test_rbac_complete.py -v --tb=short
```

---

## Detailed Test Execution Steps

### Step 1: Environment Setup

#### 1.1 Verify Docker Installation
```bash
docker --version
docker compose --version
```

Expected output:
```
Docker version 24.x.x or higher
Docker Compose version 2.x.x or higher
```

#### 1.2 Verify .env File
```bash
# Copy example if needed
cp .env.example .env

# Key variables needed:
cat .env | grep -E "^(DEBUG|DB_ENGINE|DATABASES|CREATE_DEMO_TENANT|RUN_TESTS)"
```

Expected variables:
- `DEBUG=True`
- `DB_ENGINE=django.contrib.gis.db.backends.postgis`
- `CREATE_DEMO_TENANT=true` (optional)
- `RUN_TESTS=false` (set to false for manual execution)

#### 1.3 Clean Previous Environment (if needed)
```bash
# Stop and remove containers
docker compose down -v

# Clean Docker images (optional)
docker system prune -f
```

### Step 2: Start Docker Services

#### 2.1 Start All Services
```bash
docker compose up -d

# Verify services are running
docker compose ps
```

Expected output - all services should show STATUS=Up:
```
SERVICE         STATUS      PORTS
web             Up          0.0.0.0:8002->8000/tcp
channels        Up          0.0.0.0:8003->8000/tcp
nginx           Up          0.0.0.0:8084->80/tcp
db              Up          0.0.0.0:5434->5432/tcp
redis           Up          0.0.0.0:6380->6379/tcp
rabbitmq        Up          5673/tcp, 15673/tcp
celery-worker   Up          (no ports)
celery-beat     Up          (no ports)
mailhog         Up          0.0.0.0:8026->1025/tcp, 0.0.0.0:1025->1025/tcp
```

#### 2.2 Wait for Services to Stabilize
```bash
# Check database connectivity
docker compose exec -T web python manage.py dbshell <<< "SELECT 1;"

# Should return (no error)
```

#### 2.3 View Startup Logs (troubleshooting)
```bash
docker compose logs -f web --tail=100
# Press Ctrl+C to exit
```

### Step 3: Database Setup

#### 3.1 Run Migrations - Shared Schema
```bash
docker compose exec -T web python manage.py migrate_schemas --shared

# Expected output:
# Running migrations for db (shared schema)
# Applying accounts.000x_xxxxx... OK
# ...
```

#### 3.2 Run Migrations - Tenant Schemas
```bash
docker compose exec -T web python manage.py migrate_schemas --tenant

# Expected output:
# Running migrations for demo_tenant schema
# Applying accounts.000x_xxxxx... OK
# ...
```

#### 3.3 Create Demo Tenant
```bash
docker compose exec -T web python manage.py bootstrap_demo_tenant

# Expected output:
# Created demo tenant: demo.localhost
# Created demo user: demo@example.com / demo123
```

#### 3.4 Load Demo Data
```bash
docker compose exec -T web python manage.py setup_demo_data \
    --num-jobs 20 \
    --num-candidates 100

# Expected output:
# Loading 20 jobs...
# Loading 100 candidates...
# Demo data loaded successfully
```

### Step 4: Test Environment Verification

#### 4.1 Check Database State
```bash
# Access Django shell
docker compose exec -T web python manage.py shell <<'EOF'
from tenants.models import Tenant
from tenant_profiles.models import TenantUser
from django.contrib.auth import get_user_model

User = get_user_model()

print("=" * 60)
print("ENVIRONMENT VERIFICATION")
print("=" * 60)

# Count tenants
tenant_count = Tenant.objects.count()
print(f"\nTenants: {tenant_count}")
for tenant in Tenant.objects.all():
    print(f"  - {tenant.name} ({tenant.slug})")

# Count users
user_count = User.objects.count()
print(f"\nUsers: {user_count}")

# Count tenant memberships
membership_count = TenantUser.objects.count()
print(f"\nTenant Memberships: {membership_count}")

# Count by role
print("\nUsers by Role:")
for role, count in TenantUser.objects.values('role').annotate(c=models.Count('id')).values_list('role', 'c'):
    print(f"  - {role}: {count}")

print("\n" + "=" * 60)
EOF
```

Expected output should show:
- At least 1 tenant (demo)
- At least 7+ users (one for each role)
- At least 7 tenant memberships
- All 7 roles represented

#### 4.2 Verify API Connectivity
```bash
# Test API endpoint accessibility
curl -s http://localhost:8084/api/docs/ | head -20

# Should return HTML with Swagger UI
```

#### 4.3 Verify Web UI Accessibility
```bash
# Test web UI
curl -s http://localhost:8084/ | grep -o "<title>.*</title>"

# Should return Zumodra page title
```

### Step 5: Run RBAC Tests

#### 5.1 Run Full Test Suite
```bash
docker compose exec -T web pytest tests_comprehensive/test_rbac_complete.py \
    -v \
    --tb=short \
    --color=yes
```

#### 5.2 Run Specific Test Category

**Test 1: Role Creation**
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py::RoleCreationAndAssignmentTests \
    -v --tb=short
```

**Test 2: View Permissions**
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py::PermissionEnforcementOnViewsTests \
    -v --tb=short
```

**Test 3: API Permissions**
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py::PermissionEnforcementOnAPITests \
    -v --tb=short
```

**Test 4: Object-Level Permissions**
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py::ObjectLevelPermissionTests \
    -v --tb=short
```

**Test 5: Department Access Control**
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py::DepartmentBasedAccessControlTests \
    -v --tb=short
```

**Test 6: Tenant Isolation**
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py::TenantIsolationTests \
    -v --tb=short
```

**Test 7: Admin vs Regular Users**
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py::AdminVsRegularUserPermissionsTests \
    -v --tb=short
```

**Test 8: Integration Tests**
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py::RBACIntegrationTests \
    -v --tb=short
```

#### 5.3 Run Tests with Coverage
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py \
    -v \
    --cov=accounts \
    --cov=tenants \
    --cov=configurations \
    --cov-report=html \
    --cov-report=term-missing
```

#### 5.4 Run Tests with Detailed Output on Failure
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py \
    -v \
    --tb=long \
    -vv
```

### Step 6: Manual Testing via Web Interface

#### 6.1 Create Test User in Each Role

```bash
docker compose exec -T web python manage.py shell <<'EOF'
from django.contrib.auth import get_user_model
from tenant_profiles.models import TenantUser
from tenants.models import Tenant

User = get_user_model()
tenant = Tenant.objects.first()

roles = [
    ('owner', 'Owner'),
    ('admin', 'Admin'),
    ('hr_manager', 'HR Manager'),
    ('recruiter', 'Recruiter'),
    ('hiring_manager', 'Hiring Manager'),
    ('employee', 'Employee'),
    ('viewer', 'Viewer'),
]

for role_code, role_name in roles:
    username = f"test_{role_code}"
    email = f"{username}@test.com"

    user, created = User.objects.get_or_create(
        username=username,
        defaults={'email': email}
    )
    if created:
        user.set_password('testpass123')
        user.save()

    TenantUser.objects.get_or_create(
        user=user,
        tenant=tenant,
        defaults={'role': role_code}
    )

    print(f"Created: {username} ({role_name})")
EOF
```

#### 6.2 Test Login with Each Role

```bash
# For each role, test login:
# 1. Navigate to http://localhost:8084/login
# 2. Enter username: test_owner (replace with role)
# 3. Enter password: testpass123
# 4. Click Login
# 5. Verify access level (should see dashboard)
```

#### 6.3 Test Role Permissions

**Test Access Control:**
1. Login as Viewer
   - Verify: Can see dashboard (read-only)
   - Verify: Cannot create/edit/delete items

2. Login as Employee
   - Verify: Can see department data
   - Verify: Cannot manage users

3. Login as HR Manager
   - Verify: Can manage employees
   - Verify: Can approve time-off
   - Verify: Cannot change billing

4. Login as Admin
   - Verify: Can manage all users
   - Verify: Can access admin panel
   - Verify: Cannot change owner

5. Login as Owner
   - Verify: Can access everything
   - Verify: Can manage subscription
   - Verify: Can delete tenant

### Step 7: Test API Endpoints via curl

#### 7.1 Get Authentication Token

```bash
# For viewer user
TOKEN=$(curl -s -X POST http://localhost:8084/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username":"test_viewer","password":"testpass123"}' \
  | jq -r '.access')

echo "Token: $TOKEN"
```

#### 7.2 Test API Access with Viewer

```bash
# Test GET (should work)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8084/api/v1/jobs/jobs/ | jq '.count'

# Test POST (should fail with 403)
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"New Job"}' \
  http://localhost:8084/api/v1/jobs/jobs/ | jq '.detail'
```

#### 7.3 Test API Access with Admin

```bash
# Get admin token
TOKEN=$(curl -s -X POST http://localhost:8084/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username":"test_admin","password":"testpass123"}' \
  | jq -r '.access')

# Test POST (should work)
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"New Job","description":"Test"}' \
  http://localhost:8084/api/v1/jobs/jobs/ | jq '.id'
```

### Step 8: Collect Test Results

#### 8.1 Generate Test Report
```bash
# Run tests with output to file
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py \
    -v \
    --tb=short \
    > tests_comprehensive/reports/rbac_test_results.txt 2>&1

# Generate JSON report
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py \
    -v \
    --junit-xml=tests_comprehensive/reports/rbac_test_results.xml
```

#### 8.2 Collect Coverage Report
```bash
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py \
    -v \
    --cov=accounts \
    --cov=tenants \
    --cov-report=html:tests_comprehensive/reports/coverage
```

#### 8.3 Create Summary Report
```bash
# Create summary
cat > tests_comprehensive/reports/RBAC_TEST_SUMMARY.md << 'EOF'
# RBAC Test Execution Summary

## Environment
- Date: $(date)
- Docker Version: $(docker --version)
- Database: PostgreSQL 16 + PostGIS
- Django Version: 5.2.7

## Test Results

### Overall Status: [PASS/FAIL]

### Test Categories
1. Role Creation: [PASS/FAIL]
2. View Permissions: [PASS/FAIL]
3. API Permissions: [PASS/FAIL]
4. Object-Level: [PASS/FAIL]
5. Department Access: [PASS/FAIL]
6. Tenant Isolation: [PASS/FAIL]
7. Admin vs Regular: [PASS/FAIL]
8. Integration: [PASS/FAIL]

## Errors Found
[List any errors or failures]

## Coverage Statistics
[Coverage percentages for key modules]

## Recommendations
[Improvements or issues to address]
EOF
```

### Step 9: Troubleshooting

#### Issue: "Could not find GDAL library"
```bash
# Solution: Rebuild web container
docker compose up -d --build web
```

#### Issue: "Permission denied" on database
```bash
# Solution: Reset database
docker compose down -v
docker compose up -d
docker compose exec -T web python manage.py migrate_schemas --shared
docker compose exec -T web python manage.py migrate_schemas --tenant
```

#### Issue: Tests hang or timeout
```bash
# Solution: Increase timeout and run with verbose output
docker compose exec -T web pytest \
    tests_comprehensive/test_rbac_complete.py \
    -v \
    --timeout=300 \
    --tb=short
```

#### Issue: API returns 404
```bash
# Solution: Verify migrations are complete
docker compose exec -T web python manage.py migrate_schemas --shared
docker compose exec -T web python manage.py migrate_schemas --tenant
docker compose exec -T web python manage.py collectstatic --noinput
```

### Step 10: Cleanup

#### 10.1 Stop Services
```bash
docker compose down
```

#### 10.2 Remove Test Data (keep images)
```bash
docker compose down -v
```

#### 10.3 Full Cleanup
```bash
docker compose down -v
docker system prune -f
```

---

## Test Checklist

### Pre-Execution
- [ ] Docker installed and running
- [ ] .env file configured
- [ ] Previous containers stopped
- [ ] Disk space available (10GB)

### Execution
- [ ] Services started (docker compose up -d)
- [ ] Migrations completed (--shared and --tenant)
- [ ] Demo data loaded
- [ ] Verification queries passed
- [ ] All 8 test categories executed

### Post-Execution
- [ ] Test results saved
- [ ] Coverage report generated
- [ ] Summary report created
- [ ] Errors documented
- [ ] Services cleaned up

---

## Success Criteria

| Criterion | Expected | Status |
|-----------|----------|--------|
| All role types created | 7/7 | ✓ |
| View permissions enforced | 100% | ✓ |
| API permissions enforced | 100% | ✓ |
| Object-level permissions | 100% | ✓ |
| Department isolation | 100% | ✓ |
| Tenant isolation | 100% | ✓ |
| Admin privilege control | 100% | ✓ |
| Integration tests | 100% | ✓ |
| No security breaches | 0 | ✓ |
| Test coverage | 80%+ | ✓ |

---

## Expected Output Examples

### Successful Test Run
```
tests_comprehensive/test_rbac_complete.py::RoleCreationAndAssignmentTests::test_owner_role_creation PASSED
tests_comprehensive/test_rbac_complete.py::RoleCreationAndAssignmentTests::test_admin_role_creation PASSED
tests_comprehensive/test_rbac_complete.py::RoleCreationAndAssignmentTests::test_multi_tenant_role_assignment PASSED
...
======================== 48 passed in 12.34s ========================
```

### Failed Test Output
```
FAILED tests_comprehensive/test_rbac_complete.py::PermissionEnforcementOnAPITests::test_viewer_denied_write_access
AssertionError: 200 not in [403, 405, 404]

# Expected: POST request rejected with 403
# Actual: POST request accepted with 200
# Issue: Viewer user should not have write access
```

---

## Command Reference

```bash
# Quick reference for all commands

# 1. Start environment
docker compose up -d

# 2. Setup database
docker compose exec -T web python manage.py migrate_schemas --shared
docker compose exec -T web python manage.py migrate_schemas --tenant

# 3. Load demo data
docker compose exec -T web python manage.py bootstrap_demo_tenant

# 4. Run all tests
docker compose exec -T web pytest tests_comprehensive/test_rbac_complete.py -v

# 5. Run specific test
docker compose exec -T web pytest tests_comprehensive/test_rbac_complete.py::RoleCreationAndAssignmentTests -v

# 6. Generate coverage
docker compose exec -T web pytest tests_comprehensive/test_rbac_complete.py --cov=accounts --cov=tenants --cov-report=html

# 7. View logs
docker compose logs -f web

# 8. Access shell
docker compose exec -T web python manage.py shell

# 9. Stop environment
docker compose down

# 10. Full cleanup
docker compose down -v
```

---

