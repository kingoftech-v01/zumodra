# Manual Multi-Tenancy Testing Checklist

## Quick Start
```bash
# Start Docker environment
docker compose up -d

# Wait for services to be ready
sleep 30

# Run automated tests
docker compose exec web python test_multitenancy_isolation.py

# View results
cat tests_comprehensive/reports/multitenancy_isolation_test_report.json
```

---

## Pre-Test Verification

### Environment Check
- [ ] Docker containers running: `docker compose ps`
- [ ] PostgreSQL accessible: `docker compose exec db psql -U postgres -d zumodra -c "SELECT 1"`
- [ ] Redis running: `docker compose exec redis redis-cli ping`
- [ ] Django migrations applied: `docker compose exec web python manage.py migrate_schemas --shared`

### Database Check
- [ ] Public schema exists: `\dn` shows "public"
- [ ] Tenant schemas exist: `\dn` shows "tenant_test_1", "tenant_test_2", etc.
- [ ] Tables present in public: `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'`

---

## Test Group 1: Schema Separation

### Test 1.1: Verify PostgreSQL Schemas
**Objective**: Confirm separate schemas for each tenant

**Steps**:
```bash
# Connect to database
docker compose exec db psql -U postgres -d zumodra

# List all schemas
\dn

# Expected output:
#   List of schemas
#        Name    |  Owner
#   ─────────────┼──────────
#    public      | postgres
#    tenant_test_1 | postgres
#    tenant_test_2 | postgres
```

**Pass Criteria**:
- [ ] At least 3 schemas visible (public + 2 test tenants)
- [ ] Schema names are unique
- [ ] All schemas owned by postgres user

**Result**: PASS / FAIL

---

### Test 1.2: Verify Schema Contents
**Objective**: Confirm each schema has independent tables

**Steps**:
```sql
-- Check tables in public schema
SELECT COUNT(*) FROM information_schema.tables
WHERE table_schema = 'public'
AND table_type = 'BASE TABLE';

-- Expected: ~20 tables (django, tenants, auth tables)

-- Check tables in tenant schema
SELECT COUNT(*) FROM information_schema.tables
WHERE table_schema = 'tenant_test_1'
AND table_type = 'BASE TABLE';

-- Expected: ~60+ tables (all app tables)
```

**Pass Criteria**:
- [ ] Public schema has fewer tables than tenant schemas
- [ ] Both schemas have ats_job table
- [ ] Both schemas have hr_core_employee table

**Result**: PASS / FAIL

---

## Test Group 2: Data Isolation

### Test 2.1: Create Data in Tenant 1
**Objective**: Verify data can be created in specific schema

**Steps**:
```bash
# Access web container shell
docker compose exec web bash

# Start Django shell
python manage.py shell
```

**Python Code**:
```python
from django.db import connection
from tenants.models import Tenant
from ats.models import Job
from django.contrib.auth import get_user_model

User = get_user_model()

# Get tenant 1
tenant1 = Tenant.objects.get(slug='test-tenant-1')
print(f"Tenant 1 schema: {tenant1.schema_name}")

# Switch to tenant 1
connection.set_schema(tenant1.schema_name)

# Create test job
job = Job.objects.create(
    title="Senior Software Engineer",
    description="A great job in Tenant 1",
    status='draft'
)
print(f"✓ Created job in {tenant1.name}: {job.id}")

# Verify it exists
count = Job.objects.count()
print(f"Total jobs in {tenant1.name}: {count}")

# Get tenant 2
connection.set_schema_to_public()
tenant2 = Tenant.objects.get(slug='test-tenant-2')
```

**Pass Criteria**:
- [ ] Job created successfully
- [ ] Job count increased
- [ ] No errors in execution

**Result**: PASS / FAIL

---

### Test 2.2: Verify Data NOT Visible in Tenant 2
**Objective**: Confirm data isolation between tenants

**Continue from previous Python code**:
```python
# Switch to tenant 2
connection.set_schema(tenant2.schema_name)
print(f"Switched to {tenant2.name}")

# Try to access job from tenant 1
count = Job.objects.count()
print(f"Total jobs in {tenant2.name}: {count}")
# Expected: 0 (no jobs in tenant 2)

# Try to access specific job
try:
    job_from_t1 = Job.objects.get(id=job.id)
    print("✗ ERROR: Found job from Tenant 1 in Tenant 2!")
    # DATA LEAK!
except Job.DoesNotExist:
    print(f"✓ Correctly blocked access to Tenant 1's job")

# Try creating a job in tenant 2 with same data
job2 = Job.objects.create(
    title="Product Manager",
    description="A different job in Tenant 2",
    status='draft'
)
print(f"✓ Created different job in {tenant2.name}: {job2.id}")

count2 = Job.objects.count()
print(f"Total jobs in {tenant2.name}: {count2}")

# Verify separate data
connection.set_schema(tenant1.schema_name)
t1_count = Job.objects.count()
print(f"Tenant 1: {t1_count} jobs, Tenant 2: {count2} jobs")
```

**Pass Criteria**:
- [ ] Job not found in Tenant 2 (DoesNotExist)
- [ ] Can create different job in Tenant 2
- [ ] Job counts are different

**Result**: PASS / FAIL

---

### Test 2.3: Verify Candidates Isolation
**Objective**: Test isolation with different model

**Python Code**:
```python
from ats.models import Candidate

# In tenant1 schema (should still be set)
connection.set_schema(tenant1.schema_name)

candidate1 = Candidate.objects.create(
    first_name="John",
    last_name="Doe",
    email="john@tenant1.test",
    phone="+1234567890",
    source="linkedin"
)
print(f"✓ Created candidate in {tenant1.name}: {candidate1.id}")

# Switch to tenant2
connection.set_schema(tenant2.schema_name)

# Verify can't access
try:
    found = Candidate.objects.get(id=candidate1.id)
    print("✗ DATA LEAK: Found candidate from Tenant 1 in Tenant 2")
except Candidate.DoesNotExist:
    print(f"✓ Correctly blocked candidate access across tenants")

# Create in tenant 2
candidate2 = Candidate.objects.create(
    first_name="Jane",
    last_name="Smith",
    email="jane@tenant2.test",
    phone="+0987654321",
    source="website"
)
print(f"✓ Created candidate in {tenant2.name}: {candidate2.id}")
```

**Pass Criteria**:
- [ ] Candidate not found across tenants
- [ ] Can create different candidate in each tenant
- [ ] Data successfully isolated

**Result**: PASS / FAIL

---

## Test Group 3: Subdomain Routing

### Test 3.1: Access Tenant 1 via Subdomain
**Objective**: Verify HTTP requests route to correct tenant

**Steps**:
1. Open browser
2. Navigate to: `http://test-tenant-1.localhost:8084`
3. Observe page load

**Pass Criteria**:
- [ ] Page loads without error
- [ ] No 404 page
- [ ] Can see login form or dashboard

**Result**: PASS / FAIL

---

### Test 3.2: Access Tenant 2 via Subdomain
**Objective**: Verify different subdomain routes to different tenant

**Steps**:
1. In same browser
2. Navigate to: `http://test-tenant-2.localhost:8084`
3. Observe page load

**Pass Criteria**:
- [ ] Page loads without error
- [ ] Same URL structure but different tenant
- [ ] Browser history shows both domains

**Result**: PASS / FAIL

---

### Test 3.3: Verify Data Separation in Browser
**Objective**: Confirm data from one tenant doesn't leak to other in UI

**Steps**:
1. Login to `test-tenant-1.localhost:8084` as user from Tenant 1
2. Go to Jobs page: `/jobs/`
3. Verify you can see jobs created in Test 2.1
4. Switch to `test-tenant-2.localhost:8084`
5. Login as user from Tenant 2
6. Go to Jobs page

**Pass Criteria**:
- [ ] Tenant 1 sees "Senior Software Engineer" job
- [ ] Tenant 2 sees "Product Manager" job
- [ ] No crossover in UI

**Result**: PASS / FAIL

---

## Test Group 4: User Management

### Test 4.1: Create User in Tenant 1
**Objective**: Verify users are tenant-scoped

**Python Code**:
```python
from django.contrib.auth import get_user_model
from tenants.models import Tenant

User = get_user_model()

# Switch to tenant 1
connection.set_schema(tenant1.schema_name)

user1 = User.objects.create_user(
    username='alice',
    email='alice@tenant1.test',
    password='testpass123'
)
print(f"✓ Created user in {tenant1.name}: {user1.username}")

# Verify
alice = User.objects.get(username='alice')
print(f"  User email: {alice.email}")
print(f"  Total users in {tenant1.name}: {User.objects.count()}")
```

**Pass Criteria**:
- [ ] User created in Tenant 1
- [ ] User count reflects only Tenant 1 users
- [ ] No errors

**Result**: PASS / FAIL

---

### Test 4.2: Create User in Tenant 2
**Objective**: Verify users in other tenants don't interfere

**Python Code**:
```python
# Switch to tenant 2
connection.set_schema(tenant2.schema_name)

user2 = User.objects.create_user(
    username='bob',
    email='bob@tenant2.test',
    password='testpass123'
)
print(f"✓ Created user in {tenant2.name}: {user2.username}")

# Verify
bob = User.objects.get(username='bob')
print(f"  User email: {bob.email}")
print(f"  Total users in {tenant2.name}: {User.objects.count()}")

# Try to get alice (from tenant 1)
try:
    alice_from_t2 = User.objects.get(username='alice')
    print("✗ ERROR: Found Tenant 1 user in Tenant 2!")
except User.DoesNotExist:
    print(f"✓ Correctly blocked cross-tenant user lookup")
```

**Pass Criteria**:
- [ ] Bob created in Tenant 2
- [ ] Alice not found in Tenant 2
- [ ] User counts are separate

**Result**: PASS / FAIL

---

## Test Group 5: Permission System

### Test 5.1: Check Permission Isolation
**Objective**: Verify permissions don't cross tenant boundaries

**Python Code**:
```python
from django.contrib.auth.models import Permission, Group
from django.contrib.contenttypes.models import ContentType

# In tenant 1
connection.set_schema(tenant1.schema_name)

# Create a group with permissions
job_ct = ContentType.objects.get(app_label='ats', model='job')
add_job_perm = Permission.objects.get(
    content_type=job_ct,
    codename='add_job'
)

recruiters = Group.objects.create(name='Recruiters')
recruiters.permissions.add(add_job_perm)
print(f"✓ Created 'Recruiters' group in {tenant1.name}")

user1.groups.add(recruiters)
print(f"✓ Added alice to Recruiters group")

# Verify alice has permission
has_perm = user1.has_perm('ats.add_job')
print(f"  Alice has 'add_job' permission: {has_perm}")

# Switch to tenant 2
connection.set_schema(tenant2.schema_name)

# Add bob to same group (if it exists)
try:
    recruiters_t2 = Group.objects.get(name='Recruiters')
    user2.groups.add(recruiters_t2)
    print(f"✓ Added bob to Recruiters group in {tenant2.name}")
except Group.DoesNotExist:
    print(f"✓ Recruiters group doesn't exist in {tenant2.name} (correct)")

# Check bob's permissions
has_perm_t2 = user2.has_perm('ats.add_job')
print(f"  Bob has 'add_job' permission: {has_perm_t2}")
```

**Pass Criteria**:
- [ ] Groups are tenant-specific
- [ ] Permissions don't carry between tenants
- [ ] Each tenant has independent RBAC

**Result**: PASS / FAIL

---

## Test Group 6: Cache Isolation

### Test 6.1: Verify Cache Is Tenant-Aware
**Objective**: Confirm cache doesn't leak between tenants

**Python Code**:
```python
from django.core.cache import cache
from django.utils.timezone import now

# In tenant 1
connection.set_schema(tenant1.schema_name)

# Set cache key
cache_key = 'test_cache_isolation'
cache_value = f'Data from {tenant1.name} at {now()}'
cache.set(cache_key, cache_value)
print(f"✓ Set cache in {tenant1.name}")

# Get from cache
retrieved = cache.get(cache_key)
print(f"  Retrieved from cache: {retrieved}")

# Switch to tenant 2
connection.set_schema(tenant2.schema_name)

# Try to get same cache key
retrieved_t2 = cache.get(cache_key)
if retrieved_t2 is None:
    print(f"✓ Cache correctly isolated - not visible in {tenant2.name}")
else:
    print(f"✗ CACHE LEAK: Retrieved Tenant 1 data in Tenant 2")
    print(f"  Value: {retrieved_t2}")

# Set different value in tenant 2
cache_value_t2 = f'Data from {tenant2.name} at {now()}'
cache.set(cache_key, cache_value_t2)
print(f"✓ Set different cache value in {tenant2.name}")

# Verify it's different
retrieved_t2_again = cache.get(cache_key)
print(f"  Tenant 2 cache value: {retrieved_t2_again}")
```

**Pass Criteria**:
- [ ] Cache key returns None in different tenant
- [ ] Or cache includes tenant prefix in key
- [ ] No cross-tenant cache pollution

**Result**: PASS / FAIL

---

## Test Group 7: API Access Control

### Test 7.1: API Token Isolation (if applicable)
**Objective**: Verify API tokens are tenant-scoped

**Steps**:
```bash
# Get Tenant 1 API token
TOKEN1=$(curl -X POST http://localhost:8002/api/v1/token/ \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"testpass123"}' | jq -r '.access')

echo "Tenant 1 token: $TOKEN1"

# Try to access Tenant 2 API
curl -H "Authorization: Bearer $TOKEN1" \
  http://test-tenant-2.localhost:8084/api/v1/jobs/ \
  -v
```

**Pass Criteria**:
- [ ] Returns 403 Forbidden (user not in tenant 2)
- [ ] Or returns empty results
- [ ] Token is tenant-scoped

**Result**: PASS / FAIL

---

## Test Group 8: Audit Logging

### Test 8.1: Verify Audit Logs Are Isolated
**Objective**: Confirm audit logs respect tenant boundaries

**Python Code**:
```python
from auditlog.models import LogEntry

# In tenant 1
connection.set_schema(tenant1.schema_name)

# Create something and it should be logged
job1 = Job.objects.create(
    title="Audited Job",
    description="This should be logged",
    status='draft'
)

# Check logs
logs_t1 = LogEntry.objects.filter(object_pk=str(job1.pk)).count()
print(f"✓ Audit logs in {tenant1.name}: {logs_t1}")

# Switch to tenant 2
connection.set_schema(tenant2.schema_name)

# Try to access same logs
logs_t1_from_t2 = LogEntry.objects.filter(object_pk=str(job1.pk)).count()
if logs_t1_from_t2 == 0:
    print(f"✓ Audit logs correctly isolated (not visible in {tenant2.name})")
else:
    print(f"✗ AUDIT LOG LEAK: Found {logs_t1_from_t2} logs in Tenant 2")
```

**Pass Criteria**:
- [ ] Audit logs created in tenant schema
- [ ] Audit logs not visible in other tenants
- [ ] Log count: 0 in Tenant 2 for Tenant 1's object

**Result**: PASS / FAIL

---

## Test Group 9: Error Handling

### Test 9.1: Invalid Subdomain Handling
**Objective**: Verify proper error for invalid tenant

**Steps**:
1. Navigate to: `http://nonexistent.localhost:8084`
2. Observe response

**Pass Criteria**:
- [ ] Returns 404 page
- [ ] Message indicates tenant not found
- [ ] No server error (500)
- [ ] Secure error message (no sensitive info)

**Result**: PASS / FAIL

---

### Test 9.2: Database Error Recovery
**Objective**: Verify graceful handling of DB issues

**Steps**:
```bash
# Temporarily stop database
docker compose pause db

# Try to access app
curl http://test-tenant-1.localhost:8084/

# Should get error, not hang

# Resume database
docker compose unpause db

# Should work again
curl http://test-tenant-1.localhost:8084/
```

**Pass Criteria**:
- [ ] Returns 503 Service Unavailable during DB down
- [ ] Recovers after DB is back up
- [ ] No "connection reset" to client

**Result**: PASS / FAIL

---

## Test Group 10: Performance

### Test 10.1: Schema Switching Speed
**Objective**: Verify schema switching doesn't cause performance issues

**Python Code**:
```python
import time

# Measure schema switching time
times = []
for i in range(10):
    start = time.time()
    connection.set_schema(tenant1.schema_name)
    duration = (time.time() - start) * 1000  # Convert to ms
    times.append(duration)

avg_time = sum(times) / len(times)
max_time = max(times)

print(f"✓ Schema switching performance:")
print(f"  Average: {avg_time:.2f}ms")
print(f"  Maximum: {max_time:.2f}ms")
print(f"  Expected: < 10ms")

if avg_time < 10:
    print(f"✓ Performance acceptable")
else:
    print(f"✗ Performance degraded")
```

**Pass Criteria**:
- [ ] Average < 10ms per schema switch
- [ ] No timeouts
- [ ] Consistent performance

**Result**: PASS / FAIL

---

### Test 10.2: Query Performance
**Objective**: Verify queries don't have overhead

**Python Code**:
```python
import time
from django.test.utils import override_settings

# In tenant 1
connection.set_schema(tenant1.schema_name)

# Warm up
list(Job.objects.all())

# Time multiple queries
times = []
for i in range(5):
    start = time.time()
    list(Job.objects.filter(status='draft'))
    times.append((time.time() - start) * 1000)

avg_query_time = sum(times) / len(times)
print(f"✓ Query performance: {avg_query_time:.2f}ms average")

if avg_query_time < 50:
    print(f"✓ Performance acceptable")
```

**Pass Criteria**:
- [ ] Average query time < 50ms
- [ ] No N+1 queries
- [ ] Index usage verified

**Result**: PASS / FAIL

---

## Summary Report

### Test Results

| Test Group | Test | Result |
|-----------|------|--------|
| 1. Schema Separation | 1.1 Verify PostgreSQL Schemas | PASS / FAIL |
| 1. Schema Separation | 1.2 Verify Schema Contents | PASS / FAIL |
| 2. Data Isolation | 2.1 Create Data in Tenant 1 | PASS / FAIL |
| 2. Data Isolation | 2.2 Verify Data NOT in Tenant 2 | PASS / FAIL |
| 2. Data Isolation | 2.3 Verify Candidates Isolation | PASS / FAIL |
| 3. Subdomain Routing | 3.1 Access Tenant 1 | PASS / FAIL |
| 3. Subdomain Routing | 3.2 Access Tenant 2 | PASS / FAIL |
| 3. Subdomain Routing | 3.3 Data Separation in Browser | PASS / FAIL |
| 4. User Management | 4.1 Create User in Tenant 1 | PASS / FAIL |
| 4. User Management | 4.2 Create User in Tenant 2 | PASS / FAIL |
| 5. Permission System | 5.1 Permission Isolation | PASS / FAIL |
| 6. Cache Isolation | 6.1 Cache Is Tenant-Aware | PASS / FAIL |
| 7. API Access | 7.1 API Token Isolation | PASS / FAIL |
| 8. Audit Logging | 8.1 Audit Logs Isolated | PASS / FAIL |
| 9. Error Handling | 9.1 Invalid Subdomain | PASS / FAIL |
| 9. Error Handling | 9.2 Database Error Recovery | PASS / FAIL |
| 10. Performance | 10.1 Schema Switching Speed | PASS / FAIL |
| 10. Performance | 10.2 Query Performance | PASS / FAIL |

### Data Leaks Found
- [ ] No data leaks detected
- [ ] All isolation tests passed
- [ ] Cross-tenant access blocked

### Overall Status
- [ ] All tests PASSED - **PRODUCTION READY**
- [ ] Some tests FAILED - **REVIEW REQUIRED**
- [ ] Critical issues found - **DO NOT DEPLOY**

**Tested By**: ________________
**Test Date**: ________________
**Approved By**: ________________

---

## Cleanup After Testing

```bash
# Remove test data
docker compose exec web python manage.py shell << EOF
from tenants.models import Tenant, Domain

# Delete test tenants
Tenant.objects.filter(slug__startswith='test-tenant').delete()
Domain.objects.filter(domain__startswith='test-tenant').delete()

print("✓ Test data cleaned up")
EOF

# View remaining tenants
docker compose exec web python manage.py shell << EOF
from tenants.models import Tenant
print(f"Remaining tenants: {Tenant.objects.count()}")
for t in Tenant.objects.all():
    print(f"  - {t.name} ({t.slug})")
EOF
```

---

## References
- Docker setup: `docker-compose.yml`
- Tenant models: `tenants/models.py`
- Middleware: `tenants/middleware.py`
- Test plan: `MULTITENANCY_TEST_PLAN.md`
- Architecture: `MULTITENANCY_ARCHITECTURE_ANALYSIS.md`
