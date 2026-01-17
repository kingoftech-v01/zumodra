# Multi-Tenancy Isolation Testing Plan

## Overview
Comprehensive testing of Zumodra's multi-tenant isolation to ensure complete data separation, security, and proper routing between tenants.

## Test Environment
- **Database**: PostgreSQL 16 with PostGIS
- **Framework**: django-tenants (schema-based isolation)
- **Stack**: Django 5.2.7, Python 3.12
- **Testing Framework**: pytest with Django test client

## Test Cases

### 1. Schema-Based Tenant Separation
**Objective**: Verify tenants use separate schemas in PostgreSQL

**Test Steps**:
1. Create two test tenants (tenant-1, tenant-2)
2. Verify each tenant has a unique schema_name
3. Check PostgreSQL information_schema for schema existence
4. Verify schemas are isolated at database level

**Expected Results**:
- Each tenant has distinct schema_name (e.g., tenant_test_1, tenant_test_2)
- Schemas exist in PostgreSQL
- Schemas do not share data

**Success Criteria**: PASS

---

### 2. Data Isolation Between Tenants
**Objective**: Verify data created in one tenant is not visible in another

**Test Steps**:
1. Create Job in Tenant 1
2. Create different Job in Tenant 2
3. Switch to Tenant 1 schema
4. Query for Tenant 2's job by ID - should fail
5. Count jobs in each schema - should be different

**Expected Results**:
- Tenant 1 cannot access Tenant 2's Job
- Job.DoesNotExist exception raised
- Job counts differ between schemas

**Success Criteria**: PASS if cross-tenant access raises DoesNotExist

---

### 3. Cross-Tenant Data Leak Prevention
**Objective**: Prevent unauthorized access across tenant boundaries

**Test Steps**:
1. Create sensitive Candidate record in Tenant 1
2. Attempt to access from Tenant 2
3. Verify access is blocked
4. Check for any bypasses (direct SQL, cached data, etc.)

**Expected Results**:
- Cannot retrieve Candidate from Tenant 2
- No data leakage detected
- Proper error handling

**Success Criteria**: PASS - No cross-tenant access

---

### 4. Subdomain Routing to Correct Tenant
**Objective**: Verify HTTP requests to subdomains route to correct tenant

**Test Steps**:
1. Setup primary domain for Tenant 1: test-tenant-1.localhost
2. Setup primary domain for Tenant 2: test-tenant-2.localhost
3. Make HTTP request to each domain
4. Verify correct tenant schema is used
5. Check Domain model resolution

**Expected Results**:
- Domain correctly resolves to tenant
- Tenant context set in middleware
- Correct schema used for request

**Success Criteria**: PASS - Domains route correctly

---

### 5. Shared vs Tenant-Specific Tables
**Objective**: Verify database table classification is correct

**Shared Tables** (public schema):
- auth_user
- tenants_tenant
- tenants_domain
- tenants_plan
- django_site
- django_migration

**Tenant-Specific Tables** (tenant schema):
- ats_job
- ats_candidate
- ats_application
- hr_core_employee
- hr_core_timeoff
- services_listing
- etc.

**Test Steps**:
1. Switch to public schema
2. Query Tenant model - should work
3. Query Job model - should fail or be empty
4. Switch to tenant schema
5. Query Job model - should work

**Expected Results**:
- Shared tables accessible in public schema
- Tenant tables NOT in public schema
- Each tenant schema has full set of tenant tables

**Success Criteria**: PASS - Table separation correct

---

### 6. Tenant Switching for Staff Users
**Objective**: Verify staff/superusers can safely access multiple tenants

**Test Steps**:
1. Create superuser in public schema
2. Switch to Tenant 1 schema
3. Create test Job
4. Verify superuser can access Job 1
5. Switch to Tenant 2 schema
6. Verify superuser can access Job 2 (if exists)
7. Verify can't access Job 1 from Tenant 2

**Expected Results**:
- Staff can switch between tenant schemas
- Staff can ONLY access data in current schema
- No cross-tenant access even for staff

**Success Criteria**: PASS - Staff properly isolated

---

### 7. Database Query Filtering
**Objective**: Verify Django ORM properly filters queries by schema

**Test Steps**:
1. Create multiple jobs in Tenant 1
2. Create multiple jobs in Tenant 2
3. Run query in each schema
4. Verify result sets contain only tenant's data
5. Check for accidental UNION queries or joins

**Expected Results**:
- Tenant 1 queries only return Tenant 1 data
- Tenant 2 queries only return Tenant 2 data
- No mixed results
- Query counts match expected

**Success Criteria**: PASS - Queries properly filtered

---

### 8. Permission-Based Access Control
**Objective**: Verify RBAC respects tenant boundaries

**Test Steps**:
1. Create users in both tenants
2. Create RBAC permission groups
3. Grant permissions in Tenant 1 only
4. Try to access resource with permission from other tenant
5. Verify denial of access

**Expected Results**:
- Permissions are tenant-specific
- User from Tenant 1 cannot use Tenant 2 permissions
- Proper 403 Forbidden errors

**Success Criteria**: PASS - RBAC respects tenants

---

### 9. Audit Logging Isolation
**Objective**: Verify audit logs respect tenant boundaries

**Test Steps**:
1. Create and modify Job in Tenant 1
2. Check audit log location (LogEntry model)
3. Switch to Tenant 2
4. Verify Tenant 1's audit logs NOT visible
5. Create LogEntry in Tenant 2
6. Verify separate audit trails

**Expected Results**:
- Audit logs isolated by tenant
- No cross-tenant log visibility
- Modification history accurate per tenant

**Success Criteria**: PASS - Audit logs isolated

---

### 10. Cache Isolation
**Objective**: Verify tenant-aware caching prevents data leakage

**Test Steps**:
1. Create cache entry in Tenant 1
2. Cache key should include tenant identifier
3. Switch to Tenant 2
4. Attempt to retrieve Tenant 1's cache key
5. Should not retrieve data

**Expected Results**:
- Cache keys include tenant identifier
- No cross-tenant cache hits
- Cache properly cleared on tenant switch

**Success Criteria**: PASS - Cache isolated

---

### 11. WebSocket/Real-Time Messaging Isolation
**Objective**: Verify real-time messaging respects tenant boundaries

**Test Steps**:
1. Open WebSocket in Tenant 1 as User 1
2. Open WebSocket in Tenant 2 as User 2
3. Send message in Tenant 1
4. Verify User 2 (Tenant 2) doesn't receive it
5. Check channel layer routing

**Expected Results**:
- Messages only routed to same-tenant users
- WebSocket groups are tenant-specific
- No cross-tenant messages

**Success Criteria**: PASS - Messaging isolated

---

### 12. API Token Isolation
**Objective**: Verify JWT tokens are tenant-specific

**Test Steps**:
1. Create user and token in Tenant 1
2. Create user and token in Tenant 2
3. Use Tenant 1 token to call Tenant 2 API
4. Verify 403 Forbidden or request fails
5. Check token validation logic

**Expected Results**:
- Tokens are tenant-scoped
- Cannot use Tenant 1 token for Tenant 2 API
- Proper authentication failure

**Success Criteria**: PASS - Tokens isolated

---

### 13. Session Isolation
**Objective**: Verify user sessions are tenant-specific

**Test Steps**:
1. Login user in Tenant 1
2. Get session cookie
3. Switch to Tenant 2 URL
4. Use same session cookie
5. Verify redirect to login or 403

**Expected Results**:
- Sessions are tenant-scoped
- Cannot use Tenant 1 session for Tenant 2
- Proper session validation

**Success Criteria**: PASS - Sessions isolated

---

### 14. Bulk Operations Tenant Safety
**Objective**: Verify bulk operations don't affect other tenants

**Test Steps**:
1. Create multiple Jobs in Tenant 1
2. Perform bulk delete in Tenant 1
3. Switch to Tenant 2
4. Verify Tenant 2's Jobs still exist
5. Check delete counts

**Expected Results**:
- Bulk operations only affect current tenant
- No accidental deletions across tenants
- Transaction isolation maintained

**Success Criteria**: PASS - Bulk ops isolated

---

### 15. Form/Request Data Validation
**Objective**: Verify form submissions validate within tenant context

**Test Steps**:
1. Create Job with unique field in Tenant 1
2. Create Job with same unique field in Tenant 2
3. Both should succeed (different schemas)
4. Verify no false uniqueness violations

**Expected Results**:
- Unique constraints are tenant-scoped
- Can use same slug/reference in different tenants
- Validation respects schema boundaries

**Success Criteria**: PASS - Form validation tenant-aware

---

## Automation Scripts

### Docker-based Testing
```bash
# Start environment
docker compose up -d

# Run comprehensive test
docker compose exec web python test_multitenancy_isolation.py

# Run specific test category
docker compose exec web pytest tests/test_tenants/ -v

# Check database schemas
docker compose exec db psql -U postgres -d zumodra -c "\dn"

# Verify isolation
docker compose exec db psql -U postgres -d zumodra -c "SELECT schema_name FROM tenants_tenant;"
```

### Manual Testing Checklist

#### Subdomain Routing
```
1. Start: http://localhost:8084 (public)
2. Test: http://test-tenant-1.localhost:8084 (Tenant 1)
3. Test: http://test-tenant-2.localhost:8084 (Tenant 2)
4. Create job in each
5. Verify data separation in browser
```

#### Cross-Tenant Access Prevention
```
1. Login as User 1 in Tenant 1
2. Manually access Tenant 2 URL: test-tenant-2.localhost:8084/jobs/
3. Should redirect to login or show 404
4. Cannot see Tenant 2 data as Tenant 1 user
```

#### Staff Switching
```
1. Login as superuser
2. Navigate to Django admin
3. Use tenant switching feature
4. Switch between tenants
5. Verify can only see current tenant's data
```

---

## Reporting

### Report Format (JSON)
```json
{
  "summary": {
    "total_tests": 15,
    "passed": 15,
    "failed": 0,
    "success_rate": "100%",
    "data_leaks_found": 0,
    "errors": 0
  },
  "tests": [
    {
      "name": "schema_separation",
      "status": "PASS",
      "details": "..."
    }
  ],
  "data_leaks": [],
  "errors": []
}
```

### Report Location
- JSON: `tests_comprehensive/reports/multitenancy_isolation_test_report.json`
- Text: `tests_comprehensive/reports/multitenancy_isolation_test_report.txt`
- HTML: `tests_comprehensive/reports/multitenancy_isolation_test_report.html`

---

## Success Criteria

### For Production Readiness
- ✓ ALL 15 tests PASS
- ✓ ZERO data leaks found
- ✓ ZERO cross-tenant access
- ✓ All error handling tested
- ✓ Performance acceptable (< 100ms schema switching)

### For Development
- ✓ Minimum 80% tests passing
- ✓ Known issues documented
- ✓ Remediation plan in place

---

## Known Issues & Mitigations

### Issue 1: GDAL Library Not Found (Windows)
**Impact**: Cannot run tests on Windows without Docker
**Mitigation**: Use Docker for testing, or configure GDAL on Windows
**Status**: EXPECTED on local Windows dev

### Issue 2: Django Tenants Library Caching
**Impact**: Schema might remain cached between tests
**Mitigation**: Clear cache in teardown, use transaction rollback
**Status**: HANDLED in test teardown

### Issue 3: Race Conditions in Concurrent Access
**Impact**: Multi-threaded access might cause schema mismatches
**Mitigation**: Use thread-local storage for tenant context
**Status**: HANDLED by django-tenants

---

## References
- django-tenants: https://django-tenants.readthedocs.io/
- Zumodra CLAUDE.md: Multi-tenancy section
- PostgreSQL Schemas: https://www.postgresql.org/docs/current/ddl-schemas.html
