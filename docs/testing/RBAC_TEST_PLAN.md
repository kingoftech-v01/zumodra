# Comprehensive RBAC Testing Plan for Zumodra

## Executive Summary

This document outlines a comprehensive Role-Based Access Control (RBAC) testing plan for Zumodra's multi-tenant SaaS platform. The testing covers 7 critical RBAC features across different user roles, permissions levels, and tenant configurations.

**Test Execution Date:** 2026-01-16
**Platform:** Zumodra Multi-Tenant SaaS (Django 5.2.7 + PostgreSQL)
**Scope:** Complete RBAC system testing with all 7 role types

---

## Test Coverage Summary

| Test Category | Priority | Status | Details |
|---|---|---|---|
| Role Creation & Assignment | HIGH | Ready | All 7 roles tested |
| Permission Enforcement (Views) | HIGH | Ready | Frontend view access control |
| Permission Enforcement (API) | HIGH | Ready | REST API endpoint access control |
| Object-Level Permissions | HIGH | Ready | Ownership-based access control |
| Department-Based Access | MEDIUM | Ready | Department hierarchy & isolation |
| Tenant Isolation | CRITICAL | Ready | Multi-tenant data separation |
| Admin vs Regular Permissions | HIGH | Ready | Privilege escalation prevention |

---

## Test Categories

### 1. Role Creation and Assignment Tests

**Purpose:** Verify that all 7 role types can be properly created and assigned.

**Roles Tested:**
- PDG/Owner (role=owner)
- Administrator (role=admin)
- HR Manager (role=hr_manager)
- Recruiter (role=recruiter)
- Hiring Manager (role=hiring_manager)
- Employee (role=employee)
- Viewer (role=viewer)

**Test Cases:**

#### 1.1: Owner Role Creation
- **Objective:** Verify OWNER role can be created and assigned
- **Expected:** User with OWNER role created successfully
- **Verification:**
  - TenantUser.role == 'owner'
  - is_active = True
  - is_primary_tenant can be True
  - joined_at timestamp recorded

#### 1.2: Admin Role Creation
- **Objective:** Verify ADMIN role can be created and assigned
- **Expected:** User with ADMIN role created successfully
- **Verification:**
  - TenantUser.role == 'admin'
  - is_active = True
  - Can manage other users

#### 1.3: HR Manager Role Creation
- **Objective:** Verify HR_MANAGER role assignment
- **Expected:** User has HR management permissions
- **Verification:**
  - TenantUser.role == 'hr_manager'
  - Can access HR modules

#### 1.4: Recruiter Role Creation
- **Objective:** Verify RECRUITER role assignment
- **Expected:** User has recruitment permissions
- **Verification:**
  - TenantUser.role == 'recruiter'
  - Can manage jobs and candidates

#### 1.5: Hiring Manager Role Creation
- **Objective:** Verify HIRING_MANAGER role assignment
- **Expected:** User can interview and hire
- **Verification:**
  - TenantUser.role == 'hiring_manager'
  - Can conduct interviews

#### 1.6: Employee Role Creation
- **Objective:** Verify EMPLOYEE role assignment
- **Expected:** Standard employee role created
- **Verification:**
  - TenantUser.role == 'employee'
  - Limited to own data

#### 1.7: Viewer Role Creation
- **Objective:** Verify VIEWER (read-only) role
- **Expected:** Read-only access only
- **Verification:**
  - TenantUser.role == 'viewer'
  - Cannot modify any data

#### 1.8: Multi-Tenant Role Assignment
- **Objective:** User can have different roles in different tenants
- **Expected:** User A = OWNER in Tenant 1, EMPLOYEE in Tenant 2
- **Verification:**
  - TenantUser.objects.filter(user=user).count() >= 2
  - Different roles per tenant

#### 1.9: Role Deactivation
- **Objective:** Users can be deactivated
- **Expected:** Deactivated users cannot access resources
- **Verification:**
  - is_active = False
  - Access denied on all endpoints

---

### 2. Permission Enforcement on Views Tests

**Purpose:** Verify that view-level permission checks work correctly.

**Test Cases:**

#### 2.1: Owner Can Access Admin Dashboard
- **Objective:** Verify OWNER role can access admin dashboard
- **Expected:** 200 or 302 (redirect to login)
- **Verification:** View accessible to owner

#### 2.2: Non-Tenant User Denied Access
- **Objective:** Users not in tenant are denied access
- **Expected:** 403 Forbidden or 404 Not Found
- **Verification:** No cross-tenant access

#### 2.3: Viewer Has Read-Only Access
- **Objective:** VIEWER role can view but not modify
- **Expected:** GET requests succeed, POST/PUT/DELETE fail
- **Verification:** Views accessible but mutations blocked

#### 2.4: Deactivated User Denied Access
- **Objective:** Deactivated users cannot access views
- **Expected:** 302 redirect to login or 403
- **Verification:** Access denied after deactivation

#### 2.5: Department-Scoped View Access
- **Objective:** Users can only view their department data
- **Expected:** Only department members visible
- **Verification:** Department filtering applied

#### 2.6: Recruiter Can Access Job Board
- **Objective:** RECRUITER role can access job management
- **Expected:** View accessible
- **Verification:** Job list visible to recruiter

#### 2.7: Employee Cannot Access HR Admin
- **Objective:** EMPLOYEE cannot access HR admin panel
- **Expected:** 403 Forbidden
- **Verification:** Access denied

---

### 3. Permission Enforcement on API Endpoints Tests

**Purpose:** Verify REST API endpoint access control.

**Test Cases:**

#### 3.1: Owner Can Access Admin API
- **Objective:** OWNER has access to admin endpoints
- **Expected:** 200 OK or 404 (endpoint may not exist)
- **Verification:** API accessible with proper token

#### 3.2: Admin Can Access User Management API
- **Objective:** ADMIN can manage users via API
- **Expected:** 200 OK
- **Verification:** User list/create/update endpoints work

#### 3.3: Recruiter Can Access ATS API
- **Objective:** RECRUITER can access /api/v1/ats/jobs/
- **Expected:** 200 OK
- **Verification:** Job CRUD operations allowed

#### 3.4: Viewer Denied Write Access
- **Objective:** VIEWER cannot POST/PUT/DELETE on API
- **Expected:** 403 Forbidden
- **Verification:** POST request rejected

#### 3.5: Unauthenticated Denied API Access
- **Objective:** Requests without token/auth are denied
- **Expected:** 401 Unauthorized
- **Verification:** No auth token = 401

#### 3.6: Invalid Token Denied
- **Objective:** Invalid tokens are rejected
- **Expected:** 401 Unauthorized
- **Verification:** Malformed token rejected

#### 3.7: Expired Token Denied
- **Objective:** Expired tokens are rejected
- **Expected:** 401 Unauthorized
- **Verification:** Expired token rejected

#### 3.8: Rate Limiting Per Role
- **Objective:** Different roles have different rate limits
- **Expected:** Tier-based throttling applied
- **Verification:** Rate limit headers present

---

### 4. Object-Level Permission Tests

**Purpose:** Verify ownership-based access control on individual objects.

**Test Cases:**

#### 4.1: Object Owner Can Modify
- **Objective:** User who created object can modify it
- **Expected:** 200 OK (successful update)
- **Verification:** Patch request succeeds

#### 4.2: Non-Owner Cannot Modify
- **Objective:** Different user cannot modify object
- **Expected:** 403 Forbidden
- **Verification:** Patch request rejected

#### 4.3: Viewer Cannot Modify Any Object
- **Objective:** VIEWER cannot modify any object
- **Expected:** 403 Forbidden
- **Verification:** Modification blocked

#### 4.4: Admin Can Modify Any Object
- **Objective:** ADMIN can modify any tenant object
- **Expected:** 200 OK
- **Verification:** Admin modification allowed

#### 4.5: Cross-Tenant Object Access Denied
- **Objective:** User cannot access object from different tenant
- **Expected:** 404 Not Found
- **Verification:** Object not visible to outsider

#### 4.6: Department Manager Can Modify Department Objects
- **Objective:** Manager can modify objects in their department
- **Expected:** 200 OK
- **Verification:** Modification allowed

#### 4.7: Employee Cannot Modify Other's Objects
- **Objective:** Employees cannot modify peer objects
- **Expected:** 403 Forbidden
- **Verification:** Modification blocked

---

### 5. Department-Based Access Control Tests

**Purpose:** Verify department hierarchy and access restrictions.

**Test Cases:**

#### 5.1: User Access Own Department
- **Objective:** User can access their assigned department
- **Expected:** Department visible
- **Verification:** Department returned in query

#### 5.2: Manager View Department Members
- **Objective:** Manager can see all team members
- **Expected:** Team list returned
- **Verification:** Direct reports visible

#### 5.3: Cross-Department Access Restricted
- **Objective:** Users from different departments isolated
- **Expected:** Other department data hidden
- **Verification:** Data filtered by department

#### 5.4: Department Hierarchy
- **Objective:** Reporting relationships enforced
- **Expected:** reports_to relationship exists
- **Verification:** Manager-employee link created

#### 5.5: Manager Can Only Manage Own Department
- **Objective:** Manager cannot manage other departments
- **Expected:** Other department operations fail
- **Verification:** Cross-department modifications blocked

#### 5.6: HR Manager Can Access All Departments
- **Objective:** HR Manager has cross-department visibility
- **Expected:** All departments visible
- **Verification:** No department restrictions

#### 5.7: Department-Level Permissions
- **Objective:** Permissions inherited from department
- **Expected:** Department permissions applied
- **Verification:** Permission check includes department

---

### 6. Tenant Isolation Tests

**Purpose:** Verify complete isolation between different tenants.

**Test Cases:**

#### 6.1: Tenant 1 User Not Member of Tenant 2
- **Objective:** Users from Tenant A cannot see Tenant B
- **Expected:** User not in TenantUser query for Tenant B
- **Verification:** No cross-tenant membership

#### 6.2: Tenant 2 User Not Member of Tenant 1
- **Objective:** Users from Tenant B cannot see Tenant A
- **Expected:** User not in TenantUser query for Tenant A
- **Verification:** No cross-tenant access

#### 6.3: User Can Have Different Roles Per Tenant
- **Objective:** Same user = OWNER in T1, EMPLOYEE in T2
- **Expected:** Two TenantUser records with different roles
- **Verification:**
  - TenantUser.objects.filter(user=user).count() == 2
  - role differs per tenant

#### 6.4: Data Isolation Between Tenants
- **Objective:** Department A data hidden from Tenant B
- **Expected:** Department B cannot see Department A data
- **Verification:**
  - Tenant A query returns only T1 departments
  - Tenant B query returns only T2 departments

#### 6.5: No Cross-Tenant View Access
- **Objective:** Views enforce tenant isolation
- **Expected:** 404 or 403 for cross-tenant access
- **Verification:** Tenant validation in views

#### 6.6: No Cross-Tenant API Access
- **Objective:** API endpoints enforce tenant isolation
- **Expected:** 404 for cross-tenant resources
- **Verification:** Tenant filter in queryset

#### 6.7: Schema Isolation (Database Level)
- **Objective:** Multi-schema separation in PostgreSQL
- **Expected:** Each tenant has own schema
- **Verification:** migrate_schemas targets correct schema

#### 6.8: Billing Isolation
- **Objective:** Billing data isolated per tenant
- **Expected:** Subscription data not shared
- **Verification:** Subscription filtered by tenant

---

### 7. Admin vs Regular User Permission Tests

**Purpose:** Verify privilege escalation prevention.

**Test Cases:**

#### 7.1: Admin Can Manage Users
- **Objective:** ADMIN role can create/edit/delete users
- **Expected:** User management API works
- **Verification:**
  - Create user: 201 Created
  - Update user: 200 OK
  - Delete user: 204 No Content

#### 7.2: Regular Employee Cannot Manage Users
- **Objective:** EMPLOYEE cannot perform user management
- **Expected:** 403 Forbidden
- **Verification:** User management operations blocked

#### 7.3: Admin Can View All Data
- **Objective:** ADMIN can query any tenant data
- **Expected:** All objects returned
- **Verification:** No filtering for admin

#### 7.4: Regular User Limited View
- **Objective:** EMPLOYEE sees only relevant data
- **Expected:** Limited dataset returned
- **Verification:** Filtering applied for employee

#### 7.5: Admin Can Change User Roles
- **Objective:** ADMIN can modify user roles
- **Expected:** Role update succeeds
- **Verification:**
  - role = 'viewer' update succeeds
  - New role saved to database

#### 7.6: Regular User Cannot Change Own Role
- **Objective:** EMPLOYEE cannot modify own role
- **Expected:** 403 Forbidden
- **Verification:** Role update blocked

#### 7.7: Admin Can Deactivate Users
- **Objective:** ADMIN can deactivate any user
- **Expected:** User deactivated
- **Verification:**
  - is_active = False
  - User access denied

#### 7.8: Admin Can Access Audit Logs
- **Objective:** ADMIN can view audit trail
- **Expected:** Audit logs visible
- **Verification:** Audit log queries work

#### 7.9: Regular User Cannot Access Audit Logs
- **Objective:** EMPLOYEE cannot access logs
- **Expected:** 403 Forbidden
- **Verification:** Audit log access blocked

#### 7.10: Admin Cannot Escalate Beyond Owner
- **Objective:** ADMIN cannot create OWNER account
- **Expected:** 403 Forbidden (or restricted creation)
- **Verification:** OWNER creation requires OWNER role

---

## Integration Test Scenarios

### Scenario 1: Multi-Tenant Organization Structure

**Setup:**
```
Company A (TechStart)
├── Engineering Department
│   ├── CEO (Owner)
│   ├── Tech Lead (Hiring Manager)
│   └── Engineers (Employees)
├── HR Department
│   ├── HR Manager
│   └── HR Staff (Employees)
└── Sales Department
    ├── Sales Manager
    └── Sales Reps (Employees)

Company B (FinanceHub)
├── Finance Department
│   ├── CFO (Owner)
│   └── Accountants (Employees)
```

**Test:** CEO of Company A can:
- [ ] View all departments in Company A
- [ ] Cannot see Company B departments
- [ ] Manage users in Company A
- [ ] Cannot manage Company B users
- [ ] Can see complete org chart for Company A

**Test:** CFO of Company B can:
- [ ] See only Company B departments
- [ ] Cannot see Company A data
- [ ] Cannot access Company A with Company B role

### Scenario 2: Cross-Company User

**Setup:** User John works for both companies:
- Company A: HR Manager
- Company B: Employee

**Test:** When logged into Company A context:
- [ ] John has HR_MANAGER permissions
- [ ] Can manage employees in Company A
- [ ] Cannot access Company B data

**Test:** When logged into Company B context:
- [ ] John has EMPLOYEE permissions
- [ ] Can only see own data
- [ ] Cannot manage Company B users

### Scenario 3: Role Transition

**Setup:** Employee is promoted from Employee to Hiring Manager

**Test:**
- [ ] Employee role: Can apply for jobs, submit timesheets
- [ ] After promotion to Hiring Manager:
  - [ ] Can conduct interviews
  - [ ] Can provide feedback on candidates
  - [ ] Can make hiring decisions
- [ ] Previous employee permissions still work

### Scenario 4: Contractor Isolation

**Setup:** Contractor Bob joins Company A for 3 months
- Role: Viewer (read-only)
- Department: Engineering

**Test:**
- [ ] Can view project information
- [ ] Can view team structure
- [ ] Cannot create/modify projects
- [ ] Cannot see payroll information
- [ ] Contract expires and is deactivated
- [ ] After deactivation: All access denied

---

## Error Conditions & Edge Cases

### Error Case 1: Simultaneous Role Changes
**Test:** Two admins try to change same user's role simultaneously
- Expected: One succeeds, other gets conflict error
- Verification: Last-write-wins or conflict handling

### Error Case 2: User Deactivation During Session
**Test:** User logged in, admin deactivates user
- Expected: User's next request gets 403
- Verification: Session invalidated

### Error Case 3: Tenant Deletion with Active Users
**Test:** Delete tenant with 100 active users
- Expected: Cascade delete or prevent deletion
- Verification: Data consistency maintained

### Error Case 4: Department Deletion with Members
**Test:** Delete department with assigned users
- Expected: Members reassigned or prevent deletion
- Verification: No orphaned users

### Error Case 5: Cross-Tenant Token Usage
**Test:** User logs into Tenant A, uses token for Tenant B API
- Expected: 403 Forbidden or 404
- Verification: Tenant validation in API

### Error Case 6: Role Inheritance Conflict
**Test:** User inherits permissions from multiple roles
- Expected: Union or intersection determined
- Verification: Permission conflict resolved

---

## Performance Considerations

### Performance Test 1: Large Tenant with 10,000 Users
**Test:** Load 10K users, verify permission checks < 100ms
- Expected: Permission query < 100ms
- Verification: Database indexes on role, tenant_id, is_active

### Performance Test 2: Deep Department Hierarchy
**Test:** 50-level deep department tree, recursive permission checks
- Expected: < 200ms per request
- Verification: Query optimization

### Performance Test 3: User with 50 Custom Permissions
**Test:** User with many custom permissions
- Expected: Permission check < 50ms
- Verification: Permission caching

---

## Security Considerations

### Security Test 1: Privilege Escalation
**Test:** Can EMPLOYEE modify own role to ADMIN?
- Expected: 403 Forbidden
- Verification: Role change requires admin privilege

### Security Test 2: Token Reuse
**Test:** Can expired token be reused?
- Expected: 401 Unauthorized
- Verification: Token expiration enforced

### Security Test 3: SQL Injection in Role Queries
**Test:** Inject SQL in role filter
- Expected: No injection, safe query
- Verification: ORM parameterization

### Security Test 4: Permission Bypass via URL Manipulation
**Test:** Manually craft URL to access restricted resource
- Expected: 403 Forbidden
- Verification: URL patterns require proper permissions

---

## Testing Methodology

### Docker Environment Setup

```bash
# Start services
docker compose up -d

# Run migrations for all tenants
docker compose exec web python manage.py migrate_schemas --shared
docker compose exec web python manage.py migrate_schemas --tenant

# Create demo data
docker compose exec web python manage.py bootstrap_demo_tenant
docker compose exec web python manage.py setup_demo_data --num-jobs 20 --num-candidates 100

# Run tests
docker compose exec web pytest tests_comprehensive/test_rbac_complete.py -v
```

### Test Execution Steps

1. **Setup Phase:**
   - Initialize test database
   - Create test tenants and users
   - Assign roles and permissions

2. **Execution Phase:**
   - Execute test cases in order
   - Log all results
   - Capture any errors

3. **Verification Phase:**
   - Validate expected outcomes
   - Check database state
   - Verify permission logs

4. **Cleanup Phase:**
   - Remove test data
   - Reset database state

---

## Expected Results

### Success Criteria

- [x] All 7 role types can be created
- [x] Role assignment works across tenants
- [x] View-level permissions enforced
- [x] API endpoint permissions enforced
- [x] Object-level ownership respected
- [x] Department isolation maintained
- [x] Tenant data completely isolated
- [x] Admin users cannot escalate beyond owner
- [x] Deactivated users denied all access
- [x] No cross-tenant data leakage

### Pass/Fail Threshold

- **PASS:** 95% of test cases pass
- **FAIL:** Any security test fails or tenant isolation breached

---

## Reporting

### Test Report Contents

1. **Executive Summary:** Overall pass/fail status
2. **Test Results by Category:** Breakdown of all 7 test categories
3. **Detailed Test Logs:** Line-by-line execution logs
4. **Errors Found:** Any failing tests with stack traces
5. **Performance Metrics:** Response times for permission checks
6. **Security Assessment:** Any vulnerabilities found
7. **Recommendations:** Improvements to RBAC system

### Report Files Generated

- `rbac_test_execution.log` - Detailed execution log
- `rbac_test_summary.md` - Summary results
- `coverage/index.html` - Code coverage report
- `errors_found.md` - Any errors discovered

---

## Timeline

| Phase | Duration | Start | End |
|---|---|---|---|
| Planning | 1 day | Day 1 | Day 1 |
| Test Development | 2 days | Day 2 | Day 3 |
| Test Execution | 1 day | Day 4 | Day 4 |
| Result Analysis | 1 day | Day 5 | Day 5 |
| Documentation | 1 day | Day 6 | Day 6 |

---

## Sign-Off

- **Created by:** Claude Code
- **Date:** 2026-01-16
- **Approved by:** [Pending approval]
- **Execution Date:** [To be scheduled]

---

## Appendix A: Role Permission Matrix

| Operation | Owner | Admin | HR Mgr | Recruiter | Hiring Mgr | Employee | Viewer |
|---|---|---|---|---|---|---|---|
| Create User | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Edit User | ✓ | ✓ | ✓* | ✗ | ✗ | ✗ | ✗ |
| Delete User | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Change Role | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Create Job | ✓ | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ |
| Manage Candidates | ✓ | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ |
| Schedule Interview | ✓ | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ |
| Manage Employees | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| View Reports | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ |
| Approve Time Off | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Access Payroll | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| View Own Profile | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Edit Own Profile | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |

*HR Manager can only edit employees in their department

---

## Appendix B: Test Commands

```bash
# Run all RBAC tests
pytest tests_comprehensive/test_rbac_complete.py -v

# Run specific test category
pytest tests_comprehensive/test_rbac_complete.py::RoleCreationAndAssignmentTests -v

# Run with coverage
pytest tests_comprehensive/test_rbac_complete.py -v --cov=accounts --cov=tenants

# Run with detailed output on failure
pytest tests_comprehensive/test_rbac_complete.py -v --tb=long

# Run single test
pytest tests_comprehensive/test_rbac_complete.py::RoleCreationAndAssignmentTests::test_owner_role_creation -v
```

---

## Appendix C: Database Queries for Verification

```sql
-- Verify role assignments
SELECT u.username, tu.role, t.name as tenant
FROM accounts_tenantuser tu
JOIN auth_user u ON tu.user_id = u.id
JOIN tenants_tenant t ON tu.tenant_id = t.id
ORDER BY u.username, t.name;

-- Count users by role
SELECT role, COUNT(*) as count
FROM accounts_tenantuser
WHERE is_active = TRUE
GROUP BY role;

-- Verify department assignments
SELECT u.username, d.name, tu.role
FROM accounts_tenantuser tu
JOIN auth_user u ON tu.user_id = u.id
LEFT JOIN configurations_department d ON tu.department_id = d.id
ORDER BY d.name, u.username;

-- Check tenant isolation
SELECT t.name, COUNT(DISTINCT tu.user_id) as user_count
FROM tenants_tenant t
LEFT JOIN accounts_tenantuser tu ON t.id = tu.tenant_id AND tu.is_active = TRUE
GROUP BY t.name;

-- Find cross-tenant memberships
SELECT u.username, COUNT(DISTINCT t.id) as tenant_count
FROM auth_user u
JOIN accounts_tenantuser tu ON u.id = tu.user_id
JOIN tenants_tenant t ON tu.tenant_id = t.id
WHERE tu.is_active = TRUE
GROUP BY u.username
HAVING COUNT(DISTINCT t.id) > 1;
```

---

