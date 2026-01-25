# All Errors Found - Fix Checklist

**Date:** January 11, 2026
**Environment:** Docker Development
**Status:** Needs fixes before production

---

## 🔴 CRITICAL ERRORS - Fix Immediately

### Error #1: Organization Membership Missing (18 endpoints affected)

**Error Message:**
```
403 Forbidden
{"detail": "You must be a member of this organization to access this resource."}
```

**Affected Endpoints:**
- `/api/v1/jobs/jobs/` - GET
- `/api/v1/jobs/candidates/` - GET
- `/api/v1/jobs/applications/` - GET
- `/api/v1/jobs/interviews/` - GET
- `/api/v1/jobs/offers/` - GET
- `/api/v1/jobs/pipelines/` - GET
- `/api/v1/services/services/` - GET
- `/api/v1/services/providers/` - GET
- `/api/v1/services/contracts/` - GET
- `/api/v1/services/reviews/` - GET
- `/api/v1/finance/subscriptions/` - GET
- `/api/v1/finance/invoices/` - GET

**Root Cause:**
The authenticated user (admin@demo.localhost) is not properly linked to an organization within the demo-company tenant. The permission system checks for organization membership, but the TenantUser or Organization relationship is missing or improperly configured.

**Files to Check:**
- `accounts/models.py` - TenantUser model
- `api/permissions.py` - IsMemberOfOrganization permission class
- `accounts/management/commands/create_superuser_for_tenant.py` - User creation logic

**Fix Steps:**
```python
# 1. Check the permission class
# File: api/permissions.py or accounts/permissions.py
# Look for: IsMemberOfOrganization or similar

# 2. Verify TenantUser relationship
docker compose exec web python manage.py shell
>>> from tenant_profiles.models import TenantUser
>>> from custom_account_u.models import User
>>> from tenants.models import Tenant
>>>
>>> user = User.objects.get(email='admin@demo.localhost')
>>> tenant = Tenant.objects.get(schema_name='demo-company')
>>> tu = TenantUser.objects.filter(user=user, tenant=tenant)
>>> print(f"TenantUser exists: {tu.exists()}")
>>> print(f"Is active: {tu.first().is_active if tu.exists() else 'N/A'}")
>>> print(f"Role: {tu.first().role if tu.exists() else 'N/A'}")

# 3. Check if Organization model exists and relationship
>>> from tenant_profiles.models import Organization  # Adjust import as needed
>>> org = Organization.objects.filter(tenant=tenant).first()
>>> if org:
>>>     print(f"Organization: {org.name}")
>>>     # Check if user is member of organization
>>>     # (This depends on your organization membership model)

# 4. If missing, create the relationship
# This depends on your specific models, but typically:
>>> if not tu.exists():
>>>     TenantUser.objects.create(
>>>         user=user,
>>>         tenant=tenant,
>>>         role='owner',
>>>         is_active=True
>>>     )
```

**Action Required:**
- [ ] Identify the exact permission class causing the error
- [ ] Verify TenantUser relationship exists and is active
- [ ] Check if an Organization model exists and user needs to be linked
- [ ] Update user creation command to properly create all required relationships
- [ ] Add validation in user creation to ensure organization membership

**Priority:** 🔴 CRITICAL - Blocks 72% of API functionality

---

### Error #2: HR Core 500 Internal Server Errors (3 endpoints)

**Error Message:**
```
500 Internal Server Error
ProgrammingError or AttributeError (need to check logs)
```

**Affected Endpoints:**
- `/api/v1/hr/employees/` - GET
- `/api/v1/hr/time-off-requests/` - GET
- `/api/v1/hr/performance-reviews/` - GET

**Files to Check:**
- `hr_core/api/viewsets.py`
- `hr_core/models.py`
- `hr_core/serializers.py`

**Debug Steps:**
```bash
# 1. Get full error logs
docker compose logs web | grep -A100 "hr/employees" > hr_errors.log
docker compose logs web | grep -A100 "time-off" >> hr_errors.log
docker compose logs web | grep -A100 "performance-reviews" >> hr_errors.log

# 2. Common issues to check:
# - Missing select_related() or prefetch_related() causing N+1 queries
# - Accessing relationships that don't exist
# - Missing fields in serializers
# - Incorrect queryset filters
# - Tenant schema not being switched properly
```

**Likely Causes:**
1. Database query trying to access a relationship that doesn't exist
2. Serializer referencing fields not in the model
3. Permission check failing on a non-existent field
4. Tenant context not properly set in multi-tenant environment

**Action Required:**
- [ ] Extract full stack trace from Docker logs
- [ ] Identify the exact line causing the error
- [ ] Fix the database query or model relationship
- [ ] Test with proper error handling
- [ ] Add try-except blocks to prevent future 500 errors

**Priority:** 🔴 CRITICAL - Entire HR module unusable

---

### Error #3: Messages 500 Internal Server Errors (2 endpoints)

**Error Message:**
```
500 Internal Server Error
```

**Affected Endpoints:**
- `/api/v1/messages/conversations/` - GET
- `/api/v1/messages/messages/` - GET

**Files to Check:**
- `messages_sys/api/viewsets.py`
- `messages_sys/models.py`
- `messages_sys/serializers.py`

**Debug Steps:**
```bash
# Get error logs
docker compose logs web | grep -A100 "messages/conversations" > messages_errors.log
docker compose logs web | grep -A100 "messages/messages" >> messages_errors.log

# Check if WebSocket consumers are interfering
docker compose logs channels | grep ERROR
```

**Likely Causes:**
1. Trying to access conversation participants incorrectly
2. User relationship not properly set up
3. Tenant filtering issue in multi-tenant context
4. WebSocket-related model fields being accessed in REST API

**Action Required:**
- [ ] Extract full stack trace
- [ ] Verify Message and Conversation model relationships
- [ ] Check serializer for proper field definitions
- [ ] Test conversation creation and retrieval
- [ ] Ensure tenant isolation is working

**Priority:** 🔴 CRITICAL - Real-time messaging completely broken

---

### Error #4: Careers Public API 500 Error (1 endpoint)

**Error Message:**
```
500 Internal Server Error
ProgrammingError
```

**Affected Endpoint:**
- `/api/v1/careers/jobs/` - GET (PUBLIC ENDPOINT!)

**Impact:** 🔴 SEVERE - Public job listings broken, affects external users

**Files to Check:**
- `careers/api/viewsets.py`
- `careers/models.py`
- `careers/serializers.py`

**Debug Steps:**
```bash
# Get error logs
docker compose logs web | grep -A100 "careers/jobs" > careers_errors.log

# Check database tables
docker compose exec web python manage.py shell
>>> from careers.models import Job
>>> Job.objects.count()  # This will likely fail with the same error
```

**Likely Causes:**
1. Database table doesn't exist in public schema
2. Trying to access tenant-specific data from public endpoint
3. Missing column in database
4. Schema routing issue (trying to query wrong schema)

**Special Consideration:**
This is a PUBLIC endpoint - it should work WITHOUT authentication and should show jobs across all tenants (or public jobs only). Need to verify:
- Should jobs be in public schema or tenant schemas?
- How should public job listings work in multi-tenant architecture?
- Should there be a separate public jobs table?

**Action Required:**
- [ ] Extract full error and stack trace
- [ ] Determine if careers should be public schema or tenant schema
- [ ] Fix database query to work with correct schema
- [ ] Add proper filtering for public/private jobs
- [ ] Test without authentication

**Priority:** 🔴 CRITICAL - Public-facing feature broken

---

## 🟡 HIGH PRIORITY ERRORS - Fix This Week

### Error #5: Missing API Endpoint - HR Documents

**Error Message:**
```
404 Not Found
```

**Affected Endpoint:**
- `/api/v1/hr/documents/` - GET

**Root Cause:**
DocumentViewSet not registered in API router

**Files to Fix:**
- `hr_core/api/urls.py`

**Fix:**
```python
# hr_core/api/urls.py
from rest_framework.routers import DefaultRouter
from .viewsets import DocumentViewSet  # Add this import

router = DefaultRouter()
# Add this line:
router.register(r'documents', DocumentViewSet, basename='document')
```

**Action Required:**
- [ ] Add DocumentViewSet import
- [ ] Register in router
- [ ] Test endpoint returns 200 (or 403 if org membership issue)
- [ ] Verify serializer and permissions are correct

**Priority:** 🟡 HIGH - Missing feature

---

### Error #6: Missing API Endpoint - Finance Transactions

**Error Message:**
```
404 Not Found
```

**Affected Endpoint:**
- `/api/v1/finance/transactions/` - GET

**Root Cause:**
TransactionViewSet not registered in API router

**Files to Fix:**
- `finance/api/urls.py`

**Fix:**
```python
# finance/api/urls.py
from rest_framework.routers import DefaultRouter
from .viewsets import PaymentTransactionViewSet  # Add this import

router = DefaultRouter()
# Add this line:
router.register(r'transactions', PaymentTransactionViewSet, basename='transaction')
```

**Action Required:**
- [ ] Add PaymentTransactionViewSet import (check exact class name)
- [ ] Register in router
- [ ] Test endpoint
- [ ] Verify Stripe integration doesn't break

**Priority:** 🟡 HIGH - Payment tracking unavailable

---

### Error #7: Missing API Endpoint - Analytics Reports

**Error Message:**
```
404 Not Found
```

**Affected Endpoint:**
- `/api/v1/analytics/reports/` - GET

**Root Cause:**
ReportsViewSet not registered in API router

**Files to Fix:**
- `analytics/api/urls.py`

**Fix:**
```python
# analytics/api/urls.py
from rest_framework.routers import DefaultRouter
from .viewsets import ReportViewSet  # Add this import

router = DefaultRouter()
# Add this line:
router.register(r'reports', ReportViewSet, basename='report')
```

**Action Required:**
- [ ] Check if ReportViewSet exists (may need to create it)
- [ ] Register in router
- [ ] Define what reports should return
- [ ] Test endpoint

**Priority:** 🟡 HIGH - Analytics incomplete

---

### Error #8: Missing API Endpoint - Careers Applications

**Error Message:**
```
404 Not Found
```

**Affected Endpoint:**
- `/api/v1/careers/applications/` - GET

**Root Cause:**
ApplicationViewSet not registered in API router

**Files to Fix:**
- `careers/api/urls.py`

**Fix:**
```python
# careers/api/urls.py
from rest_framework.routers import DefaultRouter
from .viewsets import ApplicationViewSet  # Add this import

router = DefaultRouter()
# Add this line:
router.register(r'applications', ApplicationViewSet, basename='application')
```

**Action Required:**
- [ ] Add ApplicationViewSet import
- [ ] Register in router
- [ ] Test endpoint
- [ ] Verify it works with public careers flow

**Priority:** 🟡 HIGH - Public application flow broken

---

## 🟢 MEDIUM PRIORITY - URL Routing Issues

### Error #9: Notifications Returning HTML Instead of JSON

**Error:** Endpoints return 200 with HTML instead of requiring authentication

**Affected Endpoints:**
- `/api/v1/notifications/` - Returns HTML (should return JSON)
- `/api/v1/notifications/preferences/` - Returns HTML (should return JSON)

**Note:** These endpoints ARE working and returning data, but they might be hitting frontend views instead of API views. Need to verify URL routing is correct.

**Files to Check:**
- `zumodra/urls.py` - Main URL configuration
- `notifications/urls.py` - Notifications URLs
- `api/urls_v1.py` - API v1 URLs

**Fix:**
```python
# Ensure API patterns come BEFORE frontend patterns in zumodra/urls.py
urlpatterns = [
    path('api/', include('api.urls')),  # Must be BEFORE frontend patterns
    path('', include('frontend.urls')),  # Frontend should be last
]
```

**Action Required:**
- [ ] Verify URL pattern order
- [ ] Check if `/api/v1/notifications/` actually returns JSON or HTML
- [ ] Test that API namespace is properly isolated
- [ ] If returning HTML, fix routing

**Priority:** 🟢 MEDIUM - Works but may have configuration issue

---

### Error #10: Analytics Dashboard Routing (Same as #9)

**Error:** Returns 200 with HTML/data instead of requiring authentication

**Affected Endpoint:**
- `/api/v1/analytics/dashboard/` - Returns 200 (may be hitting wrong view)

**Same fix as Error #9** - Verify URL routing

**Priority:** 🟢 MEDIUM - Works but verify routing is correct

---

## 📋 SUMMARY CHECKLIST

### Critical Fixes (Must do before any production use)
- [ ] Fix organization membership permission system (Error #1)
- [ ] Fix HR employees 500 error (Error #2)
- [ ] Fix HR time-off 500 error (Error #2)
- [ ] Fix HR performance reviews 500 error (Error #2)
- [ ] Fix messages conversations 500 error (Error #3)
- [ ] Fix messages messages 500 error (Error #3)
- [ ] Fix careers jobs 500 error (Error #4)

### High Priority Fixes (This week)
- [ ] Register HR documents endpoint (Error #5)
- [ ] Register finance transactions endpoint (Error #6)
- [ ] Register analytics reports endpoint (Error #7)
- [ ] Register careers applications endpoint (Error #8)

### Medium Priority (This month)
- [ ] Verify notifications URL routing (Error #9)
- [ ] Verify analytics dashboard URL routing (Error #10)

---

## 🔍 DEBUG COMMANDS

### Get All Error Logs
```bash
# Comprehensive error extraction
docker compose logs web | grep -E "ERROR|Traceback|500|Exception" > all_errors.log

# Specific module errors
docker compose logs web | grep -A50 "hr_core" | grep -E "ERROR|Traceback" > hr_errors.log
docker compose logs web | grep -A50 "messages_sys" | grep -E "ERROR|Traceback" > messages_errors.log
docker compose logs web | grep -A50 "careers" | grep -E "ERROR|Traceback" > careers_errors.log

# Real-time monitoring
docker compose logs web -f | grep ERROR
```

### Test Individual Endpoints
```bash
# Source environment and load token
cd /home/king/zumodra
source .venv/bin/activate

# Get fresh token
python3 get_auth_token.py

# Test specific endpoint with token
TOKEN=$(cat auth_token.json | python3 -c "import json,sys; print(json.load(sys.stdin)['access'])")

# Test ATS endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/jobs/jobs/

# Test HR endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/hr/employees/

# Test Messages endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/messages/conversations/
```

### Django Shell Debugging
```bash
# Access Django shell
docker compose exec web python manage.py shell

# Common debugging commands:
>>> from tenant_profiles.models import TenantUser, Organization
>>> from custom_account_u.models import User
>>> from tenants.models import Tenant
>>>
>>> # Check user setup
>>> user = User.objects.get(email='admin@demo.localhost')
>>> print(user.is_superuser, user.is_staff, user.is_active)
>>>
>>> # Check tenant relationship
>>> tu = TenantUser.objects.filter(user=user)
>>> for t in tu:
>>>     print(f"Tenant: {t.tenant.name}, Role: {t.role}, Active: {t.is_active}")
>>>
>>> # Test model queries
>>> from hr_core.models import Employee
>>> Employee.objects.count()  # This should work without error
```

---

## 📊 ERROR STATISTICS

**Total Errors:** 10
- 🔴 Critical: 4 (40%)
- 🟡 High: 4 (40%)
- 🟢 Medium: 2 (20%)

**By Category:**
- Permission/Auth Issues: 1 (10%)
- Server 500 Errors: 4 (40%)
- Missing Endpoints: 4 (40%)
- URL Routing: 2 (20%)

**Affected Modules:**
- ATS: 6 endpoints broken (permission issue)
- HR Core: 4 endpoints broken (3x 500, 1x 404)
- Services: 4 endpoints broken (permission issue)
- Finance: 3 endpoints broken (2x permission, 1x 404)
- Messages: 2 endpoints broken (500 errors)
- Careers: 2 endpoints broken (1x 500, 1x 404)
- Analytics: 1 endpoint broken (404)

---

## 🎯 RECOMMENDED FIX ORDER

1. **First:** Fix organization membership (unlocks 18 endpoints immediately)
2. **Second:** Debug and fix all 500 errors (get stack traces)
3. **Third:** Register missing endpoints (quick wins)
4. **Fourth:** Verify URL routing issues
5. **Fifth:** Add comprehensive error handling to prevent future 500s
6. **Sixth:** Write tests to catch these issues early

---

**Last Updated:** January 11, 2026
**Next Review:** After fixes applied
**Status:** Ready for development team
