# Rate Limiting Comprehensive Testing Guide

## Overview

This guide provides instructions for comprehensively testing the Zumodra API rate limiting system.

## What Gets Tested

The rate limiting test suite validates seven core aspects:

1. **Per-user rate limits enforcement** - Each user has separate rate limit counters
2. **Per-tier rate limits** - Different subscription tiers have different limits
3. **Rate limit headers** - API responses include X-RateLimit-* headers
4. **Rate limit exceeded handling** - Proper 429 responses and error messages
5. **Staff/admin bypass** - Administrative users can exceed normal limits
6. **Burst allowance** - Short-term burst limits separate from sustained rates
7. **Redis-based storage** - Rate limit data persists in Redis cache

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Python 3.10+ with Django environment
- Zumodra project cloned and configured

### Run Tests

```bash
# 1. Start Docker services
docker compose up -d

# 2. Wait for services to be healthy
sleep 30

# 3. Run the comprehensive test suite
python manage.py shell < run_rate_limit_tests.py

# Alternative: Run directly with pytest
pytest tests_comprehensive/test_rate_limiting.py -v

# 4. Check reports
# - Markdown report: tests_comprehensive/reports/RATE_LIMITING_TEST_REPORT.md
# - JSON results: tests_comprehensive/reports/rate_limiting_results.json
```

## Test Architecture

### Test Classes

#### Test1PerUserRateLimits
Tests that each user has independent rate limit tracking:
- User cannot exceed hourly limit
- Different users have separate limits
- Limits tracked by user ID in cache

#### Test2PerTierRateLimits
Tests plan-based rate limiting:
- Free tier: 100/hour sustained
- Starter tier: 500/hour sustained
- Professional tier: 2000/hour sustained
- Enterprise tier: 10000/hour sustained

#### Test3RateLimitHeaders
Verifies HTTP response headers:
- X-RateLimit-Limit (total allowed)
- X-RateLimit-Remaining (requests left)
- X-RateLimit-Reset (window reset time)

#### Test4RateLimitExceededHandling
Tests error responses when limits are exceeded:
- Returns 429 Too Many Requests
- Includes retry information
- Clear error message

#### Test5StaffAdminBypass
Tests that administrative users bypass rate limits:
- Staff users not throttled
- Superusers bypass limits
- Admin operations unrestricted

#### Test6BurstAllowance
Tests burst protection mechanism:
- Burst limit separate from sustained limit
- Rate window resets after timeout
- Burst triggers before sustained limit

#### Test7RedisStorage
Tests persistence and isolation:
- Rate limits stored in Redis cache
- Tenant isolation via cache keys
- Proper cache expiration

#### Test8RoleBasedRateLimits
Tests role-specific rate limiting:
- Owner: 5000/hour
- Admin: 3000/hour
- Member: 500/hour

#### Test9AnonymousUserLimits
Tests anonymous user throttling:
- Lower limits for unauthenticated requests
- Separate from authenticated user limits

#### Test10CacheInvalidation
Tests cache management:
- Manual cache clear resets limits
- Proper TTL handling

### Performance Tests

- Rapid sequential requests (100 in quick succession)
- Multi-user concurrent requests (5 users × 20 requests)
- Stress testing with high request rates

## Implementation Details

### Throttle Classes

Located in `api/throttling.py`:

1. **TenantAwareThrottle** - Base class with tenant context
2. **PlanBasedThrottle** - Plan-specific rate limiting
3. **PlanBurstThrottle** - Burst protection
4. **PlanDailyThrottle** - Daily quota enforcement
5. **UserRoleThrottle** - Role-based limits
6. **IPBasedThrottle** - IP-based rate limiting
7. **SuspiciousIPThrottle** - Extra restrictive for flagged IPs
8. **TenantAwareAnonThrottle** - Anonymous user limits
9. **EndpointThrottle** - Per-endpoint custom limits
10. **BulkOperationThrottle** - Special restrictive limits for bulk ops

### Rate Limit Configuration

```python
# Default rates in REST_FRAMEWORK settings
DEFAULT_THROTTLE_RATES = {
    'anon': '100/hour',      # Anonymous users
    'user': '1000/hour',     # Authenticated users
    'auth': '5/minute',      # Login/logout
    'token': '10/minute',    # JWT tokens
    'password': '3/minute',  # Password operations
    'registration': '5/hour', # Signup
    'file_upload': '20/hour', # File uploads
    'export': '10/hour',     # Data exports
}
```

### Plan-Based Rate Limits

```python
DEFAULT_PLAN_RATES = {
    'free': {
        'sustained': '100/hour',
        'burst': '10/minute',
        'daily': '500/day',
    },
    'starter': {
        'sustained': '500/hour',
        'burst': '30/minute',
        'daily': '5000/day',
    },
    'professional': {
        'sustained': '2000/hour',
        'burst': '100/minute',
        'daily': '20000/day',
    },
    'enterprise': {
        'sustained': '10000/hour',
        'burst': '500/minute',
        'daily': '100000/day',
    },
}
```

### Role-Based Rate Limits

```python
USER_ROLE_RATES = {
    'owner': '5000/hour',
    'admin': '3000/hour',
    'supervisor': '2000/hour',
    'hr': '2000/hour',
    'marketer': '2000/hour',
    'employee': '1000/hour',
    'member': '500/hour',
}
```

## Manual Testing with curl

### Test Per-User Limits

```bash
# Get JWT token
curl -X POST http://localhost:8002/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}'

# Store token
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."

# Make rapid requests
for i in {1..50}; do
  curl -H "Authorization: Bearer $TOKEN" \
    http://localhost:8002/api/v1/ats/jobs/ | jq '.detail'
done
```

### Check Rate Limit Headers

```bash
curl -i -H "Authorization: Bearer $TOKEN" \
  http://localhost:8002/api/v1/ats/jobs/ | grep -i "x-ratelimit"
```

Output should show:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1234567890
```

### Test Different Plans

```bash
# Admin command to change user's plan
docker exec zumodra_web python manage.py shell

# In Django shell:
from tenants.models import Tenant
from finance.models import Plan

tenant = Tenant.objects.get(slug='test-tenant')
free_plan = Plan.objects.get(plan_type='free')
tenant.plan = free_plan
tenant.save()
```

### Test Admin Bypass

```bash
# Get admin token
curl -X POST http://localhost:8002/api/v1/auth/token/ \
  -d '{"username":"admin","password":"adminpass"}'

# Admin should NOT get 429 even with many requests
ADMIN_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."

for i in {1..100}; do
  curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    http://localhost:8002/api/v1/ats/jobs/ | jq '.detail' || echo "Request $i"
done
```

## Testing Checklist

### Before Running Tests

- [ ] Docker services are running (`docker compose up -d`)
- [ ] Database migrations complete (`python manage.py migrate_schemas`)
- [ ] Redis is accessible and configured
- [ ] Test database populated with test data

### During Test Execution

- [ ] Watch for console output indicating test progress
- [ ] Monitor Docker logs for errors (`docker compose logs web`)
- [ ] Check Redis memory usage (`redis-cli info memory`)
- [ ] Verify no connection timeouts

### After Test Execution

- [ ] Review test report: `tests_comprehensive/reports/RATE_LIMITING_TEST_REPORT.md`
- [ ] Check JSON results: `tests_comprehensive/reports/rate_limiting_results.json`
- [ ] Verify rate limit keys in Redis:
  ```bash
  redis-cli KEYS "throttle_*" | head -20
  ```
- [ ] Check cache hit rates in logs

## Troubleshooting

### Tests Fail to Connect to API

**Solution:**
```bash
# Verify web service is running
docker compose logs web | tail -20

# Restart service
docker compose restart web

# Wait for health check
sleep 30
```

### Rate Limits Don't Trigger

**Possible Causes:**
1. Limit is very high (check DEFAULT_THROTTLE_RATES)
2. Throttle classes not enabled in view
3. Cache not configured properly

**Solutions:**
```python
# In settings.py, reduce limits for testing
DEFAULT_THROTTLE_RATES = {
    'user': '10/hour',  # Was 1000/hour
}

# Or temporarily disable throttling
DEFAULT_THROTTLE_CLASSES = []
```

### Redis Connection Errors

**Solution:**
```bash
# Check Redis container
docker ps | grep redis

# Check Redis connectivity
redis-cli ping

# Rebuild Redis
docker compose down
docker compose up -d redis
sleep 10
docker compose up -d
```

### Cache Keys Accumulating

**Solution:**
```bash
# Clear all cache
redis-cli FLUSHDB

# Or specific pattern
redis-cli KEYS "throttle_*" | xargs redis-cli DEL
```

## Performance Expectations

### Normal Load
- API response time: <100ms
- Rate limit check overhead: <5ms
- Cache hit rate: >95%

### High Load (100+ concurrent users)
- Response time may increase to 200-500ms
- Cache hit rate: ~90%
- Redis memory: Monitor with `redis-cli info memory`

## Identified Issues and Gaps

### Critical Issues

1. **Staff/Admin Bypass Not Implemented**
   - Status: MISSING
   - Impact: Admins are rate limited like regular users
   - Fix: Add bypass logic in throttle allow_request() method

### Medium Priority

2. **No Rate Limit Monitoring**
   - Status: Not implemented
   - Impact: Can't track usage patterns per tenant
   - Recommendation: Add telemetry/metrics collection

3. **Daily Limits Not Enforced by Default**
   - Status: Partially implemented
   - Impact: PlanDailyThrottle exists but not used globally
   - Recommendation: Include in DEFAULT_THROTTLE_CLASSES or document per-view

### Low Priority

4. **No Rate Limit Whitelist**
   - Status: Not implemented
   - Recommendation: Add mechanism for trusted API consumers

## Next Steps

### Phase 1: Immediate Fixes
1. Implement staff/admin bypass in TenantAwareThrottle
2. Add comprehensive logging to rate limit hits
3. Update DEFAULT_THROTTLE_CLASSES to include burst throttles

### Phase 2: Monitoring & Analytics
1. Add rate limit hit tracking to Redis
2. Create dashboard for rate limit analytics per tenant
3. Implement alerts when tenant approaches limits

### Phase 3: Enhanced Features
1. API key rate limit exemptions
2. Temporary rate limit increases (e.g., for bulk imports)
3. Rate limit reset notifications

## References

### Documentation
- DRF Throttling: https://www.django-rest-framework.org/api-guide/throttling/
- Django Cache Framework: https://docs.djangoproject.com/en/5.2/topics/cache/
- Redis Documentation: https://redis.io/docs/

### Zumodra Implementation
- Throttling module: `/api/throttling.py`
- Settings: `/zumodra/settings.py` (REST_FRAMEWORK section)
- Tenant model: `/tenants/models.py`
- Plan model: `/finance/models.py`

## Support

For issues with rate limiting tests:
1. Check Docker logs: `docker compose logs web`
2. Check Redis: `redis-cli`
3. Review test output in: `tests_comprehensive/reports/`
4. Add debug logging in `/api/throttling.py`

---

Last Updated: 2026-01-16
