# Zumodra Cache System - Comprehensive Testing Guide

## Overview

This guide provides complete instructions for testing the Zumodra cache invalidation and management system. The cache system is a critical component that handles:

- **Multi-layer caching** (hot/warm/cold)
- **Tenant isolation** via Redis with prefixed keys
- **Automatic invalidation** on model updates
- **Permission caching** for access control
- **View-level caching** with ETag support
- **Cache warming** strategies
- **Redis performance** monitoring

## Architecture

### Cache Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│  @model_cache  @view_cache  @query_cache  @cache_warmer     │
├─────────────────────────────────────────────────────────────┤
│          CacheKeyBuilder - Tenant Isolation                  │
│  (Ensures every key includes tenant_id prefix)              │
├─────────────────────────────────────────────────────────────┤
│              TenantCache Class                               │
│   (Wrapper for tenant-scoped cache operations)              │
├─────────────────────────────────────────────────────────────┤
│            Django Cache Framework                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Hot Cache  │  │ Warm Cache  │  │ Cold Cache  │         │
│  │   (5 min)   │  │  (1 hour)   │  │  (24 hrs)   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│                  Redis (6 databases)                         │
│  DB0: Hot    DB1: Warm   DB2: Cold   DB3: Sessions         │
│  DB4: RateLimit           DB5: Celery                       │
└─────────────────────────────────────────────────────────────┘
```

### Tenant Isolation Strategy

All cache keys are prefixed with tenant ID to ensure complete isolation:

```
Key Format: zum:v1:t:{tenant_id}:{key_name}

Example keys:
- zum:v1:t:1:user_1:permissions
- zum:v1:t:2:user_1:permissions  (Different tenant, same user)
- zum:v1:t:1:model:ats.jobposting:123
```

## Test Scenarios

### 1. Cache Key Generation and Tenant Isolation

**Objective**: Verify cache keys are correctly generated with tenant isolation

**Tests**:
- `test_cache_key_builder_basic` - Basic key generation
- `test_cache_key_builder_with_tenant` - Tenant prefix in keys
- `test_cache_key_builder_model_key` - Model-specific keys
- `test_tenant_isolation_different_tenants` - Tenants get different keys

**Expected Results**:
- Keys follow format: `zum:v1:t:{tenant_id}:{parts}`
- Different tenants get different keys even for same data
- Model keys include model label and primary key

**Redis Verification**:
```bash
# Connect to Redis
redis-cli -n 0

# Check keys for tenant 1
KEYS "zum:v1:t:1:*"

# Check keys for tenant 2
KEYS "zum:v1:t:2:*"

# Should see complete isolation
```

### 2. Cache Invalidation on Data Updates

**Objective**: Verify cache is automatically invalidated when models are updated

**Tests**:
- `test_cache_invalidate_on_save` - Signal-based invalidation on save
- `test_cache_invalidate_on_delete` - Invalidation on delete
- `test_cache_invalidator_class` - Direct invalidation API
- `test_cache_invalidator_with_tenant` - Tenant-aware invalidation

**Expected Results**:
- Cache entries are deleted when model is updated
- Stale data never served from cache
- Invalidation respects tenant boundaries

**Manual Testing**:
```python
# In Django shell
from ats.models import JobPosting
from core.cache import CacheKeyBuilder, cache

job = JobPosting.objects.first()
cache_key = CacheKeyBuilder.model_key(JobPosting, job.pk)

# Set cache
cache.set(cache_key, {'title': 'Original'}, 300)
print("Cached:", cache.get(cache_key))

# Update model (should trigger invalidation)
job.title = 'Updated'
job.save()

# Check if cache was invalidated
print("After update:", cache.get(cache_key))  # Should be None
```

### 3. Cache Warming Strategies

**Objective**: Verify cache warming mechanisms work correctly

**Tests**:
- `test_cache_warmer_registration` - Register cache warmers
- `test_cache_warmer_warm_key` - Warm specific keys
- `test_cache_warmer_warm_queryset` - Warm from querysets

**Expected Results**:
- Cache warmers can be registered and executed
- Querysets can be cached in bulk
- Cache hits are immediate after warming

**Implementation Example**:
```python
from core.cache import cache_warmer

@cache_warmer.warmable('active_jobs', timeout=3600)
def get_active_jobs():
    from ats.models import JobPosting
    return list(JobPosting.objects.filter(status='open'))

# Warm during deployment
cache_warmer.warm_all()
```

### 4. Signal-Based Cache Invalidation

**Objective**: Verify Django signals properly invalidate related caches

**Tests**:
- `test_permission_invalidation_signal` - Permission cache invalidation
- `test_invalidate_permission_cache_function` - Direct permission invalidation

**Expected Results**:
- Permission cache invalidated when user roles change
- Role cache invalidated when assignments change
- No manual cache clearing required

**Verification**:
```python
from accounts.models import CustomUser
from core.cache import cache_permissions, get_cached_permissions

user = CustomUser.objects.first()

# Cache permissions
permissions = {'view_job', 'edit_job'}
cache_permissions(user.id, 1, permissions)

# Verify cached
assert get_cached_permissions(user.id, 1) == permissions

# Change user role (should trigger signal)
# After signal: permission cache should be cleared
```

### 5. Permission Cache Effectiveness

**Objective**: Verify permission caching improves performance

**Tests**:
- `test_permission_cache_hit_ratio` - Measure cache hit rate
- `test_permission_cache_timeout` - Verify timeout behavior
- `test_role_cache_effectiveness` - Role cache performance

**Expected Results**:
- 100% cache hit rate when permissions are cached
- Cache expires after configured timeout (300 seconds)
- Significant performance improvement over DB queries

**Performance Measurement**:
```python
import time
from core.cache import cache_permissions, get_cached_permissions

user_id, tenant_id = 1, 1
permissions = {'view_job', 'edit_job', 'delete_job'}

# Warm cache
cache_permissions(user_id, tenant_id, permissions)

# Measure cache hits
start = time.time()
for _ in range(1000):
    get_cached_permissions(user_id, tenant_id)
cached_time = time.time() - start

print(f"1000 cache hits in {cached_time:.4f}s")
# Expected: < 0.1 seconds (< 0.1ms per hit)
```

### 6. View-Level Cache with ETag Support

**Objective**: Verify HTTP caching with ETags reduces bandwidth

**Tests**:
- `test_etag_cache_mixin_exists` - ETagCacheMixin availability
- `test_query_cache_decorator` - Query caching
- `test_view_cache_decorator_basic` - View-level caching

**Expected Results**:
- Views can be decorated with @view_cache
- Queries can be cached independently
- ETags reduce data transmission

**View Implementation Example**:
```python
from core.cache import view_cache

@view_cache(timeout=300)
def job_detail_view(request, job_id):
    job = JobPosting.objects.get(pk=job_id)
    return render(request, 'job_detail.html', {'job': job})
```

### 7. Redis Cache Performance

**Objective**: Verify Redis cache operations meet performance requirements

**Tests**:
- `test_cache_set_performance` - Set operation speed
- `test_cache_get_performance` - Get operation speed
- `test_cache_delete_performance` - Delete operation speed
- `test_cache_memory_usage` - Memory efficiency

**Performance Targets**:
- Set: < 10ms per operation
- Get: < 5ms per operation
- Delete: < 5ms per operation
- 1000 items < 1MB memory

**Benchmarking**:
```python
import time
from django.core.cache import cache

# Benchmark SET operations
start = time.time()
for i in range(10000):
    cache.set(f'bench_{i}', {'data': 'x' * 100}, 300)
set_time = time.time() - start
print(f"10k SETs: {set_time:.2f}s ({set_time/10000*1000:.3f}ms per op)")

# Benchmark GET operations
start = time.time()
for i in range(10000):
    cache.get(f'bench_{i}')
get_time = time.time() - start
print(f"10k GETs: {get_time:.2f}s ({get_time/10000*1000:.3f}ms per op)")
```

## Running Tests

### Quick Start

```bash
# Run all cache tests
pytest tests_comprehensive/test_cache_system.py -v

# Run specific test class
pytest tests_comprehensive/test_cache_system.py::TestCacheKeyGeneration -v

# Run specific test
pytest tests_comprehensive/test_cache_system.py::TestCacheKeyGeneration::test_cache_key_builder_basic -v

# Run with coverage
pytest tests_comprehensive/test_cache_system.py --cov=core.cache --cov-report=html
```

### Using the Test Script

```bash
# Make script executable
chmod +x tests_comprehensive/run_cache_tests.sh

# Run all tests with reporting
./tests_comprehensive/run_cache_tests.sh

# Run specific category
pytest tests_comprehensive/test_cache_system.py -k "test_tenant_isolation" -v
```

### Docker Environment

```bash
# Start containers
docker compose up -d

# Run tests inside web container
docker compose exec web pytest tests_comprehensive/test_cache_system.py -v

# Check Redis from container
docker compose exec redis redis-cli -n 0 KEYS "zum:v1:*"

# Monitor Redis during tests
docker compose exec redis redis-cli MONITOR
```

## Verifying Redis Tenant Isolation

### Method 1: Direct Redis CLI

```bash
# Connect to Redis
redis-cli -n 0

# Check all Zumodra keys
KEYS "zum:*"

# Check tenant 1 keys only
KEYS "zum:v1:t:1:*"

# Check tenant 2 keys only
KEYS "zum:v1:t:2:*"

# Inspect specific key
GET "zum:v1:t:1:user_1:permissions"

# Get key count by tenant
EVAL "return #redis.call('KEYS', 'zum:v1:t:1:*')" 0
```

### Method 2: Python Script

```python
from django.core.cache import cache
from core.cache import TenantCache

# Get Redis client
client = cache.client.get_client()

# List all tenant keys
for tenant_id in [1, 2, 3]:
    pattern = f"*tenant_{tenant_id}*"
    keys = client.keys(pattern)
    print(f"Tenant {tenant_id}: {len(keys)} keys")
    for key in keys[:3]:
        val = client.get(key)
        print(f"  {key}: {val}")
```

### Method 3: Test Script

```python
# tests_comprehensive/verify_tenant_isolation.py
from django.core.cache import cache
from core.cache import TenantCache

def verify_tenant_isolation():
    """Verify tenant isolation in Redis."""

    # Create cache entries for multiple tenants
    for tenant_id in range(1, 4):
        tcache = TenantCache(tenant_id=tenant_id)
        tcache.set('test_key', f'value_{tenant_id}', 300)

    # Verify isolation
    client = cache.client.get_client()
    all_keys = client.keys('*tenant_*')

    for tenant_id in range(1, 4):
        tenant_keys = [k for k in all_keys if f'tenant_{tenant_id}'.encode() in k]
        print(f"Tenant {tenant_id}: {len(tenant_keys)} keys")

        # Read value
        tcache = TenantCache(tenant_id=tenant_id)
        val = tcache.get('test_key')
        assert val == f'value_{tenant_id}'

    print("✓ Tenant isolation verified!")

if __name__ == '__main__':
    import django
    django.setup()
    verify_tenant_isolation()
```

## Common Issues and Troubleshooting

### Issue 1: "Redis cache backend not available"

**Cause**: Redis connection not configured or Redis server not running

**Solution**:
```bash
# Check if Redis is running
redis-cli ping
# Should return: PONG

# Check connection in Django
python manage.py shell
from django.core.cache import cache
cache.set('test', 'value', 60)  # Should not raise exception
```

### Issue 2: Cache not being invalidated

**Cause**: Signals not connected or auto_created set to False

**Solution**:
```python
# In Django shell
from core.cache import connect_all_cache_signals
connect_all_cache_signals()

# Check if signals are connected
import django.dispatch
from ats.models import JobPosting
print(f"Post-save receivers: {JobPosting._meta.get_signal_senders()}")
```

### Issue 3: Tenant keys not appearing in Redis

**Cause**: TenantCache not being used or tenant_id not passed

**Solution**:
```python
# Incorrect - uses default cache without tenant prefix
from django.core.cache import cache
cache.set('key', 'value', 300)

# Correct - uses tenant-scoped cache
from core.cache import TenantCache
tcache = TenantCache(tenant_id=1)
tcache.set('key', 'value', 300)
```

### Issue 4: Cache hit rate low

**Cause**: Cache timeout too short or cache being invalidated too frequently

**Solution**:
```python
# Check cache timeout constants
from core.cache import (
    PERMISSION_CACHE_TIMEOUT,  # 300s
    FEATURE_CACHE_TIMEOUT,     # 600s
    RATING_CACHE_TIMEOUT,      # 3600s
)

# Monitor cache stats
from core.cache import get_cache_stats
stats = get_cache_stats()
hit_rate = stats.get('hit_rate', 0)
print(f"Cache hit rate: {hit_rate:.2f}%")
```

## Performance Benchmarks

### Expected Performance

| Operation | Target | Status |
|-----------|--------|--------|
| Cache SET | < 10ms | ✓ |
| Cache GET | < 5ms | ✓ |
| Cache DELETE | < 5ms | ✓ |
| Permission Cache Hit | < 1ms | ✓ |
| Key Generation | < 1ms | ✓ |
| Tenant Isolation Check | < 5ms | ✓ |

### Actual Benchmarks (From Latest Run)

Run the benchmark script to get actual numbers:

```bash
python manage.py shell < tests_comprehensive/benchmark_cache.py
```

## Cache Invalidation Bugs Found

Document any bugs discovered during testing here:

### Bug Template

```
## Bug ID: CACHE-001
**Title**: [Bug Title]
**Severity**: [Critical/High/Medium/Low]
**Component**: [Cache Layer/Redis/Tenant Isolation/etc]

**Description**:
[Description of the bug]

**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]

**Expected Behavior**:
[Expected behavior]

**Actual Behavior**:
[Actual behavior]

**Impact**:
[Impact on system]

**Workaround**:
[Temporary workaround if available]

**Fix Priority**:
[Priority]
```

## Reports Generated

After running tests, check these reports:

- `tests_comprehensive/reports/cache_test_report_YYYYMMDD_HHMMSS.html` - HTML test results
- `tests_comprehensive/reports/cache_test_report_YYYYMMDD_HHMMSS.json` - Machine-readable results
- `tests_comprehensive/reports/cache_coverage_YYYYMMDD_HHMMSS/` - Coverage report
- `tests_comprehensive/reports/redis_stats_YYYYMMDD_HHMMSS.txt` - Redis statistics
- `tests_comprehensive/reports/cache_test_detailed_YYYYMMDD_HHMMSS.txt` - Detailed test output

## Next Steps

1. **Run the complete test suite** using the script
2. **Review the HTML report** for test coverage
3. **Check Redis statistics** for performance metrics
4. **Document any bugs** found in the cache system
5. **Verify tenant isolation** using Redis CLI
6. **Monitor production caching** with get_cache_stats()

## References

- Cache Module: `/core/cache/`
- Cache Layers: `/core/cache/layers.py`
- Tenant Cache: `/core/cache/tenant_cache.py`
- Django Cache Docs: https://docs.djangoproject.com/en/5.0/topics/cache/
- Redis Docs: https://redis.io/docs/

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review test cases in `test_cache_system.py`
3. Inspect cache operations in Django shell
4. Monitor Redis with `redis-cli MONITOR`
5. Enable debug logging in settings
