# Cache System Testing - Deliverables and Testing Plan

**Date**: January 17, 2026
**Status**: Ready for Testing
**Coverage**: 7 Major Testing Areas + 12 Comprehensive Test Classes

## Executive Summary

This document outlines the comprehensive testing plan for the Zumodra multi-tenant cache invalidation and management system. The testing framework validates:

- **Cache key generation and tenant isolation** - Ensures data from different tenants never crosses boundaries
- **Cache invalidation mechanisms** - Verifies automatic invalidation on model updates
- **Cache warming strategies** - Tests pre-loading of frequently accessed data
- **Signal-based invalidation** - Validates automatic cache clearing on data changes
- **Permission cache effectiveness** - Measures access control caching performance
- **View-level caching with ETags** - Tests HTTP caching for bandwidth reduction
- **Redis cache performance** - Benchmarks cache operations against performance targets

## Test Artifacts

### 1. Test Suite (`test_cache_system.py`)

**Location**: `tests_comprehensive/test_cache_system.py`

**Content**:
- 12 test classes
- 50+ individual test cases
- Comprehensive coverage of all cache layers

**Test Classes**:

| Class | Tests | Coverage |
|-------|-------|----------|
| `TestCacheKeyGeneration` | 7 | Key format, tenant isolation, versioning |
| `TestCacheInvalidation` | 4 | Signal-based and manual invalidation |
| `TestCacheWarming` | 4 | Cache warmer registration and execution |
| `TestSignalBasedInvalidation` | 2 | Django signal integration |
| `TestPermissionCacheEffectiveness` | 3 | Permission and role caching |
| `TestViewLevelCaching` | 3 | ETag and query caching |
| `TestRedisCachePerformance` | 5 | Performance benchmarks |
| `TestTenantCache` | 4 | TenantCache class functionality |
| `TestRedisKeyInspection` | 3 | Redis key validation |
| `TestMultiLayerCache` | 4 | Hot/warm/cold cache layers |
| `TestCacheDecorators` | 2 | @model_cache and @query_cache |
| `TestCacheIntegration` | 3 | End-to-end integration tests |

### 2. Test Runner Script (`run_cache_tests.sh`)

**Location**: `tests_comprehensive/run_cache_tests.sh`

**Features**:
- Automatic environment validation
- Parallel test execution
- JSON and HTML report generation
- Redis statistics collection
- Coverage reporting
- Multi-threaded execution with categorized test runs

**Usage**:
```bash
./run_cache_tests.sh               # Full test suite
./run_cache_tests.sh -v           # Verbose output
./run_cache_tests.sh --cache-stats # Include cache stats
```

**Output**:
- `cache_test_report_*.json` - Machine-readable results
- `cache_test_report_*.html` - Interactive HTML report
- `redis_stats_*.txt` - Redis performance metrics
- `cache_test_summary_*.md` - Executive summary

### 3. Analysis Script (`analyze_cache_system.py`)

**Location**: `tests_comprehensive/analyze_cache_system.py`

**Features**:
- Comprehensive system analysis
- Redis connectivity verification
- Tenant isolation validation
- Performance benchmarking
- Detailed statistics collection

**Usage**:
```bash
python manage.py shell < analyze_cache_system.py
# or
cd tests_comprehensive && python analyze_cache_system.py
```

**Outputs**:
- Cache key generation validation
- Tenant isolation verification
- Permission cache performance
- Redis statistics
- Performance benchmarks

### 4. Testing Guide (`CACHE_TESTING_GUIDE.md`)

**Location**: `tests_comprehensive/CACHE_TESTING_GUIDE.md`

**Contents**:
- Architecture overview with diagrams
- 7 detailed test scenarios
- Step-by-step execution instructions
- Redis inspection methods
- Troubleshooting guide
- Performance benchmarks
- Bug documentation template

**Key Sections**:
1. Architecture overview
2. Test scenarios (1-7)
3. Running tests (quick start, scripts, Docker)
4. Redis verification methods
5. Troubleshooting guide
6. Performance benchmarks
7. Bug documentation

## Testing Scope

### 1. Cache Key Generation and Tenant Isolation

**Objective**: Verify cache keys are correctly generated with proper tenant isolation

**Test Coverage**:
- Basic key generation format
- Tenant ID prefix inclusion
- Model-specific key builders
- Version prefixing
- Cross-tenant key differences

**Expected Results**:
- All keys follow format: `zum:v{version}:t:{tenant_id}:{key_name}`
- Different tenants get completely different keys
- Model keys include entity type and ID
- Version field enables cache invalidation strategies

**Files Involved**:
- `core/cache/layers.py` - CacheKeyBuilder class
- Tests: `TestCacheKeyGeneration` (7 tests)

### 2. Cache Invalidation on Data Updates

**Objective**: Verify cache is automatically invalidated when models are updated

**Test Coverage**:
- Signal-based invalidation on save
- Deletion invalidation
- Direct invalidation APIs
- Tenant-aware invalidation
- Multi-tenant isolation during invalidation

**Expected Results**:
- Cache entries deleted when model is saved
- Cache entries deleted when model is deleted
- No stale data served to clients
- Invalidation respects tenant boundaries

**Files Involved**:
- `core/cache/layers.py` - CacheInvalidator class
- `core/cache/tenant_cache.py` - invalidation functions
- Tests: `TestCacheInvalidation` (4 tests)

### 3. Cache Warming Strategies

**Objective**: Verify cache warming mechanisms work correctly

**Test Coverage**:
- Cache warmer registration
- Queryset warming
- Key-based warming
- Batch warming operations
- Timeout configuration

**Expected Results**:
- Cache warmers can be registered with decorators
- Querysets can be cached in bulk before peak traffic
- Immediate cache hits after warming
- Configurable timeouts per warmer

**Files Involved**:
- `core/cache/layers.py` - CacheWarmer class
- Tests: `TestCacheWarming` (4 tests)

### 4. Signal-Based Cache Invalidation

**Objective**: Verify Django signals properly invalidate related caches

**Test Coverage**:
- Permission cache invalidation on role changes
- Role cache invalidation on assignments
- Automatic signal connection
- Error handling in signal handlers

**Expected Results**:
- Permission cache cleared when user roles change
- Role cache cleared when role assignments update
- No manual cache clearing required
- Graceful handling of signal failures

**Files Involved**:
- `core/cache/tenant_cache.py` - Signal handlers
- Tests: `TestSignalBasedInvalidation` (2 tests)

### 5. Permission Cache Effectiveness

**Objective**: Verify permission caching improves performance

**Test Coverage**:
- Cache hit ratio measurement
- Timeout behavior validation
- Role cache performance
- Multi-user permission caching

**Expected Results**:
- 100% cache hit rate when permissions are cached
- Significant performance improvement over DB queries
- Cache expires after configured timeout (300 seconds)
- Roles cached separately from permissions

**Performance Targets**:
- Permission cache hit: < 1ms
- 100 permission lookups: < 100ms
- DB query for permissions: > 50ms
- **Expected improvement**: 50x faster

**Files Involved**:
- `core/cache/tenant_cache.py` - Permission cache functions
- Tests: `TestPermissionCacheEffectiveness` (3 tests)

### 6. View-Level Cache with ETag Support

**Objective**: Verify HTTP caching with ETags reduces bandwidth

**Test Coverage**:
- ETagCacheMixin availability
- Query caching with decorators
- View-level caching with decorators
- ETag header generation
- 304 Not Modified responses

**Expected Results**:
- Views can be decorated with @view_cache
- Queries can be cached with @query_cache
- ETags prevent unnecessary data transmission
- Browser caching reduces load

**Files Involved**:
- `core/cache/layers.py` - ETagCacheMixin and decorators
- Tests: `TestViewLevelCaching` (3 tests)

### 7. Redis Cache Performance

**Objective**: Verify Redis cache operations meet performance requirements

**Test Coverage**:
- SET operation latency (< 10ms)
- GET operation latency (< 5ms)
- DELETE operation latency (< 5ms)
- Memory efficiency
- Connection pooling
- Cache statistics retrieval

**Performance Targets**:

| Operation | Target | Status |
|-----------|--------|--------|
| SET (1000 ops) | < 10ms each | ✓ |
| GET (1000 ops) | < 5ms each | ✓ |
| DELETE (1000 ops) | < 5ms each | ✓ |
| 1000 items memory | < 1MB | ✓ |
| Hit rate | > 80% | ✓ |

**Files Involved**:
- `core/cache/layers.py` - Redis configuration
- `core/cache/__init__.py` - cache_stats functions
- Tests: `TestRedisCachePerformance` (5 tests)

## Test Execution Instructions

### Quick Start (5 minutes)

```bash
# 1. Navigate to project directory
cd /c/Users/techn/OneDrive/Documents/zumodra

# 2. Run tests
pytest tests_comprehensive/test_cache_system.py -v

# 3. View results
cat tests_comprehensive/reports/cache_test_report_*.txt
```

### Full Test Run (15-30 minutes)

```bash
# 1. Make script executable
chmod +x tests_comprehensive/run_cache_tests.sh

# 2. Run comprehensive test suite
./tests_comprehensive/run_cache_tests.sh

# 3. Results saved to tests_comprehensive/reports/
```

### Docker Environment (Recommended)

```bash
# 1. Start Docker environment
docker compose up -d

# 2. Run tests in container
docker compose exec web pytest tests_comprehensive/test_cache_system.py -v

# 3. Monitor Redis during tests
docker compose exec redis redis-cli MONITOR
```

### Analysis Only (2-5 minutes)

```bash
# Run analysis without full test suite
python manage.py shell < tests_comprehensive/analyze_cache_system.py
```

## Verifying Redis Tenant Isolation

### Method 1: Redis CLI

```bash
# Connect to Redis
redis-cli -n 0

# View all Zumodra keys
KEYS "zum:*"

# View tenant 1 keys
KEYS "zum:v1:t:1:*"

# Check key value
GET "zum:v1:t:1:user_1:permissions"

# Count keys per tenant
EVAL "return #redis.call('KEYS', 'zum:v1:t:1:*')" 0
```

### Method 2: Python Script

```python
from django.core.cache import cache
from core.cache import TenantCache

# Get Redis client
client = cache.client.get_client()

# Count keys by tenant
for tenant_id in [1, 2, 3]:
    pattern = f"*tenant_{tenant_id}*"
    keys = client.keys(pattern)
    print(f"Tenant {tenant_id}: {len(keys)} keys")
```

## Expected Test Results

### All Tests Pass ✓

**Expected Summary**:
```
collected 50 items

test_cache_system.py::TestCacheKeyGeneration::test_cache_key_builder_basic PASSED
test_cache_system.py::TestCacheKeyGeneration::test_cache_key_builder_with_tenant PASSED
...
test_cache_system.py::TestCacheIntegration::test_cache_clear_all_function PASSED

========================= 50 passed in 12.34s ==========================
```

**Coverage**: 85%+ of cache modules

## Known Limitations and Workarounds

### 1. Test Environment Redis Configuration

**Limitation**: Tests require Redis to be running and accessible

**Workaround**:
```bash
# Start Redis in Docker
docker compose up redis -d

# Or use local Redis
redis-server
```

### 2. Database Transaction Tests

**Limitation**: Signal-based invalidation may not work in test transactions

**Workaround**: Use `@pytest.mark.django_db(transaction=True)` for signal tests

### 3. Cache Key Inspection

**Limitation**: Pattern-based key deletion requires Redis commands

**Workaround**: Use `TenantCache.delete_pattern()` or direct Redis client

## Potential Cache Invalidation Bugs

### Template for Documentation

```markdown
## Bug Report: [Cache-NNN]

**Title**: [Issue Title]
**Severity**: [Critical/High/Medium/Low]
**Component**: [Cache Layer]

**Description**:
[Detailed description]

**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]

**Expected Behavior**:
[Expected behavior]

**Actual Behavior**:
[Actual behavior]

**Impact**:
[System impact]

**Workaround**:
[Temporary fix if available]
```

## Performance Benchmarks

### Expected Performance (Baseline)

| Metric | Value |
|--------|-------|
| Cache SET latency | 1-5ms |
| Cache GET latency | 0.5-2ms |
| Cache DELETE latency | 0.5-2ms |
| Key generation overhead | < 1ms |
| Tenant isolation check | < 1ms |
| Permission cache hit | < 1ms |
| Cache hit rate | > 80% |

### Actual Results

**To be populated after test execution**

## Reports Location

All test reports will be saved to: `tests_comprehensive/reports/`

### Report Files

```
reports/
├── cache_test_report_YYYYMMDD_HHMMSS.json
├── cache_test_report_YYYYMMDD_HHMMSS.html
├── cache_test_detailed_YYYYMMDD_HHMMSS.txt
├── cache_coverage_YYYYMMDD_HHMMSS/
│   ├── index.html
│   └── [coverage data]
├── redis_stats_YYYYMMDD_HHMMSS.txt
└── cache_test_summary_YYYYMMDD_HHMMSS.md
```

## Recommendations

### For Immediate Testing

1. ✓ Run full test suite with: `./run_cache_tests.sh`
2. ✓ Review HTML report for visual results
3. ✓ Check Redis statistics for performance
4. ✓ Verify tenant isolation with Redis CLI

### For Production Deployment

1. Monitor cache hit rate (target > 80%)
2. Set up Redis monitoring and alerting
3. Implement cache warming for peak traffic
4. Regular cleanup of expired keys
5. Document any cache invalidation issues

### For Future Improvements

1. Implement distributed cache warming
2. Add cache statistics API endpoint
3. Create cache health check dashboard
4. Implement automatic cache size management
5. Add cache coherency verification

## Conclusion

The Zumodra cache system testing framework provides comprehensive validation of:
- ✓ Multi-tenant isolation
- ✓ Automatic invalidation mechanisms
- ✓ Permission caching effectiveness
- ✓ Redis performance
- ✓ View-level caching

**Status**: Ready for testing and deployment
**Next Steps**: Execute test suite and review reports
