#!/bin/bash
# =============================================================================
# Zumodra Cache System Comprehensive Testing Script
# =============================================================================
#
# Tests:
# 1. Cache key generation and tenant isolation
# 2. Cache invalidation on data updates
# 3. Cache warming strategies
# 4. Signal-based cache invalidation
# 5. Permission cache effectiveness
# 6. View-level cache with ETag support
# 7. Redis cache performance
#
# Usage:
#   ./run_cache_tests.sh          # Run all tests
#   ./run_cache_tests.sh -k test_tenant_isolation   # Run specific test
#   ./run_cache_tests.sh -v       # Verbose output
#   ./run_cache_tests.sh --cache-stats  # Include cache stats
#
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_FILE="tests_comprehensive/test_cache_system.py"
REPORT_DIR="tests_comprehensive/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/cache_test_report_${TIMESTAMP}.json"
DETAILED_REPORT="$REPORT_DIR/cache_test_detailed_${TIMESTAMP}.txt"
REDIS_STATS_REPORT="$REPORT_DIR/redis_stats_${TIMESTAMP}.txt"

# Ensure report directory exists
mkdir -p "$REPORT_DIR"

echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}Zumodra Cache System Testing${NC}"
echo -e "${BLUE}=================================================${NC}"
echo ""

# Check if Django server is running
echo -e "${YELLOW}[1/5] Checking Django/Redis environment...${NC}"
python manage.py shell << 'EOF' 2>/dev/null
from django.core.cache import cache
try:
    cache.set('test_key', 'test_value', 60)
    if cache.get('test_key') == 'test_value':
        print("✓ Cache backend (Redis) is working")
        cache.delete('test_key')
    else:
        print("✗ Cache backend is not functioning properly")
except Exception as e:
    print(f"✗ Cache error: {e}")
EOF

# Run pytest with coverage
echo ""
echo -e "${YELLOW}[2/5] Running pytest with coverage...${NC}"
pytest "$TEST_FILE" \
    -v \
    --tb=short \
    --json-report \
    --json-report-file="$REPORT_FILE" \
    --html="$REPORT_DIR/cache_test_report_${TIMESTAMP}.html" \
    --html-report-file="$REPORT_DIR/cache_test_report_${TIMESTAMP}.html" \
    --cov=core.cache \
    --cov-report=html:"$REPORT_DIR/cache_coverage_${TIMESTAMP}" \
    --cov-report=term-missing \
    2>&1 | tee "$DETAILED_REPORT"

# Collect Redis statistics
echo ""
echo -e "${YELLOW}[3/5] Collecting Redis cache statistics...${NC}"
python manage.py shell << 'EOF' > "$REDIS_STATS_REPORT" 2>&1
from django.core.cache import cache
from core.cache import get_cache_stats, CacheKeyBuilder, TenantCache

print("=" * 70)
print("REDIS CACHE STATISTICS")
print("=" * 70)

try:
    stats = get_cache_stats()
    if stats:
        print("\nCache Stats:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    else:
        print("Could not retrieve cache statistics")
except Exception as e:
    print(f"Error retrieving stats: {e}")

# Check for tenant-scoped keys
print("\n" + "=" * 70)
print("REDIS TENANT ISOLATION VERIFICATION")
print("=" * 70)

try:
    # Create test keys for different tenants
    for tenant_id in [1, 2, 3]:
        tcache = TenantCache(tenant_id=tenant_id)
        tcache.set(f'tenant_test_{tenant_id}', f'value_{tenant_id}', 300)

    print("\n✓ Successfully created tenant-scoped cache entries")

    # Try to get Redis client and inspect keys
    try:
        client = cache.client.get_client()
        tenant_keys = client.keys('*tenant_*')
        print(f"✓ Found {len(tenant_keys)} tenant-scoped keys in Redis")

        # Sample keys
        if tenant_keys:
            print("\nSample tenant keys:")
            for key in tenant_keys[:5]:
                print(f"  - {key.decode() if isinstance(key, bytes) else key}")
    except Exception as e:
        print(f"  Could not inspect Redis keys: {e}")

except Exception as e:
    print(f"Error: {e}")

# Verify cache key format
print("\n" + "=" * 70)
print("CACHE KEY FORMAT VERIFICATION")
print("=" * 70)

key1 = CacheKeyBuilder.build('test', 'key', tenant_id=1)
key2 = CacheKeyBuilder.build('test', 'key', tenant_id=2)

print(f"\nTenant 1 key: {key1}")
print(f"Tenant 2 key: {key2}")
print(f"✓ Keys are properly isolated: {key1 != key2}")
EOF

# Run specific tests by category
echo ""
echo -e "${YELLOW}[4/5] Running tests by category...${NC}"

# Test categories
declare -a test_categories=(
    "test_cache_key_generation and TestCacheKeyGeneration"
    "test_cache_invalidation and TestCacheInvalidation"
    "test_cache_warming and TestCacheWarming"
    "test_permission_cache and TestPermissionCacheEffectiveness"
    "test_redis_cache_performance and TestRedisCachePerformance"
    "test_tenant_cache and TestTenantCache"
)

for test_cat in "${test_categories[@]}"; do
    echo ""
    echo -e "${YELLOW}Running: $test_cat${NC}"
    pytest "$TEST_FILE" -k "$test_cat" -v --tb=short 2>&1 | tail -10
done

# Summary
echo ""
echo -e "${YELLOW}[5/5] Generating summary report...${NC}"

# Create summary
cat > "$REPORT_DIR/cache_test_summary_${TIMESTAMP}.md" << 'SUMMARY_EOF'
# Cache System Testing Summary

## Overview
Comprehensive testing of Zumodra's multi-layer caching infrastructure including:
- Redis-backed cache operations
- Multi-tenant cache isolation
- Cache invalidation mechanisms
- Permission caching
- Cache warming strategies

## Test Coverage

### 1. Cache Key Generation and Tenant Isolation
- Basic cache key generation
- Tenant-scoped keys
- Model-specific key builders
- Version prefixing

### 2. Cache Invalidation
- Automatic invalidation on model save/delete
- Signal-based invalidation
- Manual invalidation APIs
- Tenant-aware invalidation

### 3. Cache Warming
- Registered cache warmers
- Queryset warming
- Key warming
- Batch warming operations

### 4. Permission Cache
- User permission caching
- Role caching
- Cache hit ratio measurement
- Timeout verification

### 5. Redis Performance
- Set operation performance
- Get operation performance
- Delete operation performance
- Memory usage monitoring

### 6. Multi-tenant Isolation
- Key isolation between tenants
- Cache operations per tenant
- Tenant-specific invalidation
- Redis key inspection

## Reports Generated
- `cache_test_report_*.json` - Machine-readable test results
- `cache_test_report_*.html` - HTML test report
- `cache_coverage_*/` - Coverage report directory
- `redis_stats_*.txt` - Redis statistics
- This summary file

## Next Steps
1. Review detailed test results in HTML report
2. Check coverage report for untested code
3. Verify Redis statistics for performance
4. Monitor tenant isolation in production
5. Implement caching in high-traffic endpoints

SUMMARY_EOF

echo -e "${GREEN}✓ Tests completed${NC}"
echo -e "${GREEN}✓ Report generated: $REPORT_FILE${NC}"
echo -e "${GREEN}✓ Detailed report: $DETAILED_REPORT${NC}"
echo -e "${GREEN}✓ Redis stats: $REDIS_STATS_REPORT${NC}"
echo -e "${GREEN}✓ Summary: $REPORT_DIR/cache_test_summary_${TIMESTAMP}.md${NC}"

echo ""
echo -e "${BLUE}Report Location: $REPORT_DIR/${NC}"
echo ""
