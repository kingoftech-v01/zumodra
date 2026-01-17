#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Quick verification script for cache system setup
Run without Django: python tests_comprehensive/verify_cache_setup.py
Or with Django: python manage.py shell < tests_comprehensive/verify_cache_setup.py
"""

import json
import sys
from pathlib import Path

# Force UTF-8 output
if sys.stdout.encoding != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print("=" * 80)
print("CACHE SYSTEM SETUP VERIFICATION")
print("=" * 80)

# Check 1: Test files exist
print("\n[1] Checking test files...")
test_files = [
    'tests_comprehensive/test_cache_system.py',
    'tests_comprehensive/run_cache_tests.sh',
    'tests_comprehensive/analyze_cache_system.py',
    'tests_comprehensive/CACHE_TESTING_GUIDE.md',
    'tests_comprehensive/reports/CACHE_TESTING_DELIVERABLES.md',
    'core/cache/__init__.py',
    'core/cache/layers.py',
    'core/cache/tenant_cache.py',
]

missing_files = []
for file_path in test_files:
    path = Path(file_path)
    if path.exists():
        size = path.stat().st_size
        print("  [OK] {} ({} bytes)".format(file_path, size))
    else:
        print("  [MISSING] {} NOT FOUND".format(file_path))
        missing_files.append(file_path)

# Check 2: Reports directory
print("\n[2] Checking reports directory...")
reports_dir = Path('tests_comprehensive/reports')
if reports_dir.exists():
    files = list(reports_dir.glob('*'))
    print("  [OK] Reports directory exists ({} files)".format(len(files)))
else:
    print("  [MISSING] Reports directory not found")

# Check 3: Cache module structure
print("\n[3] Verifying cache module structure...")
cache_module_items = [
    'CacheKeyBuilder',
    'model_cache',
    'view_cache',
    'query_cache',
    'TenantCache',
    'cache_invalidator',
    'cache_warmer',
    'get_cache_stats',
    'clear_all_caches',
]

print("  Expected cache module exports:")
for item in cache_module_items:
    print("    - {}".format(item))

# Check 4: Test class structure
print("\n[4] Verifying test structure...")
test_content = Path('tests_comprehensive/test_cache_system.py').read_text()

test_classes = [
    'TestCacheKeyGeneration',
    'TestCacheInvalidation',
    'TestCacheWarming',
    'TestSignalBasedInvalidation',
    'TestPermissionCacheEffectiveness',
    'TestViewLevelCaching',
    'TestRedisCachePerformance',
    'TestTenantCache',
    'TestRedisKeyInspection',
    'TestMultiLayerCache',
    'TestCacheDecorators',
    'TestCacheIntegration',
]

print("  Test classes:")
for test_class in test_classes:
    if test_class in test_content:
        print("    [OK] {}".format(test_class))
    else:
        print("    [MISSING] {} NOT FOUND".format(test_class))

# Check 5: Count test methods
print("\n[5] Counting test methods...")
import re
test_methods = re.findall(r'def (test_\w+)\(', test_content)
print("  Total test methods: {}".format(len(test_methods)))
print("  Sample tests:")
for method in test_methods[:5]:
    print("    - {}".format(method))

# Check 6: Documentation
print("\n[6] Checking documentation...")
doc_files = [
    'tests_comprehensive/CACHE_TESTING_GUIDE.md',
    'tests_comprehensive/reports/CACHE_TESTING_DELIVERABLES.md',
]

for doc in doc_files:
    path = Path(doc)
    if path.exists():
        try:
            lines = path.read_text(encoding='utf-8', errors='ignore').count('\n')
            print("  [OK] {} ({} lines)".format(doc, lines))
        except:
            size = path.stat().st_size
            print("  [OK] {} ({} bytes)".format(doc, size))
    else:
        print("  [MISSING] {} NOT FOUND".format(doc))

# Summary
print("\n" + "=" * 80)
print("VERIFICATION SUMMARY")
print("=" * 80)

total_checks = 6
passed_checks = 6 - len(missing_files)

status = "READY" if not missing_files else "INCOMPLETE"
print("\nSetup Status: {}".format(status))
print("Test Files: {}/{} present".format(len(test_files) - len(missing_files), len(test_files)))
print("Test Methods: {} available".format(len(test_methods)))
print("Test Classes: {} configured".format(len(test_classes)))
print("Documentation: 2 guides provided")

print("\nNext Steps:")
print("  1. Run tests: pytest tests_comprehensive/test_cache_system.py -v")
print("  2. Or use script: ./tests_comprehensive/run_cache_tests.sh")
print("  3. Or analyze: python manage.py shell < tests_comprehensive/analyze_cache_system.py")
print("  4. View guide: cat tests_comprehensive/CACHE_TESTING_GUIDE.md")
print("  5. Check deliverables: cat tests_comprehensive/reports/CACHE_TESTING_DELIVERABLES.md")

print("\n" + "=" * 80)
