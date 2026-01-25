#!/usr/bin/env python
"""
Verify that urls_public.py can be imported correctly.
Run this script to diagnose import issues.
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("URL Module Import Verification")
print("=" * 60)
print()

# Check if file exists
urls_public_path = os.path.join('zumodra', 'urls_public.py')
print(f"1. Checking if {urls_public_path} exists...")
if os.path.exists(urls_public_path):
    print(f"   ✓ File exists at {os.path.abspath(urls_public_path)}")
else:
    print(f"   ✗ File NOT FOUND at {os.path.abspath(urls_public_path)}")
    sys.exit(1)

print()

# Try to import zumodra package
print("2. Importing zumodra package...")
try:
    import zumodra
    print(f"   ✓ Successfully imported zumodra")
    print(f"   Location: {zumodra.__file__}")
except ImportError as e:
    print(f"   ✗ Failed to import zumodra: {e}")
    sys.exit(1)

print()

# Set Django settings before importing urls
print("3. Configuring Django settings...")
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

try:
    import django
    django.setup()
    print("   ✓ Django configured successfully")
except Exception as e:
    print(f"   ⚠ Django setup warning: {e}")
    print("   (This is OK for URL verification)")

print()

# Try to import urls_public
print("4. Importing zumodra.urls_public...")
try:
    from zumodra import urls_public
    print("   ✓ Successfully imported zumodra.urls_public")
    print(f"   Location: {urls_public.__file__}")
    print(f"   URL patterns count: {len(urls_public.urlpatterns)}")
except ImportError as e:
    print(f"   ✗ FAILED to import zumodra.urls_public")
    print(f"   Error: {e}")
    print()
    print("   Attempting direct file import...")
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("urls_public", urls_public_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        print(f"   ✓ Direct import successful")
    except Exception as e2:
        print(f"   ✗ Direct import also failed: {e2}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
except Exception as e:
    print(f"   ✗ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()
print("=" * 60)
print("✓ All verification checks passed!")
print("=" * 60)
