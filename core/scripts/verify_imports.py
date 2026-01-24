#!/usr/bin/env python
"""
Quick import verification script for entrypoint.
Checks that critical imports work without full Django setup.
"""
import sys

def check_imports():
    """Check critical imports."""
    errors = []

    print("[INFO] Verifying critical imports...")

    # Check tenants.views imports
    try:
        with open('tenants/views.py', 'r') as f:
            content = f.read()
            if 'from rest_framework.decorators import action, api_view, permission_classes' in content:
                print("[OK] tenants/views.py has api_view import")
            else:
                errors.append("tenants/views.py missing 'api_view' import")
                print("[ERROR] tenants/views.py missing 'api_view' import")

            # Check for IsAuthenticated import
            if 'from rest_framework.permissions import IsAuthenticated' in content:
                print("[OK] tenants/views.py has IsAuthenticated import")
            else:
                errors.append("tenants/views.py missing 'IsAuthenticated' import")
                print("[ERROR] tenants/views.py missing 'IsAuthenticated' import")
    except Exception as e:
        errors.append(f"Could not read tenants/views.py: {e}")
        print(f"[ERROR] Could not read tenants/views.py: {e}")

    # Check tenant_profiles.views imports
    try:
        with open('accounts/views.py', 'r') as f:
            content = f.read()
            if 'from rest_framework.decorators import action, api_view, permission_classes' in content:
                print("[OK] accounts/views.py has api_view import")
            else:
                errors.append("accounts/views.py missing 'api_view' import")
                print("[ERROR] accounts/views.py missing 'api_view' import")

            # Check for IsAuthenticated import
            if 'from rest_framework.permissions import IsAuthenticated' in content:
                print("[OK] accounts/views.py has IsAuthenticated import")
            else:
                errors.append("accounts/views.py missing 'IsAuthenticated' import")
                print("[ERROR] accounts/views.py missing 'IsAuthenticated' import")
    except Exception as e:
        errors.append(f"Could not read accounts/views.py: {e}")
        print(f"[ERROR] Could not read accounts/views.py: {e}")

    # Check critical files exist
    critical_files = [
        'tenants/decorators.py',
        'templates/components/tenant_type_switcher.html',
        'templates/components/verification_badges.html',
        'templates/components/company_only_wrapper_start.html',
    ]

    import os
    for filepath in critical_files:
        if os.path.exists(filepath):
            print(f"[OK] {filepath} exists")
        else:
            errors.append(f"Missing file: {filepath}")
            print(f"[ERROR] Missing file: {filepath}")

    # Check URL configurations
    try:
        with open('accounts/urls.py', 'r') as f:
            content = f.read()
            if "path('verify/kyc/', views.submit_kyc_verification" in content:
                print("[OK] accounts/urls.py has verification routes")
            else:
                errors.append("accounts/urls.py missing verification routes")
                print("[ERROR] accounts/urls.py missing verification routes")
    except Exception as e:
        errors.append(f"Could not read accounts/urls.py: {e}")
        print(f"[ERROR] Could not read accounts/urls.py: {e}")

    try:
        with open('tenants/urls.py', 'r') as f:
            content = f.read()
            if "path('verify/ein/', views.submit_ein_verification" in content:
                print("[OK] tenants/urls.py has EIN verification routes")
            else:
                errors.append("tenants/urls.py missing EIN verification routes")
                print("[ERROR] tenants/urls.py missing EIN verification routes")
    except Exception as e:
        errors.append(f"Could not read tenants/urls.py: {e}")
        print(f"[ERROR] Could not read tenants/urls.py: {e}")

    if errors:
        print(f"\n[FAILED] {len(errors)} import verification errors:")
        for error in errors:
            print(f"  - {error}")
        print("\nThis usually means the server needs to pull latest code:")
        print("  git pull origin main")
        return 1
    else:
        print("\n[SUCCESS] All critical imports verified!")
        return 0

if __name__ == '__main__':
    sys.exit(check_imports())
