#!/usr/bin/env python3
"""
Migration Status Checker for Zumodra
Verifies all apps have proper migration setup
"""
import os
import sys
from pathlib import Path

# Apps from settings_tenants.py
SHARED_APPS = [
    'django_tenants',
    'tenants',
    'custom_account_u',
    'integrations',
    'core',
    'security',
    'ai_matching',
    'marketing',
    'newsletter',
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'django_filters',
    'drf_spectacular',
    'user_agents',
    'analytical',
    'django_celery_beat',
]

TENANT_APPS = [
    'main',
    'blog',
    'finance',
    'messages_sys',
    'configurations',
    'dashboard_service',
    'dashboard',
    'services',
    'appointment',
    'api',
    'notifications',
    'analytics',
    'accounts',
    'ats',
    'hr_core',
    'careers',
]

# Third-party apps we can skip
SKIP_APPS = {
    'django_tenants', 'rest_framework', 'rest_framework_simplejwt',
    'corsheaders', 'django_filters', 'drf_spectacular', 'user_agents',
    'analytical', 'django_celery_beat', 'django', 'allauth', 'django_otp',
    'wagtail', 'channels',
}


def check_app_migrations(app_name):
    """Check migration status for a single app"""
    # Skip third-party apps
    if any(skip in app_name for skip in SKIP_APPS):
        return None

    # Handle special cases
    app_dir = Path(app_name.replace('.', '/'))
    if not app_dir.exists():
        return None

    migrations_dir = app_dir / 'migrations'
    init_file = migrations_dir / '__init__.py'
    models_file = app_dir / 'models.py'

    result = {
        'app': app_name,
        'has_migrations_dir': migrations_dir.exists(),
        'has_init': init_file.exists(),
        'has_models': False,
        'migration_files': [],
        'status': 'unknown'
    }

    # Check for models
    if models_file.exists():
        try:
            with open(models_file, 'r', encoding='utf-8') as f:
                content = f.read()
                result['has_models'] = 'models.Model' in content
        except Exception as e:
            result['status'] = f'error_reading_models: {e}'
            return result

    # Check for migration files
    if migrations_dir.exists():
        try:
            result['migration_files'] = [
                f.name for f in migrations_dir.glob('*.py')
                if f.name != '__init__.py' and not f.name.startswith('__pycache__')
            ]
        except Exception as e:
            result['status'] = f'error_reading_migrations: {e}'
            return result

    # Determine status
    if not result['has_migrations_dir']:
        result['status'] = 'MISSING_DIR'
    elif not result['has_init']:
        result['status'] = 'MISSING_INIT'
    elif result['has_models'] and not result['migration_files']:
        result['status'] = 'NEEDS_MIGRATIONS'
    elif result['has_models'] and result['migration_files']:
        result['status'] = 'OK_WITH_MODELS'
    else:
        result['status'] = 'OK_NO_MODELS'

    return result


def main():
    """Main verification function"""
    print("=" * 100)
    print("ZUMODRA MIGRATION STATUS VERIFICATION")
    print("=" * 100)
    print()

    all_apps = set(SHARED_APPS + TENANT_APPS)
    results = []

    for app in sorted(all_apps):
        result = check_app_migrations(app)
        if result:
            results.append(result)

    # Categorize results
    missing_dir = [r for r in results if r['status'] == 'MISSING_DIR']
    missing_init = [r for r in results if r['status'] == 'MISSING_INIT']
    needs_migrations = [r for r in results if r['status'] == 'NEEDS_MIGRATIONS']
    ok_with_models = [r for r in results if r['status'] == 'OK_WITH_MODELS']
    ok_no_models = [r for r in results if r['status'] == 'OK_NO_MODELS']
    errors = [r for r in results if r['status'].startswith('error')]

    # Print detailed table
    print(f"{'APP':<25} {'MODELS':<8} {'MIG DIR':<8} {'__init__':<9} {'MIGRATIONS':<15} {'STATUS':<20}")
    print("-" * 100)

    for r in results:
        models_str = 'Yes' if r['has_models'] else 'No'
        dir_str = 'Yes' if r['has_migrations_dir'] else 'NO'
        init_str = 'Yes' if r['has_init'] else 'NO'
        mig_count = f"{len(r['migration_files'])} file(s)" if r['migration_files'] else 'NONE'

        status_display = r['status'].replace('_', ' ')

        print(f"{r['app']:<25} {models_str:<8} {dir_str:<8} {init_str:<9} {mig_count:<15} {status_display:<20}")

    print("=" * 100)
    print()

    # Print summary
    print("SUMMARY:")
    print("-" * 100)
    print(f"  Total apps checked:      {len(results)}")
    print(f"  OK (with models):        {len(ok_with_models)}")
    print(f"  OK (no models):          {len(ok_no_models)}")
    print(f"  Missing migrations dir:  {len(missing_dir)}")
    print(f"  Missing __init__.py:     {len(missing_init)}")
    print(f"  Need migration files:    {len(needs_migrations)}")
    print(f"  Errors:                  {len(errors)}")
    print()

    # Print actionable items
    exit_code = 0

    if missing_dir:
        print("ACTION REQUIRED - Missing migrations/ directories:")
        for r in missing_dir:
            print(f"  mkdir -p {r['app']}/migrations")
            print(f"  touch {r['app']}/migrations/__init__.py")
        print()
        exit_code = 1

    if missing_init:
        print("ACTION REQUIRED - Missing migrations/__init__.py files:")
        for r in missing_init:
            print(f"  touch {r['app']}/migrations/__init__.py")
        print()
        exit_code = 1

    if needs_migrations:
        print("ACTION REQUIRED - Apps need migration files generated:")
        app_names = ' '.join([r['app'] for r in needs_migrations])
        print(f"  python manage.py makemigrations {app_names}")
        print()
        print("  Or individually:")
        for r in needs_migrations:
            print(f"  python manage.py makemigrations {r['app']}")
        print()
        exit_code = 1

    if errors:
        print("ERRORS:")
        for r in errors:
            print(f"  {r['app']}: {r['status']}")
        print()
        exit_code = 2

    if exit_code == 0:
        print("[OK] All apps are properly configured!")
        print()
        print("Next steps:")
        print("  1. Commit any new migration files")
        print("  2. Deploy to server with: bash deploy_migration_fix.sh")
        print()

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
