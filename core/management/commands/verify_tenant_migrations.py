"""
Verify tenant migrations are applied across all tenant schemas.

This command checks all tenant schemas for pending migrations and optionally
applies them automatically. Designed for automated monitoring and CI/CD pipelines.

Usage:
    python manage.py verify_tenant_migrations                    # Check all
    python manage.py verify_tenant_migrations --fix               # Auto-fix
    python manage.py verify_tenant_migrations --tenant=demo       # Specific tenant
    python manage.py verify_tenant_migrations --app=finance       # Specific app
    python manage.py verify_tenant_migrations --json              # JSON output
"""

import json
import sys
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django_tenants.utils import schema_context, get_tenant_model


class Command(BaseCommand):
    help = 'Verify tenant migrations are applied across all tenant schemas'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Check specific tenant schema only'
        )
        parser.add_argument(
            '--app',
            type=str,
            help='Check specific app only'
        )
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Automatically fix by applying missing migrations'
        )
        parser.add_argument(
            '--json',
            action='store_true',
            help='Output results in JSON format'
        )
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Only output errors and warnings'
        )

    def handle(self, *args, **options):
        tenant_filter = options.get('tenant')
        app_filter = options.get('app')
        auto_fix = options.get('fix')
        json_output = options.get('json')
        quiet = options.get('quiet')

        Tenant = get_tenant_model()

        # Get tenants to check
        if tenant_filter:
            tenants = Tenant.objects.filter(schema_name=tenant_filter)
            if not tenants.exists():
                self._error(
                    f"Tenant '{tenant_filter}' not found",
                    json_output,
                    exit_code=1
                )
                return
        else:
            tenants = Tenant.objects.exclude(schema_name='public')

        if not tenants.exists():
            self._success(
                "No tenant schemas to check",
                json_output,
                {'total_tenants': 0}
            )
            return

        # Check each tenant
        results = {
            'total_tenants': tenants.count(),
            'tenants_ok': 0,
            'tenants_with_issues': 0,
            'tenants': []
        }

        for tenant in tenants:
            tenant_result = self._check_tenant(tenant, app_filter, quiet)
            results['tenants'].append(tenant_result)

            if tenant_result['pending_count'] > 0:
                results['tenants_with_issues'] += 1
            else:
                results['tenants_ok'] += 1

        # Auto-fix if requested
        if auto_fix and results['tenants_with_issues'] > 0:
            if not quiet and not json_output:
                self.stdout.write(
                    self.style.WARNING(
                        f"\nApplying migrations to {results['tenants_with_issues']} tenant(s)..."
                    )
                )

            try:
                call_command('migrate_schemas', '--tenant', '--noinput', verbosity=0 if quiet else 1)

                # Re-check after fix
                fixed_results = {
                    'total_tenants': tenants.count(),
                    'tenants_ok': 0,
                    'tenants_with_issues': 0,
                    'tenants': []
                }

                for tenant in tenants:
                    tenant_result = self._check_tenant(tenant, app_filter, quiet=True)
                    fixed_results['tenants'].append(tenant_result)

                    if tenant_result['pending_count'] > 0:
                        fixed_results['tenants_with_issues'] += 1
                    else:
                        fixed_results['tenants_ok'] += 1

                results = fixed_results
                results['auto_fixed'] = True

                if not quiet and not json_output:
                    if results['tenants_with_issues'] == 0:
                        self.stdout.write(
                            self.style.SUCCESS("✓ All migrations applied successfully!")
                        )
                    else:
                        self.stdout.write(
                            self.style.ERROR(
                                f"✗ Still have {results['tenants_with_issues']} tenant(s) with issues"
                            )
                        )

            except Exception as e:
                results['auto_fix_error'] = str(e)
                if not quiet and not json_output:
                    self.stdout.write(
                        self.style.ERROR(f"✗ Auto-fix failed: {e}")
                    )

        # Output results
        if json_output:
            self.stdout.write(json.dumps(results, indent=2))
        elif not quiet:
            self._print_summary(results)

        # Exit with appropriate code for CI/CD
        if results['tenants_with_issues'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    def _check_tenant(self, tenant, app_filter=None, quiet=False):
        """Check a single tenant for pending migrations."""
        result = {
            'schema_name': tenant.schema_name,
            'domain': tenant.get_primary_domain().domain if hasattr(tenant, 'get_primary_domain') else None,
            'pending_count': 0,
            'pending_migrations': []
        }

        try:
            with schema_context(tenant.schema_name):
                executor = MigrationExecutor(connection)
                targets = executor.loader.graph.leaf_nodes()
                pending = executor.migration_plan(targets)

                # Filter by app if specified
                if app_filter:
                    pending = [m for m in pending if m[0].app_label == app_filter]

                result['pending_count'] = len(pending)
                result['pending_migrations'] = [
                    {
                        'app': migration[0].app_label,
                        'name': migration[0].name
                    }
                    for migration in pending
                ]

                if not quiet and result['pending_count'] > 0:
                    self.stdout.write(
                        self.style.WARNING(
                            f"  {tenant.schema_name}: {result['pending_count']} pending migration(s)"
                        )
                    )
                    for migration in result['pending_migrations'][:5]:
                        self.stdout.write(
                            f"    - {migration['app']}.{migration['name']}"
                        )
                    if result['pending_count'] > 5:
                        self.stdout.write(
                            f"    ... and {result['pending_count'] - 5} more"
                        )

        except Exception as e:
            result['error'] = str(e)
            if not quiet:
                self.stdout.write(
                    self.style.ERROR(f"  {tenant.schema_name}: Error checking migrations - {e}")
                )

        return result

    def _print_summary(self, results):
        """Print human-readable summary."""
        self.stdout.write("\n" + "=" * 60)
        self.stdout.write(self.style.HTTP_INFO("Tenant Migration Verification Summary"))
        self.stdout.write("=" * 60)

        self.stdout.write(f"Total tenants checked: {results['total_tenants']}")
        self.stdout.write(
            self.style.SUCCESS(f"✓ Tenants OK: {results['tenants_ok']}")
        )

        if results['tenants_with_issues'] > 0:
            self.stdout.write(
                self.style.WARNING(f"⚠ Tenants with issues: {results['tenants_with_issues']}")
            )

        if results.get('auto_fixed'):
            self.stdout.write(
                self.style.SUCCESS("\n✓ Automatic fix applied")
            )

        if results.get('auto_fix_error'):
            self.stdout.write(
                self.style.ERROR(f"\n✗ Auto-fix error: {results['auto_fix_error']}")
            )

        self.stdout.write("=" * 60 + "\n")

    def _success(self, message, json_output, data=None):
        """Output success message."""
        if json_output:
            output = data or {}
            output['status'] = 'success'
            output['message'] = message
            self.stdout.write(json.dumps(output, indent=2))
        else:
            self.stdout.write(self.style.SUCCESS(f"✓ {message}"))

    def _error(self, message, json_output, exit_code=1):
        """Output error message and exit."""
        if json_output:
            self.stdout.write(json.dumps({
                'status': 'error',
                'message': message
            }, indent=2))
        else:
            self.stdout.write(self.style.ERROR(f"✗ {message}"))
        sys.exit(exit_code)
