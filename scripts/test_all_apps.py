#!/usr/bin/env python
"""
Comprehensive Testing Script for All Django Apps
Tests each app and generates detailed reports
"""
import os
import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path

# Django setup
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
import django
django.setup()

from django.apps import apps
from django.core.management import call_command
from django.urls import get_resolver
from django.db import connection

# List of all apps to test
APPS_TO_TEST = [
    'accounting', 'ai_matching', 'analytics', 'api', 'billing', 'blog',
    'careers', 'configurations', 'core', 'core_identity', 'dashboard',
    'escrow', 'expenses', 'finance_webhooks', 'hr_core', 'integrations',
    'interviews', 'jobs', 'jobs_public', 'main', 'marketing_campaigns',
    'messages_sys', 'notifications', 'payments', 'payroll', 'projects',
    'projects_public', 'security', 'services', 'services_public',
    'stripe_connect', 'subscriptions', 'tax', 'tenant_profiles', 'tenants'
]


class AppTester:
    def __init__(self, app_name):
        self.app_name = app_name
        self.results = {
            'app_name': app_name,
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'urls': {},
            'models': {},
            'migrations': {},
            'overall_status': 'UNKNOWN'
        }
        self.report_dir = Path(app_name) / 'reports'
        self.report_dir.mkdir(exist_ok=True)

    def test_pytest(self):
        """Run pytest for the app"""
        print(f"\n{'='*60}")
        print(f"Testing {self.app_name} - Running pytest...")
        print(f"{'='*60}")

        try:
            test_path = f"{self.app_name}/tests"
            if not Path(test_path).exists():
                self.results['tests'] = {
                    'status': 'SKIP',
                    'message': 'No tests directory found',
                    'passed': 0,
                    'failed': 0,
                    'errors': []
                }
                return

            result = subprocess.run(
                ['pytest', test_path, '-v', '--tb=short', '--json-report',
                 f'--json-report-file={self.report_dir}/pytest_report.json'],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Try to read JSON report
            json_report_path = self.report_dir / 'pytest_report.json'
            if json_report_path.exists():
                with open(json_report_path, 'r') as f:
                    pytest_data = json.load(f)
                    self.results['tests'] = {
                        'status': 'PASS' if result.returncode == 0 else 'FAIL',
                        'passed': pytest_data.get('summary', {}).get('passed', 0),
                        'failed': pytest_data.get('summary', {}).get('failed', 0),
                        'total': pytest_data.get('summary', {}).get('total', 0),
                        'duration': pytest_data.get('duration', 0)
                    }
            else:
                self.results['tests'] = {
                    'status': 'PASS' if result.returncode == 0 else 'FAIL',
                    'stdout': result.stdout[:500],
                    'stderr': result.stderr[:500] if result.stderr else None
                }

        except subprocess.TimeoutExpired:
            self.results['tests'] = {'status': 'TIMEOUT', 'message': 'Tests timed out after 5 minutes'}
        except Exception as e:
            self.results['tests'] = {'status': 'ERROR', 'message': str(e)}

    def check_urls(self):
        """Check URL patterns for the app"""
        print(f"\nChecking URL patterns for {self.app_name}...")

        try:
            url_file = Path(self.app_name) / 'urls.py'
            if not url_file.exists():
                self.results['urls'] = {
                    'status': 'SKIP',
                    'message': 'No urls.py found',
                    'patterns': []
                }
                return

            # Try to import and count URL patterns
            try:
                from importlib import import_module
                urls_module = import_module(f'{self.app_name}.urls')
                if hasattr(urls_module, 'urlpatterns'):
                    pattern_count = len(urls_module.urlpatterns)
                    self.results['urls'] = {
                        'status': 'PASS',
                        'pattern_count': pattern_count,
                        'has_urlpatterns': True
                    }
                else:
                    self.results['urls'] = {
                        'status': 'WARN',
                        'message': 'urls.py exists but no urlpatterns found'
                    }
            except Exception as e:
                self.results['urls'] = {
                    'status': 'ERROR',
                    'message': f'Error importing urls: {str(e)}'
                }

        except Exception as e:
            self.results['urls'] = {'status': 'ERROR', 'message': str(e)}

    def check_models(self):
        """Check models for the app"""
        print(f"\nChecking models for {self.app_name}...")

        try:
            app_config = apps.get_app_config(self.app_name)
            models = app_config.get_models()

            model_info = []
            for model in models:
                fields = [f.name for f in model._meta.get_fields()]
                model_info.append({
                    'name': model.__name__,
                    'table': model._meta.db_table,
                    'field_count': len(fields),
                    'fields': fields
                })

            self.results['models'] = {
                'status': 'PASS',
                'model_count': len(models),
                'models': model_info
            }

        except LookupError:
            self.results['models'] = {
                'status': 'SKIP',
                'message': f'App {self.app_name} not in INSTALLED_APPS'
            }
        except Exception as e:
            self.results['models'] = {'status': 'ERROR', 'message': str(e)}

    def check_migrations(self):
        """Check migration status for the app"""
        print(f"\nChecking migrations for {self.app_name}...")

        try:
            migrations_dir = Path(self.app_name) / 'migrations'
            if not migrations_dir.exists():
                self.results['migrations'] = {
                    'status': 'SKIP',
                    'message': 'No migrations directory found'
                }
                return

            migration_files = list(migrations_dir.glob('*.py'))
            migration_files = [f for f in migration_files if f.name != '__init__.py']

            # Check for unapplied migrations
            try:
                result = subprocess.run(
                    ['python', 'manage.py', 'showmigrations', self.app_name, '--plan'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                unapplied = [line for line in result.stdout.split('\n') if '[ ]' in line]

                self.results['migrations'] = {
                    'status': 'PASS' if len(unapplied) == 0 else 'WARN',
                    'total_migrations': len(migration_files),
                    'unapplied_count': len(unapplied),
                    'unapplied': unapplied
                }
            except Exception as e:
                self.results['migrations'] = {
                    'status': 'WARN',
                    'message': f'Could not check migration status: {str(e)}',
                    'total_migrations': len(migration_files)
                }

        except Exception as e:
            self.results['migrations'] = {'status': 'ERROR', 'message': str(e)}

    def check_app_structure(self):
        """Check basic app structure"""
        print(f"\nChecking app structure for {self.app_name}...")

        app_path = Path(self.app_name)
        structure = {
            'has_models': (app_path / 'models.py').exists(),
            'has_views': (app_path / 'views.py').exists(),
            'has_urls': (app_path / 'urls.py').exists(),
            'has_admin': (app_path / 'admin.py').exists(),
            'has_tests': (app_path / 'tests').exists() or (app_path / 'tests.py').exists(),
            'has_apps': (app_path / 'apps.py').exists(),
        }

        self.results['structure'] = structure

    def determine_overall_status(self):
        """Determine overall status based on all tests"""
        statuses = []

        if self.results['tests'].get('status') in ['FAIL', 'ERROR']:
            statuses.append('FAIL')
        if self.results['urls'].get('status') == 'ERROR':
            statuses.append('WARN')
        if self.results['models'].get('status') == 'ERROR':
            statuses.append('FAIL')
        if self.results['migrations'].get('status') == 'WARN':
            statuses.append('WARN')

        if 'FAIL' in statuses:
            self.results['overall_status'] = 'FAIL'
        elif 'WARN' in statuses:
            self.results['overall_status'] = 'WARN'
        else:
            self.results['overall_status'] = 'PASS'

    def generate_report(self):
        """Generate detailed report"""
        print(f"\nGenerating report for {self.app_name}...")

        # JSON report
        json_path = self.report_dir / 'test_report.json'
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        # Human-readable report
        md_path = self.report_dir / 'test_report.md'
        with open(md_path, 'w') as f:
            f.write(f"# Test Report: {self.app_name}\n\n")
            f.write(f"**Generated:** {self.results['timestamp']}\n\n")
            f.write(f"**Overall Status:** {self.results['overall_status']}\n\n")
            f.write("---\n\n")

            # Tests section
            f.write("## Unit Tests (pytest)\n\n")
            tests = self.results['tests']
            f.write(f"- **Status:** {tests.get('status', 'UNKNOWN')}\n")
            if 'passed' in tests:
                f.write(f"- **Passed:** {tests['passed']}\n")
                f.write(f"- **Failed:** {tests['failed']}\n")
                f.write(f"- **Total:** {tests['total']}\n")
            if 'message' in tests:
                f.write(f"- **Note:** {tests['message']}\n")
            f.write("\n")

            # URLs section
            f.write("## URL Patterns\n\n")
            urls = self.results['urls']
            f.write(f"- **Status:** {urls.get('status', 'UNKNOWN')}\n")
            if 'pattern_count' in urls:
                f.write(f"- **Pattern Count:** {urls['pattern_count']}\n")
            if 'message' in urls:
                f.write(f"- **Note:** {urls['message']}\n")
            f.write("\n")

            # Models section
            f.write("## Models\n\n")
            models = self.results['models']
            f.write(f"- **Status:** {models.get('status', 'UNKNOWN')}\n")
            if 'model_count' in models:
                f.write(f"- **Model Count:** {models['model_count']}\n")
                if models['models']:
                    f.write("\n### Model Details:\n\n")
                    for model in models['models']:
                        f.write(f"- **{model['name']}** ({model['field_count']} fields)\n")
            if 'message' in models:
                f.write(f"- **Note:** {models['message']}\n")
            f.write("\n")

            # Migrations section
            f.write("## Migrations\n\n")
            migrations = self.results['migrations']
            f.write(f"- **Status:** {migrations.get('status', 'UNKNOWN')}\n")
            if 'total_migrations' in migrations:
                f.write(f"- **Total Migrations:** {migrations['total_migrations']}\n")
            if 'unapplied_count' in migrations:
                f.write(f"- **Unapplied:** {migrations['unapplied_count']}\n")
            if 'message' in migrations:
                f.write(f"- **Note:** {migrations['message']}\n")
            f.write("\n")

            # Structure section
            f.write("## App Structure\n\n")
            if 'structure' in self.results:
                structure = self.results['structure']
                f.write("| Component | Present |\n")
                f.write("|-----------|----------|\n")
                for key, value in structure.items():
                    f.write(f"| {key.replace('has_', '').title()} | {'✓' if value else '✗'} |\n")

        print(f"  → Report saved to {md_path}")
        return self.results

    def run_all_tests(self):
        """Run all tests for the app"""
        self.check_app_structure()
        self.check_models()
        self.check_migrations()
        self.check_urls()
        self.test_pytest()
        self.determine_overall_status()
        return self.generate_report()


def main():
    """Main function to test all apps"""
    print("=" * 80)
    print("COMPREHENSIVE APP TESTING")
    print("=" * 80)
    print(f"\nStarting comprehensive testing of {len(APPS_TO_TEST)} apps...")
    print(f"Timestamp: {datetime.now()}\n")

    all_results = []
    summary = {'PASS': 0, 'WARN': 0, 'FAIL': 0, 'SKIP': 0}

    for app_name in APPS_TO_TEST:
        try:
            tester = AppTester(app_name)
            result = tester.run_all_tests()
            all_results.append(result)

            status = result['overall_status']
            summary[status] = summary.get(status, 0) + 1

            print(f"\n{'='*60}")
            print(f"✓ Completed testing {app_name}: {status}")
            print(f"{'='*60}\n")

        except Exception as e:
            print(f"\n✗ Error testing {app_name}: {e}")
            summary['FAIL'] += 1

    # Generate master report
    master_report_path = Path('test_results') / 'master_report.json'
    master_report_path.parent.mkdir(exist_ok=True)

    master_data = {
        'timestamp': datetime.now().isoformat(),
        'summary': summary,
        'total_apps': len(APPS_TO_TEST),
        'results': all_results
    }

    with open(master_report_path, 'w') as f:
        json.dump(master_data, f, indent=2)

    # Generate master markdown report
    master_md_path = Path('test_results') / 'master_report.md'
    with open(master_md_path, 'w') as f:
        f.write("# Master Test Report - All Apps\n\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
        f.write("## Summary\n\n")
        f.write(f"- **Total Apps Tested:** {len(APPS_TO_TEST)}\n")
        f.write(f"- **Passed:** {summary['PASS']}\n")
        f.write(f"- **Warnings:** {summary['WARN']}\n")
        f.write(f"- **Failed:** {summary['FAIL']}\n")
        f.write(f"- **Skipped:** {summary.get('SKIP', 0)}\n\n")

        f.write("## App Results\n\n")
        f.write("| App | Status | Tests | Models | Migrations | URLs |\n")
        f.write("|-----|--------|-------|--------|------------|------|\n")

        for result in all_results:
            app = result['app_name']
            status = result['overall_status']
            tests = result['tests'].get('status', 'N/A')
            models = result['models'].get('status', 'N/A')
            migrations = result['migrations'].get('status', 'N/A')
            urls = result['urls'].get('status', 'N/A')

            f.write(f"| {app} | {status} | {tests} | {models} | {migrations} | {urls} |\n")

    print("\n" + "=" * 80)
    print("TESTING COMPLETE")
    print("=" * 80)
    print(f"\nMaster reports saved to:")
    print(f"  - {master_report_path}")
    print(f"  - {master_md_path}")
    print(f"\nSummary:")
    print(f"  PASS: {summary['PASS']}")
    print(f"  WARN: {summary['WARN']}")
    print(f"  FAIL: {summary['FAIL']}")
    print(f"  Total: {len(APPS_TO_TEST)}")


if __name__ == '__main__':
    main()
