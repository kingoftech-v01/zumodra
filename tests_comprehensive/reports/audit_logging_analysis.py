"""
Audit Logging System Analysis and Documentation

This script analyzes the audit logging implementation in Zumodra
without requiring database connection.
"""

import os
import sys
import json
import re
from pathlib import Path
from datetime import datetime


class AuditLoggingAnalyzer:
    """Analyzes audit logging implementation in codebase."""

    def __init__(self, root_path):
        self.root_path = Path(root_path)
        self.findings = {
            'summary': {},
            'models': [],
            'implementations': [],
            'gaps': [],
            'recommendations': [],
        }

    def analyze(self):
        """Run complete analysis."""
        self.find_audit_models()
        self.find_auditlog_registrations()
        self.analyze_logging_coverage()
        self.check_authentication_logging()
        self.check_permission_changes()
        self.check_data_access_logging()
        self.check_retention_policies()
        self.generate_report()

    def find_audit_models(self):
        """Find audit-related models."""
        print("Finding audit models...")

        models_file = self.root_path / 'tenants' / 'models.py'
        if models_file.exists():
            content = models_file.read_text()
            if 'class AuditLog' in content:
                self.findings['models'].append({
                    'name': 'AuditLog',
                    'location': 'tenants/models.py',
                    'description': 'Main tenant-scoped audit log model',
                })

    def find_auditlog_registrations(self):
        """Find django-auditlog registrations."""
        print("Finding auditlog registrations...")

        registered = []
        for py_file in self.root_path.rglob('*.py'):
            if '.venv' in str(py_file):
                continue

            try:
                content = py_file.read_text(errors='ignore')
            except:
                continue

            matches = re.findall(
                r'auditlog\.register\(([^)]+)\)',
                content
            )

            if matches:
                for match in matches:
                    registered.append({
                        'model': match.strip(),
                        'file': str(py_file.relative_to(self.root_path)),
                    })

        self.findings['implementations'].append({
            'type': 'auditlog_registrations',
            'count': len(registered),
            'models': registered,
        })

    def analyze_logging_coverage(self):
        """Analyze what actions are being logged."""
        print("Analyzing logging coverage...")

        patterns = {
            'create_logging': r'AuditLog\.ActionType\.CREATE',
            'update_logging': r'AuditLog\.ActionType\.UPDATE',
            'delete_logging': r'AuditLog\.ActionType\.DELETE',
            'login_logging': r'AuditLog\.ActionType\.LOGIN',
            'logout_logging': r'AuditLog\.ActionType\.LOGOUT',
            'permission_logging': r'AuditLog\.ActionType\.PERMISSION_CHANGE',
            'export_logging': r'AuditLog\.ActionType\.EXPORT',
        }

        coverage = {}
        for action, pattern in patterns.items():
            found_in = []
            for py_file in self.root_path.rglob('*.py'):
                if '.venv' in str(py_file):
                    continue

                try:
                    if re.search(pattern, py_file.read_text(errors='ignore')):
                        found_in.append(str(py_file.relative_to(self.root_path)))
                except:
                    continue

            coverage[action] = len(found_in) > 0
            if found_in:
                print(f"  - {action}: Found in {len(found_in)} files")

        self.findings['implementations'].append({
            'type': 'action_coverage',
            'coverage': coverage,
        })

    def check_authentication_logging(self):
        """Check authentication logging implementation."""
        print("Checking authentication logging...")

        auth_file = self.root_path / 'accounts' / 'authentication.py'
        if auth_file.exists():
            content = auth_file.read_text()

            has_login_logging = 'login' in content.lower() and 'log' in content.lower()
            has_logout_logging = 'logout' in content.lower() and 'log' in content.lower()
            has_failed_attempt = 'failed' in content.lower() and 'attempt' in content.lower()

            self.findings['implementations'].append({
                'type': 'authentication_logging',
                'login_logging': has_login_logging,
                'logout_logging': has_logout_logging,
                'failed_attempts': has_failed_attempt,
            })

            if not has_login_logging:
                self.findings['gaps'].append(
                    'Login events not explicitly logged in authentication module'
                )

    def check_permission_changes(self):
        """Check permission change logging."""
        print("Checking permission change logging...")

        accounts_models = self.root_path / 'accounts' / 'models.py'
        if accounts_models.exists():
            content = accounts_models.read_text()

            has_role_tracking = 'role' in content.lower()

            self.findings['implementations'].append({
                'type': 'permission_tracking',
                'role_tracking': has_role_tracking,
            })

    def check_data_access_logging(self):
        """Check data access logging."""
        print("Checking data access logging...")

        has_export_logging = False
        for py_file in self.root_path.rglob('*.py'):
            if '.venv' in str(py_file):
                continue

            try:
                content = py_file.read_text(errors='ignore')
                if 'ActionType.EXPORT' in content:
                    has_export_logging = True
                    break
            except:
                continue

        self.findings['implementations'].append({
            'type': 'data_access_logging',
            'export_logging': has_export_logging,
        })

    def check_retention_policies(self):
        """Check audit log retention and archival."""
        print("Checking retention policies...")

        tasks_file = self.root_path / 'zumodra' / 'tasks.py'
        if tasks_file.exists():
            content = tasks_file.read_text()

            has_archival = 'archival' in content.lower() or 'archive' in content.lower()
            has_retention = 'retention' in content.lower() or 'cutoff' in content.lower()
            has_cleanup = 'cleanup' in content.lower() or 'delete' in content.lower()

            self.findings['implementations'].append({
                'type': 'retention_policies',
                'archival_tasks': has_archival,
                'retention_policy': has_retention,
                'cleanup_tasks': has_cleanup,
            })

    def generate_report(self):
        """Generate comprehensive report."""
        report = self._create_report()

        report_file = self.root_path / 'tests_comprehensive' / 'reports' / 'audit_logging_analysis.txt'
        report_file.parent.mkdir(parents=True, exist_ok=True)
        with open(report_file, 'w') as f:
            f.write(report)

        print(f"\nReport saved to: {report_file}")
        print("\n" + "="*80)
        print(report)

    def _create_report(self):
        """Create the analysis report."""
        lines = []
        lines.append("=" * 80)
        lines.append("ZUMODRA AUDIT LOGGING SYSTEM ANALYSIS")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("")

        lines.append("1. AUDIT LOG MODELS")
        lines.append("-" * 80)
        if self.findings['models']:
            for model in self.findings['models']:
                lines.append(f"  Model: {model['name']}")
                lines.append(f"  Location: {model['location']}")
                lines.append(f"  Description: {model['description']}")
                lines.append("")
        else:
            lines.append("  No audit log models found")
        lines.append("")

        lines.append("2. DJANGO-AUDITLOG INTEGRATIONS")
        lines.append("-" * 80)
        for impl in self.findings['implementations']:
            if impl['type'] == 'auditlog_registrations':
                lines.append(f"  Total Models Registered: {impl['count']}")
                for reg in impl['models'][:10]:
                    lines.append(f"    - {reg['model']} (in {reg['file']})")
                if len(impl['models']) > 10:
                    lines.append(f"    ... and {len(impl['models']) - 10} more")
        lines.append("")

        lines.append("3. LOGGING COVERAGE")
        lines.append("-" * 80)
        for impl in self.findings['implementations']:
            if impl['type'] == 'action_coverage':
                for action, covered in impl['coverage'].items():
                    status = "OK" if covered else "MISSING"
                    lines.append(f"  {action}: {status}")
        lines.append("")

        lines.append("4. AUTHENTICATION LOGGING")
        lines.append("-" * 80)
        for impl in self.findings['implementations']:
            if impl['type'] == 'authentication_logging':
                login = "OK" if impl['login_logging'] else "MISSING"
                logout = "OK" if impl['logout_logging'] else "MISSING"
                failed = "OK" if impl['failed_attempts'] else "MISSING"
                lines.append(f"  Login Logging: {login}")
                lines.append(f"  Logout Logging: {logout}")
                lines.append(f"  Failed Attempts: {failed}")
        lines.append("")

        lines.append("5. PERMISSION CHANGE TRACKING")
        lines.append("-" * 80)
        for impl in self.findings['implementations']:
            if impl['type'] == 'permission_tracking':
                role = "OK" if impl['role_tracking'] else "MISSING"
                lines.append(f"  Role Tracking: {role}")
        lines.append("")

        lines.append("6. DATA ACCESS LOGGING")
        lines.append("-" * 80)
        for impl in self.findings['implementations']:
            if impl['type'] == 'data_access_logging':
                export = "OK" if impl['export_logging'] else "MISSING"
                lines.append(f"  Export Logging: {export}")
        lines.append("")

        lines.append("7. RETENTION POLICIES")
        lines.append("-" * 80)
        for impl in self.findings['implementations']:
            if impl['type'] == 'retention_policies':
                archival = "OK" if impl['archival_tasks'] else "MISSING"
                retention = "OK" if impl['retention_policy'] else "MISSING"
                cleanup = "OK" if impl['cleanup_tasks'] else "MISSING"
                lines.append(f"  Archival Tasks: {archival}")
                lines.append(f"  Retention Policy: {retention}")
                lines.append(f"  Cleanup Tasks: {cleanup}")
        lines.append("")

        lines.append("8. IDENTIFIED GAPS")
        lines.append("-" * 80)
        if self.findings['gaps']:
            for i, gap in enumerate(self.findings['gaps'], 1):
                lines.append(f"  {i}. {gap}")
        else:
            lines.append("  No major gaps identified")
        lines.append("")

        return "\n".join(lines)


def main():
    """Main entry point."""
    root_path = Path(__file__).parent.parent.parent

    analyzer = AuditLoggingAnalyzer(root_path)
    analyzer.analyze()


if __name__ == '__main__':
    main()
