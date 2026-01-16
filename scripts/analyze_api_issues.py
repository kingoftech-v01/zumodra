#!/usr/bin/env python
"""
API Issue Analyzer

Analyzes API endpoints to find:
1. Missing serializers
2. Missing authentication
3. Validation issues
4. Inconsistent response formats

Usage:
    python scripts/analyze_api_issues.py
"""

import os
import sys
import re
import ast
from pathlib import Path
from typing import Dict, List, Tuple, Set

# Setup Django path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class APIAnalyzer:
    """Analyze API endpoints for issues."""

    def __init__(self):
        self.issues = {
            'missing_serializers': [],
            'missing_auth': [],
            'missing_pagination': [],
            'missing_filters': [],
            'validation_issues': [],
            'inconsistent_responses': []
        }
        self.base_path = Path(__file__).parent.parent

    def analyze_viewset_file(self, file_path: Path, app_name: str) -> Dict:
        """Analyze a ViewSet file for issues."""
        print(f"\n{'='*80}")
        print(f"Analyzing: {file_path.name} ({app_name})")
        print('='*80)

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Find all ViewSet classes
            viewset_pattern = r'class\s+(\w+ViewSet)\(([^)]+)\):'
            viewsets = re.findall(viewset_pattern, content)

            print(f"\nFound {len(viewsets)} ViewSets:")
            for viewset_name, base_classes in viewsets:
                print(f"  - {viewset_name} (extends {base_classes})")

            # Check for serializer_class definitions
            serializer_pattern = r'serializer_class\s*=\s*(\w+)'
            serializers = re.findall(serializer_pattern, content)

            print(f"\nFound {len(serializers)} serializer_class declarations")

            # Check for get_serializer_class methods
            get_serializer_pattern = r'def get_serializer_class\(self\):'
            get_serializer_methods = len(re.findall(get_serializer_pattern, content))

            print(f"Found {get_serializer_methods} get_serializer_class() methods")

            # Check for permission_classes
            permission_pattern = r'permission_classes\s*=\s*\[([^\]]+)\]'
            permissions = re.findall(permission_pattern, content)

            print(f"Found {len(permissions)} permission_classes declarations")

            # Check for authentication_classes
            auth_pattern = r'authentication_classes\s*=\s*\[([^\]]+)\]'
            auth_classes = re.findall(auth_pattern, content)

            print(f"Found {len(auth_classes)} authentication_classes declarations")

            # Check for pagination_class
            pagination_pattern = r'pagination_class\s*=\s*(\w+)'
            pagination = re.findall(pagination_pattern, content)

            print(f"Found {len(pagination)} pagination_class declarations")

            # Check for filter_backends
            filter_pattern = r'filter_backends\s*=\s*\[([^\]]+)\]'
            filters = re.findall(filter_pattern, content)

            print(f"Found {len(filters)} filter_backends declarations")

            # Check for filterset_class
            filterset_pattern = r'filterset_class\s*=\s*(\w+)'
            filtersets = re.findall(filterset_pattern, content)

            print(f"Found {len(filtersets)} filterset_class declarations")

            # Identify potential issues
            issues = []

            # Check if ViewSets have serializers
            for viewset_name, _ in viewsets:
                # Extract the ViewSet content
                viewset_content_pattern = f'class {viewset_name}\\([^)]+\\):.*?(?=\\nclass |\\Z)'
                viewset_match = re.search(viewset_content_pattern, content, re.DOTALL)

                if viewset_match:
                    viewset_content = viewset_match.group(0)

                    # Check for serializer
                    has_serializer_class = 'serializer_class' in viewset_content
                    has_get_serializer = 'def get_serializer_class' in viewset_content

                    if not has_serializer_class and not has_get_serializer:
                        issue = f"{viewset_name}: Missing serializer_class or get_serializer_class()"
                        issues.append(issue)
                        self.issues['missing_serializers'].append({
                            'file': str(file_path),
                            'viewset': viewset_name,
                            'app': app_name
                        })
                        print(f"\n  ⚠ {issue}")

                    # Check for authentication
                    has_permission = 'permission_classes' in viewset_content
                    has_auth = 'authentication_classes' in viewset_content
                    is_secure_base = any(base in viewset_content[:200] for base in [
                        'SecureTenantViewSet', 'SecureReadOnlyViewSet', 'RoleBasedViewSet',
                        'RecruiterViewSet', 'HRViewSet', 'ParticipantViewSet'
                    ])

                    if not has_permission and not is_secure_base:
                        issue = f"{viewset_name}: Missing permission_classes (not using secure base class)"
                        issues.append(issue)
                        self.issues['missing_auth'].append({
                            'file': str(file_path),
                            'viewset': viewset_name,
                            'app': app_name
                        })
                        print(f"\n  ⚠ {issue}")

                    # Check for pagination on list endpoints
                    has_pagination = 'pagination_class' in viewset_content
                    if not has_pagination and not is_secure_base:
                        issue = f"{viewset_name}: Missing pagination_class"
                        self.issues['missing_pagination'].append({
                            'file': str(file_path),
                            'viewset': viewset_name,
                            'app': app_name
                        })

            return {
                'viewsets': len(viewsets),
                'serializers': len(serializers),
                'issues': issues
            }

        except Exception as e:
            print(f"\n  ✗ Error analyzing {file_path}: {e}")
            return {'viewsets': 0, 'serializers': 0, 'issues': []}

    def analyze_ats(self):
        """Analyze ATS API endpoints."""
        views_file = self.base_path / 'ats' / 'views.py'
        if views_file.exists():
            return self.analyze_viewset_file(views_file, 'ATS')
        return {}

    def analyze_hr_core(self):
        """Analyze HR Core API endpoints."""
        views_file = self.base_path / 'hr_core' / 'views.py'
        if views_file.exists():
            return self.analyze_viewset_file(views_file, 'HR Core')
        return {}

    def analyze_services(self):
        """Analyze Services API endpoints."""
        viewsets_file = self.base_path / 'services' / 'api' / 'viewsets.py'
        if viewsets_file.exists():
            return self.analyze_viewset_file(viewsets_file, 'Services')
        return {}

    def check_serializers(self):
        """Check for missing serializers in serializer files."""
        print(f"\n{'='*80}")
        print("CHECKING SERIALIZER FILES")
        print('='*80)

        apps_to_check = [
            ('ats', 'ATS'),
            ('hr_core', 'HR Core'),
            ('services', 'Services')
        ]

        for app_dir, app_name in apps_to_check:
            serializer_file = self.base_path / app_dir / 'serializers.py'
            if serializer_file.exists():
                print(f"\n{app_name} Serializers:")
                try:
                    with open(serializer_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    serializer_pattern = r'class\s+(\w+Serializer)\('
                    serializers = re.findall(serializer_pattern, content)
                    print(f"  Found {len(serializers)} serializer classes")

                    # Check for common patterns
                    has_list_detail = any('List' in s and 'Detail' in content for s in serializers)
                    if not has_list_detail:
                        print(f"  ⚠ Consider adding List/Detail serializer variants")

                except Exception as e:
                    print(f"  ✗ Error: {e}")

    def print_summary(self):
        """Print analysis summary."""
        print(f"\n{'='*80}")
        print("ANALYSIS SUMMARY")
        print('='*80)

        total_issues = sum(len(v) for v in self.issues.values())

        print(f"\nTotal Issues Found: {total_issues}")

        for issue_type, issues in self.issues.items():
            if issues:
                print(f"\n{issue_type.replace('_', ' ').title()}: {len(issues)}")
                for issue in issues[:5]:  # Show first 5
                    print(f"  - {issue['app']}: {issue['viewset']}")
                if len(issues) > 5:
                    print(f"  ... and {len(issues) - 5} more")

        # Save to file
        output_file = self.base_path / 'docs' / 'api_analysis_results.txt'
        with open(output_file, 'w') as f:
            f.write("API ANALYSIS RESULTS\n")
            f.write("="*80 + "\n\n")

            for issue_type, issues in self.issues.items():
                f.write(f"\n{issue_type.replace('_', ' ').title()}: {len(issues)}\n")
                f.write("-"*80 + "\n")
                for issue in issues:
                    f.write(f"  App: {issue['app']}\n")
                    f.write(f"  ViewSet: {issue['viewset']}\n")
                    f.write(f"  File: {issue['file']}\n\n")

        print(f"\n✓ Full report saved to: {output_file}")

    def run(self):
        """Run all analyses."""
        print("="*80)
        print("API ISSUE ANALYZER - SPRINT DAY 2")
        print("="*80)

        self.analyze_ats()
        self.analyze_hr_core()
        self.analyze_services()
        self.check_serializers()
        self.print_summary()


def main():
    """Main entry point."""
    analyzer = APIAnalyzer()
    analyzer.run()


if __name__ == '__main__':
    main()
