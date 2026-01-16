#!/usr/bin/env python
"""
API Endpoint Testing Script

This script tests all major API endpoints in the ATS, HR Core, and Services apps
to identify broken endpoints, missing serializers, and validation issues.

Usage:
    python scripts/test_api_endpoints.py
"""

import os
import sys
import django
import json
from typing import Dict, List, Tuple

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
django.setup()

from django.test import RequestFactory, Client
from django.contrib.auth import get_user_model
from django.urls import reverse, resolve, get_resolver
from rest_framework.test import APIClient, force_authenticate
from rest_framework import status

User = get_user_model()


class EndpointTester:
    """Test API endpoints systematically."""

    def __init__(self):
        self.client = APIClient()
        self.factory = RequestFactory()
        self.results = {
            'passed': [],
            'failed': [],
            'missing_serializers': [],
            'auth_issues': [],
            'validation_issues': []
        }
        self.user = None
        self.tenant = None

    def setup_test_user(self):
        """Create or get test user with proper permissions."""
        try:
            from tenants.models import Tenant
            from django_tenants.utils import schema_context

            # Get or create public tenant
            tenant, _ = Tenant.objects.get_or_create(
                schema_name='public',
                defaults={
                    'name': 'Public Tenant',
                    'domain_url': 'localhost',
                    'subdomain': 'public'
                }
            )
            self.tenant = tenant

            # Create test user
            with schema_context(tenant.schema_name):
                self.user, created = User.objects.get_or_create(
                    email='testadmin@test.com',
                    defaults={
                        'username': 'testadmin',
                        'is_staff': True,
                        'is_superuser': True,
                    }
                )
                if created:
                    self.user.set_password('testpass123')
                    self.user.save()

            self.client.force_authenticate(user=self.user)
            print(f"✓ Test user created: {self.user.email}")

        except Exception as e:
            print(f"✗ Failed to setup test user: {e}")
            return False
        return True

    def test_endpoint(self, url: str, method: str = 'GET', data: dict = None) -> Tuple[bool, str, dict]:
        """
        Test a single endpoint.

        Returns:
            (success, message, response_data)
        """
        try:
            if method == 'GET':
                response = self.client.get(url)
            elif method == 'POST':
                response = self.client.post(url, data=data or {}, format='json')
            elif method == 'PUT':
                response = self.client.put(url, data=data or {}, format='json')
            elif method == 'PATCH':
                response = self.client.patch(url, data=data or {}, format='json')
            elif method == 'DELETE':
                response = self.client.delete(url)
            else:
                return False, f"Unknown method: {method}", {}

            # Check response
            if response.status_code in [200, 201, 204]:
                return True, f"Success ({response.status_code})", response.data if hasattr(response, 'data') else {}
            elif response.status_code in [401, 403]:
                return False, f"Auth error ({response.status_code})", {}
            elif response.status_code == 404:
                return False, "Not found (404)", {}
            elif response.status_code == 500:
                return False, f"Server error (500): {response.data if hasattr(response, 'data') else ''}", {}
            else:
                return False, f"Failed ({response.status_code}): {response.data if hasattr(response, 'data') else ''}", {}

        except Exception as e:
            return False, f"Exception: {str(e)}", {}

    def test_ats_endpoints(self):
        """Test ATS API endpoints."""
        print("\n" + "="*80)
        print("TESTING ATS ENDPOINTS")
        print("="*80)

        ats_endpoints = [
            ('/api/v1/ats/categories/', 'GET', 'Job Categories List'),
            ('/api/v1/ats/pipelines/', 'GET', 'Pipelines List'),
            ('/api/v1/ats/stages/', 'GET', 'Pipeline Stages List'),
            ('/api/v1/ats/jobs/', 'GET', 'Job Postings List'),
            ('/api/v1/ats/candidates/', 'GET', 'Candidates List'),
            ('/api/v1/ats/applications/', 'GET', 'Applications List'),
            ('/api/v1/ats/interviews/', 'GET', 'Interviews List'),
            ('/api/v1/ats/feedback/', 'GET', 'Interview Feedback List'),
            ('/api/v1/ats/offers/', 'GET', 'Offers List'),
            ('/api/v1/ats/saved-searches/', 'GET', 'Saved Searches List'),
            ('/api/v1/ats/dashboard/stats/', 'GET', 'Dashboard Stats'),
            ('/api/v1/ats/interview-slots/', 'GET', 'Interview Slots List'),
            ('/api/v1/ats/offer-templates/', 'GET', 'Offer Templates List'),
            ('/api/v1/ats/approvals/', 'GET', 'Offer Approvals List'),
        ]

        for url, method, name in ats_endpoints:
            success, message, data = self.test_endpoint(url, method)
            status_icon = "✓" if success else "✗"
            print(f"{status_icon} {name:45} {message}")

            if success:
                self.results['passed'].append({'url': url, 'name': name})
            else:
                self.results['failed'].append({'url': url, 'name': name, 'error': message})

    def test_hr_endpoints(self):
        """Test HR Core API endpoints."""
        print("\n" + "="*80)
        print("TESTING HR CORE ENDPOINTS")
        print("="*80)

        hr_endpoints = [
            ('/api/v1/hr/employees/', 'GET', 'Employees List'),
            ('/api/v1/hr/time-off-types/', 'GET', 'Time-Off Types List'),
            ('/api/v1/hr/time-off-requests/', 'GET', 'Time-Off Requests List'),
            ('/api/v1/hr/onboarding-checklists/', 'GET', 'Onboarding Checklists List'),
            ('/api/v1/hr/onboarding-tasks/', 'GET', 'Onboarding Tasks List'),
            ('/api/v1/hr/employee-onboardings/', 'GET', 'Employee Onboardings List'),
            ('/api/v1/hr/document-templates/', 'GET', 'Document Templates List'),
            ('/api/v1/hr/employee-documents/', 'GET', 'Employee Documents List'),
            ('/api/v1/hr/offboardings/', 'GET', 'Offboardings List'),
            ('/api/v1/hr/performance-reviews/', 'GET', 'Performance Reviews List'),
            ('/api/v1/hr/pips/', 'GET', 'PIPs List'),
            ('/api/v1/hr/pip-milestones/', 'GET', 'PIP Milestones List'),
            ('/api/v1/hr/pip-progress-notes/', 'GET', 'PIP Progress Notes List'),
            ('/api/v1/hr/org-chart/', 'GET', 'Org Chart'),
            ('/api/v1/hr/team-calendar/', 'GET', 'Team Calendar'),
            ('/api/v1/hr/dashboard/stats/', 'GET', 'HR Dashboard Stats'),
        ]

        for url, method, name in hr_endpoints:
            success, message, data = self.test_endpoint(url, method)
            status_icon = "✓" if success else "✗"
            print(f"{status_icon} {name:45} {message}")

            if success:
                self.results['passed'].append({'url': url, 'name': name})
            else:
                self.results['failed'].append({'url': url, 'name': name, 'error': message})

    def test_services_endpoints(self):
        """Test Services Marketplace API endpoints."""
        print("\n" + "="*80)
        print("TESTING SERVICES MARKETPLACE ENDPOINTS")
        print("="*80)

        services_endpoints = [
            ('/api/v1/services/categories/', 'GET', 'Service Categories List'),
            ('/api/v1/services/tags/', 'GET', 'Service Tags List'),
            ('/api/v1/services/providers/', 'GET', 'Service Providers List'),
            ('/api/v1/services/services/', 'GET', 'Services List'),
            ('/api/v1/services/requests/', 'GET', 'Client Requests List'),
            ('/api/v1/services/proposals/', 'GET', 'Proposals List'),
            ('/api/v1/services/contracts/', 'GET', 'Contracts List'),
            ('/api/v1/services/reviews/', 'GET', 'Reviews List'),
            ('/api/v1/services/analytics/', 'GET', 'Marketplace Analytics'),
        ]

        for url, method, name in services_endpoints:
            success, message, data = self.test_endpoint(url, method)
            status_icon = "✓" if success else "✗"
            print(f"{status_icon} {name:45} {message}")

            if success:
                self.results['passed'].append({'url': url, 'name': name})
            else:
                self.results['failed'].append({'url': url, 'name': name, 'error': message})

    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*80)
        print("TEST SUMMARY")
        print("="*80)

        total = len(self.results['passed']) + len(self.results['failed'])
        passed = len(self.results['passed'])
        failed = len(self.results['failed'])

        print(f"\nTotal Endpoints Tested: {total}")
        print(f"✓ Passed: {passed} ({passed/total*100:.1f}%)")
        print(f"✗ Failed: {failed} ({failed/total*100:.1f}%)")

        if self.results['failed']:
            print("\n" + "-"*80)
            print("FAILED ENDPOINTS:")
            print("-"*80)
            for item in self.results['failed']:
                print(f"\n  {item['name']}")
                print(f"  URL: {item['url']}")
                print(f"  Error: {item['error']}")

        # Save results to JSON
        with open('docs/api_test_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        print("\n✓ Full results saved to: docs/api_test_results.json")

    def run_all_tests(self):
        """Run all endpoint tests."""
        print("="*80)
        print("API ENDPOINT TESTING - SPRINT DAY 2")
        print("="*80)

        if not self.setup_test_user():
            print("\n✗ Cannot proceed without test user")
            return

        self.test_ats_endpoints()
        self.test_hr_endpoints()
        self.test_services_endpoints()
        self.print_summary()


def main():
    """Main entry point."""
    tester = EndpointTester()
    tester.run_all_tests()


if __name__ == '__main__':
    main()
