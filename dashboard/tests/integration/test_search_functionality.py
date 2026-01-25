#!/usr/bin/env python
"""
Search Functionality Test Suite for Zumodra Production Environment
==================================================================

Tests all search features across the platform:
1. Global search in dashboard header
2. Job search/filtering on careers page
3. Candidate search in ATS
4. Employee search in HR
5. Freelancer/service search on browse page

Domain: https://zumodra.rhematek-solutions.com
Author: Rhematek Solutions
Date: 2026-01-16
"""

import requests
import json
import sys
from typing import Dict, List, Tuple
from datetime import datetime


class SearchTester:
    """Test suite for search functionality across Zumodra platform."""

    def __init__(self, base_url: str, username: str = None, password: str = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.username = username
        self.password = password
        self.results = {
            'passed': [],
            'failed': [],
            'errors': [],
            'performance': {}
        }

    def login(self) -> bool:
        """Authenticate and establish session."""
        if not self.username or not self.password:
            print("⚠️  No credentials provided - testing public endpoints only")
            return False

        try:
            # Get CSRF token
            login_page = self.session.get(f'{self.base_url}/accounts/login/')
            if login_page.status_code != 200:
                self.results['errors'].append(f"Login page not accessible: {login_page.status_code}")
                return False

            # Extract CSRF token from cookies or HTML
            csrf_token = self.session.cookies.get('csrftoken')

            # Perform login
            login_data = {
                'login': self.username,
                'password': self.password,
                'csrfmiddlewaretoken': csrf_token
            }

            response = self.session.post(
                f'{self.base_url}/accounts/login/',
                data=login_data,
                headers={'Referer': f'{self.base_url}/accounts/login/'}
            )

            if response.status_code == 200 and 'dashboard' in response.url.lower():
                print("✅ Authentication successful")
                return True
            else:
                self.results['errors'].append(f"Login failed: {response.status_code}")
                return False

        except Exception as e:
            self.results['errors'].append(f"Login error: {str(e)}")
            return False

    def test_global_search(self) -> Dict:
        """Test global search in dashboard (requires authentication)."""
        print("\n[SEARCH] Testing Global Search in Dashboard...")

        test_cases = [
            ('developer', 'jobs, candidates, or employees with "developer"'),
            ('john', 'people named John'),
            ('hr', 'HR-related items'),
            ('manager', 'managers or management positions'),
        ]

        results = []

        for query, description in test_cases:
            try:
                start_time = datetime.now()

                response = self.session.get(
                    f'{self.base_url}/dashboard/search/',
                    params={'q': query},
                    headers={'HX-Request': 'true'}
                )

                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()

                if response.status_code == 200:
                    # Check if response is HTML (HTMX partial)
                    content = response.text

                    result = {
                        'query': query,
                        'description': description,
                        'status': 'PASS' if len(content) > 100 else 'FAIL',
                        'response_time': f"{duration:.2f}s",
                        'has_results': 'zu-search-results' in content,
                        'sections_found': []
                    }

                    # Check which sections have results
                    if 'Jobs' in content:
                        result['sections_found'].append('jobs')
                    if 'Candidates' in content:
                        result['sections_found'].append('candidates')
                    if 'Employees' in content:
                        result['sections_found'].append('employees')
                    if 'Applications' in content:
                        result['sections_found'].append('applications')

                    results.append(result)

                    if result['status'] == 'PASS':
                        self.results['passed'].append(f"Global search: {query}")
                    else:
                        self.results['failed'].append(f"Global search: {query} - no results")

                elif response.status_code == 403:
                    results.append({
                        'query': query,
                        'description': description,
                        'status': 'SKIP',
                        'error': 'Authentication required'
                    })
                else:
                    results.append({
                        'query': query,
                        'description': description,
                        'status': 'FAIL',
                        'error': f"HTTP {response.status_code}"
                    })
                    self.results['failed'].append(f"Global search: {query} - HTTP {response.status_code}")

            except Exception as e:
                results.append({
                    'query': query,
                    'description': description,
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.results['errors'].append(f"Global search {query}: {str(e)}")

        return {'test': 'Global Search', 'results': results}

    def test_careers_job_search(self) -> Dict:
        """Test job search and filtering on careers page."""
        print("\n🔍 Testing Careers Page Job Search...")

        test_cases = [
            ({}, 'All jobs listing'),
            ({'search': 'developer'}, 'Search for developer jobs'),
            ({'search': 'manager'}, 'Search for manager jobs'),
            ({'job_type': 'full_time'}, 'Filter by full-time jobs'),
            ({'remote_policy': 'remote'}, 'Filter by remote jobs'),
            ({'experience_level': 'mid'}, 'Filter by mid-level positions'),
        ]

        results = []

        for params, description in test_cases:
            try:
                start_time = datetime.now()

                response = self.session.get(
                    f'{self.base_url}/api/careers/jobs/',
                    params=params
                )

                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()

                if response.status_code == 200:
                    data = response.json()

                    result = {
                        'params': params,
                        'description': description,
                        'status': 'PASS',
                        'response_time': f"{duration:.2f}s",
                        'total_results': len(data) if isinstance(data, list) else data.get('count', 0),
                    }

                    results.append(result)
                    self.results['passed'].append(f"Careers search: {description}")

                else:
                    results.append({
                        'params': params,
                        'description': description,
                        'status': 'FAIL',
                        'error': f"HTTP {response.status_code}"
                    })
                    self.results['failed'].append(f"Careers search: {description} - HTTP {response.status_code}")

            except Exception as e:
                results.append({
                    'params': params,
                    'description': description,
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.results['errors'].append(f"Careers search {description}: {str(e)}")

        return {'test': 'Careers Job Search', 'results': results}

    def test_ats_candidate_search(self) -> Dict:
        """Test candidate search in ATS (requires authentication)."""
        print("\n🔍 Testing ATS Candidate Search...")

        test_cases = [
            ({'q': 'developer'}, 'Search candidates by skill'),
            ({'q': 'john'}, 'Search candidates by name'),
            ({'q': 'engineer'}, 'Search candidates by title'),
        ]

        results = []

        for params, description in test_cases:
            try:
                start_time = datetime.now()

                # Try to access candidate list page with search
                response = self.session.get(
                    f'{self.base_url}/ats/candidates/',
                    params=params
                )

                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()

                if response.status_code == 200:
                    content = response.text

                    result = {
                        'params': params,
                        'description': description,
                        'status': 'PASS' if 'candidate' in content.lower() else 'FAIL',
                        'response_time': f"{duration:.2f}s",
                        'page_loaded': len(content) > 1000,
                    }

                    results.append(result)

                    if result['status'] == 'PASS':
                        self.results['passed'].append(f"ATS candidate search: {description}")
                    else:
                        self.results['failed'].append(f"ATS candidate search: {description}")

                elif response.status_code == 403:
                    results.append({
                        'params': params,
                        'description': description,
                        'status': 'SKIP',
                        'error': 'Authentication required'
                    })
                else:
                    results.append({
                        'params': params,
                        'description': description,
                        'status': 'FAIL',
                        'error': f"HTTP {response.status_code}"
                    })
                    self.results['failed'].append(f"ATS candidate search: {description} - HTTP {response.status_code}")

            except Exception as e:
                results.append({
                    'params': params,
                    'description': description,
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.results['errors'].append(f"ATS candidate search {description}: {str(e)}")

        return {'test': 'ATS Candidate Search', 'results': results}

    def test_hr_employee_search(self) -> Dict:
        """Test employee search in HR (requires authentication)."""
        print("\n🔍 Testing HR Employee Search...")

        test_cases = [
            ({'q': 'john'}, 'Search employees by name'),
            ({'q': 'manager'}, 'Search employees by title'),
            ({'department': '1'}, 'Filter by department'),
        ]

        results = []

        for params, description in test_cases:
            try:
                start_time = datetime.now()

                response = self.session.get(
                    f'{self.base_url}/hr/employees/',
                    params=params
                )

                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()

                if response.status_code == 200:
                    content = response.text

                    result = {
                        'params': params,
                        'description': description,
                        'status': 'PASS' if 'employee' in content.lower() else 'FAIL',
                        'response_time': f"{duration:.2f}s",
                        'page_loaded': len(content) > 1000,
                    }

                    results.append(result)

                    if result['status'] == 'PASS':
                        self.results['passed'].append(f"HR employee search: {description}")
                    else:
                        self.results['failed'].append(f"HR employee search: {description}")

                elif response.status_code == 403:
                    results.append({
                        'params': params,
                        'description': description,
                        'status': 'SKIP',
                        'error': 'Authentication required or company-only feature'
                    })
                else:
                    results.append({
                        'params': params,
                        'description': description,
                        'status': 'FAIL',
                        'error': f"HTTP {response.status_code}"
                    })
                    self.results['failed'].append(f"HR employee search: {description} - HTTP {response.status_code}")

            except Exception as e:
                results.append({
                    'params': params,
                    'description': description,
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.results['errors'].append(f"HR employee search {description}: {str(e)}")

        return {'test': 'HR Employee Search', 'results': results}

    def test_service_freelancer_search(self) -> Dict:
        """Test freelancer/service search on browse page."""
        print("\n🔍 Testing Service/Freelancer Search...")

        test_cases = [
            ({'search': 'web design'}, 'Search for web design services'),
            ({'search': 'developer'}, 'Search for developer services'),
            ({'category': '1'}, 'Filter by category'),
            ({'sort': 'price'}, 'Sort by price'),
        ]

        results = []

        for params, description in test_cases:
            try:
                start_time = datetime.now()

                response = self.session.get(
                    f'{self.base_url}/services/browse/',
                    params=params
                )

                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()

                if response.status_code == 200:
                    content = response.text

                    result = {
                        'params': params,
                        'description': description,
                        'status': 'PASS' if 'service' in content.lower() or 'browse' in content.lower() else 'FAIL',
                        'response_time': f"{duration:.2f}s",
                        'page_loaded': len(content) > 1000,
                    }

                    results.append(result)

                    if result['status'] == 'PASS':
                        self.results['passed'].append(f"Service search: {description}")
                    else:
                        self.results['failed'].append(f"Service search: {description}")

                else:
                    results.append({
                        'params': params,
                        'description': description,
                        'status': 'FAIL',
                        'error': f"HTTP {response.status_code}"
                    })
                    self.results['failed'].append(f"Service search: {description} - HTTP {response.status_code}")

            except Exception as e:
                results.append({
                    'params': params,
                    'description': description,
                    'status': 'ERROR',
                    'error': str(e)
                })
                self.results['errors'].append(f"Service search {description}: {str(e)}")

        return {'test': 'Service/Freelancer Search', 'results': results}

    def run_all_tests(self) -> Dict:
        """Run all search tests and compile results."""
        print("="*80)
        print("ZUMODRA SEARCH FUNCTIONALITY TEST SUITE")
        print("="*80)
        print(f"Domain: {self.base_url}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)

        all_results = []

        # Test public endpoints first
        all_results.append(self.test_careers_job_search())
        all_results.append(self.test_service_freelancer_search())

        # Attempt login for authenticated tests
        authenticated = self.login()

        if authenticated:
            all_results.append(self.test_global_search())
            all_results.append(self.test_ats_candidate_search())
            all_results.append(self.test_hr_employee_search())
        else:
            print("\n⚠️  Skipping authenticated tests (global search, ATS, HR)")

        # Generate summary report
        self.print_summary(all_results)

        return {
            'summary': {
                'total_tests': len(self.results['passed']) + len(self.results['failed']),
                'passed': len(self.results['passed']),
                'failed': len(self.results['failed']),
                'errors': len(self.results['errors']),
                'success_rate': f"{(len(self.results['passed']) / max(len(self.results['passed']) + len(self.results['failed']), 1)) * 100:.1f}%"
            },
            'details': all_results,
            'passed': self.results['passed'],
            'failed': self.results['failed'],
            'errors': self.results['errors']
        }

    def print_summary(self, all_results: List[Dict]):
        """Print formatted test summary."""
        print("\n" + "="*80)
        print("TEST RESULTS SUMMARY")
        print("="*80)

        for test_suite in all_results:
            print(f"\n{test_suite['test']}:")
            print("-" * 80)

            for result in test_suite['results']:
                status_icon = {
                    'PASS': '✅',
                    'FAIL': '❌',
                    'ERROR': '⚠️',
                    'SKIP': '⏭️'
                }.get(result['status'], '❓')

                print(f"  {status_icon} {result.get('description', result.get('query', 'Unknown'))}")

                if result['status'] == 'PASS':
                    if 'response_time' in result:
                        print(f"     Response time: {result['response_time']}")
                    if 'total_results' in result:
                        print(f"     Results found: {result['total_results']}")
                    if 'sections_found' in result and result['sections_found']:
                        print(f"     Sections: {', '.join(result['sections_found'])}")
                elif result['status'] in ['FAIL', 'ERROR']:
                    if 'error' in result:
                        print(f"     Error: {result['error']}")

        print("\n" + "="*80)
        print("OVERALL SUMMARY")
        print("="*80)
        print(f"✅ Passed: {len(self.results['passed'])}")
        print(f"❌ Failed: {len(self.results['failed'])}")
        print(f"⚠️  Errors: {len(self.results['errors'])}")

        total = len(self.results['passed']) + len(self.results['failed'])
        if total > 0:
            success_rate = (len(self.results['passed']) / total) * 100
            print(f"\nSuccess Rate: {success_rate:.1f}%")

        print("="*80)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Test Zumodra search functionality')
    parser.add_argument('--url', default='https://zumodra.rhematek-solutions.com',
                        help='Base URL of Zumodra instance')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--output', help='Output JSON file for results')

    args = parser.parse_args()

    # Create tester instance
    tester = SearchTester(args.url, args.username, args.password)

    # Run all tests
    results = tester.run_all_tests()

    # Save to JSON if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n📄 Results saved to: {args.output}")

    # Exit with appropriate code
    sys.exit(0 if len(results['summary']['failed']) == 0 else 1)


if __name__ == '__main__':
    main()
