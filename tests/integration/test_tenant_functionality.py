#!/usr/bin/env python
"""
DEPRECATED: Comprehensive Tenant Testing Script for Zumodra

⚠️ WARNING: This test script is DEPRECATED.

FREELANCER tenant type has been removed from the system.
The demo-freelancer tenant no longer exists.
Individual freelancers are now FreelancerProfile user profiles (not tenants).

All tenants are now COMPANY type only.

For FreelancerProfile testing, see:
- accounts/tests/integration/test_freelancer_profile_workflows.py
- accounts/tests/api/test_freelancer_profile_api.py

This script tests:
1. ~~Freelancer Tenant~~ (REMOVED)
2. Company Tenant (demo-company.zumodra.rhematek-solutions.com)
3. Tenant 404 Page (nonexistent-tenant.zumodra.rhematek-solutions.com)

Usage:
    python test_tenant_functionality.py  # Only tests company tenant and 404 page
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Tuple
from urllib.parse import urljoin

# Configuration
BASE_URL_FREELANCER = "https://demo-freelancer.zumodra.rhematek-solutions.com"
BASE_URL_COMPANY = "https://demo-company.zumodra.rhematek-solutions.com"
BASE_URL_NONEXISTENT = "https://nonexistent-tenant.zumodra.rhematek-solutions.com"

# Disable SSL warnings for development
requests.packages.urllib3.disable_warnings()

class TenantTester:
    """Test Zumodra tenant functionality"""

    def __init__(self, name: str, base_url: str):
        self.name = name
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False  # Allow self-signed certificates
        self.results = []

    def test_url(self, path: str, expected_status: int = 200) -> Dict:
        """Test a single URL endpoint"""
        url = urljoin(self.base_url, path)
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)

            passed = response.status_code == expected_status
            return {
                'path': path,
                'url': url,
                'status_code': response.status_code,
                'expected_status': expected_status,
                'passed': passed,
                'content_length': len(response.content),
                'error': None,
                'content_sample': response.text[:500] if response.text else None,
            }
        except Exception as e:
            return {
                'path': path,
                'url': url,
                'status_code': None,
                'expected_status': expected_status,
                'passed': False,
                'content_length': 0,
                'error': str(e),
                'content_sample': None,
            }

    def test_public_pages(self) -> List[Dict]:
        """Test public/marketing pages"""
        pages = [
            ('/', 200, 'Homepage'),
            ('/about/', 200, 'About Page'),
            ('/pricing/', 200, 'Pricing Page'),
            ('/faq/', 200, 'FAQ Page'),
            ('/contact/', 200, 'Contact Page'),
            ('/accounts/login/', 200, 'Login Page'),
            ('/accounts/signup/', 200, 'Signup Page'),
        ]

        results = []
        for path, expected_status, label in pages:
            result = self.test_url(path, expected_status)
            result['label'] = label
            results.append(result)

        return results

    def test_protected_pages(self) -> List[Dict]:
        """Test pages that require authentication"""
        pages = [
            ('/app/dashboard/', 'Dashboard'),
            ('/app/ats/jobs/', 'ATS Jobs'),
            ('/app/ats/candidates/', 'ATS Candidates'),
            ('/app/profile/', 'User Profile'),
        ]

        results = []
        for path, label in pages:
            result = self.test_url(path, 302)  # Should redirect to login
            result['label'] = label
            results.append(result)

        return results

    def check_branding(self, response_text: str) -> Dict:
        """Check for branding elements"""
        branding = {
            'zumodra_mentions': response_text.count('Zumodra'),
            'freelanhub_mentions': response_text.count('FreelanHub'),
            'has_logo': 'logo' in response_text.lower(),
            'has_hero': 'hero' in response_text.lower(),
        }
        return branding

    def run_all_tests(self) -> Dict:
        """Run all tests for this tenant"""
        print(f"\n{'='*70}")
        print(f"Testing: {self.name}")
        print(f"Base URL: {self.base_url}")
        print(f"{'='*70}\n")

        results = {
            'tenant_name': self.name,
            'base_url': self.base_url,
            'tested_at': datetime.now().isoformat(),
            'public_pages': self.test_public_pages(),
            'protected_pages': self.test_protected_pages(),
            'summary': {}
        }

        # Get homepage for branding check
        homepage = self.test_url('/', 200)
        if homepage['passed'] and homepage['content_sample']:
            results['branding'] = self.check_branding(homepage['content_sample'])

        # Calculate summary
        all_tests = results['public_pages'] + results['protected_pages']
        passed = sum(1 for t in all_tests if t['passed'])
        total = len(all_tests)

        results['summary'] = {
            'total_tests': total,
            'passed': passed,
            'failed': total - passed,
            'pass_rate': f"{(passed/total*100):.1f}%" if total > 0 else "0%",
        }

        return results


class NotFoundTester:
    """Test 404 error page handling"""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False

    def test_404_page(self) -> Dict:
        """Test the 404 error page"""
        try:
            response = self.session.get(self.base_url, timeout=10, allow_redirects=False)

            return {
                'url': self.base_url,
                'status_code': response.status_code,
                'passed': response.status_code == 404,
                'content_length': len(response.content),
                'content_sample': response.text[:1000] if response.text else None,
                'error': None,
                'headers': dict(response.headers),
            }
        except Exception as e:
            return {
                'url': self.base_url,
                'status_code': None,
                'passed': False,
                'content_length': 0,
                'content_sample': None,
                'error': str(e),
                'headers': {},
            }

    def check_error_page_features(self, response_text: str) -> Dict:
        """Check for proper error page features"""
        features = {
            'has_error_heading': any(x in response_text.lower() for x in ['oops', 'not found', 'error']),
            'has_back_button': 'back' in response_text.lower() or 'homepage' in response_text.lower(),
            'has_helpful_message': any(x in response_text.lower() for x in ['looking for', 'cannot find', 'missing']),
            'has_support_info': 'support' in response_text.lower() or 'contact' in response_text.lower(),
            'mentions_tenant': 'tenant' in response_text.lower(),
            'proper_styling': 'class=' in response_text or 'style=' in response_text,
        }
        return features


def format_test_result(result: Dict) -> str:
    """Format a test result for display"""
    status = "✓ PASS" if result['passed'] else "✗ FAIL"
    path = result.get('path', result.get('url', 'unknown'))
    status_code = result.get('status_code', 'ERR')
    return f"{status} | {path:40} | Status: {status_code}"


def generate_report() -> str:
    """Generate comprehensive test report"""

    report = []
    report.append("="*80)
    report.append("ZUMODRA TENANT TESTING REPORT")
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("="*80)

    # Test 1: Freelancer Tenant
    report.append("\n\nPART 1: FREELANCER TENANT TESTING")
    report.append("-" * 80)

    freelancer_tester = TenantTester("Freelancer Tenant", BASE_URL_FREELANCER)
    freelancer_results = freelancer_tester.run_all_tests()

    report.append(f"\nPublic Pages (should load with 200):")
    for test in freelancer_results['public_pages']:
        report.append(f"  {format_test_result(test)}")

    report.append(f"\nProtected Pages (should redirect with 302):")
    for test in freelancer_results['protected_pages']:
        report.append(f"  {format_test_result(test)}")

    report.append(f"\nSummary:")
    report.append(f"  Total Tests: {freelancer_results['summary']['total_tests']}")
    report.append(f"  Passed: {freelancer_results['summary']['passed']}")
    report.append(f"  Failed: {freelancer_results['summary']['failed']}")
    report.append(f"  Pass Rate: {freelancer_results['summary']['pass_rate']}")

    if 'branding' in freelancer_results:
        report.append(f"\nBranding Check:")
        report.append(f"  Zumodra mentions: {freelancer_results['branding']['zumodra_mentions']}")
        report.append(f"  FreelanHub mentions: {freelancer_results['branding']['freelanhub_mentions']}")
        report.append(f"  Has logo: {freelancer_results['branding']['has_logo']}")
        report.append(f"  Has hero section: {freelancer_results['branding']['has_hero']}")

    # Test 2: Company Tenant (for comparison)
    report.append("\n\nPART 2: COMPANY TENANT TESTING (for comparison)")
    report.append("-" * 80)

    company_tester = TenantTester("Company Tenant", BASE_URL_COMPANY)
    company_results = company_tester.run_all_tests()

    report.append(f"\nPublic Pages Summary:")
    for test in company_results['public_pages']:
        report.append(f"  {format_test_result(test)}")

    report.append(f"\nSummary:")
    report.append(f"  Total Tests: {company_results['summary']['total_tests']}")
    report.append(f"  Passed: {company_results['summary']['passed']}")
    report.append(f"  Failed: {company_results['summary']['failed']}")
    report.append(f"  Pass Rate: {company_results['summary']['pass_rate']}")

    # Test 3: 404 Page
    report.append("\n\nPART 3: TENANT 404 PAGE TESTING")
    report.append("-" * 80)

    notfound_tester = NotFoundTester(BASE_URL_NONEXISTENT)
    notfound_result = notfound_tester.test_404_page()

    report.append(f"\n404 Page Test:")
    report.append(f"  URL: {notfound_result['url']}")
    report.append(f"  Status Code: {notfound_result['status_code']}")
    report.append(f"  Result: {'✓ PASS (HTTP 404)' if notfound_result['passed'] else '✗ FAIL'}")

    if notfound_result['error']:
        report.append(f"  Error: {notfound_result['error']}")
    else:
        features = notfound_tester.check_error_page_features(notfound_result['content_sample'] or '')
        report.append(f"\n404 Page Features:")
        report.append(f"  Has error heading: {features['has_error_heading']}")
        report.append(f"  Has back button: {features['has_back_button']}")
        report.append(f"  Has helpful message: {features['has_helpful_message']}")
        report.append(f"  Has support info: {features['has_support_info']}")
        report.append(f"  Mentions tenant: {features['mentions_tenant']}")
        report.append(f"  Has proper styling: {features['proper_styling']}")

        report.append(f"\n  Content Sample:")
        if notfound_result['content_sample']:
            lines = notfound_result['content_sample'].split('\n')[:10]
            for line in lines:
                if line.strip():
                    report.append(f"    {line[:70]}")

    # Comparison and Analysis
    report.append("\n\nPART 4: COMPARISON & ANALYSIS")
    report.append("-" * 80)

    report.append(f"\nFreelancer vs Company Tenant:")
    report.append(f"  Freelancer Pass Rate: {freelancer_results['summary']['pass_rate']}")
    report.append(f"  Company Pass Rate: {company_results['summary']['pass_rate']}")

    freelancer_pass = freelancer_results['summary']['passed']
    company_pass = company_results['summary']['passed']

    if freelancer_pass == company_pass:
        report.append(f"  ✓ Both tenants have equal functionality")
    elif freelancer_pass > company_pass:
        report.append(f"  ✓ Freelancer tenant performing better")
    else:
        diff = company_pass - freelancer_pass
        report.append(f"  ⚠ Freelancer tenant has {diff} fewer passing tests")

    # Recommendations
    report.append("\n\nPART 5: RECOMMENDATIONS")
    report.append("-" * 80)

    if freelancer_results['summary']['failed'] > 0:
        report.append(f"\n1. Freelancer Tenant Issues:")
        report.append(f"   - {freelancer_results['summary']['failed']} tests failed")
        report.append(f"   - Review error logs for broken pages")
        report.append(f"   - Verify all required views are implemented")
    else:
        report.append(f"\n1. ✓ Freelancer tenant is fully functional")

    if notfound_result['passed']:
        report.append(f"\n2. ✓ 404 page is properly configured and returns correct status")
    else:
        report.append(f"\n2. ⚠ 404 page needs attention:")
        if notfound_result['error']:
            report.append(f"   - Error: {notfound_result['error']}")
        else:
            report.append(f"   - Unexpected status code: {notfound_result['status_code']}")

    report.append(f"\n3. Testing Limitations:")
    report.append(f"   - Could not test authenticated pages (would need login credentials)")
    report.append(f"   - Could not test file uploads or form submissions")
    report.append(f"   - Could not test real-time features (WebSockets)")

    report.append("\n" + "="*80)
    report.append("END OF REPORT")
    report.append("="*80)

    return "\n".join(report)


if __name__ == '__main__':
    report = generate_report()

    # Save report to file
    report_filename = f"TENANT_TEST_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(report)

    # Print with encoding handling
    try:
        print(report)
    except UnicodeEncodeError:
        # Fallback for console with limited encoding support
        report_safe = report.encode('ascii', 'replace').decode('ascii')
        print(report_safe)

    print(f"\n\nReport saved to: {report_filename}")
