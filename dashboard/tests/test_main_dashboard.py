#!/usr/bin/env python
"""
Main Dashboard Testing Script
=============================

Tests all dashboard-related URLs on the production environment:
https://demo-company.zumodra.rhematek-solutions.com

Tasks:
1. Create/find test user credentials
2. Authenticate to frontend
3. Test ALL dashboard URLs:
   - /app/dashboard/ (main dashboard)
   - /app/dashboard/search/ (global search)
   - /app/dashboard/htmx/quick-stats/ (HTMX quick stats)
   - /app/dashboard/htmx/recent-activity/ (HTMX recent activity)
   - /app/dashboard/htmx/upcoming-interviews/ (HTMX upcoming interviews)
   - /app/dashboard/account-settings/ (account settings)
   - /app/dashboard/help/ (help page)
4. Screenshot all pages
5. Test functionality
6. Report findings

Author: Claude Code
Date: 2026-01-16
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Test configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
TEST_USER_EMAIL = "testuser@demo.com"
TEST_USER_PASSWORD = "TestPass123!"
SCREENSHOTS_DIR = Path(__file__).parent / "test_results" / "dashboard"

# Dashboard URLs to test
DASHBOARD_URLS = [
    {
        'url': '/app/dashboard/',
        'name': 'Main Dashboard',
        'method': 'GET',
        'requires_auth': True,
        'screenshot': 'main_dashboard.png',
        'description': 'Main dashboard with widgets and statistics'
    },
    {
        'url': '/app/dashboard/search/',
        'name': 'Global Search',
        'method': 'GET',
        'requires_auth': True,
        'screenshot': 'global_search.png',
        'params': {'q': 'test'},
        'description': 'Global search across jobs, candidates, employees'
    },
    {
        'url': '/app/dashboard/htmx/quick-stats/',
        'name': 'Quick Stats (HTMX)',
        'method': 'GET',
        'requires_auth': True,
        'screenshot': 'htmx_quick_stats.png',
        'headers': {'HX-Request': 'true'},
        'description': 'HTMX endpoint for refreshing dashboard quick stats'
    },
    {
        'url': '/app/dashboard/htmx/recent-activity/',
        'name': 'Recent Activity (HTMX)',
        'method': 'GET',
        'requires_auth': True,
        'screenshot': 'htmx_recent_activity.png',
        'headers': {'HX-Request': 'true'},
        'description': 'HTMX endpoint for recent activity feed'
    },
    {
        'url': '/app/dashboard/htmx/upcoming-interviews/',
        'name': 'Upcoming Interviews (HTMX)',
        'method': 'GET',
        'requires_auth': True,
        'screenshot': 'htmx_upcoming_interviews.png',
        'headers': {'HX-Request': 'true'},
        'description': 'HTMX endpoint for upcoming interviews widget'
    },
    {
        'url': '/app/dashboard/account-settings/',
        'name': 'Account Settings',
        'method': 'GET',
        'requires_auth': True,
        'screenshot': 'account_settings.png',
        'description': 'Account settings page (may redirect to allauth)'
    },
    {
        'url': '/app/dashboard/help/',
        'name': 'Help Page',
        'method': 'GET',
        'requires_auth': True,
        'screenshot': 'help_page.png',
        'description': 'Help and support page'
    },
]


class DashboardTester:
    """Main dashboard testing class."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = self._create_session()
        self.csrf_token = None
        self.test_results = []
        self.screenshots_dir = SCREENSHOTS_DIR

        # Create screenshots directory
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Screenshots will be saved to: {self.screenshots_dir}")

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic."""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Dashboard Test Bot)',
            'Accept': 'text/html,application/json,*/*',
        })

        return session

    def get_csrf_token(self, html_content: str) -> Optional[str]:
        """Extract CSRF token from HTML."""
        import re

        # Try multiple patterns
        patterns = [
            r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']',
            r'<input[^>]+csrfmiddlewaretoken[^>]+value=["\']([^"\']+)["\']',
            r'csrfToken\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, html_content)
            if match:
                return match.group(1)

        return None

    def login(self, email: str, password: str) -> bool:
        """
        Authenticate user and establish session.

        Returns:
            True if login successful, False otherwise
        """
        logger.info(f"Attempting login as {email}...")

        # Step 1: Get login page to retrieve CSRF token
        login_url = f"{self.base_url}/accounts/login/"

        try:
            response = self.session.get(login_url, timeout=10)
            response.raise_for_status()

            # Extract CSRF token
            self.csrf_token = self.get_csrf_token(response.text)

            if not self.csrf_token:
                logger.error("Failed to extract CSRF token from login page")
                return False

            logger.info(f"CSRF token obtained: {self.csrf_token[:20]}...")

            # Step 2: Submit login form
            login_data = {
                'login': email,
                'password': password,
                'csrfmiddlewaretoken': self.csrf_token,
            }

            headers = {
                'Referer': login_url,
                'Content-Type': 'application/x-www-form-urlencoded',
            }

            response = self.session.post(
                login_url,
                data=login_data,
                headers=headers,
                allow_redirects=True,
                timeout=10
            )

            # Check if login was successful
            if response.status_code == 200:
                # Check if we're redirected to dashboard or still on login page
                if '/login/' in response.url:
                    logger.error("Login failed - still on login page")
                    logger.error(f"Response content: {response.text[:500]}")
                    return False

                logger.info(f"Login successful! Redirected to: {response.url}")
                return True
            else:
                logger.error(f"Login failed with status code: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Login error: {e}")
            return False

    def test_url(self, url_config: Dict) -> Dict:
        """
        Test a single dashboard URL.

        Args:
            url_config: URL configuration dictionary

        Returns:
            Test result dictionary
        """
        url = url_config['url']
        full_url = f"{self.base_url}{url}"

        logger.info(f"\nTesting: {url_config['name']}")
        logger.info(f"URL: {full_url}")
        logger.info(f"Description: {url_config['description']}")

        result = {
            'name': url_config['name'],
            'url': url,
            'full_url': full_url,
            'method': url_config['method'],
            'description': url_config['description'],
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'status_code': None,
            'response_time_ms': None,
            'content_length': None,
            'content_type': None,
            'errors': [],
            'warnings': [],
            'notes': [],
        }

        try:
            # Prepare request
            method = url_config.get('method', 'GET')
            params = url_config.get('params', {})
            headers = url_config.get('headers', {})

            # Make request
            start_time = time.time()

            if method == 'GET':
                response = self.session.get(
                    full_url,
                    params=params,
                    headers=headers,
                    timeout=10
                )
            else:
                response = self.session.request(
                    method,
                    full_url,
                    params=params,
                    headers=headers,
                    timeout=10
                )

            end_time = time.time()
            response_time_ms = (end_time - start_time) * 1000

            # Record response details
            result['status_code'] = response.status_code
            result['response_time_ms'] = round(response_time_ms, 2)
            result['content_length'] = len(response.content)
            result['content_type'] = response.headers.get('Content-Type', 'unknown')

            # Check status code
            if response.status_code == 200:
                result['success'] = True
                result['notes'].append(f"✓ Page loaded successfully in {response_time_ms:.0f}ms")
            elif response.status_code == 302 or response.status_code == 301:
                result['warnings'].append(f"⚠ Redirect to: {response.headers.get('Location')}")
                result['success'] = True  # Redirects can be intentional
            elif response.status_code == 404:
                result['errors'].append("✗ 404 Not Found - URL does not exist")
            elif response.status_code == 500:
                result['errors'].append("✗ 500 Internal Server Error")
            elif response.status_code == 403:
                result['errors'].append("✗ 403 Forbidden - Permission denied")
            elif response.status_code == 401:
                result['errors'].append("✗ 401 Unauthorized - Authentication required")
            else:
                result['warnings'].append(f"⚠ Unexpected status code: {response.status_code}")

            # Analyze content
            content_text = response.text.lower()

            # Check for error indicators in content
            if 'error' in content_text and response.status_code == 200:
                result['warnings'].append("⚠ Error text found in response content")

            if 'exception' in content_text:
                result['warnings'].append("⚠ Exception text found in response")

            # Check for HTMX responses
            if headers.get('HX-Request') == 'true':
                if len(response.content) > 0:
                    result['notes'].append(f"✓ HTMX partial returned ({len(response.content)} bytes)")
                else:
                    result['warnings'].append("⚠ HTMX request returned empty content")

            # Save screenshot placeholder (would require selenium for actual screenshots)
            if 'screenshot' in url_config:
                screenshot_path = self.screenshots_dir / url_config['screenshot']
                result['screenshot_path'] = str(screenshot_path)
                result['notes'].append(f"Screenshot path: {screenshot_path}")

            # Log success
            if result['success']:
                logger.info(f"✓ SUCCESS - Status: {response.status_code}, Time: {response_time_ms:.0f}ms")
            else:
                logger.error(f"✗ FAILED - Status: {response.status_code}")

        except requests.exceptions.Timeout:
            result['errors'].append("✗ Request timeout (>10s)")
            logger.error("✗ Request timeout")

        except requests.exceptions.ConnectionError as e:
            result['errors'].append(f"✗ Connection error: {str(e)}")
            logger.error(f"✗ Connection error: {e}")

        except Exception as e:
            result['errors'].append(f"✗ Unexpected error: {str(e)}")
            logger.error(f"✗ Error: {e}")

        return result

    def run_all_tests(self) -> List[Dict]:
        """Run all dashboard tests."""
        logger.info("="*80)
        logger.info("MAIN DASHBOARD TESTING")
        logger.info("="*80)
        logger.info(f"Base URL: {self.base_url}")
        logger.info(f"Total URLs to test: {len(DASHBOARD_URLS)}")

        # Test each URL
        for url_config in DASHBOARD_URLS:
            result = self.test_url(url_config)
            self.test_results.append(result)
            time.sleep(0.5)  # Brief pause between requests

        return self.test_results

    def generate_report(self) -> Dict:
        """Generate comprehensive test report."""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r['success'])
        failed_tests = total_tests - passed_tests

        report = {
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'success_rate': round((passed_tests / total_tests * 100), 2) if total_tests > 0 else 0,
                'timestamp': datetime.now().isoformat(),
            },
            'test_results': self.test_results,
        }

        return report

    def print_summary(self):
        """Print test summary to console."""
        report = self.generate_report()
        summary = report['summary']

        logger.info("\n" + "="*80)
        logger.info("TEST SUMMARY")
        logger.info("="*80)
        logger.info(f"Total Tests:    {summary['total_tests']}")
        logger.info(f"Passed:         {summary['passed']} ✓")
        logger.info(f"Failed:         {summary['failed']} ✗")
        logger.info(f"Success Rate:   {summary['success_rate']}%")
        logger.info("="*80)

        # Print individual results
        logger.info("\nDETAILED RESULTS:")
        logger.info("-"*80)

        for result in self.test_results:
            status = "✓ PASS" if result['success'] else "✗ FAIL"
            logger.info(f"\n{status} - {result['name']}")
            logger.info(f"  URL: {result['url']}")
            logger.info(f"  Status Code: {result['status_code']}")
            logger.info(f"  Response Time: {result['response_time_ms']}ms")

            if result['errors']:
                logger.info("  Errors:")
                for error in result['errors']:
                    logger.info(f"    - {error}")

            if result['warnings']:
                logger.info("  Warnings:")
                for warning in result['warnings']:
                    logger.info(f"    - {warning}")

            if result['notes']:
                logger.info("  Notes:")
                for note in result['notes']:
                    logger.info(f"    - {note}")

        logger.info("\n" + "="*80)

    def save_report(self, filename: str = "dashboard_test_report.json"):
        """Save test report to JSON file."""
        report = self.generate_report()
        report_path = self.screenshots_dir / filename

        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"\nReport saved to: {report_path}")
        return report_path


def create_test_user():
    """
    Create a test user via Django management command or API.

    NOTE: This would require access to the Django shell or admin API.
    For now, we'll document the credentials that should be created manually.
    """
    logger.info("\n" + "="*80)
    logger.info("TEST USER CREDENTIALS")
    logger.info("="*80)
    logger.info("Please ensure the following test user exists:")
    logger.info(f"  Email: {TEST_USER_EMAIL}")
    logger.info(f"  Password: {TEST_USER_PASSWORD}")
    logger.info("="*80)
    logger.info("\nTo create this user, run on the server:")
    logger.info("  python manage.py shell")
    logger.info("  >>> from custom_account_u.models import CustomUser")
    logger.info(f"  >>> user = CustomUser.objects.create_user('{TEST_USER_EMAIL}', '{TEST_USER_PASSWORD}')")
    logger.info("  >>> user.save()")
    logger.info("="*80 + "\n")


def main():
    """Main test execution."""
    create_test_user()

    # Initialize tester
    tester = DashboardTester(BASE_URL)

    # Login
    login_success = tester.login(TEST_USER_EMAIL, TEST_USER_PASSWORD)

    if not login_success:
        logger.error("\n" + "="*80)
        logger.error("LOGIN FAILED")
        logger.error("="*80)
        logger.error("Cannot proceed with dashboard tests without authentication.")
        logger.error("Please verify:")
        logger.error("  1. Test user exists in the database")
        logger.error("  2. Credentials are correct")
        logger.error("  3. Server is accessible")
        logger.error("="*80)
        return 1

    # Run all tests
    tester.run_all_tests()

    # Print summary
    tester.print_summary()

    # Save report
    tester.save_report()

    logger.info("\n✓ Testing complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
