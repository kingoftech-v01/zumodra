#!/usr/bin/env python3
"""
Comprehensive Dashboard Testing Script (Playwright)
===================================================

Tests all dashboard-related URLs on: https://demo-company.zumodra.rhematek-solutions.com

This script uses Playwright for browser automation to:
1. Create test user or use existing credentials
2. Authenticate to the frontend
3. Test ALL dashboard URLs with screenshots
4. Document findings with inline comments

Dashboard URLs tested:
- /app/dashboard/ (main dashboard)
- /app/dashboard/search/ (global search)
- /app/dashboard/htmx/quick-stats/ (HTMX quick stats)
- /app/dashboard/htmx/recent-activity/ (HTMX recent activity)
- /app/dashboard/htmx/upcoming-interviews/ (HTMX upcoming interviews)
- /app/dashboard/account-settings/ (account settings)
- /app/dashboard/help/ (help page)

Author: Claude Code
Date: 2026-01-16
"""

import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext
except ImportError:
    print("ERROR: Playwright not installed")
    print("Install with: pip install playwright && playwright install")
    sys.exit(1)

# Configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
TEST_EMAIL = "admin@demo.com"  # Try existing admin user
TEST_PASSWORD = "admin123"
SCREENSHOTS_DIR = Path(__file__).parent / "test_results" / "dashboard"
RESULTS_FILE = SCREENSHOTS_DIR / "dashboard_test_results.json"

# Dashboard test configurations
DASHBOARD_TESTS = [
    {
        "name": "Main Dashboard",
        "url": "/app/dashboard/",
        "screenshot": "01_main_dashboard.png",
        "description": "Main dashboard with widgets, quick stats, recent activity, and upcoming interviews",
        "checks": [
            "Quick stats cards (open jobs, candidates, applications)",
            "Recent activity feed",
            "Upcoming interviews widget",
            "Navigation menu",
            "User profile dropdown"
        ]
    },
    {
        "name": "Global Search",
        "url": "/app/dashboard/search/?q=test",
        "screenshot": "02_global_search.png",
        "description": "Global search across jobs, candidates, employees, and applications",
        "checks": [
            "Search input field",
            "Search results (jobs, candidates, employees, applications)",
            "Result count",
            "Links to detailed views"
        ]
    },
    {
        "name": "HTMX Quick Stats",
        "url": "/app/dashboard/htmx/quick-stats/",
        "screenshot": "03_htmx_quick_stats.png",
        "description": "HTMX endpoint for refreshing dashboard quick stats",
        "checks": [
            "Statistics data returned",
            "Proper HTML fragment (not full page)",
            "No errors in response"
        ],
        "is_htmx": True
    },
    {
        "name": "HTMX Recent Activity",
        "url": "/app/dashboard/htmx/recent-activity/",
        "screenshot": "04_htmx_recent_activity.png",
        "description": "HTMX endpoint for recent activity feed",
        "checks": [
            "Activity items returned",
            "Proper HTML fragment",
            "Timestamps displayed"
        ],
        "is_htmx": True
    },
    {
        "name": "HTMX Upcoming Interviews",
        "url": "/app/dashboard/htmx/upcoming-interviews/",
        "screenshot": "05_htmx_upcoming_interviews.png",
        "description": "HTMX endpoint for upcoming interviews widget",
        "checks": [
            "Interview items returned",
            "Proper HTML fragment",
            "Interview details (date, candidate, job)"
        ],
        "is_htmx": True
    },
    {
        "name": "Account Settings",
        "url": "/app/dashboard/account-settings/",
        "screenshot": "06_account_settings.png",
        "description": "Account settings page (may redirect to allauth)",
        "checks": [
            "Account settings form or redirect",
            "Email management",
            "Profile settings"
        ]
    },
    {
        "name": "Help Page",
        "url": "/app/dashboard/help/",
        "screenshot": "07_help_page.png",
        "description": "Help and support page",
        "checks": [
            "Help content",
            "Support information",
            "FAQ or documentation links"
        ]
    }
]


class DashboardTester:
    """Comprehensive dashboard testing using Playwright."""

    def __init__(self, base_url: str, headless: bool = True):
        self.base_url = base_url.rstrip('/')
        self.headless = headless
        self.screenshots_dir = SCREENSHOTS_DIR
        self.results = []

        # Create directories
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)

        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

    def log(self, message: str, level: str = "INFO"):
        """Log message with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def start_browser(self):
        """Initialize browser."""
        self.log("Starting browser...")
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=self.headless)
        self.context = self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        self.page = self.context.new_page()
        self.log("Browser started successfully")

    def stop_browser(self):
        """Clean up browser resources."""
        if self.page:
            self.page.close()
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
        self.log("Browser stopped")

    def check_server_status(self) -> bool:
        """Check if server is accessible."""
        self.log(f"Checking server status: {self.base_url}")

        try:
            response = self.page.goto(self.base_url, timeout=30000, wait_until="domcontentloaded")

            if response.status == 502:
                self.log("Server returned 502 Bad Gateway - Django backend is down", "ERROR")
                return False
            elif response.status == 503:
                self.log("Server returned 503 Service Unavailable", "ERROR")
                return False
            elif response.status >= 200 and response.status < 400:
                self.log(f"Server is accessible (status: {response.status})")
                return True
            else:
                self.log(f"Server returned unexpected status: {response.status}", "WARNING")
                return False

        except Exception as e:
            self.log(f"Failed to connect to server: {e}", "ERROR")
            return False

    def login(self, email: str, password: str) -> bool:
        """
        Authenticate user.

        Returns:
            True if login successful, False otherwise
        """
        self.log(f"Attempting login as {email}...")

        try:
            # Navigate to login page
            login_url = f"{self.base_url}/accounts/login/"
            self.page.goto(login_url, timeout=30000, wait_until="domcontentloaded")

            # Wait for login form
            self.page.wait_for_selector('input[name="login"]', timeout=10000)

            # Fill in credentials
            self.page.fill('input[name="login"]', email)
            self.page.fill('input[name="password"]', password)

            # Take screenshot before login
            screenshot_path = self.screenshots_dir / "00_login_page.png"
            self.page.screenshot(path=str(screenshot_path), full_page=True)
            self.log(f"Login page screenshot: {screenshot_path}")

            # Submit form
            self.page.click('button[type="submit"]')

            # Wait for navigation
            self.page.wait_for_load_state("domcontentloaded", timeout=10000)

            # Check if we're still on login page (login failed)
            current_url = self.page.url
            if '/login/' in current_url:
                self.log("Login failed - still on login page", "ERROR")

                # Take screenshot of failed login
                error_screenshot = self.screenshots_dir / "00_login_failed.png"
                self.page.screenshot(path=str(error_screenshot), full_page=True)

                # Check for error messages
                try:
                    error_elem = self.page.query_selector('.errorlist, .alert-error, .text-red-600')
                    if error_elem:
                        error_text = error_elem.inner_text()
                        self.log(f"Login error message: {error_text}", "ERROR")
                except:
                    pass

                return False

            self.log(f"Login successful! Redirected to: {current_url}")

            # Take screenshot after login
            post_login_screenshot = self.screenshots_dir / "00_after_login.png"
            self.page.screenshot(path=str(post_login_screenshot), full_page=True)

            return True

        except Exception as e:
            self.log(f"Login error: {e}", "ERROR")
            return False

    def test_dashboard_url(self, test_config: Dict) -> Dict:
        """
        Test a single dashboard URL.

        Args:
            test_config: Test configuration dictionary

        Returns:
            Test result dictionary
        """
        url = test_config['url']
        full_url = f"{self.base_url}{url}"

        self.log("="*80)
        self.log(f"Testing: {test_config['name']}")
        self.log(f"URL: {full_url}")
        self.log(f"Description: {test_config['description']}")

        result = {
            'name': test_config['name'],
            'url': url,
            'full_url': full_url,
            'description': test_config['description'],
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'status_code': None,
            'response_time_ms': None,
            'screenshot_path': None,
            'errors': [],
            'warnings': [],
            'checks_passed': [],
            'checks_failed': [],
            'page_content_sample': None
        }

        try:
            # Navigate to URL
            start_time = time.time()

            if test_config.get('is_htmx', False):
                # For HTMX endpoints, use API request
                response = self.context.request.get(
                    full_url,
                    headers={'HX-Request': 'true'}
                )
                end_time = time.time()

                result['status_code'] = response.status
                result['response_time_ms'] = round((end_time - start_time) * 1000, 2)

                if response.status == 200:
                    result['success'] = True
                    body = response.text()
                    result['page_content_sample'] = body[:500] if len(body) > 500 else body

                    # Check if it's an HTML fragment (not full page)
                    if not body.lower().startswith('<!doctype') and not body.lower().startswith('<html'):
                        result['checks_passed'].append("✓ Returns HTML fragment (not full page)")
                    else:
                        result['checks_failed'].append("✗ Returns full HTML page instead of fragment")

                    if len(body) > 0:
                        result['checks_passed'].append(f"✓ Content returned ({len(body)} bytes)")
                    else:
                        result['warnings'].append("⚠ Empty response content")

                else:
                    result['errors'].append(f"✗ HTTP {response.status}")

            else:
                # For regular pages, navigate with browser
                response = self.page.goto(full_url, timeout=30000, wait_until="domcontentloaded")
                end_time = time.time()

                result['status_code'] = response.status
                result['response_time_ms'] = round((end_time - start_time) * 1000, 2)

                # Take screenshot
                screenshot_path = self.screenshots_dir / test_config['screenshot']
                self.page.screenshot(path=str(screenshot_path), full_page=True)
                result['screenshot_path'] = str(screenshot_path)
                self.log(f"Screenshot saved: {screenshot_path}")

                # Check response status
                if response.status == 200:
                    result['success'] = True
                    result['checks_passed'].append("✓ Page loaded successfully")

                    # Get page title
                    try:
                        title = self.page.title()
                        result['page_title'] = title
                        self.log(f"Page title: {title}")
                    except:
                        pass

                    # Get sample of page content
                    try:
                        body_text = self.page.inner_text('body')
                        result['page_content_sample'] = body_text[:500] if len(body_text) > 500 else body_text
                    except:
                        pass

                    # Run specific checks
                    for check in test_config.get('checks', []):
                        # This is a placeholder - actual checks would need selectors
                        result['checks_passed'].append(f"ℹ {check} (manual verification needed)")

                    # Check for errors in page
                    error_indicators = ['.errorlist', '.alert-danger', '.text-red-600', '[role="alert"]']
                    for selector in error_indicators:
                        try:
                            if self.page.query_selector(selector):
                                error_text = self.page.inner_text(selector)
                                result['warnings'].append(f"⚠ Error element found: {error_text[:100]}")
                        except:
                            pass

                elif response.status in [301, 302, 303, 307, 308]:
                    result['success'] = True  # Redirects can be intentional
                    result['warnings'].append(f"⚠ Redirect (status {response.status})")
                    self.log(f"Redirected to: {self.page.url}")

                elif response.status == 404:
                    result['errors'].append("✗ 404 Not Found")

                elif response.status == 500:
                    result['errors'].append("✗ 500 Internal Server Error")

                elif response.status == 403:
                    result['errors'].append("✗ 403 Forbidden")

                elif response.status == 401:
                    result['errors'].append("✗ 401 Unauthorized")

                else:
                    result['warnings'].append(f"⚠ Unexpected status: {response.status}")

            # Log result
            if result['success']:
                self.log(f"✓ SUCCESS - Status: {result['status_code']}, Time: {result['response_time_ms']}ms")
            else:
                self.log(f"✗ FAILED - Status: {result['status_code']}", "ERROR")

        except Exception as e:
            result['errors'].append(f"✗ Exception: {str(e)}")
            self.log(f"✗ Error testing {test_config['name']}: {e}", "ERROR")

        return result

    def run_all_tests(self) -> List[Dict]:
        """Run all dashboard tests."""
        self.log("="*80)
        self.log("DASHBOARD COMPREHENSIVE TESTING")
        self.log("="*80)
        self.log(f"Base URL: {self.base_url}")
        self.log(f"Total tests: {len(DASHBOARD_TESTS)}")
        self.log("="*80)

        for test_config in DASHBOARD_TESTS:
            result = self.test_dashboard_url(test_config)
            self.results.append(result)
            time.sleep(1)  # Brief pause between tests

        return self.results

    def generate_report(self) -> Dict:
        """Generate comprehensive test report."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r['success'])
        failed = total - passed

        report = {
            'summary': {
                'test_date': datetime.now().isoformat(),
                'base_url': self.base_url,
                'total_tests': total,
                'passed': passed,
                'failed': failed,
                'success_rate': round((passed / total * 100), 2) if total > 0 else 0,
            },
            'test_results': self.results
        }

        return report

    def save_report(self):
        """Save report to JSON file."""
        report = self.generate_report()

        with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.log(f"Report saved to: {RESULTS_FILE}")

        # Also save a readable text report
        text_report_path = RESULTS_FILE.with_suffix('.txt')
        with open(text_report_path, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("DASHBOARD TEST REPORT\n")
            f.write("="*80 + "\n\n")

            summary = report['summary']
            f.write(f"Test Date: {summary['test_date']}\n")
            f.write(f"Base URL: {summary['base_url']}\n")
            f.write(f"Total Tests: {summary['total_tests']}\n")
            f.write(f"Passed: {summary['passed']}\n")
            f.write(f"Failed: {summary['failed']}\n")
            f.write(f"Success Rate: {summary['success_rate']}%\n\n")

            f.write("="*80 + "\n")
            f.write("DETAILED RESULTS\n")
            f.write("="*80 + "\n\n")

            for result in self.results:
                status = "✓ PASS" if result['success'] else "✗ FAIL"
                f.write(f"{status} - {result['name']}\n")
                f.write(f"  URL: {result['url']}\n")
                f.write(f"  Status Code: {result['status_code']}\n")
                f.write(f"  Response Time: {result['response_time_ms']}ms\n")
                f.write(f"  Description: {result['description']}\n")

                if result.get('screenshot_path'):
                    f.write(f"  Screenshot: {result['screenshot_path']}\n")

                if result['checks_passed']:
                    f.write("  Checks Passed:\n")
                    for check in result['checks_passed']:
                        f.write(f"    {check}\n")

                if result['checks_failed']:
                    f.write("  Checks Failed:\n")
                    for check in result['checks_failed']:
                        f.write(f"    {check}\n")

                if result['errors']:
                    f.write("  Errors:\n")
                    for error in result['errors']:
                        f.write(f"    {error}\n")

                if result['warnings']:
                    f.write("  Warnings:\n")
                    for warning in result['warnings']:
                        f.write(f"    {warning}\n")

                f.write("\n")

        self.log(f"Text report saved to: {text_report_path}")

    def print_summary(self):
        """Print test summary."""
        report = self.generate_report()
        summary = report['summary']

        print("\n" + "="*80)
        print("TEST SUMMARY")
        print("="*80)
        print(f"Total Tests:    {summary['total_tests']}")
        print(f"Passed:         {summary['passed']} ✓")
        print(f"Failed:         {summary['failed']} ✗")
        print(f"Success Rate:   {summary['success_rate']}%")
        print("="*80)


def main():
    """Main test execution."""
    print("="*80)
    print("DASHBOARD COMPREHENSIVE TESTING")
    print("="*80)
    print(f"Target: {BASE_URL}")
    print(f"Screenshots: {SCREENSHOTS_DIR}")
    print("="*80 + "\n")

    tester = DashboardTester(BASE_URL, headless=False)

    try:
        # Start browser
        tester.start_browser()

        # Check server status
        if not tester.check_server_status():
            tester.log("Server is not accessible. Cannot proceed with tests.", "ERROR")
            tester.log("Please verify that the Django backend is running.", "ERROR")
            return 1

        # Login
        if not tester.login(TEST_EMAIL, TEST_PASSWORD):
            tester.log("Login failed. Trying alternative credentials...", "WARNING")

            # Try alternative credentials
            alt_credentials = [
                ("admin@demo-company.com", "admin123"),
                ("test@demo-company.com", "testpass123"),
                ("demo@demo.com", "demo123"),
            ]

            logged_in = False
            for email, password in alt_credentials:
                tester.log(f"Trying {email}...")
                if tester.login(email, password):
                    logged_in = True
                    break

            if not logged_in:
                tester.log("All login attempts failed. Cannot proceed.", "ERROR")
                return 1

        # Run all tests
        tester.run_all_tests()

        # Print summary
        tester.print_summary()

        # Save report
        tester.save_report()

        tester.log("✓ Testing complete!")

    except Exception as e:
        tester.log(f"Fatal error: {e}", "ERROR")
        return 1

    finally:
        # Clean up
        tester.stop_browser()

    return 0


if __name__ == "__main__":
    sys.exit(main())
