"""
Dashboard API Testing Script for Zumodra (No Selenium)

This script tests dashboard endpoints using requests only.
Use this for quick API-level testing.

Domain: https://zumodra.rhematek-solutions.com
Test Date: 2026-01-16
"""

import json
import os
import re
import sys
from datetime import datetime

import requests
from bs4 import BeautifulSoup

# Fix encoding for Windows console
if sys.platform == 'win32':
    os.system('chcp 65001 > nul')
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')


class DashboardAPITester:
    """Test dashboard endpoints via HTTP requests."""

    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {
            'test_date': datetime.now().isoformat(),
            'base_url': base_url,
            'tests': [],
            'summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'warnings': 0
            }
        }

    def add_result(self, name, status, details=None, errors=None):
        """Add a test result."""
        self.results['tests'].append({
            'name': name,
            'status': status,
            'details': details or {},
            'errors': errors or []
        })
        self.results['summary']['total'] += 1
        self.results['summary'][status] += 1

    def login(self):
        """Login to the dashboard."""
        print(f"\n[LOGIN] Logging in to {self.base_url}...")

        try:
            # Get login page to retrieve CSRF token
            login_url = f"{self.base_url}/accounts/login/"
            response = self.session.get(login_url, timeout=10)

            if response.status_code != 200:
                print(f"[LOGIN] ✗ Failed to load login page: HTTP {response.status_code}")
                return False

            # Parse CSRF token
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = None

            # Try to find CSRF token in form
            csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            if csrf_input:
                csrf_token = csrf_input.get('value')

            if not csrf_token:
                print("[LOGIN] ✗ Could not find CSRF token")
                return False

            # Submit login form
            login_data = {
                'login': self.username,
                'password': self.password,
                'csrfmiddlewaretoken': csrf_token,
            }

            response = self.session.post(
                login_url,
                data=login_data,
                headers={'Referer': login_url},
                timeout=10,
                allow_redirects=True
            )

            # Check if login was successful
            if 'dashboard' in response.url or response.status_code == 200:
                print("[LOGIN] ✓ Successfully logged in")
                return True
            else:
                print(f"[LOGIN] ✗ Login failed: redirected to {response.url}")
                return False

        except Exception as e:
            print(f"[LOGIN] ✗ Login error: {e}")
            return False

    def test_dashboard_page(self):
        """Test 1: Dashboard page loads."""
        test_name = "Dashboard Page Load"
        print(f"\n[TEST] {test_name}")

        try:
            response = self.session.get(f"{self.base_url}/dashboard/", timeout=10)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Check for key elements
                has_stats = bool(soup.find_all(class_=re.compile(r'stats|counter')))
                has_chart = bool(soup.find(id='chart-timeline'))
                has_notifications = bool(soup.find(class_=re.compile(r'notification')))

                details = {
                    'status_code': response.status_code,
                    'page_size': len(response.text),
                    'has_stats_cards': has_stats,
                    'has_chart': has_chart,
                    'has_notifications': has_notifications,
                }

                if has_stats and (has_chart or has_notifications):
                    self.add_result(test_name, 'passed', details)
                    print(f"  ✓ {test_name} passed")
                    print(f"    - Stats cards: {has_stats}")
                    print(f"    - Chart: {has_chart}")
                    print(f"    - Notifications: {has_notifications}")
                else:
                    self.add_result(test_name, 'warning', details, ['Missing some dashboard elements'])
                    print(f"  ⚠ {test_name} warning - some elements missing")
            else:
                self.add_result(test_name, 'failed', {'status_code': response.status_code})
                print(f"  ✗ {test_name} failed: HTTP {response.status_code}")

        except Exception as e:
            self.add_result(test_name, 'failed', errors=[str(e)])
            print(f"  ✗ {test_name} failed: {e}")

    def test_htmx_quick_stats(self):
        """Test 2: HTMX Quick Stats endpoint."""
        test_name = "HTMX Quick Stats"
        print(f"\n[TEST] {test_name}")

        try:
            response = self.session.get(
                f"{self.base_url}/dashboard/htmx/quick-stats/",
                headers={'HX-Request': 'true'},
                timeout=10
            )

            details = {'status_code': response.status_code}

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                stats_cards = soup.find_all(class_=re.compile(r'stats-card|counter'))
                details['card_count'] = len(stats_cards)

                # Try to extract stat values
                stats = {}
                for card in stats_cards:
                    label_elem = card.find(class_=re.compile(r'label|title'))
                    value_elem = card.find(class_=re.compile(r'value|heading'))

                    if label_elem and value_elem:
                        stats[label_elem.text.strip()] = value_elem.text.strip()

                details['stats'] = stats

                if len(stats_cards) >= 3:
                    self.add_result(test_name, 'passed', details)
                    print(f"  ✓ {test_name} passed - {len(stats_cards)} cards")
                    for label, value in stats.items():
                        print(f"    - {label}: {value}")
                else:
                    self.add_result(test_name, 'warning', details, ['Less than 3 stat cards found'])
                    print(f"  ⚠ {test_name} warning - only {len(stats_cards)} cards")

            elif response.status_code == 204:
                self.add_result(test_name, 'passed', details)
                print(f"  ✓ {test_name} passed (204 No Content - empty state)")

            else:
                self.add_result(test_name, 'failed', details)
                print(f"  ✗ {test_name} failed: HTTP {response.status_code}")

        except Exception as e:
            self.add_result(test_name, 'failed', errors=[str(e)])
            print(f"  ✗ {test_name} failed: {e}")

    def test_htmx_recent_activity(self):
        """Test 3: HTMX Recent Activity endpoint."""
        test_name = "HTMX Recent Activity"
        print(f"\n[TEST] {test_name}")

        try:
            response = self.session.get(
                f"{self.base_url}/dashboard/htmx/recent-activity/",
                headers={'HX-Request': 'true'},
                timeout=10
            )

            details = {'status_code': response.status_code}

            if response.status_code in [200, 204]:
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    activity_items = soup.find_all(class_=re.compile(r'item|activity|notification'))
                    details['activity_count'] = len(activity_items)
                    print(f"  ✓ {test_name} passed - {len(activity_items)} items")
                else:
                    print(f"  ✓ {test_name} passed (empty state)")

                self.add_result(test_name, 'passed', details)
            else:
                self.add_result(test_name, 'failed', details)
                print(f"  ✗ {test_name} failed: HTTP {response.status_code}")

        except Exception as e:
            self.add_result(test_name, 'failed', errors=[str(e)])
            print(f"  ✗ {test_name} failed: {e}")

    def test_htmx_upcoming_interviews(self):
        """Test 4: HTMX Upcoming Interviews endpoint."""
        test_name = "HTMX Upcoming Interviews"
        print(f"\n[TEST] {test_name}")

        try:
            response = self.session.get(
                f"{self.base_url}/dashboard/htmx/upcoming-interviews/",
                headers={'HX-Request': 'true'},
                timeout=10
            )

            details = {'status_code': response.status_code}

            if response.status_code in [200, 204]:
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    interview_rows = soup.find_all('tr')
                    details['interview_count'] = max(0, len(interview_rows) - 1)  # Exclude header
                    print(f"  ✓ {test_name} passed - {details['interview_count']} interviews")
                else:
                    print(f"  ✓ {test_name} passed (empty state)")

                self.add_result(test_name, 'passed', details)
            else:
                self.add_result(test_name, 'failed', details)
                print(f"  ✗ {test_name} failed: HTTP {response.status_code}")

        except Exception as e:
            self.add_result(test_name, 'failed', errors=[str(e)])
            print(f"  ✗ {test_name} failed: {e}")

    def test_global_search(self):
        """Test 5: Global search endpoint."""
        test_name = "Global Search"
        print(f"\n[TEST] {test_name}")

        try:
            response = self.session.get(
                f"{self.base_url}/dashboard/search/",
                params={'q': 'test'},
                headers={'HX-Request': 'true'},
                timeout=10
            )

            details = {'status_code': response.status_code}

            if response.status_code == 200:
                try:
                    # Try JSON response
                    data = response.json()
                    details['result_count'] = data.get('total_count', 0)
                    details['has_jobs'] = len(data.get('jobs', [])) > 0
                    details['has_candidates'] = len(data.get('candidates', [])) > 0

                    self.add_result(test_name, 'passed', details)
                    print(f"  ✓ {test_name} passed - {details['result_count']} results")
                except json.JSONDecodeError:
                    # HTML response is also OK
                    details['response_type'] = 'html'
                    self.add_result(test_name, 'passed', details)
                    print(f"  ✓ {test_name} passed (HTML response)")
            else:
                self.add_result(test_name, 'failed', details)
                print(f"  ✗ {test_name} failed: HTTP {response.status_code}")

        except Exception as e:
            self.add_result(test_name, 'failed', errors=[str(e)])
            print(f"  ✗ {test_name} failed: {e}")

    def test_static_assets(self):
        """Test 6: Check if key static assets load."""
        test_name = "Static Assets"
        print(f"\n[TEST] {test_name}")

        assets = {
            'HTMX': '/staticfiles/assets/js/vendor/htmx.min.js',
            'Alpine.js': '/staticfiles/assets/js/vendor/alpine.min.js',
            'Tailwind CSS': '/staticfiles/dist/css/output.css',
        }

        passed_assets = 0
        failed_assets = []

        for asset_name, asset_path in assets.items():
            try:
                response = self.session.head(
                    f"{self.base_url}{asset_path}",
                    timeout=5
                )

                if response.status_code == 200:
                    passed_assets += 1
                    print(f"  ✓ {asset_name} loaded")
                else:
                    failed_assets.append(f"{asset_name} (HTTP {response.status_code})")
                    print(f"  ✗ {asset_name} failed: HTTP {response.status_code}")

            except Exception as e:
                failed_assets.append(f"{asset_name} ({str(e)})")
                print(f"  ✗ {asset_name} error: {e}")

        details = {
            'total_assets': len(assets),
            'passed': passed_assets,
            'failed': failed_assets
        }

        if passed_assets == len(assets):
            self.add_result(test_name, 'passed', details)
        elif passed_assets > 0:
            self.add_result(test_name, 'warning', details, failed_assets)
        else:
            self.add_result(test_name, 'failed', details, failed_assets)

    def save_results(self):
        """Save results to JSON file."""
        output_file = 'dashboard_api_test_results.json'

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n[RESULTS] Saved to {output_file}")

    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*80)
        print("DASHBOARD API TEST SUMMARY")
        print("="*80)
        print(f"Base URL: {self.base_url}")
        print(f"Test Date: {self.results['test_date']}")
        print(f"\nTotal Tests: {self.results['summary']['total']}")
        print(f"Passed: {self.results['summary']['passed']} ✓")
        print(f"Failed: {self.results['summary']['failed']} ✗")
        print(f"Warnings: {self.results['summary']['warnings']} ⚠")

        if self.results['summary']['failed'] > 0:
            print(f"\n⚠ Status: TESTS FAILED")
        elif self.results['summary']['warnings'] > 0:
            print(f"\n⚠ Status: TESTS PASSED WITH WARNINGS")
        else:
            print(f"\n✓ Status: ALL TESTS PASSED")

        print("="*80)

        # Print detailed results
        print("\nDETAILED RESULTS:")
        print("-"*80)
        for test in self.results['tests']:
            status_icon = {'passed': '✓', 'failed': '✗', 'warning': '⚠'}.get(test['status'], '?')
            print(f"{status_icon} {test['name']}: {test['status'].upper()}")

            if test['details']:
                for key, value in test['details'].items():
                    if isinstance(value, (str, int, bool)):
                        print(f"    {key}: {value}")

            if test['errors']:
                for error in test['errors']:
                    print(f"    Error: {error}")

        print("="*80)

    def run_all_tests(self):
        """Run all dashboard API tests."""
        print("\n" + "="*80)
        print("DASHBOARD API TESTING - Zumodra")
        print("="*80)
        print(f"Target: {self.base_url}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)

        try:
            # Login
            if not self.login():
                print("\n[ERROR] Failed to login. Aborting tests.")
                return False

            # Run tests
            self.test_dashboard_page()
            self.test_htmx_quick_stats()
            self.test_htmx_recent_activity()
            self.test_htmx_upcoming_interviews()
            self.test_global_search()
            self.test_static_assets()

            # Save and print results
            self.save_results()
            self.print_summary()

            return self.results['summary']['failed'] == 0

        except Exception as e:
            print(f"\n[ERROR] Test execution failed: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main entry point."""
    # Configuration
    BASE_URL = "https://zumodra.rhematek-solutions.com"

    print("Dashboard API Testing for Zumodra")
    print("="*80)

    USERNAME = input("Enter username: ").strip()
    PASSWORD = input("Enter password: ").strip()

    if not USERNAME or not PASSWORD:
        print("Error: Username and password are required")
        return

    # Run tests
    tester = DashboardAPITester(BASE_URL, USERNAME, PASSWORD)
    success = tester.run_all_tests()

    # Exit with appropriate code
    import sys
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
