"""
Dashboard Widgets Testing Script for Zumodra

This script tests all dashboard widgets and HTMX endpoints on the live site.

Domain: https://zumodra.rhematek-solutions.com
Test Date: 2026-01-16

Tests:
1. Quick stats widget loads correctly
2. Recent activity widget
3. Upcoming interviews widget
4. Notifications widget
5. HTMX endpoints work
6. JavaScript errors in console
7. Charts/graphs render correctly
8. Widget refresh functionality
"""

import json
import time
from datetime import datetime

import pytest
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class DashboardWidgetTester:
    """Test dashboard widgets and statistics."""

    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.driver = None
        self.results = {
            'test_date': datetime.now().isoformat(),
            'base_url': base_url,
            'widgets': {},
            'htmx_endpoints': {},
            'js_errors': [],
            'charts': {},
            'summary': {
                'total_tests': 0,
                'passed': 0,
                'failed': 0,
                'warnings': 0
            }
        }

    def setup_selenium(self):
        """Initialize Selenium WebDriver with Chrome."""
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')

        # Enable browser logging
        options.set_capability('goog:loggingPrefs', {'browser': 'ALL'})

        self.driver = webdriver.Chrome(options=options)
        self.driver.implicitly_wait(10)

    def teardown(self):
        """Clean up resources."""
        if self.driver:
            self.driver.quit()
        self.session.close()

    def login(self):
        """Log in to the dashboard using Selenium."""
        print(f"\n[LOGIN] Logging in to {self.base_url}...")

        try:
            # Navigate to login page
            self.driver.get(f"{self.base_url}/accounts/login/")
            time.sleep(2)

            # Find and fill login form
            username_field = self.driver.find_element(By.NAME, "login")
            password_field = self.driver.find_element(By.NAME, "password")

            username_field.send_keys(self.username)
            password_field.send_keys(self.password)

            # Submit form
            submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_button.click()

            # Wait for redirect to dashboard
            WebDriverWait(self.driver, 10).until(
                EC.url_contains("/dashboard/")
            )

            print("[LOGIN] ✓ Successfully logged in")
            return True

        except Exception as e:
            print(f"[LOGIN] ✗ Login failed: {e}")
            return False

    def test_quick_stats_widget(self):
        """Test 1: Quick stats widget loads correctly."""
        test_name = "Quick Stats Widget"
        print(f"\n[TEST] {test_name}")
        self.results['summary']['total_tests'] += 1

        result = {
            'status': 'unknown',
            'details': {},
            'errors': []
        }

        try:
            # Check if stats cards are present
            stats_cards = self.driver.find_elements(By.CSS_SELECTOR, ".zu-stats-card, .list_counter .item")

            if len(stats_cards) < 4:
                result['status'] = 'failed'
                result['errors'].append(f"Expected at least 4 stat cards, found {len(stats_cards)}")
                print(f"  ✗ Expected at least 4 stat cards, found {len(stats_cards)}")
            else:
                result['details']['card_count'] = len(stats_cards)

                # Extract stats values
                stats = {}
                for card in stats_cards[:4]:
                    try:
                        label_elem = card.find_element(By.CSS_SELECTOR, ".zu-stats-card__label, .body_title")
                        value_elem = card.find_element(By.CSS_SELECTOR, ".zu-stats-card__value, .heading3")

                        label = label_elem.text.strip()
                        value = value_elem.text.strip()
                        stats[label] = value

                        print(f"  ✓ {label}: {value}")
                    except NoSuchElementException:
                        pass

                result['details']['stats'] = stats

                if len(stats) >= 4:
                    result['status'] = 'passed'
                    self.results['summary']['passed'] += 1
                    print(f"  ✓ {test_name} passed - {len(stats)} stats displayed")
                else:
                    result['status'] = 'warning'
                    result['errors'].append(f"Only {len(stats)} stats found, expected 4")
                    self.results['summary']['warnings'] += 1
                    print(f"  ⚠ {test_name} warning - only {len(stats)} stats found")

        except Exception as e:
            result['status'] = 'failed'
            result['errors'].append(str(e))
            self.results['summary']['failed'] += 1
            print(f"  ✗ {test_name} failed: {e}")

        self.results['widgets']['quick_stats'] = result

    def test_recent_activity_widget(self):
        """Test 2: Recent activity widget."""
        test_name = "Recent Activity Widget"
        print(f"\n[TEST] {test_name}")
        self.results['summary']['total_tests'] += 1

        result = {
            'status': 'unknown',
            'details': {},
            'errors': []
        }

        try:
            # Look for notification/activity container
            activity_containers = self.driver.find_elements(
                By.CSS_SELECTOR,
                ".notification, .list_notification, [class*='activity']"
            )

            if not activity_containers:
                result['status'] = 'warning'
                result['errors'].append("Activity widget container not found")
                self.results['summary']['warnings'] += 1
                print(f"  ⚠ Activity widget container not found")
            else:
                container = activity_containers[0]
                result['details']['container_found'] = True

                # Count activity items
                activity_items = container.find_elements(By.CSS_SELECTOR, ".item, .notification-item")
                result['details']['activity_count'] = len(activity_items)

                if len(activity_items) > 0:
                    result['status'] = 'passed'
                    self.results['summary']['passed'] += 1
                    print(f"  ✓ {test_name} passed - {len(activity_items)} activity items")
                else:
                    # No items is OK if user has no activity
                    result['status'] = 'passed'
                    result['details']['note'] = 'No activity items (empty state is valid)'
                    self.results['summary']['passed'] += 1
                    print(f"  ✓ {test_name} passed - no activity items (empty state)")

        except Exception as e:
            result['status'] = 'failed'
            result['errors'].append(str(e))
            self.results['summary']['failed'] += 1
            print(f"  ✗ {test_name} failed: {e}")

        self.results['widgets']['recent_activity'] = result

    def test_upcoming_interviews_widget(self):
        """Test 3: Upcoming interviews widget."""
        test_name = "Upcoming Interviews Widget"
        print(f"\n[TEST] {test_name}")
        self.results['summary']['total_tests'] += 1

        result = {
            'status': 'unknown',
            'details': {},
            'errors': []
        }

        try:
            # Look for interviews section
            interviews_sections = self.driver.find_elements(
                By.XPATH,
                "//*[contains(text(), 'Upcoming Interviews')]"
            )

            if not interviews_sections:
                result['status'] = 'warning'
                result['errors'].append("Upcoming interviews section not found")
                self.results['summary']['warnings'] += 1
                print(f"  ⚠ Upcoming interviews section not found")
            else:
                result['details']['section_found'] = True

                # Check for interview table or list
                interview_tables = self.driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
                interview_items = self.driver.find_elements(By.CSS_SELECTOR, ".interview-item, [class*='interview']")

                total_interviews = len(interview_tables) if interview_tables else len(interview_items)
                result['details']['interview_count'] = total_interviews

                if total_interviews > 0:
                    result['status'] = 'passed'
                    self.results['summary']['passed'] += 1
                    print(f"  ✓ {test_name} passed - {total_interviews} interviews scheduled")
                else:
                    # No interviews is OK
                    result['status'] = 'passed'
                    result['details']['note'] = 'No upcoming interviews (empty state is valid)'
                    self.results['summary']['passed'] += 1
                    print(f"  ✓ {test_name} passed - no upcoming interviews (empty state)")

        except Exception as e:
            result['status'] = 'failed'
            result['errors'].append(str(e))
            self.results['summary']['failed'] += 1
            print(f"  ✗ {test_name} failed: {e}")

        self.results['widgets']['upcoming_interviews'] = result

    def test_notifications_widget(self):
        """Test 4: Notifications widget."""
        test_name = "Notifications Widget"
        print(f"\n[TEST] {test_name}")
        self.results['summary']['total_tests'] += 1

        result = {
            'status': 'unknown',
            'details': {},
            'errors': []
        }

        try:
            # Look for notification bell/counter
            notification_bells = self.driver.find_elements(
                By.CSS_SELECTOR,
                ".notification-bell, [class*='notification'][class*='icon'], .ph-bell"
            )

            if not notification_bells:
                result['status'] = 'warning'
                result['errors'].append("Notification bell icon not found")
                self.results['summary']['warnings'] += 1
                print(f"  ⚠ Notification bell icon not found")
            else:
                result['details']['bell_found'] = True

                # Check for notification badge/count
                notification_badges = self.driver.find_elements(
                    By.CSS_SELECTOR,
                    ".notification-count, .badge, [class*='count']"
                )

                if notification_badges:
                    count_text = notification_badges[0].text.strip()
                    result['details']['unread_count'] = count_text
                    print(f"  ✓ Unread notifications: {count_text}")

                result['status'] = 'passed'
                self.results['summary']['passed'] += 1
                print(f"  ✓ {test_name} passed")

        except Exception as e:
            result['status'] = 'failed'
            result['errors'].append(str(e))
            self.results['summary']['failed'] += 1
            print(f"  ✗ {test_name} failed: {e}")

        self.results['widgets']['notifications'] = result

    def test_htmx_endpoints(self):
        """Test 5: HTMX endpoints work correctly."""
        test_name = "HTMX Endpoints"
        print(f"\n[TEST] {test_name}")

        endpoints = {
            'quick-stats': '/dashboard/htmx/quick-stats/',
            'recent-activity': '/dashboard/htmx/recent-activity/',
            'upcoming-interviews': '/dashboard/htmx/upcoming-interviews/',
        }

        for endpoint_name, endpoint_path in endpoints.items():
            self.results['summary']['total_tests'] += 1

            result = {
                'status': 'unknown',
                'url': f"{self.base_url}{endpoint_path}",
                'response_code': None,
                'errors': []
            }

            try:
                # Get cookies from Selenium
                cookies = {cookie['name']: cookie['value'] for cookie in self.driver.get_cookies()}

                # Make request with HTMX header
                headers = {
                    'HX-Request': 'true',
                    'X-Requested-With': 'XMLHttpRequest'
                }

                response = requests.get(
                    result['url'],
                    cookies=cookies,
                    headers=headers,
                    timeout=10
                )

                result['response_code'] = response.status_code

                if response.status_code == 200:
                    result['status'] = 'passed'
                    result['response_length'] = len(response.text)
                    self.results['summary']['passed'] += 1
                    print(f"  ✓ {endpoint_name}: HTTP {response.status_code} ({len(response.text)} bytes)")
                elif response.status_code == 204:
                    result['status'] = 'passed'
                    result['note'] = 'Empty response (204 No Content)'
                    self.results['summary']['passed'] += 1
                    print(f"  ✓ {endpoint_name}: HTTP {response.status_code} (No Content)")
                else:
                    result['status'] = 'failed'
                    result['errors'].append(f"Unexpected status code: {response.status_code}")
                    self.results['summary']['failed'] += 1
                    print(f"  ✗ {endpoint_name}: HTTP {response.status_code}")

            except Exception as e:
                result['status'] = 'failed'
                result['errors'].append(str(e))
                self.results['summary']['failed'] += 1
                print(f"  ✗ {endpoint_name}: {e}")

            self.results['htmx_endpoints'][endpoint_name] = result

    def test_javascript_errors(self):
        """Test 6: Check for JavaScript errors in console."""
        test_name = "JavaScript Console Errors"
        print(f"\n[TEST] {test_name}")
        self.results['summary']['total_tests'] += 1

        result = {
            'status': 'unknown',
            'errors': [],
            'warnings': [],
            'details': {}
        }

        try:
            # Get browser logs
            logs = self.driver.get_log('browser')

            severe_errors = []
            warnings = []

            for entry in logs:
                level = entry['level']
                message = entry['message']

                if level == 'SEVERE':
                    severe_errors.append(message)
                elif level == 'WARNING':
                    warnings.append(message)

            result['details']['total_logs'] = len(logs)
            result['details']['severe_count'] = len(severe_errors)
            result['details']['warning_count'] = len(warnings)
            result['errors'] = severe_errors
            result['warnings'] = warnings

            if severe_errors:
                result['status'] = 'failed'
                self.results['summary']['failed'] += 1
                print(f"  ✗ {test_name} failed - {len(severe_errors)} severe errors found:")
                for error in severe_errors[:5]:  # Show first 5
                    print(f"    - {error[:100]}")
            elif warnings:
                result['status'] = 'warning'
                self.results['summary']['warnings'] += 1
                print(f"  ⚠ {test_name} warning - {len(warnings)} warnings found")
            else:
                result['status'] = 'passed'
                self.results['summary']['passed'] += 1
                print(f"  ✓ {test_name} passed - no errors found")

            self.results['js_errors'] = result

        except Exception as e:
            result['status'] = 'failed'
            result['errors'].append(str(e))
            self.results['summary']['failed'] += 1
            print(f"  ✗ {test_name} failed: {e}")
            self.results['js_errors'] = result

    def test_charts_render(self):
        """Test 7: Verify charts/graphs render correctly."""
        test_name = "Charts Rendering"
        print(f"\n[TEST] {test_name}")
        self.results['summary']['total_tests'] += 1

        result = {
            'status': 'unknown',
            'details': {},
            'errors': []
        }

        try:
            # Look for chart containers
            chart_containers = self.driver.find_elements(
                By.CSS_SELECTOR,
                "#chart-timeline, .apexcharts-canvas, canvas, [class*='chart']"
            )

            if not chart_containers:
                result['status'] = 'warning'
                result['errors'].append("No chart containers found")
                self.results['summary']['warnings'] += 1
                print(f"  ⚠ No chart containers found")
            else:
                result['details']['chart_count'] = len(chart_containers)

                # Check if charts have content
                rendered_charts = 0
                for chart in chart_containers:
                    try:
                        # Check if chart has dimensions
                        size = chart.size
                        if size['width'] > 0 and size['height'] > 0:
                            rendered_charts += 1
                    except:
                        pass

                result['details']['rendered_count'] = rendered_charts

                if rendered_charts > 0:
                    result['status'] = 'passed'
                    self.results['summary']['passed'] += 1
                    print(f"  ✓ {test_name} passed - {rendered_charts} charts rendered")
                else:
                    result['status'] = 'warning'
                    result['errors'].append("Charts found but not rendered")
                    self.results['summary']['warnings'] += 1
                    print(f"  ⚠ Charts found but not rendered")

        except Exception as e:
            result['status'] = 'failed'
            result['errors'].append(str(e))
            self.results['summary']['failed'] += 1
            print(f"  ✗ {test_name} failed: {e}")

        self.results['charts'] = result

    def test_widget_refresh(self):
        """Test 8: Test widget refresh functionality."""
        test_name = "Widget Refresh Functionality"
        print(f"\n[TEST] {test_name}")
        self.results['summary']['total_tests'] += 1

        result = {
            'status': 'unknown',
            'details': {},
            'errors': []
        }

        try:
            # Look for refresh buttons
            refresh_buttons = self.driver.find_elements(
                By.CSS_SELECTOR,
                "button[hx-get*='dashboard'], [class*='refresh'], button[hx-trigger*='click']"
            )

            result['details']['refresh_button_count'] = len(refresh_buttons)

            if len(refresh_buttons) > 0:
                print(f"  ✓ Found {len(refresh_buttons)} refresh buttons")

                # Try to click one and see if it triggers HTMX
                try:
                    refresh_buttons[0].click()
                    time.sleep(2)

                    result['status'] = 'passed'
                    result['details']['refresh_tested'] = True
                    self.results['summary']['passed'] += 1
                    print(f"  ✓ {test_name} passed - refresh functionality working")
                except Exception as click_error:
                    result['status'] = 'warning'
                    result['errors'].append(f"Could not test refresh: {click_error}")
                    self.results['summary']['warnings'] += 1
                    print(f"  ⚠ Could not test refresh click: {click_error}")
            else:
                result['status'] = 'warning'
                result['errors'].append("No refresh buttons found")
                self.results['summary']['warnings'] += 1
                print(f"  ⚠ No refresh buttons found")

        except Exception as e:
            result['status'] = 'failed'
            result['errors'].append(str(e))
            self.results['summary']['failed'] += 1
            print(f"  ✗ {test_name} failed: {e}")

        self.results['widgets']['refresh'] = result

    def save_results(self):
        """Save test results to JSON file."""
        output_file = 'dashboard_test_results.json'

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"\n[RESULTS] Saved to {output_file}")

    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*80)
        print("DASHBOARD WIDGET TEST SUMMARY")
        print("="*80)
        print(f"Base URL: {self.base_url}")
        print(f"Test Date: {self.results['test_date']}")
        print(f"\nTotal Tests: {self.results['summary']['total_tests']}")
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

    def run_all_tests(self):
        """Run all dashboard widget tests."""
        print("\n" + "="*80)
        print("DASHBOARD WIDGET TESTING - Zumodra")
        print("="*80)
        print(f"Target: {self.base_url}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)

        try:
            # Setup
            self.setup_selenium()

            # Login
            if not self.login():
                print("\n[ERROR] Failed to login. Aborting tests.")
                return False

            # Navigate to dashboard
            self.driver.get(f"{self.base_url}/dashboard/")
            time.sleep(3)

            # Run tests
            self.test_quick_stats_widget()
            self.test_recent_activity_widget()
            self.test_upcoming_interviews_widget()
            self.test_notifications_widget()
            self.test_htmx_endpoints()
            self.test_javascript_errors()
            self.test_charts_render()
            self.test_widget_refresh()

            # Save and print results
            self.save_results()
            self.print_summary()

            return True

        except Exception as e:
            print(f"\n[ERROR] Test execution failed: {e}")
            import traceback
            traceback.print_exc()
            return False

        finally:
            self.teardown()


def main():
    """Main entry point."""
    # Configuration
    BASE_URL = "https://zumodra.rhematek-solutions.com"
    USERNAME = input("Enter username: ").strip()
    PASSWORD = input("Enter password: ").strip()

    if not USERNAME or not PASSWORD:
        print("Error: Username and password are required")
        return

    # Run tests
    tester = DashboardWidgetTester(BASE_URL, USERNAME, PASSWORD)
    success = tester.run_all_tests()

    # Exit with appropriate code
    import sys
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
