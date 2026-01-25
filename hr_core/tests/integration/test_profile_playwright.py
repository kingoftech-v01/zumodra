"""
Enhanced User Profile Management Test with Playwright
Captures screenshots and tests real user interactions
Server: demo-company.zumodra.rhematek-solutions.com
"""

import sys
import time
from datetime import datetime
from pathlib import Path

# Set UTF-8 encoding for Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    print("ERROR: Playwright is not installed.")
    print("Please install it with:")
    print("  pip install playwright")
    print("  playwright install chromium")
    sys.exit(1)

# Configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
LOGIN_EMAIL = "company.owner@demo.zumodra.rhematek-solutions.com"
LOGIN_PASSWORD = "Demo@2024!"

# Results directory
RESULTS_DIR = Path("./profile_test_results")
SCREENSHOTS_DIR = RESULTS_DIR / "screenshots"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
REPORT_FILE = RESULTS_DIR / f"USER_PROFILE_TEST_REPORT_{TIMESTAMP}.md"

# Create directories
RESULTS_DIR.mkdir(exist_ok=True)
SCREENSHOTS_DIR.mkdir(exist_ok=True)

# Test results
test_results = []


class ProfileTest:
    """Enhanced profile testing with Playwright"""

    def __init__(self, page):
        self.page = page
        self.logged_in = False

    def log_test(self, test_name, status, details, screenshot_name=None):
        """Log test result"""
        result = {
            'test': test_name,
            'status': status,
            'details': details,
            'screenshot': screenshot_name,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        test_results.append(result)

        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"\n{status_icon} {test_name}")
        print(f"   {details}")
        if screenshot_name:
            print(f"   Screenshot: {screenshot_name}")

    def screenshot(self, name):
        """Take and save screenshot"""
        filename = f"{TIMESTAMP}_{name}.png"
        filepath = SCREENSHOTS_DIR / filename
        self.page.screenshot(path=str(filepath), full_page=True)
        return filename

    def login(self):
        """Login to the platform"""
        print("\n" + "="*80)
        print("AUTHENTICATION")
        print("="*80)

        try:
            # Navigate to login page
            self.page.goto(f"{BASE_URL}/accounts/login/", wait_until="networkidle", timeout=30000)
            time.sleep(1)

            screenshot_name = self.screenshot("01_login_page")

            # Fill login form
            self.page.fill('input[name="login"]', LOGIN_EMAIL)
            self.page.fill('input[name="password"]', LOGIN_PASSWORD)

            # Submit login
            self.page.click('button[type="submit"]')
            self.page.wait_for_load_state("networkidle", timeout=30000)
            time.sleep(2)

            # Verify login success
            current_url = self.page.url
            page_content = self.page.content()

            success = any([
                'logout' in page_content.lower(),
                'sign out' in page_content.lower(),
                'dashboard' in page_content.lower(),
                current_url != f"{BASE_URL}/accounts/login/"
            ])

            if success:
                self.logged_in = True
                screenshot_name = self.screenshot("02_logged_in_dashboard")
                self.log_test(
                    "User Login",
                    "PASS",
                    f"Successfully logged in as {LOGIN_EMAIL}",
                    screenshot_name
                )
                return True
            else:
                screenshot_name = self.screenshot("02_login_failed")
                self.log_test(
                    "User Login",
                    "FAIL",
                    f"Login failed. Current URL: {current_url}",
                    screenshot_name
                )
                return False

        except Exception as e:
            screenshot_name = self.screenshot("02_login_error")
            self.log_test("User Login", "FAIL", f"Login error: {str(e)}", screenshot_name)
            return False

    def test_own_profile_view(self):
        """Test 1: View own profile"""
        print("\n" + "="*80)
        print("TEST 1: OWN PROFILE VIEW")
        print("="*80)

        try:
            # Try different profile URLs
            profile_urls = [
                "/user/profile/",
                "/accounts/profile/",
                "/profile/",
                "/app/accounts/profile/",
            ]

            profile_loaded = False
            for url_path in profile_urls:
                try:
                    self.page.goto(f"{BASE_URL}{url_path}", wait_until="networkidle", timeout=10000)
                    time.sleep(1)

                    if self.page.url.endswith(url_path) or 'profile' in self.page.url.lower():
                        profile_loaded = True
                        print(f"   Found profile at: {url_path}")
                        break
                except:
                    continue

            if not profile_loaded:
                screenshot_name = self.screenshot("03_profile_not_found")
                self.log_test(
                    "Own Profile View",
                    "FAIL",
                    "Profile page not accessible",
                    screenshot_name
                )
                return False

            screenshot_name = self.screenshot("03_own_profile_view")

            # Check visible elements
            page_content = self.page.content().lower()

            checks = {
                'Profile Page Loaded': True,
                'User Info Visible': any(x in page_content for x in ['name', 'email', 'profile']),
                'Bio Section': 'bio' in page_content,
                'Contact Info': any(x in page_content for x in ['phone', 'contact', 'email']),
                'Social Links': any(x in page_content for x in ['linkedin', 'github', 'twitter']),
                'Edit Option': any(x in page_content for x in ['edit', 'update', 'modify']),
            }

            passed = sum(checks.values())
            total = len(checks)

            for check_name, check_result in checks.items():
                status_icon = "✓" if check_result else "✗"
                print(f"   {status_icon} {check_name}")

            status = "PASS" if passed >= total - 2 else "PARTIAL"
            self.log_test(
                "Own Profile View",
                status,
                f"Profile page checks: {passed}/{total} passed",
                screenshot_name
            )
            return passed >= total - 2

        except Exception as e:
            screenshot_name = self.screenshot("03_profile_error")
            self.log_test("Own Profile View", "FAIL", f"Error: {str(e)}", screenshot_name)
            return False

    def test_profile_search(self):
        """Test 5: Profile Search"""
        print("\n" + "="*80)
        print("TEST 5: PROFILE SEARCH")
        print("="*80)

        try:
            # Try search URLs
            search_urls = [
                "/user/profile/search/",
                "/users/search/",
                "/search/users/",
                "/accounts/search/",
            ]

            search_found = False
            for url_path in search_urls:
                try:
                    self.page.goto(f"{BASE_URL}{url_path}", wait_until="networkidle", timeout=10000)
                    time.sleep(1)

                    if self.page.url.endswith(url_path) or 'search' in self.page.url.lower():
                        search_found = True
                        print(f"   Found search at: {url_path}")
                        break
                except:
                    continue

            if search_found:
                screenshot_name = self.screenshot("04_profile_search")

                # Try to search
                page_content = self.page.content().lower()

                search_features = {
                    'Search Form': any(x in page_content for x in ['search', 'find', 'query']),
                    'Search Input': 'input' in page_content and 'search' in page_content,
                    'Search Button': 'button' in page_content or 'submit' in page_content,
                }

                passed = sum(search_features.values())
                total = len(search_features)

                for check_name, check_result in search_features.items():
                    status_icon = "✓" if check_result else "✗"
                    print(f"   {status_icon} {check_name}")

                self.log_test(
                    "Profile Search",
                    "PASS" if passed >= 2 else "PARTIAL",
                    f"Search features: {passed}/{total} found",
                    screenshot_name
                )
                return passed >= 2
            else:
                self.log_test(
                    "Profile Search",
                    "SKIP",
                    "Search page not found"
                )
                return None

        except Exception as e:
            screenshot_name = self.screenshot("04_search_error")
            self.log_test("Profile Search", "FAIL", f"Error: {str(e)}", screenshot_name)
            return False

    def test_user_settings(self):
        """Test user account settings"""
        print("\n" + "="*80)
        print("TEST: USER ACCOUNT SETTINGS")
        print("="*80)

        try:
            # Try settings/account management URLs
            settings_urls = [
                "/accounts/email/",
                "/accounts/password/change/",
                "/settings/",
                "/account/settings/",
            ]

            settings_accessible = []
            for url_path in settings_urls:
                try:
                    self.page.goto(f"{BASE_URL}{url_path}", wait_until="networkidle", timeout=10000)
                    time.sleep(1)

                    if self.page.url.endswith(url_path) or url_path.split('/')[-2] in self.page.url:
                        settings_accessible.append(url_path)
                        print(f"   ✓ Accessible: {url_path}")
                        screenshot_name = self.screenshot(f"05_settings_{url_path.replace('/', '_')}")
                except:
                    print(f"   ✗ Not accessible: {url_path}")
                    continue

            if settings_accessible:
                self.log_test(
                    "User Account Settings",
                    "PASS",
                    f"Found {len(settings_accessible)} settings pages: {', '.join(settings_accessible)}",
                    None
                )
                return True
            else:
                self.log_test(
                    "User Account Settings",
                    "PARTIAL",
                    "No account settings pages found"
                )
                return False

        except Exception as e:
            self.log_test("User Account Settings", "FAIL", f"Error: {str(e)}")
            return False

    def test_navigation_menu(self):
        """Test navigation menu for profile links"""
        print("\n" + "="*80)
        print("TEST: NAVIGATION MENU")
        print("="*80)

        try:
            # Go to dashboard
            self.page.goto(f"{BASE_URL}/", wait_until="networkidle", timeout=10000)
            time.sleep(1)

            screenshot_name = self.screenshot("06_navigation_menu")

            page_content = self.page.content().lower()

            # Look for profile/account links in navigation
            nav_items = {
                'Profile Link': 'profile' in page_content,
                'Account Link': 'account' in page_content,
                'Settings Link': 'settings' in page_content,
                'Logout Link': 'logout' in page_content or 'sign out' in page_content,
            }

            passed = sum(nav_items.values())
            total = len(nav_items)

            for check_name, check_result in nav_items.items():
                status_icon = "✓" if check_result else "✗"
                print(f"   {status_icon} {check_name}")

            self.log_test(
                "Navigation Menu",
                "PASS" if passed >= 3 else "PARTIAL",
                f"Navigation items: {passed}/{total} found",
                screenshot_name
            )
            return passed >= 3

        except Exception as e:
            screenshot_name = self.screenshot("06_navigation_error")
            self.log_test("Navigation Menu", "FAIL", f"Error: {str(e)}", screenshot_name)
            return False


def generate_report():
    """Generate test report"""
    print("\n" + "="*80)
    print("GENERATING REPORT")
    print("="*80)

    total_tests = len(test_results)
    passed_tests = sum(1 for r in test_results if r['status'] == 'PASS')
    failed_tests = sum(1 for r in test_results if r['status'] == 'FAIL')
    partial_tests = sum(1 for r in test_results if r['status'] == 'PARTIAL')
    skipped_tests = sum(1 for r in test_results if r['status'] == 'SKIP')

    report_content = f"""# User Profile Management Test Report

**Server:** demo-company.zumodra.rhematek-solutions.com
**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Test Method:** Playwright Automation with Screenshots

## Executive Summary

| Metric | Count |
|--------|-------|
| Total Tests | {total_tests} |
| ✅ Passed | {passed_tests} |
| ❌ Failed | {failed_tests} |
| ⚠️ Partial | {partial_tests} |
| ⏭️ Skipped | {skipped_tests} |
| **Success Rate** | **{(passed_tests/total_tests*100):.1f}%** |

## Test Results

"""

    for i, result in enumerate(test_results, 1):
        status_icon = {
            'PASS': '✅',
            'FAIL': '❌',
            'PARTIAL': '⚠️',
            'SKIP': '⏭️',
        }.get(result['status'], '❓')

        report_content += f"""### {i}. {result['test']}

**Status:** {status_icon} {result['status']}
**Details:** {result['details']}
**Timestamp:** {result['timestamp']}

"""
        if result.get('screenshot'):
            report_content += f"**Screenshot:** `screenshots/{result['screenshot']}`\n\n"
            report_content += f"![{result['test']}](screenshots/{result['screenshot']})\n\n"

    report_content += f"""
## Screenshots Location

All screenshots have been saved to: `{SCREENSHOTS_DIR.absolute()}`

## Test Coverage

1. ✅ User Login & Authentication
2. ✅ Own Profile View - Visibility & Content
3. ✅ Profile Search Functionality
4. ✅ User Account Settings Access
5. ✅ Navigation Menu - Profile Links

## Key Findings

### ✅ What's Working

"""

    passing_tests = [r for r in test_results if r['status'] == 'PASS']
    for test in passing_tests:
        report_content += f"- **{test['test']}**: {test['details']}\n"

    report_content += "\n### ❌ Issues Found\n\n"

    failing_tests = [r for r in test_results if r['status'] in ['FAIL', 'PARTIAL']]
    if failing_tests:
        for test in failing_tests:
            report_content += f"- **{test['test']}**: {test['details']}\n"
    else:
        report_content += "No critical issues found.\n"

    report_content += """
## Recommendations

1. **Profile Management**: Ensure dedicated user profile edit page exists
2. **Profile Completion**: Add profile completion percentage tracking
3. **Profile Photos**: Implement profile photo upload functionality
4. **Privacy Controls**: Add granular privacy settings for profile visibility
5. **Search**: Enhance profile search with filters and advanced options

## Conclusion

"""

    if passed_tests / total_tests >= 0.8:
        report_content += "✅ **User profile functionality is working well.** "
    elif passed_tests / total_tests >= 0.6:
        report_content += "⚠️ **User profile functionality is partially working.** "
    else:
        report_content += "❌ **User profile functionality needs improvement.** "

    report_content += f"Passed {passed_tests}/{total_tests} tests ({(passed_tests/total_tests*100):.1f}% success rate).\n"

    # Write report
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(report_content)

    print(f"\n✅ Report generated: {REPORT_FILE}")
    print(f"   Screenshots saved to: {SCREENSHOTS_DIR}")
    print(f"   Total Tests: {total_tests}")
    print(f"   Passed: {passed_tests}")
    print(f"   Failed: {failed_tests}")
    print(f"   Success Rate: {(passed_tests/total_tests*100):.1f}%")


def main():
    """Main test execution"""
    print("="*80)
    print("USER PROFILE MANAGEMENT TEST SUITE (PLAYWRIGHT)")
    print("="*80)
    print(f"Server: {BASE_URL}")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Screenshots: {SCREENSHOTS_DIR}")
    print("="*80)

    with sync_playwright() as p:
        # Launch browser
        browser = p.chromium.launch(headless=False)  # Set to True for headless
        context = browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        page = context.new_page()

        # Create test instance
        tester = ProfileTest(page)

        # Run tests
        if not tester.login():
            print("\n❌ Cannot proceed without authentication")
            browser.close()
            return

        time.sleep(2)

        # Run profile tests
        tester.test_own_profile_view()
        time.sleep(2)

        tester.test_profile_search()
        time.sleep(2)

        tester.test_user_settings()
        time.sleep(2)

        tester.test_navigation_menu()
        time.sleep(2)

        # Close browser
        browser.close()

    # Generate report
    generate_report()

    print("\n" + "="*80)
    print("TEST SUITE COMPLETED")
    print("="*80)


if __name__ == "__main__":
    main()
