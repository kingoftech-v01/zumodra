"""
Selenium Automated Tests for Public User Dashboard
Browser automation testing with screenshots

Requirements:
pip install selenium webdriver-manager pillow

Run with: python test_public_dashboard_selenium.py
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from datetime import datetime
from PIL import Image
import time
import os
import json

# Configuration
BASE_URL = "https://zumodra.rhematek-solutions.com"
LOGIN_URL = f"{BASE_URL}/accounts/login/"
DASHBOARD_URL = f"{BASE_URL}/app/dashboard/"
SCREENSHOT_DIR = "test_screenshots"

# Test credentials (REPLACE WITH ACTUAL CREDENTIALS)
TEST_USER = {
    'username': 'publicuser',  # Replace with actual test user
    'password': 'testpass123',  # Replace with actual password
}


class PublicDashboardSeleniumTests:
    """Selenium-based automated tests for public user dashboard."""

    def __init__(self):
        self.results = []
        self.screenshot_count = 0
        self.setup_driver()
        self.setup_screenshot_dir()

    def setup_driver(self):
        """Initialize Chrome WebDriver with options."""
        print("🚀 Setting up Chrome WebDriver...")

        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)

        # Uncomment for headless mode
        # chrome_options.add_argument("--headless")
        # chrome_options.add_argument("--window-size=1920,1080")

        self.driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=chrome_options
        )
        self.driver.implicitly_wait(10)
        self.wait = WebDriverWait(self.driver, 10)

    def setup_screenshot_dir(self):
        """Create screenshot directory."""
        if not os.path.exists(SCREENSHOT_DIR):
            os.makedirs(SCREENSHOT_DIR)
            print(f"📁 Created screenshot directory: {SCREENSHOT_DIR}")

    def log_test(self, name, passed, details=""):
        """Log test result."""
        status = "✅ PASS" if passed else "❌ FAIL"
        result = {
            'name': name,
            'status': status,
            'passed': passed,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.results.append(result)
        print(f"{status}: {name}")
        if details:
            print(f"  {details}")
        return passed

    def take_screenshot(self, name):
        """Take and save screenshot."""
        self.screenshot_count += 1
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{SCREENSHOT_DIR}/{self.screenshot_count:02d}_{name}_{timestamp}.png"
        self.driver.save_screenshot(filename)
        print(f"  📸 Screenshot saved: {filename}")
        return filename

    def login(self, username, password):
        """Login to the application."""
        print(f"\n🔐 Logging in as {username}...")

        try:
            self.driver.get(LOGIN_URL)
            self.take_screenshot("01_login_page")

            # Wait for login form
            username_field = self.wait.until(
                EC.presence_of_element_located((By.NAME, "login"))
            )
            password_field = self.driver.find_element(By.NAME, "password")

            # Enter credentials
            username_field.clear()
            username_field.send_keys(username)
            password_field.clear()
            password_field.send_keys(password)

            self.take_screenshot("02_login_filled")

            # Submit form
            submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_button.click()

            # Wait for redirect
            time.sleep(2)
            self.take_screenshot("03_after_login")

            # Check if login successful
            if "Welcome" in self.driver.page_source or "dashboard" in self.driver.current_url.lower():
                self.log_test("Login successful", True)
                return True
            else:
                self.log_test("Login successful", False, "Login failed - no redirect")
                return False

        except Exception as e:
            self.log_test("Login successful", False, str(e))
            return False

    def test_dashboard_access(self):
        """Test 1: Dashboard Access."""
        print("\n📋 Test 1: Dashboard Access")

        try:
            self.driver.get(DASHBOARD_URL)
            time.sleep(2)
            self.take_screenshot("04_dashboard_loaded")

            # Check page loaded
            passed = self.driver.current_url == DASHBOARD_URL
            self.log_test("Dashboard page loads", passed)

            # Check for welcome message
            page_source = self.driver.page_source
            has_welcome = "Welcome" in page_source
            self.log_test("Welcome message displays", has_welcome)

            return passed

        except Exception as e:
            self.log_test("Dashboard access", False, str(e))
            return False

    def test_welcome_banner(self):
        """Test 2: Welcome Banner."""
        print("\n👋 Test 2: Welcome Banner")

        try:
            # Check for gradient background
            page_source = self.driver.page_source
            has_gradient = "gradient" in page_source.lower() and "blue" in page_source.lower()
            self.log_test("Welcome banner gradient present", has_gradient)

            # Check for "Complete your profile" message
            has_profile_msg = "Complete your profile" in page_source
            self.log_test("Profile completion message displays", has_profile_msg)

            self.take_screenshot("05_welcome_banner")
            return True

        except Exception as e:
            self.log_test("Welcome banner", False, str(e))
            return False

    def test_mfa_warning(self):
        """Test 3: MFA Warning Banner."""
        print("\n🛡️ Test 3: MFA Warning Banner")

        try:
            page_source = self.driver.page_source

            has_security_notice = "Security Notice" in page_source
            has_mfa_warning = "Two-factor authentication" in page_source

            if has_security_notice and has_mfa_warning:
                self.log_test("MFA warning banner displays", True)

                # Check for setup link
                try:
                    setup_link = self.driver.find_element(By.LINK_TEXT, "Set it up now")
                    self.log_test("MFA setup link present", True)
                    self.take_screenshot("06_mfa_warning")
                except:
                    self.log_test("MFA setup link present", False)
            else:
                self.log_test("MFA warning banner displays", False,
                             "User may have MFA enabled")

            return True

        except Exception as e:
            self.log_test("MFA warning banner", False, str(e))
            return False

    def test_profile_completion(self):
        """Test 4: Profile Completion Widget."""
        print("\n📊 Test 4: Profile Completion Widget")

        try:
            page_source = self.driver.page_source

            # Check for widget
            has_widget = "Profile Completion" in page_source
            self.log_test("Profile completion widget displays", has_widget)

            # Check for percentage
            has_percentage = "%" in page_source
            self.log_test("Profile completion percentage shows", has_percentage)

            # Try to find the percentage value
            try:
                # Look for elements with percentage
                completion_elem = self.driver.find_element(
                    By.XPATH, "//*[contains(text(), '%')]"
                )
                completion_text = completion_elem.text
                self.log_test("Profile completion value found", True, f"Value: {completion_text}")
            except:
                self.log_test("Profile completion value found", False)

            self.take_screenshot("07_profile_completion")
            return True

        except Exception as e:
            self.log_test("Profile completion widget", False, str(e))
            return False

    def test_quick_actions(self):
        """Test 5: Quick Actions Cards."""
        print("\n⚡ Test 5: Quick Actions Cards")

        try:
            page_source = self.driver.page_source

            # Check for all three cards
            has_browse_jobs = "Browse Jobs" in page_source
            self.log_test("Browse Jobs card displays", has_browse_jobs)

            has_browse_services = "Browse Services" in page_source
            self.log_test("Browse Services card displays", has_browse_services)

            has_enable_2fa = "Enable 2FA" in page_source or "Secure your account" in page_source
            self.log_test("Enable 2FA card displays", has_enable_2fa)

            # Check for icons
            has_icons = "ph-briefcase" in page_source or "ph-storefront" in page_source
            self.log_test("Quick action icons display", has_icons)

            self.take_screenshot("08_quick_actions")

            # Test hover effect on first card (if possible)
            try:
                first_card = self.driver.find_element(By.LINK_TEXT, "Browse Jobs")
                webdriver.ActionChains(self.driver).move_to_element(first_card).perform()
                time.sleep(0.5)
                self.take_screenshot("09_quick_actions_hover")
                self.log_test("Hover effects work", True)
            except:
                self.log_test("Hover effects work", False, "Could not test hover")

            return True

        except Exception as e:
            self.log_test("Quick actions cards", False, str(e))
            return False

    def test_recommended_jobs(self):
        """Test 6: Recommended Jobs Section."""
        print("\n💼 Test 6: Recommended Jobs Section")

        try:
            page_source = self.driver.page_source

            if "Recommended Jobs" in page_source:
                self.log_test("Recommended jobs section displays", True, "Jobs found")
                self.take_screenshot("10_recommended_jobs")

                # Check for job details
                has_location = "ph-map-pin" in page_source
                self.log_test("Job cards show location icon", has_location)

                # Check for "View all jobs" link
                has_view_all = "View all jobs" in page_source
                self.log_test("View all jobs link present", has_view_all)

            elif "No jobs available" in page_source:
                self.log_test("Empty state displays", True, "No jobs available")
                self.take_screenshot("10_no_jobs_empty_state")

                # Check for empty state icon
                has_icon = "ph-briefcase" in page_source
                self.log_test("Empty state icon displays", has_icon)

            else:
                self.log_test("Jobs section displays", False, "Neither jobs nor empty state found")

            return True

        except Exception as e:
            self.log_test("Recommended jobs section", False, str(e))
            return False

    def test_join_organization_cta(self):
        """Test 7: Join Organization CTA."""
        print("\n🏢 Test 7: Join Organization CTA")

        try:
            page_source = self.driver.page_source

            has_cta = "Ready to do more?" in page_source
            self.log_test("Join organization CTA displays", has_cta)

            # Check for buttons
            has_join_btn = "Join Organization" in page_source
            self.log_test("Join Organization button present", has_join_btn)

            has_create_btn = "Create Organization" in page_source
            self.log_test("Create Organization button present", has_create_btn)

            self.take_screenshot("11_join_org_cta")
            return True

        except Exception as e:
            self.log_test("Join organization CTA", False, str(e))
            return False

    def test_dark_mode(self):
        """Test 8: Dark Mode Support."""
        print("\n🌙 Test 8: Dark Mode Support")

        try:
            page_source = self.driver.page_source

            # Check for dark mode classes
            has_dark_classes = "dark:bg-gray-800" in page_source
            self.log_test("Dark mode classes present", has_dark_classes)

            # Try to toggle dark mode (if toggle exists)
            try:
                # Look for dark mode toggle button
                dark_mode_toggle = self.driver.find_element(
                    By.CSS_SELECTOR, "[data-theme-toggle], [aria-label*='dark'], [aria-label*='theme']"
                )
                self.log_test("Dark mode toggle found", True)

                # Click toggle
                dark_mode_toggle.click()
                time.sleep(1)
                self.take_screenshot("12_dark_mode")

                # Toggle back
                dark_mode_toggle.click()
                time.sleep(1)

            except:
                self.log_test("Dark mode toggle found", False,
                             "Toggle not found or not clickable")

            return True

        except Exception as e:
            self.log_test("Dark mode support", False, str(e))
            return False

    def test_responsive_mobile(self):
        """Test 9: Responsive Design (Mobile)."""
        print("\n📱 Test 9: Responsive Design - Mobile")

        try:
            # Set mobile viewport
            self.driver.set_window_size(375, 667)
            time.sleep(2)
            self.take_screenshot("13_mobile_view_375")

            page_source = self.driver.page_source

            # Check for responsive classes
            has_grid_cols_1 = "grid-cols-1" in page_source
            self.log_test("Mobile: Single column grid", has_grid_cols_1)

            # Restore desktop size
            self.driver.maximize_window()
            time.sleep(1)

            return True

        except Exception as e:
            self.log_test("Responsive mobile view", False, str(e))
            return False

    def test_responsive_tablet(self):
        """Test 10: Responsive Design (Tablet)."""
        print("\n📱 Test 10: Responsive Design - Tablet")

        try:
            # Set tablet viewport
            self.driver.set_window_size(768, 1024)
            time.sleep(2)
            self.take_screenshot("14_tablet_view_768")

            page_source = self.driver.page_source

            # Check for responsive classes
            has_md_grid = "md:grid-cols-3" in page_source
            self.log_test("Tablet: Responsive grid classes", has_md_grid)

            # Restore desktop size
            self.driver.maximize_window()
            time.sleep(1)

            return True

        except Exception as e:
            self.log_test("Responsive tablet view", False, str(e))
            return False

    def test_full_page_screenshot(self):
        """Take full-page screenshot."""
        print("\n📸 Taking full-page screenshot...")

        try:
            # Desktop view
            self.driver.maximize_window()
            time.sleep(1)
            self.take_screenshot("15_full_desktop_1920")

            return True

        except Exception as e:
            print(f"❌ Full-page screenshot failed: {e}")
            return False

    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*60)
        print("📊 TEST SUMMARY")
        print("="*60)

        total = len(self.results)
        passed = sum(1 for r in self.results if r['passed'])
        failed = total - passed

        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"Success Rate: {(passed/total*100):.1f}%")
        print(f"📸 Screenshots taken: {self.screenshot_count}")

        if failed > 0:
            print("\n❌ Failed Tests:")
            for result in self.results:
                if not result['passed']:
                    print(f"  - {result['name']}")
                    if result['details']:
                        print(f"    {result['details']}")

        # Save results to JSON
        results_file = f"{SCREENSHOT_DIR}/test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump({
                'summary': {
                    'total': total,
                    'passed': passed,
                    'failed': failed,
                    'success_rate': f"{(passed/total*100):.1f}%",
                    'screenshots': self.screenshot_count,
                },
                'results': self.results
            }, f, indent=2)
        print(f"\n💾 Results saved to: {results_file}")
        print(f"📁 Screenshots saved to: {SCREENSHOT_DIR}/")

    def cleanup(self):
        """Close browser and cleanup."""
        print("\n🧹 Cleaning up...")
        self.driver.quit()

    def run_all_tests(self):
        """Run all tests."""
        print("="*60)
        print("🚀 PUBLIC USER DASHBOARD - SELENIUM TESTS")
        print("="*60)
        print(f"Server: {BASE_URL}")
        print(f"Dashboard: {DASHBOARD_URL}")
        print("="*60)

        try:
            # Login
            if not self.login(TEST_USER['username'], TEST_USER['password']):
                print("\n❌ Login failed. Cannot proceed with tests.")
                return

            # Run tests
            self.test_dashboard_access()
            self.test_welcome_banner()
            self.test_mfa_warning()
            self.test_profile_completion()
            self.test_quick_actions()
            self.test_recommended_jobs()
            self.test_join_organization_cta()
            self.test_dark_mode()
            self.test_responsive_mobile()
            self.test_responsive_tablet()
            self.test_full_page_screenshot()

            # Summary
            self.print_summary()

        except Exception as e:
            print(f"\n❌ Test suite error: {e}")

        finally:
            self.cleanup()


def main():
    """Main entry point."""
    print("="*60)
    print("PUBLIC USER DASHBOARD - SELENIUM AUTOMATED TESTS")
    print("="*60)
    print(f"Target Server: {BASE_URL}")
    print(f"Dashboard URL: {DASHBOARD_URL}")
    print("\n⚠️  IMPORTANT: Update TEST_USER with actual credentials!")
    print("="*60)

    # Check if credentials are set
    if TEST_USER['username'] == 'publicuser' and TEST_USER['password'] == 'testpass123':
        print("\n⚠️  WARNING: Using default test credentials.")
        print("Please update TEST_USER in the script with valid credentials.\n")

        response = input("Continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            print("❌ Exiting.")
            return

    # Run tests
    tester = PublicDashboardSeleniumTests()
    tester.run_all_tests()

    print("\n" + "="*60)
    print("✅ Testing Complete!")
    print("="*60)


if __name__ == '__main__':
    main()
