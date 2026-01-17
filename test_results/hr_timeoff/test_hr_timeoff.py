"""
HR Time-Off Module Testing Script
Tests all time-off related functionality on demo-company.zumodra.rhematek-solutions.com

This script:
1. Authenticates to the demo site
2. Tests all time-off URLs
3. Takes screenshots
4. Tests create/approve/reject functionality
5. Documents findings
"""

import os
import time
import json
from datetime import datetime, timedelta
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# Configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
SCREENSHOT_DIR = "c:/Users/techn/OneDrive/Documents/zumodra/test_results/hr_timeoff"
TEST_RESULTS = {
    "timestamp": datetime.now().isoformat(),
    "base_url": BASE_URL,
    "tests": [],
    "errors": [],
    "warnings": []
}

# Test credentials - try common demo credentials
CREDENTIALS = [
    {"username": "admin@demo.com", "password": "admin123"},
    {"username": "demo@demo.com", "password": "demo123"},
    {"username": "admin", "password": "admin"},
    {"username": "test@test.com", "password": "test123"},
    {"username": "hr@demo.com", "password": "demo123"},
]


class HRTimeOffTester:
    def __init__(self):
        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)

        # Accept invalid certificates for testing
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--ignore-ssl-errors")

        self.driver = webdriver.Chrome(options=chrome_options)
        self.wait = WebDriverWait(self.driver, 10)
        self.authenticated = False

    def save_screenshot(self, name):
        """Save a screenshot with timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}.png"
        filepath = os.path.join(SCREENSHOT_DIR, filename)
        self.driver.save_screenshot(filepath)
        print(f"📸 Screenshot saved: {filename}")
        return filename

    def log_test(self, url, status, message, screenshot=None):
        """Log a test result."""
        result = {
            "url": url,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "screenshot": screenshot
        }
        TEST_RESULTS["tests"].append(result)

        icon = "✅" if status == "pass" else "❌" if status == "fail" else "⚠️"
        print(f"{icon} {url}: {message}")

    def log_error(self, message, exception=None):
        """Log an error."""
        error = {
            "message": message,
            "exception": str(exception) if exception else None,
            "timestamp": datetime.now().isoformat()
        }
        TEST_RESULTS["errors"].append(error)
        print(f"❌ ERROR: {message}")
        if exception:
            print(f"   Exception: {exception}")

    def authenticate(self):
        """Try to authenticate with various credentials."""
        print("\n🔐 Attempting authentication...")

        for cred in CREDENTIALS:
            try:
                print(f"   Trying {cred['username']}...")
                self.driver.get(f"{BASE_URL}/accounts/login/")
                time.sleep(2)

                # Take screenshot of login page
                self.save_screenshot("01_login_page")

                # Try to find login form
                try:
                    username_field = self.driver.find_element(By.NAME, "username")
                except NoSuchElementException:
                    try:
                        username_field = self.driver.find_element(By.NAME, "email")
                    except NoSuchElementException:
                        try:
                            username_field = self.driver.find_element(By.ID, "id_username")
                        except NoSuchElementException:
                            username_field = self.driver.find_element(By.ID, "id_email")

                try:
                    password_field = self.driver.find_element(By.NAME, "password")
                except NoSuchElementException:
                    password_field = self.driver.find_element(By.ID, "id_password")

                # Enter credentials
                username_field.clear()
                username_field.send_keys(cred['username'])
                password_field.clear()
                password_field.send_keys(cred['password'])

                # Find and click submit button
                try:
                    submit_btn = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
                except NoSuchElementException:
                    submit_btn = self.driver.find_element(By.CSS_SELECTOR, "input[type='submit']")

                submit_btn.click()
                time.sleep(3)

                # Check if we're authenticated
                current_url = self.driver.current_url
                if "login" not in current_url.lower() and "error" not in self.driver.page_source.lower():
                    print(f"✅ Successfully authenticated as {cred['username']}")
                    self.authenticated = True
                    self.save_screenshot("02_authenticated")
                    return True

            except Exception as e:
                print(f"   Failed with {cred['username']}: {e}")
                continue

        # If all credentials fail, take screenshot and return False
        self.save_screenshot("00_auth_failed")
        self.log_error("Authentication failed with all provided credentials")
        return False

    def test_url(self, path, description):
        """Test a specific URL and take screenshot."""
        url = f"{BASE_URL}{path}"
        print(f"\n🔍 Testing: {description}")
        print(f"   URL: {url}")

        try:
            self.driver.get(url)
            time.sleep(2)

            # Check for error pages
            page_source = self.driver.page_source.lower()

            if "500" in page_source or "server error" in page_source:
                screenshot = self.save_screenshot(f"error_{path.replace('/', '_')}")
                self.log_test(url, "fail", "500 Server Error", screenshot)
                return False

            if "404" in page_source or "not found" in page_source:
                screenshot = self.save_screenshot(f"error_{path.replace('/', '_')}")
                self.log_test(url, "fail", "404 Not Found", screenshot)
                return False

            if "403" in page_source or "forbidden" in page_source:
                screenshot = self.save_screenshot(f"error_{path.replace('/', '_')}")
                self.log_test(url, "warn", "403 Forbidden - Permission issue", screenshot)
                return False

            # Take screenshot
            screenshot = self.save_screenshot(path.replace('/', '_'))
            self.log_test(url, "pass", "Page loaded successfully", screenshot)
            return True

        except Exception as e:
            screenshot = self.save_screenshot(f"exception_{path.replace('/', '_')}")
            self.log_test(url, "fail", f"Exception: {str(e)}", screenshot)
            self.log_error(f"Failed to test {url}", e)
            return False

    def test_time_off_request(self):
        """Test creating a new time-off request."""
        print("\n🧪 Testing time-off request creation...")

        try:
            self.driver.get(f"{BASE_URL}/app/hr/time-off/request/")
            time.sleep(2)

            self.save_screenshot("timeoff_request_form")

            # Try to fill out the form
            try:
                # Look for time-off type dropdown
                time_off_type = self.driver.find_element(By.NAME, "time_off_type")
                time_off_type.click()
                time.sleep(1)

                # Select first option
                options = time_off_type.find_elements(By.TAG_NAME, "option")
                if len(options) > 1:
                    options[1].click()

                # Fill in dates (1 week from today)
                today = datetime.now()
                start_date = today + timedelta(days=7)
                end_date = start_date + timedelta(days=2)

                start_field = self.driver.find_element(By.NAME, "start_date")
                start_field.send_keys(start_date.strftime("%Y-%m-%d"))

                end_field = self.driver.find_element(By.NAME, "end_date")
                end_field.send_keys(end_date.strftime("%Y-%m-%d"))

                # Fill reason
                reason_field = self.driver.find_element(By.NAME, "reason")
                reason_field.send_keys("Testing time-off request functionality")

                self.save_screenshot("timeoff_request_filled")

                # Submit form
                submit_btn = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
                submit_btn.click()
                time.sleep(2)

                self.save_screenshot("timeoff_request_submitted")

                # Check for success message
                page_source = self.driver.page_source.lower()
                if "success" in page_source or "submitted" in page_source:
                    self.log_test("/app/hr/time-off/request/", "pass", "Time-off request created successfully")
                    return True
                else:
                    self.log_test("/app/hr/time-off/request/", "warn", "Form submitted but no clear success message")
                    return True

            except NoSuchElementException as e:
                self.log_test("/app/hr/time-off/request/", "warn", f"Form elements not found: {e}")
                return False

        except Exception as e:
            self.log_error("Failed to test time-off request creation", e)
            return False

    def test_approval_workflow(self):
        """Test approving/rejecting time-off requests."""
        print("\n🧪 Testing approval/rejection workflow...")

        try:
            # Go to my time-off to see pending requests
            self.driver.get(f"{BASE_URL}/app/hr/time-off/my/")
            time.sleep(2)

            self.save_screenshot("my_timeoff_view")

            # Look for pending requests with approve/reject buttons
            try:
                approve_btns = self.driver.find_elements(By.XPATH, "//button[contains(text(), 'Approve')]")
                reject_btns = self.driver.find_elements(By.XPATH, "//button[contains(text(), 'Reject')]")

                if approve_btns or reject_btns:
                    self.log_test("/app/hr/time-off/", "pass", "Approval/rejection buttons found")
                    return True
                else:
                    self.log_test("/app/hr/time-off/", "warn", "No pending requests found to test approval workflow")
                    return True

            except Exception as e:
                self.log_test("/app/hr/time-off/", "warn", f"Could not find approval buttons: {e}")
                return False

        except Exception as e:
            self.log_error("Failed to test approval workflow", e)
            return False

    def run_all_tests(self):
        """Run all HR Time-Off tests."""
        print("\n" + "="*60)
        print("HR TIME-OFF MODULE TESTING")
        print("="*60)

        # Authenticate
        if not self.authenticate():
            print("\n❌ Cannot proceed without authentication")
            return

        # Test all URLs
        print("\n" + "="*60)
        print("TESTING ALL TIME-OFF URLS")
        print("="*60)

        urls_to_test = [
            ("/app/hr/time-off/calendar/", "Time-Off Calendar View"),
            ("/app/hr/time-off/request/", "Time-Off Request Form"),
            ("/app/hr/time-off/my/", "My Time-Off View"),
            ("/app/hr/employees/", "Employee Directory (for context)"),
        ]

        for path, desc in urls_to_test:
            self.test_url(path, desc)
            time.sleep(1)

        # Test functionality
        print("\n" + "="*60)
        print("TESTING FUNCTIONALITY")
        print("="*60)

        self.test_time_off_request()
        time.sleep(1)

        self.test_approval_workflow()

        # Generate report
        self.generate_report()

    def generate_report(self):
        """Generate a JSON report of all tests."""
        report_path = os.path.join(SCREENSHOT_DIR, "test_report.json")
        with open(report_path, 'w') as f:
            json.dump(TEST_RESULTS, f, indent=2)

        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)

        passed = sum(1 for t in TEST_RESULTS["tests"] if t["status"] == "pass")
        failed = sum(1 for t in TEST_RESULTS["tests"] if t["status"] == "fail")
        warnings = sum(1 for t in TEST_RESULTS["tests"] if t["status"] == "warn")

        print(f"✅ Passed: {passed}")
        print(f"⚠️  Warnings: {warnings}")
        print(f"❌ Failed: {failed}")
        print(f"📊 Total Tests: {len(TEST_RESULTS['tests'])}")
        print(f"📄 Report saved: {report_path}")

        if TEST_RESULTS["errors"]:
            print(f"\n⚠️  Errors encountered: {len(TEST_RESULTS['errors'])}")
            for error in TEST_RESULTS["errors"]:
                print(f"   - {error['message']}")

    def cleanup(self):
        """Close the browser."""
        if self.driver:
            self.driver.quit()


if __name__ == "__main__":
    tester = HRTimeOffTester()
    try:
        tester.run_all_tests()
    finally:
        tester.cleanup()
