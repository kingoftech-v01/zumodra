#!/usr/bin/env python
"""
Comprehensive Error Handling and Edge Case Testing Script
Tests error scenarios, validation, CSRF protection, and edge cases
on demo-company.zumodra.rhematek-solutions.com
"""

import time
import json
import requests
from datetime import datetime
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException


class ErrorHandlingTester:
    def __init__(self):
        self.base_url = "https://demo-company.zumodra.rhematek-solutions.com"
        self.results_dir = Path("test_results/errors")
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Demo credentials from DEMO_WALKTHROUGH.md
        self.valid_email = "demo@zumodra.com"
        self.valid_password = "Demo123!"

        # Test results
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "base_url": self.base_url,
            "tests": [],
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "warnings": 0
            },
            "security_concerns": [],
            "error_pages": {},
            "edge_cases": []
        }

        # Setup Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)

        self.driver = webdriver.Chrome(options=chrome_options)
        self.wait = WebDriverWait(self.driver, 10)

    def log_test(self, test_name, status, message, screenshot_name=None, details=None):
        """Log test result"""
        result = {
            "test": test_name,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "screenshot": screenshot_name,
            "details": details or {}
        }
        self.results["tests"].append(result)
        self.results["summary"]["total"] += 1

        if status == "PASS":
            self.results["summary"]["passed"] += 1
            print(f"✓ {test_name}: {message}")
        elif status == "FAIL":
            self.results["summary"]["failed"] += 1
            print(f"✗ {test_name}: {message}")
        elif status == "WARNING":
            self.results["summary"]["warnings"] += 1
            print(f"⚠ {test_name}: {message}")

    def take_screenshot(self, name):
        """Take screenshot and save to results directory"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}.png"
        filepath = self.results_dir / filename
        self.driver.save_screenshot(str(filepath))
        print(f"  Screenshot saved: {filename}")
        return filename

    def add_security_concern(self, concern, severity="MEDIUM"):
        """Add security concern to report"""
        self.results["security_concerns"].append({
            "concern": concern,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        })
        print(f"  🔒 SECURITY {severity}: {concern}")

    # ========================================
    # Test 1: Unauthenticated Access Tests
    # ========================================

    def test_unauthenticated_access(self):
        """Test access to protected pages without login"""
        print("\n" + "="*80)
        print("TEST 1: UNAUTHENTICATED ACCESS TO PROTECTED PAGES")
        print("="*80)

        protected_pages = [
            "/app/dashboard/",
            "/app/ats/jobs/",
            "/app/ats/candidates/",
            "/app/ats/pipeline/",
            "/app/ats/interviews/",
            "/app/hr/employees/",
            "/app/hr/time-off/calendar/",
            "/api/v1/ats/jobs/",
            "/api/v1/hr/employees/",
        ]

        for page in protected_pages:
            try:
                url = f"{self.base_url}{page}"
                self.driver.get(url)
                time.sleep(2)

                current_url = self.driver.current_url

                # Check if redirected to login
                if "login" in current_url.lower():
                    screenshot = self.take_screenshot(f"unauth_redirect_{page.replace('/', '_')}")
                    self.log_test(
                        f"Unauthenticated access: {page}",
                        "PASS",
                        "Correctly redirected to login page",
                        screenshot,
                        {"redirected_to": current_url}
                    )
                elif current_url == url:
                    screenshot = self.take_screenshot(f"unauth_allowed_{page.replace('/', '_')}")
                    self.log_test(
                        f"Unauthenticated access: {page}",
                        "FAIL",
                        "Page accessible without authentication!",
                        screenshot
                    )
                    self.add_security_concern(
                        f"Protected page {page} is accessible without authentication",
                        "HIGH"
                    )
                else:
                    screenshot = self.take_screenshot(f"unauth_other_{page.replace('/', '_')}")
                    self.log_test(
                        f"Unauthenticated access: {page}",
                        "WARNING",
                        f"Unexpected redirect to: {current_url}",
                        screenshot
                    )

            except Exception as e:
                self.log_test(
                    f"Unauthenticated access: {page}",
                    "FAIL",
                    f"Error accessing page: {str(e)}"
                )

    # ========================================
    # Test 2: 404 Error Testing
    # ========================================

    def test_404_errors(self):
        """Test non-existent resource access"""
        print("\n" + "="*80)
        print("TEST 2: NON-EXISTENT RESOURCE ACCESS (404 SCENARIOS)")
        print("="*80)

        non_existent_urls = [
            "/nonexistent-page",
            "/app/ats/jobs/99999/",
            "/app/ats/candidates/99999/",
            "/app/hr/employees/99999/",
            "/api/v1/ats/jobs/99999/",
            "/app/ats/interviews/99999/",
            "/totally-fake-url-12345",
            "/app/../../../etc/passwd",  # Path traversal attempt
            "/admin/../../../secret",  # Another path traversal
        ]

        for url_path in non_existent_urls:
            try:
                url = f"{self.base_url}{url_path}"
                self.driver.get(url)
                time.sleep(2)

                page_source = self.driver.page_source.lower()

                # Check for 404 indicators
                has_404_text = "404" in page_source or "not found" in page_source
                has_error_page = "error" in page_source

                screenshot = self.take_screenshot(f"404_{url_path.replace('/', '_')}")

                if has_404_text:
                    # Check if error page is user-friendly
                    has_helpful_message = any(phrase in page_source for phrase in [
                        "page not found",
                        "doesn't exist",
                        "can't find",
                        "return home",
                        "go back"
                    ])

                    if has_helpful_message:
                        self.log_test(
                            f"404 Error: {url_path}",
                            "PASS",
                            "User-friendly 404 page displayed",
                            screenshot
                        )
                    else:
                        self.log_test(
                            f"404 Error: {url_path}",
                            "WARNING",
                            "404 page lacks helpful navigation",
                            screenshot
                        )

                    # Store 404 page info
                    if "404_page" not in self.results["error_pages"]:
                        self.results["error_pages"]["404_page"] = {
                            "screenshot": screenshot,
                            "user_friendly": has_helpful_message
                        }
                else:
                    self.log_test(
                        f"404 Error: {url_path}",
                        "WARNING",
                        "No clear 404 indication found",
                        screenshot
                    )

            except Exception as e:
                self.log_test(
                    f"404 Error: {url_path}",
                    "FAIL",
                    f"Error testing URL: {str(e)}"
                )

    # ========================================
    # Test 3: Login with Invalid Data
    # ========================================

    def test_invalid_login_data(self):
        """Test login form with various invalid inputs"""
        print("\n" + "="*80)
        print("TEST 3: LOGIN FORM VALIDATION WITH INVALID DATA")
        print("="*80)

        test_cases = [
            {
                "name": "Empty credentials",
                "email": "",
                "password": "",
                "expected": "Email and password required"
            },
            {
                "name": "Invalid email format",
                "email": "notanemail",
                "password": "SomePassword123!",
                "expected": "Valid email required"
            },
            {
                "name": "SQL injection attempt",
                "email": "admin'--",
                "password": "' OR '1'='1",
                "expected": "Login failed"
            },
            {
                "name": "XSS attempt",
                "email": "<script>alert('xss')</script>@test.com",
                "password": "password",
                "expected": "Login failed"
            },
            {
                "name": "Wrong password",
                "email": self.valid_email,
                "password": "WrongPassword123!",
                "expected": "Invalid credentials"
            },
            {
                "name": "Very long email",
                "email": "a" * 300 + "@example.com",
                "password": "Test123!",
                "expected": "Email too long or invalid"
            },
            {
                "name": "Special characters in password",
                "email": "test@test.com",
                "password": "!@#$%^&*()_+-=[]{}|;':\",./<>?`~",
                "expected": "Login failed"
            }
        ]

        for test_case in test_cases:
            try:
                # Go to login page
                self.driver.get(f"{self.base_url}/accounts/login/")
                time.sleep(2)

                # Fill in form
                try:
                    email_field = self.driver.find_element(By.NAME, "login")
                    password_field = self.driver.find_element(By.NAME, "password")

                    email_field.clear()
                    email_field.send_keys(test_case["email"])
                    password_field.clear()
                    password_field.send_keys(test_case["password"])

                    # Submit form
                    submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
                    submit_button.click()
                    time.sleep(3)

                    page_source = self.driver.page_source.lower()

                    # Check for error messages
                    has_error = any(keyword in page_source for keyword in [
                        "invalid",
                        "incorrect",
                        "error",
                        "failed",
                        "required",
                        "wrong"
                    ])

                    # Check if still on login page (not logged in)
                    still_on_login = "login" in self.driver.current_url.lower()

                    screenshot = self.take_screenshot(f"login_invalid_{test_case['name'].replace(' ', '_')}")

                    if has_error and still_on_login:
                        self.log_test(
                            f"Invalid login: {test_case['name']}",
                            "PASS",
                            "Login correctly rejected with error message",
                            screenshot
                        )
                    elif not still_on_login:
                        self.log_test(
                            f"Invalid login: {test_case['name']}",
                            "FAIL",
                            "Login succeeded with invalid credentials!",
                            screenshot
                        )
                        self.add_security_concern(
                            f"Login succeeded with invalid data: {test_case['name']}",
                            "CRITICAL"
                        )
                    else:
                        self.log_test(
                            f"Invalid login: {test_case['name']}",
                            "WARNING",
                            "No clear error message displayed",
                            screenshot
                        )

                except NoSuchElementException as e:
                    self.log_test(
                        f"Invalid login: {test_case['name']}",
                        "FAIL",
                        f"Could not find form elements: {str(e)}"
                    )

            except Exception as e:
                self.log_test(
                    f"Invalid login: {test_case['name']}",
                    "FAIL",
                    f"Error during test: {str(e)}"
                )

    # ========================================
    # Test 4: CSRF Protection
    # ========================================

    def test_csrf_protection(self):
        """Test CSRF protection on forms"""
        print("\n" + "="*80)
        print("TEST 4: CSRF PROTECTION TESTING")
        print("="*80)

        # Test POST request without CSRF token
        try:
            # Test login POST without CSRF token
            response = requests.post(
                f"{self.base_url}/accounts/login/",
                data={
                    "login": self.valid_email,
                    "password": self.valid_password
                },
                allow_redirects=False
            )

            if response.status_code == 403:
                self.log_test(
                    "CSRF Protection: Login form",
                    "PASS",
                    "POST request without CSRF token correctly rejected (403)",
                    details={"status_code": response.status_code}
                )
            elif "csrf" in response.text.lower():
                self.log_test(
                    "CSRF Protection: Login form",
                    "PASS",
                    "CSRF validation error returned",
                    details={"status_code": response.status_code}
                )
            else:
                self.log_test(
                    "CSRF Protection: Login form",
                    "FAIL",
                    f"Request not blocked (status: {response.status_code})",
                    details={"status_code": response.status_code}
                )
                self.add_security_concern(
                    "CSRF protection may not be working properly",
                    "HIGH"
                )

        except Exception as e:
            self.log_test(
                "CSRF Protection: Login form",
                "FAIL",
                f"Error testing CSRF: {str(e)}"
            )

        # Check if CSRF token is present in forms
        try:
            self.driver.get(f"{self.base_url}/accounts/login/")
            time.sleep(2)

            page_source = self.driver.page_source
            has_csrf_token = "csrfmiddlewaretoken" in page_source or "csrf_token" in page_source

            screenshot = self.take_screenshot("csrf_token_check")

            if has_csrf_token:
                self.log_test(
                    "CSRF Token: Presence check",
                    "PASS",
                    "CSRF token found in login form",
                    screenshot
                )
            else:
                self.log_test(
                    "CSRF Token: Presence check",
                    "WARNING",
                    "CSRF token not found in form HTML",
                    screenshot
                )

        except Exception as e:
            self.log_test(
                "CSRF Token: Presence check",
                "FAIL",
                f"Error checking CSRF token: {str(e)}"
            )

    # ========================================
    # Test 5: Permission Boundaries (403)
    # ========================================

    def test_permission_boundaries(self):
        """Test permission boundaries after login"""
        print("\n" + "="*80)
        print("TEST 5: PERMISSION BOUNDARIES AND 403 SCENARIOS")
        print("="*80)

        # First, login
        try:
            self.driver.get(f"{self.base_url}/accounts/login/")
            time.sleep(2)

            email_field = self.driver.find_element(By.NAME, "login")
            password_field = self.driver.find_element(By.NAME, "password")

            email_field.send_keys(self.valid_email)
            password_field.send_keys(self.valid_password)

            submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_button.click()
            time.sleep(3)

            # Try to access potentially restricted pages
            restricted_urls = [
                "/admin/",  # Django admin (if not superuser)
                "/api/v1/hr/employees/1/salary/",  # Sensitive endpoint
                "/app/hr/payroll/",  # Potentially restricted
            ]

            for url_path in restricted_urls:
                try:
                    url = f"{self.base_url}{url_path}"
                    self.driver.get(url)
                    time.sleep(2)

                    page_source = self.driver.page_source.lower()

                    # Check for 403 or permission denied
                    has_403 = "403" in page_source or "forbidden" in page_source
                    has_permission_denied = "permission denied" in page_source or "not authorized" in page_source

                    screenshot = self.take_screenshot(f"permission_{url_path.replace('/', '_')}")

                    if has_403 or has_permission_denied:
                        self.log_test(
                            f"Permission boundary: {url_path}",
                            "PASS",
                            "Access correctly denied",
                            screenshot
                        )

                        # Store 403 page info
                        if "403_page" not in self.results["error_pages"]:
                            self.results["error_pages"]["403_page"] = {
                                "screenshot": screenshot,
                                "user_friendly": "permission" in page_source or "access denied" in page_source
                            }
                    else:
                        # Check if page actually loaded with content
                        if len(page_source) > 1000:  # Assuming real pages have content
                            self.log_test(
                                f"Permission boundary: {url_path}",
                                "WARNING",
                                "Page may be accessible (check if expected)",
                                screenshot
                            )

                except Exception as e:
                    self.log_test(
                        f"Permission boundary: {url_path}",
                        "FAIL",
                        f"Error testing permission: {str(e)}"
                    )

        except Exception as e:
            self.log_test(
                "Permission boundaries",
                "FAIL",
                f"Could not complete permission tests: {str(e)}"
            )

    # ========================================
    # Test 6: Edge Cases
    # ========================================

    def test_edge_cases(self):
        """Test edge cases with extreme inputs"""
        print("\n" + "="*80)
        print("TEST 6: EDGE CASES (LONG INPUT, SPECIAL CHARACTERS, EMPTY SUBMISSIONS)")
        print("="*80)

        # Go to login page for testing
        self.driver.get(f"{self.base_url}/accounts/login/")
        time.sleep(2)

        edge_cases = [
            {
                "name": "Very long input (5000 chars)",
                "email": "a" * 5000 + "@test.com",
                "password": "Test123!",
                "expected": "Should be rejected or truncated"
            },
            {
                "name": "Unicode characters",
                "email": "test@测试.中国",
                "password": "パスワード123!",
                "expected": "Should handle gracefully"
            },
            {
                "name": "Null bytes",
                "email": "test\x00@test.com",
                "password": "pass\x00word",
                "expected": "Should be rejected"
            },
            {
                "name": "Multiple @ symbols",
                "email": "test@@@@test.com",
                "password": "Test123!",
                "expected": "Should be rejected"
            },
            {
                "name": "Whitespace only",
                "email": "   ",
                "password": "   ",
                "expected": "Should be rejected"
            },
            {
                "name": "HTML tags",
                "email": "<b>test@test.com</b>",
                "password": "<script>alert(1)</script>",
                "expected": "Should be sanitized or rejected"
            }
        ]

        for case in edge_cases:
            try:
                # Refresh page
                self.driver.get(f"{self.base_url}/accounts/login/")
                time.sleep(2)

                email_field = self.driver.find_element(By.NAME, "login")
                password_field = self.driver.find_element(By.NAME, "password")

                email_field.clear()
                try:
                    email_field.send_keys(case["email"])
                except Exception as e:
                    # Some inputs might cause Selenium errors
                    pass

                password_field.clear()
                try:
                    password_field.send_keys(case["password"])
                except Exception as e:
                    pass

                submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
                submit_button.click()
                time.sleep(3)

                page_source = self.driver.page_source.lower()

                # Check if still on login page (rejected)
                still_on_login = "login" in self.driver.current_url.lower()
                has_error = any(keyword in page_source for keyword in [
                    "error", "invalid", "required"
                ])

                screenshot = self.take_screenshot(f"edge_case_{case['name'].replace(' ', '_')}")

                if still_on_login or has_error:
                    self.log_test(
                        f"Edge case: {case['name']}",
                        "PASS",
                        "Invalid input correctly handled",
                        screenshot
                    )
                else:
                    self.log_test(
                        f"Edge case: {case['name']}",
                        "WARNING",
                        "Input accepted (verify if expected)",
                        screenshot
                    )

                self.results["edge_cases"].append({
                    "case": case["name"],
                    "handled_correctly": still_on_login or has_error,
                    "screenshot": screenshot
                })

            except Exception as e:
                self.log_test(
                    f"Edge case: {case['name']}",
                    "FAIL",
                    f"Error during test: {str(e)}"
                )

    # ========================================
    # Test 7: Error Page Quality
    # ========================================

    def test_error_page_quality(self):
        """Verify error pages are user-friendly"""
        print("\n" + "="*80)
        print("TEST 7: ERROR PAGE QUALITY ASSESSMENT")
        print("="*80)

        # We've already captured error pages, now assess them
        if self.results["error_pages"]:
            for error_type, info in self.results["error_pages"].items():
                if info.get("user_friendly"):
                    self.log_test(
                        f"Error page quality: {error_type}",
                        "PASS",
                        "Error page contains helpful information",
                        info.get("screenshot")
                    )
                else:
                    self.log_test(
                        f"Error page quality: {error_type}",
                        "WARNING",
                        "Error page could be more user-friendly",
                        info.get("screenshot")
                    )
        else:
            self.log_test(
                "Error page quality",
                "WARNING",
                "No error pages were captured during testing"
            )

    # ========================================
    # Generate Report
    # ========================================

    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "="*80)
        print("GENERATING COMPREHENSIVE REPORT")
        print("="*80)

        # Save JSON report
        json_path = self.results_dir / f"error_handling_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n✓ JSON report saved: {json_path}")

        # Generate Markdown report
        md_path = self.results_dir / f"ERROR_HANDLING_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        with open(md_path, 'w', encoding='utf-8') as f:
            f.write("# Error Handling and Edge Case Test Report\n\n")
            f.write(f"**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Base URL:** {self.base_url}\n\n")

            # Summary
            f.write("## Test Summary\n\n")
            f.write(f"- **Total Tests:** {self.results['summary']['total']}\n")
            f.write(f"- **Passed:** {self.results['summary']['passed']}\n")
            f.write(f"- **Failed:** {self.results['summary']['failed']}\n")
            f.write(f"- **Warnings:** {self.results['summary']['warnings']}\n\n")

            pass_rate = (self.results['summary']['passed'] / self.results['summary']['total'] * 100) if self.results['summary']['total'] > 0 else 0
            f.write(f"**Pass Rate:** {pass_rate:.1f}%\n\n")

            # Security Concerns
            if self.results['security_concerns']:
                f.write("## [!] Security Concerns\n\n")
                for concern in self.results['security_concerns']:
                    f.write(f"### {concern['severity']} Severity\n")
                    f.write(f"- **Issue:** {concern['concern']}\n")
                    f.write(f"- **Timestamp:** {concern['timestamp']}\n\n")
            else:
                f.write("## [OK] Security Concerns\n\n")
                f.write("No critical security concerns detected during testing.\n\n")

            # Error Pages Assessment
            f.write("## Error Pages Assessment\n\n")
            if self.results['error_pages']:
                for error_type, info in self.results['error_pages'].items():
                    f.write(f"### {error_type.upper()}\n")
                    f.write(f"- **User-Friendly:** {'Yes' if info.get('user_friendly') else 'Needs Improvement'}\n")
                    f.write(f"- **Screenshot:** `{info.get('screenshot')}`\n\n")
            else:
                f.write("No error pages were captured during testing.\n\n")

            # Detailed Test Results
            f.write("## Detailed Test Results\n\n")

            current_test_group = None
            for test in self.results['tests']:
                test_group = test['test'].split(':')[0] if ':' in test['test'] else test['test']
                if test_group != current_test_group:
                    current_test_group = test_group
                    f.write(f"### {current_test_group}\n\n")

                status_emoji = "[PASS]" if test['status'] == "PASS" else "[FAIL]" if test['status'] == "FAIL" else "[WARN]"
                f.write(f"{status_emoji} **{test['test']}**\n")
                f.write(f"- Status: {test['status']}\n")
                f.write(f"- Message: {test['message']}\n")
                if test.get('screenshot'):
                    f.write(f"- Screenshot: `{test['screenshot']}`\n")
                if test.get('details'):
                    f.write(f"- Details: {json.dumps(test['details'], indent=2)}\n")
                f.write("\n")

            # Recommendations
            f.write("## Recommendations\n\n")

            if self.results['summary']['failed'] > 0:
                f.write("### High Priority\n")
                for test in self.results['tests']:
                    if test['status'] == 'FAIL':
                        f.write(f"- Fix: {test['test']} - {test['message']}\n")
                f.write("\n")

            if self.results['summary']['warnings'] > 0:
                f.write("### Medium Priority\n")
                for test in self.results['tests']:
                    if test['status'] == 'WARNING':
                        f.write(f"- Review: {test['test']} - {test['message']}\n")
                f.write("\n")

            # Edge Cases Summary
            if self.results['edge_cases']:
                f.write("## Edge Cases Summary\n\n")
                for case in self.results['edge_cases']:
                    status = "[OK] Handled" if case['handled_correctly'] else "[WARN] Review Needed"
                    f.write(f"- **{case['case']}:** {status}\n")
                f.write("\n")

            # Next Steps
            f.write("## Next Steps\n\n")
            f.write("1. Review all failed tests and address security concerns\n")
            f.write("2. Improve error pages to be more user-friendly\n")
            f.write("3. Add additional validation for edge cases\n")
            f.write("4. Implement rate limiting if not already present\n")
            f.write("5. Review CSRF protection implementation\n")
            f.write("6. Test with additional user roles for permission boundaries\n\n")

            # All Screenshots
            f.write("## Screenshots\n\n")
            f.write("All screenshots have been saved to `test_results/errors/`\n\n")
            for test in self.results['tests']:
                if test.get('screenshot'):
                    f.write(f"- `{test['screenshot']}` - {test['test']}\n")

        print(f"✓ Markdown report saved: {md_path}")

        return json_path, md_path

    # ========================================
    # Main Test Runner
    # ========================================

    def run_all_tests(self):
        """Run all error handling tests"""
        print("\n")
        print("="*80)
        print("STARTING ERROR HANDLING AND EDGE CASE TESTING")
        print("="*80)
        print(f"Base URL: {self.base_url}")
        print(f"Results directory: {self.results_dir}")
        print("="*80)

        try:
            # Run all test groups
            self.test_unauthenticated_access()
            self.test_404_errors()
            self.test_invalid_login_data()
            self.test_csrf_protection()
            self.test_permission_boundaries()
            self.test_edge_cases()
            self.test_error_page_quality()

            # Generate report
            json_path, md_path = self.generate_report()

            # Print final summary
            print("\n" + "="*80)
            print("TEST EXECUTION COMPLETE")
            print("="*80)
            print(f"\n✓ Total Tests: {self.results['summary']['total']}")
            print(f"✓ Passed: {self.results['summary']['passed']}")
            print(f"x Failed: {self.results['summary']['failed']}")
            print(f"! Warnings: {self.results['summary']['warnings']}")

            if self.results['security_concerns']:
                print(f"\n[!] Security Concerns: {len(self.results['security_concerns'])}")
                for concern in self.results['security_concerns']:
                    print(f"  - [{concern['severity']}] {concern['concern']}")

            print(f"\n[Reports saved]:")
            print(f"  - JSON: {json_path}")
            print(f"  - Markdown: {md_path}")
            print(f"\n[Screenshots saved to]: {self.results_dir}")

        except Exception as e:
            print(f"\n[X] CRITICAL ERROR: {str(e)}")
            import traceback
            traceback.print_exc()

        finally:
            # Cleanup
            print("\nCleaning up...")
            self.driver.quit()
            print("✓ Browser closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.driver.quit()


# ========================================
# Main Execution
# ========================================

if __name__ == "__main__":
    print("""
    ================================================================

           ZUMODRA ERROR HANDLING & EDGE CASE TEST SUITE

      Testing: demo-company.zumodra.rhematek-solutions.com

    ================================================================
    """)

    with ErrorHandlingTester() as tester:
        tester.run_all_tests()

    print("\n" + "="*80)
    print("ALL TESTS COMPLETED")
    print("="*80)
