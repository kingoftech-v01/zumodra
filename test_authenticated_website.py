#!/usr/bin/env python3
"""
Zumodra Authenticated Website Testing Script
=============================================

This script tests the Zumodra production website with authenticated access
using Playwright to capture real screenshots and verify functionality.

Test URL: https://demo-company.zumodra.rhematek-solutions.com
Login: company.owner@demo.zumodra.rhematek-solutions.com
Password: Demo@2024!

FINDINGS SUMMARY:
-----------------
This script will document all findings inline with comments near the relevant
test functions. Each test captures:
- Screenshot of the page
- HTTP status code
- UI visibility and functionality
- Any errors, missing templates, or broken functionality
- Performance metrics (page load time)

SETUP INSTRUCTIONS:
-------------------
1. Install Playwright:
   pip install playwright pytest-playwright
   playwright install chromium

2. Run the test:
   python test_authenticated_website.py

3. Results will be saved to:
   - Screenshots: ./test_results/screenshots/
   - Test report: Console output with detailed findings

TEST COVERAGE:
--------------
1. Authentication flow (login page)
2. Dashboard (/app/dashboard/)
3. ATS Jobs (/app/ats/jobs/)
4. ATS Candidates (/app/ats/candidates/)
5. ATS Applications (/app/ats/applications/)
6. ATS Pipeline (/app/ats/pipeline/)
7. ATS Interviews (/app/ats/interviews/)
8. HR Employees (/app/hr/employees/)
9. HR Time Off (/app/hr/time-off/)
10. Services (/services/ or /app/services/)
11. User Profile (/app/accounts/profile/)
"""

import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Set UTF-8 encoding for console output (Windows compatibility)
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Check if playwright is installed
try:
    from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext, TimeoutError as PlaywrightTimeoutError
except ImportError:
    print("ERROR: Playwright is not installed.")
    print("Please install it with:")
    print("  pip install playwright pytest-playwright")
    print("  playwright install chromium")
    sys.exit(1)


# Test Configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
LOGIN_EMAIL = "company.owner@demo.zumodra.rhematek-solutions.com"
LOGIN_PASSWORD = "Demo@2024!"

# Test results directory
RESULTS_DIR = Path("./test_results")
SCREENSHOTS_DIR = RESULTS_DIR / "screenshots"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")


class TestResult:
    """Store test results for a single page"""
    def __init__(self, page_name: str, url: str):
        self.page_name = page_name
        self.url = url
        self.status_code: Optional[int] = None
        self.load_time: Optional[float] = None
        self.screenshot_path: Optional[str] = None
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.success: bool = False
        self.ui_elements_visible: List[str] = []
        self.ui_elements_missing: List[str] = []
        self.console_errors: List[str] = []

    def to_dict(self) -> Dict:
        """Convert result to dictionary for JSON serialization"""
        return {
            "page_name": self.page_name,
            "url": self.url,
            "status_code": self.status_code,
            "load_time": self.load_time,
            "screenshot_path": self.screenshot_path,
            "errors": self.errors,
            "warnings": self.warnings,
            "success": self.success,
            "ui_elements_visible": self.ui_elements_visible,
            "ui_elements_missing": self.ui_elements_missing,
            "console_errors": self.console_errors
        }


class ZumodraWebsiteTester:
    """Main test orchestrator for authenticated Zumodra website testing"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.authenticated = False

        # Ensure results directories exist
        SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    def setup_browser(self, playwright):
        """Initialize browser with proper configuration"""
        print(f"[{self._timestamp()}] Launching browser...")

        self.browser = playwright.chromium.launch(
            headless=True,  # Run in headless mode for automation
            slow_mo=100,  # Slow down by 100ms
        )

        # Create context with viewport and user agent
        self.context = self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

        # Enable request/response interception for status codes
        self.context.set_default_timeout(60000)  # 60 seconds timeout

        self.page = self.context.new_page()

        # Listen to console messages
        self.page.on("console", lambda msg: self._handle_console(msg))

        # Listen to page errors
        self.page.on("pageerror", lambda exc: self._handle_page_error(exc))

        print(f"[{self._timestamp()}] Browser launched successfully")

    def _handle_console(self, msg):
        """Handle console messages from the browser"""
        if msg.type == "error":
            error_text = f"Console Error: {msg.text}"
            print(f"[{self._timestamp()}] {error_text}")

    def _handle_page_error(self, exc):
        """Handle uncaught page errors"""
        error_text = f"Page Error: {str(exc)}"
        print(f"[{self._timestamp()}] {error_text}")

    def _timestamp(self) -> str:
        """Get current timestamp for logging"""
        return datetime.now().strftime("%H:%M:%S")

    def login(self) -> bool:
        """
        Authenticate to the Zumodra platform

        FINDING: This tests the login functionality at /accounts/login/
        - Verifies login form is present
        - Tests credential submission
        - Checks for successful authentication redirect
        - Validates session establishment

        POTENTIAL ISSUES TO CHECK:
        - CSRF token validation
        - 2FA requirements (if enabled)
        - Rate limiting on login attempts
        - Proper redirect after login
        """
        result = TestResult("Login Page", f"{BASE_URL}/en-us/accounts/login/")
        start_time = time.time()

        try:
            print(f"\n[{self._timestamp()}] ============================================")
            print(f"[{self._timestamp()}] TESTING: Login Page")
            print(f"[{self._timestamp()}] ============================================")
            print(f"[{self._timestamp()}] Navigating to: {result.url}")

            # Navigate to login page
            response = self.page.goto(result.url, wait_until="domcontentloaded", timeout=60000)
            result.status_code = response.status if response else None
            result.load_time = time.time() - start_time

            print(f"[{self._timestamp()}] Status Code: {result.status_code}")
            print(f"[{self._timestamp()}] Load Time: {result.load_time:.2f}s")

            # Take screenshot of login page
            screenshot_path = SCREENSHOTS_DIR / f"01_login_page_{TIMESTAMP}.png"
            self.page.screenshot(path=str(screenshot_path), full_page=True)
            result.screenshot_path = str(screenshot_path)
            print(f"[{self._timestamp()}] Screenshot saved: {screenshot_path}")

            # Check for login form elements
            print(f"[{self._timestamp()}] Checking for login form elements...")

            # FINDING: Check if email/username field exists
            try:
                email_field = self.page.locator('input[name="login"], input[type="email"], input[name="username"]').first
                if email_field.is_visible(timeout=5000):
                    result.ui_elements_visible.append("Email/Login field")
                    print(f"[{self._timestamp()}] ✓ Email/Login field found")
                else:
                    result.ui_elements_missing.append("Email/Login field not visible")
                    result.warnings.append("Email field exists but not visible")
            except Exception as e:
                result.ui_elements_missing.append("Email/Login field")
                result.errors.append(f"Email field not found: {str(e)}")
                print(f"[{self._timestamp()}] ✗ Email/Login field not found")

            # FINDING: Check if password field exists
            try:
                password_field = self.page.locator('input[type="password"]').first
                if password_field.is_visible(timeout=5000):
                    result.ui_elements_visible.append("Password field")
                    print(f"[{self._timestamp()}] ✓ Password field found")
                else:
                    result.ui_elements_missing.append("Password field not visible")
                    result.warnings.append("Password field exists but not visible")
            except Exception as e:
                result.ui_elements_missing.append("Password field")
                result.errors.append(f"Password field not found: {str(e)}")
                print(f"[{self._timestamp()}] ✗ Password field not found")

            # FINDING: Check if submit button exists
            try:
                submit_button = self.page.locator('button[type="submit"], input[type="submit"]').first
                if submit_button.is_visible(timeout=5000):
                    result.ui_elements_visible.append("Submit button")
                    print(f"[{self._timestamp()}] ✓ Submit button found")
                else:
                    result.ui_elements_missing.append("Submit button not visible")
                    result.warnings.append("Submit button exists but not visible")
            except Exception as e:
                result.ui_elements_missing.append("Submit button")
                result.errors.append(f"Submit button not found: {str(e)}")
                print(f"[{self._timestamp()}] ✗ Submit button not found")

            # If login form is not present, we can't proceed
            if result.ui_elements_missing:
                result.errors.append("Login form incomplete - cannot proceed with authentication")
                result.success = False
                self.results.append(result)
                return False

            # Fill in login credentials
            print(f"[{self._timestamp()}] Filling in login credentials...")

            # Try different field name variations
            try:
                # Wait a moment for the page to be fully ready
                time.sleep(1)

                # Try 'login' field first (django-allauth default)
                if self.page.locator('input[name="login"]').count() > 0:
                    email_input = self.page.locator('input[name="login"]').first
                    email_input.click()
                    email_input.fill(LOGIN_EMAIL)
                    print(f"[{self._timestamp()}] Filled 'login' field")
                # Try 'email' field
                elif self.page.locator('input[type="email"]').count() > 0:
                    email_input = self.page.locator('input[type="email"]').first
                    email_input.click()
                    email_input.fill(LOGIN_EMAIL)
                    print(f"[{self._timestamp()}] Filled 'email' field")
                # Try placeholder text
                elif self.page.locator('input[placeholder*="Email" i]').count() > 0:
                    email_input = self.page.locator('input[placeholder*="Email" i]').first
                    email_input.click()
                    email_input.fill(LOGIN_EMAIL)
                    print(f"[{self._timestamp()}] Filled email field by placeholder")
                # Try 'username' field
                elif self.page.locator('input[name="username"]').count() > 0:
                    email_input = self.page.locator('input[name="username"]').first
                    email_input.click()
                    email_input.fill(LOGIN_EMAIL)
                    print(f"[{self._timestamp()}] Filled 'username' field")
                else:
                    raise Exception("No valid email/username field found")

                # Fill password
                password_input = self.page.locator('input[type="password"]').first
                password_input.click()
                password_input.fill(LOGIN_PASSWORD)
                print(f"[{self._timestamp()}] Credentials filled")

                # Wait a moment after filling
                time.sleep(1)

            except Exception as e:
                result.errors.append(f"Failed to fill credentials: {str(e)}")
                result.success = False
                self.results.append(result)
                return False

            # Take screenshot before submission
            screenshot_path = SCREENSHOTS_DIR / f"02_login_filled_{TIMESTAMP}.png"
            self.page.screenshot(path=str(screenshot_path), full_page=True)
            print(f"[{self._timestamp()}] Screenshot before submission saved")

            # Submit login form
            print(f"[{self._timestamp()}] Submitting login form...")

            # Click submit button and wait for navigation
            try:
                with self.page.expect_navigation(timeout=30000):
                    submit_button.click()

                print(f"[{self._timestamp()}] Form submitted, waiting for response...")

                # Wait a bit for any redirects
                self.page.wait_for_load_state("networkidle")
                time.sleep(2)

                # Take screenshot after submission
                screenshot_path = SCREENSHOTS_DIR / f"03_after_login_{TIMESTAMP}.png"
                self.page.screenshot(path=str(screenshot_path), full_page=True)
                print(f"[{self._timestamp()}] Screenshot after login saved")

                current_url = self.page.url
                print(f"[{self._timestamp()}] Current URL after login: {current_url}")

                # FINDING: Check if login was successful
                # Successful login should redirect away from /accounts/login/
                if "/accounts/login/" in current_url or "/login/" in current_url:
                    # Still on login page - check for error messages
                    print(f"[{self._timestamp()}] Still on login page, checking for errors...")

                    error_selectors = [
                        ".alert-danger",
                        ".alert-error",
                        ".error",
                        ".errorlist",
                        "[class*='error']",
                        ".invalid-feedback",
                        ".form-error",
                        "[role='alert']"
                    ]

                    error_found = False
                    for selector in error_selectors:
                        try:
                            if self.page.locator(selector).count() > 0:
                                elements = self.page.locator(selector).all()
                                for elem in elements:
                                    if elem.is_visible():
                                        error_text = elem.text_content().strip()
                                        if error_text:
                                            result.errors.append(f"Login error displayed: {error_text}")
                                            print(f"[{self._timestamp()}] ✗ Login failed: {error_text}")
                                            error_found = True
                        except:
                            pass

                    if not error_found:
                        # Check page HTML for error messages
                        page_content = self.page.content()
                        if "incorrect" in page_content.lower() or "invalid" in page_content.lower():
                            result.errors.append("Login failed - credentials may be incorrect")
                            print(f"[{self._timestamp()}] ✗ Login failed - credentials may be incorrect")
                        else:
                            result.errors.append("Login failed - still on login page with no error message (credentials or CSRF issue)")
                            print(f"[{self._timestamp()}] ✗ Login failed - no redirect occurred (check credentials)")

                    result.success = False
                    self.authenticated = False
                else:
                    # Successfully redirected away from login page
                    result.success = True
                    self.authenticated = True
                    print(f"[{self._timestamp()}] ✓ Login successful - redirected to {current_url}")

                    # Check if we're on a dashboard or app page
                    if "/app/" in current_url or "/dashboard/" in current_url:
                        result.ui_elements_visible.append("Redirected to authenticated area")
                    else:
                        result.warnings.append(f"Redirected to unexpected URL: {current_url}")

            except PlaywrightTimeoutError:
                result.errors.append("Login submission timeout - no navigation occurred")
                result.success = False
                self.authenticated = False
                print(f"[{self._timestamp()}] ✗ Login submission timeout")
            except Exception as e:
                result.errors.append(f"Login submission error: {str(e)}")
                result.success = False
                self.authenticated = False
                print(f"[{self._timestamp()}] ✗ Login submission error: {str(e)}")

        except Exception as e:
            result.errors.append(f"Login test error: {str(e)}")
            result.success = False
            self.authenticated = False
            print(f"[{self._timestamp()}] ✗ Login test error: {str(e)}")

        finally:
            self.results.append(result)
            self._print_result_summary(result)

        return self.authenticated

    def test_page(self, page_name: str, relative_url: str,
                  ui_elements_to_check: List[str] = None,
                  required_text: List[str] = None) -> TestResult:
        """
        Test a specific page after authentication

        Args:
            page_name: Human-readable page name
            relative_url: URL path relative to BASE_URL
            ui_elements_to_check: List of CSS selectors to verify
            required_text: List of text strings that should be present

        Returns:
            TestResult object with findings
        """
        full_url = f"{BASE_URL}{relative_url}"
        result = TestResult(page_name, full_url)
        start_time = time.time()

        print(f"\n[{self._timestamp()}] ============================================")
        print(f"[{self._timestamp()}] TESTING: {page_name}")
        print(f"[{self._timestamp()}] ============================================")
        print(f"[{self._timestamp()}] URL: {full_url}")

        try:
            # Navigate to page
            response = self.page.goto(full_url, wait_until="domcontentloaded", timeout=60000)
            result.status_code = response.status if response else None
            result.load_time = time.time() - start_time

            print(f"[{self._timestamp()}] Status Code: {result.status_code}")
            print(f"[{self._timestamp()}] Load Time: {result.load_time:.2f}s")

            # Check for redirects to login (indicates auth issue)
            if "/accounts/login/" in self.page.url:
                result.errors.append("Redirected to login page - authentication may have expired or URL requires different permissions")
                result.success = False
                print(f"[{self._timestamp()}] ✗ Redirected to login - authentication issue")

                # Take screenshot of redirect
                screenshot_name = f"{page_name.lower().replace(' ', '_')}_redirect_{TIMESTAMP}.png"
                screenshot_path = SCREENSHOTS_DIR / screenshot_name
                self.page.screenshot(path=str(screenshot_path), full_page=True)
                result.screenshot_path = str(screenshot_path)

                return result

            # Check status code
            if result.status_code and result.status_code >= 400:
                result.errors.append(f"HTTP {result.status_code} error")
                print(f"[{self._timestamp()}] ✗ HTTP {result.status_code} error")

                if result.status_code == 404:
                    result.errors.append("Page not found - URL may be incorrect or view not implemented")
                elif result.status_code == 403:
                    result.errors.append("Forbidden - user may not have permission to access this page")
                elif result.status_code == 500:
                    result.errors.append("Internal server error - check backend logs")

            # Wait for page to be fully loaded
            self.page.wait_for_load_state("domcontentloaded")
            time.sleep(1)  # Additional wait for dynamic content

            # Take screenshot
            screenshot_name = f"{page_name.lower().replace(' ', '_')}_{TIMESTAMP}.png"
            screenshot_path = SCREENSHOTS_DIR / screenshot_name
            self.page.screenshot(path=str(screenshot_path), full_page=True)
            result.screenshot_path = str(screenshot_path)
            print(f"[{self._timestamp()}] Screenshot saved: {screenshot_path}")

            # Check for common error indicators in the page
            error_indicators = [
                (".alert-danger", "Danger alert"),
                (".error", "Error message"),
                ("text=/error/i", "Error text"),
                ("text=/not found/i", "Not found text"),
                ("text=/500/i", "Server error text"),
                ("text=/404/i", "404 error text"),
            ]

            for selector, description in error_indicators:
                try:
                    if self.page.locator(selector).count() > 0:
                        error_element = self.page.locator(selector).first
                        if error_element.is_visible():
                            error_text = error_element.text_content()
                            result.errors.append(f"{description} found: {error_text}")
                            print(f"[{self._timestamp()}] ✗ {description}: {error_text}")
                except:
                    pass  # Selector didn't match, continue

            # Check for required UI elements
            if ui_elements_to_check:
                print(f"[{self._timestamp()}] Checking for required UI elements...")
                for selector in ui_elements_to_check:
                    try:
                        element = self.page.locator(selector).first
                        if element.count() > 0 and element.is_visible(timeout=5000):
                            result.ui_elements_visible.append(selector)
                            print(f"[{self._timestamp()}] ✓ Found: {selector}")
                        else:
                            result.ui_elements_missing.append(selector)
                            result.warnings.append(f"UI element not visible: {selector}")
                            print(f"[{self._timestamp()}] ⚠ Not visible: {selector}")
                    except Exception as e:
                        result.ui_elements_missing.append(selector)
                        result.warnings.append(f"UI element not found: {selector}")
                        print(f"[{self._timestamp()}] ✗ Not found: {selector}")

            # Check for required text
            if required_text:
                print(f"[{self._timestamp()}] Checking for required text...")
                page_content = self.page.content()
                for text in required_text:
                    if text.lower() in page_content.lower():
                        result.ui_elements_visible.append(f"Text: {text}")
                        print(f"[{self._timestamp()}] ✓ Found text: {text}")
                    else:
                        result.ui_elements_missing.append(f"Text: {text}")
                        result.warnings.append(f"Required text not found: {text}")
                        print(f"[{self._timestamp()}] ✗ Text not found: {text}")

            # Check for template errors
            template_error_patterns = [
                "TemplateDoesNotExist",
                "TemplateSyntaxError",
                "NoReverseMatch",
                "Page not found (404)",
                "Server Error (500)",
            ]

            page_text = self.page.content()
            for pattern in template_error_patterns:
                if pattern in page_text:
                    result.errors.append(f"Template error detected: {pattern}")
                    print(f"[{self._timestamp()}] ✗ Template error: {pattern}")

            # Overall success determination
            if not result.errors and result.status_code and result.status_code < 400:
                result.success = True
                print(f"[{self._timestamp()}] ✓ Page test PASSED")
            else:
                result.success = False
                print(f"[{self._timestamp()}] ✗ Page test FAILED")

        except PlaywrightTimeoutError:
            result.errors.append("Page load timeout - page took too long to load")
            result.success = False
            print(f"[{self._timestamp()}] ✗ Page load timeout")
        except Exception as e:
            result.errors.append(f"Page test error: {str(e)}")
            result.success = False
            print(f"[{self._timestamp()}] ✗ Page test error: {str(e)}")

        finally:
            self.results.append(result)
            self._print_result_summary(result)

        return result

    def _print_result_summary(self, result: TestResult):
        """Print a summary of test result"""
        print(f"\n[{self._timestamp()}] --- Test Summary ---")
        print(f"[{self._timestamp()}] Page: {result.page_name}")
        print(f"[{self._timestamp()}] Success: {'✓ YES' if result.success else '✗ NO'}")
        print(f"[{self._timestamp()}] Status Code: {result.status_code}")
        print(f"[{self._timestamp()}] Load Time: {result.load_time:.2f}s" if result.load_time else "N/A")
        print(f"[{self._timestamp()}] Errors: {len(result.errors)}")
        print(f"[{self._timestamp()}] Warnings: {len(result.warnings)}")
        print(f"[{self._timestamp()}] Screenshot: {result.screenshot_path}")

    def run_all_tests(self):
        """
        Run all tests for the Zumodra platform

        TESTING PLAN:
        1. Login and authenticate
        2. Test all major pages in sequence
        3. Capture screenshots and status for each
        4. Document findings
        """
        print(f"\n{'='*60}")
        print(f"Zumodra Authenticated Website Testing")
        print(f"{'='*60}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Base URL: {BASE_URL}")
        print(f"Results Directory: {RESULTS_DIR}")
        print(f"{'='*60}\n")

        with sync_playwright() as playwright:
            try:
                # Setup browser
                self.setup_browser(playwright)

                # Authenticate
                if not self.login():
                    print(f"\n[{self._timestamp()}] ✗ Authentication failed - cannot proceed with tests")
                    return

                print(f"\n[{self._timestamp()}] ✓ Authentication successful - proceeding with page tests")

                # Test 1: Dashboard
                # FINDING: Main dashboard should show quick stats, recent activity, navigation
                self.test_page(
                    "Dashboard",
                    "/en-us/app/dashboard/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",  # Page title
                        ".card, .widget, .stat-card",  # Dashboard cards
                        "nav, .sidebar, .navigation",  # Navigation
                    ],
                    required_text=["Dashboard", "Welcome"]
                )

                # Test 2: ATS Jobs
                # FINDING: Jobs listing page - create/edit/duplicate/delete functionality
                # Expected: Job cards/table, search/filter, create button
                self.test_page(
                    "ATS Jobs",
                    "/en-us/app/ats/jobs/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",
                        ".job-card, .job-item, table",
                        "button, .btn, a[href*='create']",  # Create button
                    ],
                    required_text=["Jobs", "Position"]
                )

                # Test 3: ATS Candidates
                # FINDING: Candidates listing with profiles/CVs
                # Expected: Candidate cards/table, search, profile links
                self.test_page(
                    "ATS Candidates",
                    "/en-us/app/ats/candidates/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",
                        ".candidate-card, .candidate-item, table",
                        "input[type='search'], .search-box",
                    ],
                    required_text=["Candidates", "Applicants"]
                )

                # Test 4: ATS Applications
                # FINDING: Applications workflow management
                # Expected: Application list, status indicators, workflow actions
                self.test_page(
                    "ATS Applications",
                    "/en-us/app/ats/applications/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",
                        ".application-card, .application-item, table",
                        ".status, .badge",
                    ],
                    required_text=["Applications", "Status"]
                )

                # Test 5: ATS Pipeline
                # FINDING: Pipeline board for visual workflow management
                # Expected: Kanban board, drag-drop columns, candidate cards
                self.test_page(
                    "ATS Pipeline",
                    "/en-us/app/ats/pipeline/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",
                        ".pipeline-column, .kanban-column, .board-column",
                        ".candidate-card, .pipeline-card",
                    ],
                    required_text=["Pipeline", "Stage"]
                )

                # Test 6: ATS Interviews
                # FINDING: Interview scheduling with schedule/reschedule/cancel/feedback
                # Expected: Interview calendar/list, scheduling controls, feedback forms
                self.test_page(
                    "ATS Interviews",
                    "/en-us/app/ats/interviews/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",
                        ".interview-card, .interview-item, table, .calendar",
                        "button, .btn",
                    ],
                    required_text=["Interviews", "Schedule"]
                )

                # Test 7: HR Employees
                # FINDING: Employee directory and management
                # Expected: Employee cards/table, profile links, org chart
                self.test_page(
                    "HR Employees",
                    "/en-us/app/hr/employees/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",
                        ".employee-card, .employee-item, table",
                        "input[type='search'], .search-box",
                    ],
                    required_text=["Employees", "Directory"]
                )

                # Test 8: HR Time Off
                # FINDING: Time-off calendar and request management
                # Expected: Calendar view, request forms, approval controls
                self.test_page(
                    "HR Time Off",
                    "/en-us/app/hr/time-off/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",
                        ".calendar, .timeoff-item, table",
                        "button, .btn",
                    ],
                    required_text=["Time Off", "Leave", "Vacation"]
                )

                # Test 9: Services (Marketplace)
                # FINDING: Freelance marketplace services
                # Expected: Service listings, proposals, contracts
                # Note: URL might be /services/ or /app/services/
                self.test_page(
                    "Services Marketplace",
                    "/en-us/app/services/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",
                        ".service-card, .service-item, table",
                    ],
                    required_text=["Services", "Marketplace"]
                )

                # Test 9b: Try alternate services URL if first one fails
                if not self.results[-1].success:
                    print(f"[{self._timestamp()}] Trying alternate services URL...")
                    self.test_page(
                        "Services Marketplace (Alt)",
                        "/en-us/services/",
                        ui_elements_to_check=[
                            "h1, h2, .page-title",
                            ".service-card, .service-item, table",
                        ],
                        required_text=["Services", "Marketplace"]
                    )

                # Test 10: User Profile
                # FINDING: User profile management and settings
                # Expected: Profile form, settings, KYC status, trust score
                self.test_page(
                    "User Profile",
                    "/en-us/app/accounts/profile/",
                    ui_elements_to_check=[
                        "h1, h2, .page-title",
                        "form, .profile-form",
                        "input, textarea",
                    ],
                    required_text=["Profile", "Account"]
                )

                print(f"\n[{self._timestamp()}] ✓ All tests completed")

            except Exception as e:
                print(f"\n[{self._timestamp()}] ✗ Test suite error: {str(e)}")
                import traceback
                traceback.print_exc()
            finally:
                # Cleanup
                if self.context:
                    self.context.close()
                if self.browser:
                    self.browser.close()

        # Generate final report
        self.generate_report()

    def generate_report(self):
        """Generate final test report"""
        print(f"\n{'='*60}")
        print(f"FINAL TEST REPORT")
        print(f"{'='*60}")
        print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Tests: {len(self.results)}")

        passed = sum(1 for r in self.results if r.success)
        failed = sum(1 for r in self.results if not r.success)

        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(passed/len(self.results)*100):.1f}%")

        print(f"\n{'='*60}")
        print(f"DETAILED RESULTS")
        print(f"{'='*60}\n")

        for i, result in enumerate(self.results, 1):
            print(f"{i}. {result.page_name}")
            print(f"   URL: {result.url}")
            print(f"   Status: {'✓ PASS' if result.success else '✗ FAIL'}")
            print(f"   HTTP Code: {result.status_code}")
            print(f"   Load Time: {result.load_time:.2f}s" if result.load_time else "N/A")

            if result.errors:
                print(f"   Errors ({len(result.errors)}):")
                for error in result.errors:
                    print(f"     - {error}")

            if result.warnings:
                print(f"   Warnings ({len(result.warnings)}):")
                for warning in result.warnings:
                    print(f"     - {warning}")

            if result.ui_elements_missing:
                print(f"   Missing UI Elements:")
                for element in result.ui_elements_missing:
                    print(f"     - {element}")

            print(f"   Screenshot: {result.screenshot_path}")
            print()

        # Save JSON report
        json_report_path = RESULTS_DIR / f"test_report_{TIMESTAMP}.json"
        with open(json_report_path, 'w') as f:
            json.dump({
                "timestamp": TIMESTAMP,
                "base_url": BASE_URL,
                "total_tests": len(self.results),
                "passed": passed,
                "failed": failed,
                "success_rate": f"{(passed/len(self.results)*100):.1f}%",
                "results": [r.to_dict() for r in self.results]
            }, f, indent=2)

        print(f"{'='*60}")
        print(f"JSON report saved to: {json_report_path}")
        print(f"Screenshots saved to: {SCREENSHOTS_DIR}")
        print(f"{'='*60}\n")

        # Print summary of critical issues
        critical_issues = []
        for result in self.results:
            if not result.success and result.page_name != "Login Page":
                critical_issues.append({
                    "page": result.page_name,
                    "url": result.url,
                    "errors": result.errors
                })

        if critical_issues:
            print(f"\n{'='*60}")
            print(f"CRITICAL ISSUES REQUIRING ATTENTION")
            print(f"{'='*60}\n")

            for issue in critical_issues:
                print(f"Page: {issue['page']}")
                print(f"URL: {issue['url']}")
                print(f"Issues:")
                for error in issue['errors']:
                    print(f"  - {error}")
                print()

                # Suggest fixes based on error patterns
                print(f"Suggested Fixes:")
                for error in issue['errors']:
                    if "404" in error or "not found" in error.lower():
                        print(f"  - Check URL routing in urls.py")
                        print(f"  - Verify view exists in views.py or template_views.py")
                        print(f"  - Ensure URL namespace is correct (e.g., frontend:ats:*)")
                    elif "500" in error or "server error" in error.lower():
                        print(f"  - Check backend logs for exceptions")
                        print(f"  - Verify database migrations are applied")
                        print(f"  - Check for missing template files")
                    elif "403" in error or "forbidden" in error.lower():
                        print(f"  - Check permission decorators on view")
                        print(f"  - Verify user has required role/permissions")
                    elif "template" in error.lower():
                        print(f"  - Check template exists in correct directory")
                        print(f"  - Verify template extends correct base")
                        print(f"  - Check for syntax errors in template")
                    elif "redirect" in error.lower() and "login" in error.lower():
                        print(f"  - Add @login_required decorator to view")
                        print(f"  - Check authentication middleware is enabled")
                        print(f"  - Verify session is being maintained")
                print()


if __name__ == "__main__":
    """
    Main execution

    EXECUTION INSTRUCTIONS:
    1. Ensure Playwright is installed: pip install playwright pytest-playwright
    2. Install browser drivers: playwright install chromium
    3. Run script: python test_authenticated_website.py
    4. Review output and screenshots in ./test_results/

    FINDINGS WILL BE DOCUMENTED IN:
    - Console output with detailed logs
    - Screenshots in ./test_results/screenshots/
    - JSON report in ./test_results/test_report_*.json
    """

    tester = ZumodraWebsiteTester()
    tester.run_all_tests()

    print("\n" + "="*60)
    print("Testing complete!")
    print("="*60)
    print("\nNext Steps:")
    print("1. Review the console output above for detailed findings")
    print("2. Check screenshots in ./test_results/screenshots/")
    print("3. Review JSON report in ./test_results/")
    print("4. Address critical issues identified in the report")
    print("5. Fix any broken URLs, missing templates, or permission issues")
    print("\nFor any errors found, check:")
    print("- URL patterns in **/urls*.py files")
    print("- View implementations in **/views.py or **/template_views.py")
    print("- Template files in templates/ directory")
    print("- Permission decorators on views")
    print("- Database migrations status")
    print("="*60)
