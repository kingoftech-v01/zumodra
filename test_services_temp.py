#!/usr/bin/env python3
"""
Zumodra ATS Frontend Testing Script
====================================

Tests the Applicant Tracking System (ATS) frontend views on the production server:
https://zumodra.rhematek-solutions.com

This script performs comprehensive testing of all ATS features including:
- Job listings and management
- Candidate directory and profiles
- Application workflow
- Pipeline board (Kanban)
- Interview scheduling and management
- Offer management
- Background checks

REQUIREMENTS:
-------------
pip install playwright pytest-playwright
playwright install chromium

CREDENTIALS:
------------
URL: https://demo-company.zumodra.rhematek-solutions.com
Email: company.owner@demo.zumodra.rhematek-solutions.com
Password: Demo@2024!

USAGE:
------
python test_ats_frontend.py

RESULTS:
--------
- Console output with detailed test results
- Screenshots: ./ats_test_results/screenshots/
- JSON report: ./ats_test_results/ats_test_report_*.json
- HTML report: ./ats_test_results/ats_test_report_*.html
"""

import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# UTF-8 encoding for Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Check Playwright installation
try:
    from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext, TimeoutError as PlaywrightTimeoutError
except ImportError:
    print("ERROR: Playwright is not installed.")
    print("Install with: pip install playwright pytest-playwright")
    print("Then run: playwright install chromium")
    sys.exit(1)


# Test Configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
LOGIN_EMAIL = "company.owner@demo.zumodra.rhematek-solutions.com"
LOGIN_PASSWORD = "Demo@2024!"

# Test results directory
RESULTS_DIR = Path("./ats_test_results")
SCREENSHOTS_DIR = RESULTS_DIR / "screenshots"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")


@dataclass
class TestResult:
    """Test result for a single test scenario"""
    scenario_name: str
    url: str
    status: str = "PENDING"  # PASS, FAIL, SKIP, ERROR
    status_code: Optional[int] = None
    load_time: Optional[float] = None
    screenshot_path: Optional[str] = None
    errors: List[str] = None
    warnings: List[str] = None
    notes: List[str] = None
    ui_elements_found: List[str] = None
    ui_elements_missing: List[str] = None
    console_errors: List[str] = None
    performance_issues: List[str] = None

    def __post_init__(self):
        self.errors = self.errors or []
        self.warnings = self.warnings or []
        self.notes = self.notes or []
        self.ui_elements_found = self.ui_elements_found or []
        self.ui_elements_missing = self.ui_elements_missing or []
        self.console_errors = self.console_errors or []
        self.performance_issues = self.performance_issues or []

    def add_error(self, error: str):
        self.errors.append(error)
        self.status = "FAIL"

    def add_warning(self, warning: str):
        self.warnings.append(warning)

    def add_note(self, note: str):
        self.notes.append(note)

    def set_pass(self):
        if self.status != "FAIL":
            self.status = "PASS"

    def to_dict(self):
        return asdict(self)


class ATSFrontendTester:
    """ATS Frontend Testing Suite"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.authenticated = False

        # Ensure directories exist
        SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

        # Track console errors
        self.console_errors = []

    def log(self, message: str):
        """Log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")

    def setup_browser(self, playwright):
        """Initialize Playwright browser"""
        self.log("Launching browser...")

        self.browser = playwright.chromium.launch(
            headless=False,  # Set to True for CI/CD
            slow_mo=50,
        )

        self.context = self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )

        self.context.set_default_timeout(30000)  # 30 seconds

        self.page = self.context.new_page()

        # Listen to console
        self.page.on("console", self._handle_console)
        self.page.on("pageerror", self._handle_page_error)

        self.log("Browser launched successfully")

    def _handle_console(self, msg):
        """Handle browser console messages"""
        if msg.type in ["error", "warning"]:
            self.console_errors.append(f"{msg.type.upper()}: {msg.text}")

    def _handle_page_error(self, exc):
        """Handle page errors"""
        self.console_errors.append(f"PAGE ERROR: {str(exc)}")

    def take_screenshot(self, name: str) -> str:
        """Take screenshot and return path"""
        screenshot_path = SCREENSHOTS_DIR / f"{name}_{TIMESTAMP}.png"
        self.page.screenshot(path=str(screenshot_path), full_page=True)
        return str(screenshot_path)

    def login(self) -> bool:
        """Authenticate to the platform"""
        self.log("\n" + "="*60)
        self.log("AUTHENTICATION")
        self.log("="*60)

        result = TestResult("Login", f"{BASE_URL}/en-us/accounts/login/")
        start_time = time.time()

        try:
            self.log(f"Navigating to: {result.url}")
            response = self.page.goto(result.url, wait_until="domcontentloaded")
            result.status_code = response.status
            result.load_time = time.time() - start_time

            # Screenshot of login page
            result.screenshot_path = self.take_screenshot("01_login_page")

            # Fill credentials
            self.page.fill('input[name="login"]', LOGIN_EMAIL)
            self.page.fill('input[type="password"]', LOGIN_PASSWORD)

            # Screenshot before submit
            self.take_screenshot("02_login_filled")

            # Submit and wait for navigation
            with self.page.expect_navigation(timeout=30000):
                self.page.click('button[type="submit"]')

            self.page.wait_for_load_state("networkidle")

            # Screenshot after login
            self.take_screenshot("03_after_login")

            current_url = self.page.url

            # Check if login was successful
            if "/accounts/login/" not in current_url:
                self.authenticated = True
                result.set_pass()
                result.add_note(f"Successfully authenticated, redirected to: {current_url}")
                self.log("✓ Authentication successful")
            else:
                self.authenticated = False
                result.add_error("Authentication failed - still on login page")
                self.log("✗ Authentication failed")

        except Exception as e:
            result.add_error(f"Authentication error: {str(e)}")
            self.authenticated = False

        finally:
            self.results.append(result)

        return self.authenticated

    def test_scenario(self, scenario_name: str, relative_url: str,
                      checks: Dict[str, any]) -> TestResult:
        """
        Test a specific scenario

        Args:
            scenario_name: Name of the test scenario
            relative_url: URL path relative to BASE_URL
            checks: Dictionary of checks to perform
        """
        full_url = f"{BASE_URL}{relative_url}"
        result = TestResult(scenario_name, full_url)

        self.log(f"\n{'='*60}")
        self.log(f"TEST: {scenario_name}")
        self.log(f"{'='*60}")
        self.log(f"URL: {full_url}")

        start_time = time.time()

        try:
            # Navigate to page
            response = self.page.goto(full_url, wait_until="domcontentloaded")
            result.status_code = response.status
            result.load_time = time.time() - start_time

            self.log(f"Status Code: {result.status_code}")
            self.log(f"Load Time: {result.load_time:.2f}s")

            # Check for slow load
            if result.load_time > 3.0:
                result.performance_issues.append(f"Slow page load: {result.load_time:.2f}s")

            # Wait for page to settle
            self.page.wait_for_load_state("domcontentloaded")
            time.sleep(1)

            # Take screenshot
            screenshot_name = scenario_name.lower().replace(" ", "_").replace("/", "_")
            result.screenshot_path = self.take_screenshot(screenshot_name)

            # Check if redirected to login (auth issue)
            if "/accounts/login/" in self.page.url:
                result.add_error("Redirected to login - authentication expired or insufficient permissions")
                return result

            # Check HTTP status
            if result.status_code >= 400:
                result.add_error(f"HTTP {result.status_code} error")
                if result.status_code == 404:
                    result.add_note("Page not found - URL may be incorrect or view not implemented")
                elif result.status_code == 403:
                    result.add_note("Forbidden - user may not have permission")
                elif result.status_code == 500:
                    result.add_note("Internal server error - check backend logs")

            # Perform checks
            if "title" in checks:
                self._check_element(result, checks["title"], "Page title")

            if "ui_elements" in checks:
                for selector in checks["ui_elements"]:
                    self._check_element(result, selector, f"UI element: {selector}")

            if "required_text" in checks:
                page_content = self.page.content()
                for text in checks["required_text"]:
                    if text.lower() in page_content.lower():
                        result.ui_elements_found.append(f"Text: {text}")
                    else:
                        result.ui_elements_missing.append(f"Text: {text}")
                        result.add_warning(f"Required text not found: {text}")

            if "actions" in checks:
                for action in checks["actions"]:
                    self._perform_action(result, action)

            # Check for error messages on page
            self._check_for_errors(result)

            # If no errors, mark as pass
            if not result.errors:
                result.set_pass()
                self.log(f"✓ Test PASSED: {scenario_name}")
            else:
                self.log(f"✗ Test FAILED: {scenario_name}")
                for error in result.errors:
                    self.log(f"  Error: {error}")

        except PlaywrightTimeoutError:
            result.add_error("Page load timeout")
        except Exception as e:
            result.add_error(f"Test error: {str(e)}")

        finally:
            self.results.append(result)
            self._print_result_summary(result)

        return result

    def _check_element(self, result: TestResult, selector: str, description: str):
        """Check if element exists and is visible"""
        try:
            element = self.page.locator(selector).first
            if element.count() > 0:
                if element.is_visible(timeout=3000):
                    result.ui_elements_found.append(description)
                    self.log(f"  ✓ Found: {description}")
                else:
                    result.ui_elements_missing.append(description)
                    result.add_warning(f"Element exists but not visible: {description}")
            else:
                result.ui_elements_missing.append(description)
                result.add_warning(f"Element not found: {description}")
        except Exception as e:
            result.ui_elements_missing.append(description)
            result.add_warning(f"Error checking element {description}: {str(e)}")

    def _perform_action(self, result: TestResult, action: Dict):
        """Perform an action on the page"""
        try:
            action_type = action.get("type")

            if action_type == "click":
                selector = action.get("selector")
                self.page.click(selector, timeout=5000)
                result.add_note(f"Clicked: {selector}")
                time.sleep(1)  # Wait for any effects

            elif action_type == "fill":
                selector = action.get("selector")
                value = action.get("value")
                self.page.fill(selector, value, timeout=5000)
                result.add_note(f"Filled: {selector}")

            elif action_type == "check_visibility":
                selector = action.get("selector")
                if self.page.locator(selector).is_visible(timeout=5000):
                    result.add_note(f"Element visible after action: {selector}")
                else:
                    result.add_warning(f"Element not visible after action: {selector}")

        except Exception as e:
            result.add_warning(f"Action failed: {str(e)}")

    def _check_for_errors(self, result: TestResult):
        """Check page for error indicators"""
        error_selectors = [
            ".alert-danger",
            ".alert-error",
            ".error-message",
            "[class*='error']"
        ]

        for selector in error_selectors:
            try:
                elements = self.page.locator(selector).all()
                for elem in elements:
                    if elem.is_visible():
                        text = elem.text_content().strip()
                        if text and len(text) > 0:
                            result.add_error(f"Error message on page: {text}")
            except:
                pass

    def _print_result_summary(self, result: TestResult):
        """Print test result summary"""
        self.log(f"\n--- Result Summary ---")
        self.log(f"Status: {result.status}")
        self.log(f"Errors: {len(result.errors)}")
        self.log(f"Warnings: {len(result.warnings)}")
        self.log(f"Screenshot: {result.screenshot_path}")

    # =============================================================================
    # ATS TEST SCENARIOS
    # =============================================================================

    def test_job_listing_view(self):
        """Test 1: Job Listing View"""
        return self.test_scenario(
            "Job Listing View",
            "/en-us/app/ats/jobs/",
            {
                "title": "h1, .page-title, .page-header",
                "ui_elements": [
                    ".job-card, .job-item, table, .jobs-table",  # Job list
                    "input[type='search'], .search-box, input[placeholder*='search' i]",  # Search
                    ".filter, select, .filter-dropdown",  # Filters
                    "button[href*='create'], .btn-create, a[href*='create']",  # Create button
                ],
                "required_text": ["Jobs", "Position", "Status"]
            }
        )

    def test_candidate_list_view(self):
        """Test 2: Candidate List View"""
        return self.test_scenario(
            "Candidate List View",
            "/en-us/app/ats/candidates/",
            {
                "title": "h1, .page-title",
                "ui_elements": [
                    ".candidate-card, .candidate-item, table",
                    "input[type='search'], .search-box",
                    ".filter, select",
                ],
                "required_text": ["Candidates", "Name", "Email"]
            }
        )

    def test_pipeline_board_view(self):
        """Test 5: Pipeline Board View (Kanban)"""
        return self.test_scenario(
            "Pipeline Board View",
            "/en-us/app/ats/pipeline/",
            {
                "title": "h1, .page-title",
                "ui_elements": [
                    ".pipeline-column, .kanban-column, .board-column, [class*='column']",
                    ".candidate-card, .application-card, [draggable='true']",
                    ".stage-header, .column-header",
                ],
                "required_text": ["Pipeline", "Applied", "Screening", "Interview"]
            }
        )

    def test_interview_list_view(self):
        """Test 4: Interview List View"""
        return self.test_scenario(
            "Interview List View",
            "/en-us/app/ats/interviews/",
            {
                "title": "h1, .page-title",
                "ui_elements": [
                    ".interview-card, .interview-item, table",
                    ".calendar, .schedule",
                    "button, .btn",
                ],
                "required_text": ["Interviews", "Schedule", "Upcoming"]
            }
        )

    def test_job_detail_view(self):
        """Test 6: Job Detail View (if we can get a job ID)"""
        # First, try to get a job from the listing
        try:
            self.page.goto(f"{BASE_URL}/en-us/app/ats/jobs/", wait_until="domcontentloaded")

            # Try to find first job link
            job_links = self.page.locator("a[href*='/jobs/']").all()
            if job_links:
                first_job_url = job_links[0].get_attribute("href")
                if first_job_url:
                    return self.test_scenario(
                        "Job Detail View",
                        first_job_url if first_job_url.startswith("/") else f"/{first_job_url}",
                        {
                            "title": "h1, .page-title",
                            "ui_elements": [
                                ".job-description, .description",
                                ".applicants, .applications",
                                "button[href*='edit'], .btn-edit",
                            ],
                            "required_text": ["Description", "Requirements", "Applications"]
                        }
                    )
        except:
            pass

        # If we can't get a specific job, create a placeholder result
        result = TestResult("Job Detail View", f"{BASE_URL}/en-us/app/ats/jobs/[id]/")
        result.status = "SKIP"
        result.add_note("Could not find a job to view details")
        self.results.append(result)
        return result

    def test_candidate_detail_view(self):
        """Test 7: Candidate Detail View"""
        try:
            self.page.goto(f"{BASE_URL}/en-us/app/ats/candidates/", wait_until="domcontentloaded")

            # Try to find first candidate link
            candidate_links = self.page.locator("a[href*='/candidates/']").all()
            if candidate_links:
                first_candidate_url = candidate_links[0].get_attribute("href")
                if first_candidate_url:
                    return self.test_scenario(
                        "Candidate Detail View",
                        first_candidate_url if first_candidate_url.startswith("/") else f"/{first_candidate_url}",
                        {
                            "title": "h1, .page-title, .candidate-name",
                            "ui_elements": [
                                ".candidate-info, .profile",
                                ".resume, .cv",
                                ".applications, .application-history",
                                ".timeline, .activity",
                            ],
                            "required_text": ["Profile", "Applications", "Timeline"]
                        }
                    )
        except:
            pass

        result = TestResult("Candidate Detail View", f"{BASE_URL}/en-us/app/ats/candidates/[id]/")
        result.status = "SKIP"
        result.add_note("Could not find a candidate to view details")
        self.results.append(result)
        return result

    def test_application_detail_view(self):
        """Test 3: Application Detail View"""
        try:
            # Navigate to pipeline to find an application
            self.page.goto(f"{BASE_URL}/en-us/app/ats/pipeline/", wait_until="domcontentloaded")
            time.sleep(2)

            # Try to find application link
            app_links = self.page.locator("a[href*='/applications/']").all()
            if app_links:
                first_app_url = app_links[0].get_attribute("href")
                if first_app_url:
                    return self.test_scenario(
                        "Application Detail View",
                        first_app_url if first_app_url.startswith("/") else f"/{first_app_url}",
                        {
                            "title": "h1, .page-title",
                            "ui_elements": [
                                ".application-info, .applicant-info",
                                ".resume-link, .cv-link, a[href*='resume']",
                                ".cover-letter, .cover-letter-section",
                                ".status-selector, select[name*='status']",
                                ".notes, .add-note, textarea",
                                ".timeline, .activity-log",
                            ],
                            "required_text": ["Application", "Status", "Notes"]
                        }
                    )
        except:
            pass

        result = TestResult("Application Detail View", f"{BASE_URL}/en-us/app/ats/applications/[id]/")
        result.status = "SKIP"
        result.add_note("Could not find an application to view details")
        self.results.append(result)
        return result

    def test_offer_list_view(self):
        """Test 8: Offer Management"""
        return self.test_scenario(
            "Offer List View",
            "/en-us/app/ats/offers/",
            {
                "title": "h1, .page-title",
                "ui_elements": [
                    ".offer-card, .offer-item, table",
                    ".status, .badge",
                ],
                "required_text": ["Offers", "Status", "Candidate"]
            }
        )

    def test_job_creation_form(self):
        """Test 6: Job Creation Form"""
        return self.test_scenario(
            "Job Creation Form",
            "/en-us/app/ats/jobs/create/",
            {
                "title": "h1, .page-title",
                "ui_elements": [
                    "form, .job-form",
                    "input[name*='title'], #id_title",
                    "textarea[name*='description'], #id_description",
                    "select[name*='category'], select[name*='job_type']",
                    "button[type='submit'], .btn-submit",
                ],
                "required_text": ["Create", "Job", "Title", "Description"]
            }
        )

    def test_interview_scheduling_form(self):
        """Test 7: Interview Scheduling"""
        # Try to access scheduling from interview list
        try:
            self.page.goto(f"{BASE_URL}/en-us/app/ats/interviews/", wait_until="domcontentloaded")
            time.sleep(1)

            # Look for schedule button
            schedule_buttons = self.page.locator("button[href*='schedule'], a[href*='schedule'], .btn-schedule").all()
            if schedule_buttons and len(schedule_buttons) > 0:
                schedule_buttons[0].click()
                time.sleep(2)

                result = TestResult("Interview Scheduling Form", self.page.url)
                result.screenshot_path = self.take_screenshot("interview_schedule_form")

                # Check form elements
                form_elements = [
                    "input[type='date'], input[type='datetime-local']",
                    "select[name*='type']",
                    "input[name*='location'], textarea[name*='location']",
                    "input[name*='link'], input[placeholder*='zoom' i], input[placeholder*='meet' i]",
                ]

                for selector in form_elements:
                    self._check_element(result, selector, f"Form field: {selector}")

                if result.ui_elements_found:
                    result.set_pass()

                self.results.append(result)
                return result
        except:
            pass

        result = TestResult("Interview Scheduling Form", f"{BASE_URL}/en-us/app/ats/interviews/schedule/")
        result.status = "SKIP"
        result.add_note("Could not access interview scheduling form")
        self.results.append(result)
        return result

    # =============================================================================
    # MAIN TEST RUNNER
    # =============================================================================

    def run_all_tests(self):
        """Run all ATS frontend tests"""
        self.log("\n" + "="*60)
        self.log("ZUMODRA ATS FRONTEND TEST SUITE")
        self.log("="*60)
        self.log(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log(f"Base URL: {BASE_URL}")
        self.log(f"Results Directory: {RESULTS_DIR}")
        self.log("="*60)

        with sync_playwright() as playwright:
            try:
                # Setup
                self.setup_browser(playwright)

                # Authenticate
                if not self.login():
                    self.log("\n✗ Authentication failed - cannot proceed")
                    return

                self.log("\n✓ Authentication successful")

                # Run test scenarios
                self.log("\n" + "="*60)
                self.log("RUNNING ATS FRONTEND TESTS")
                self.log("="*60)

                # Test 1: Job Listing
                self.test_job_listing_view()

                # Test 2: Candidate List
                self.test_candidate_list_view()

                # Test 3: Application Detail (from pipeline)
                self.test_application_detail_view()

                # Test 4: Interview List
                self.test_interview_list_view()

                # Test 5: Pipeline Board
                self.test_pipeline_board_view()

                # Test 6: Job Creation Form
                self.test_job_creation_form()

                # Test 7: Interview Scheduling
                self.test_interview_scheduling_form()

                # Test 8: Offer List
                self.test_offer_list_view()

                # Test 9: Job Detail (from job list)
                self.test_job_detail_view()

                # Test 10: Candidate Detail (from candidate list)
                self.test_candidate_detail_view()

                self.log("\n✓ All tests completed")

            except Exception as e:
                self.log(f"\n✗ Test suite error: {str(e)}")
                import traceback
                traceback.print_exc()

            finally:
                # Cleanup
                if self.context:
                    self.context.close()
                if self.browser:
                    self.browser.close()

        # Generate reports
        self.generate_reports()

    def generate_reports(self):
        """Generate test reports"""
        self.log("\n" + "="*60)
        self.log("GENERATING REPORTS")
        self.log("="*60)

        # Calculate statistics
        total = len([r for r in self.results if r.status != "SKIP"])
        passed = len([r for r in self.results if r.status == "PASS"])
        failed = len([r for r in self.results if r.status == "FAIL"])
        skipped = len([r for r in self.results if r.status == "SKIP"])

        # Console report
        self.log("\n" + "="*60)
        self.log("FINAL TEST REPORT")
        self.log("="*60)
        self.log(f"Total Tests: {total + skipped}")
        self.log(f"Passed: {passed} ✓")
        self.log(f"Failed: {failed} ✗")
        self.log(f"Skipped: {skipped} ⊘")
        if total > 0:
            self.log(f"Success Rate: {(passed/total*100):.1f}%")
        self.log("="*60)

        # Detailed results
        self.log("\nDETAILED RESULTS:")
        self.log("="*60)

        for i, result in enumerate(self.results, 1):
            status_symbol = {
                "PASS": "✓",
                "FAIL": "✗",
                "SKIP": "⊘",
                "ERROR": "✗"
            }.get(result.status, "?")

            self.log(f"\n{i}. {result.scenario_name} {status_symbol} {result.status}")
            self.log(f"   URL: {result.url}")
            if result.status_code:
                self.log(f"   HTTP Status: {result.status_code}")
            if result.load_time:
                self.log(f"   Load Time: {result.load_time:.2f}s")

            if result.errors:
                self.log(f"   Errors:")
                for error in result.errors:
                    self.log(f"     • {error}")

            if result.warnings:
                self.log(f"   Warnings:")
                for warning in result.warnings:
                    self.log(f"     • {warning}")

            if result.performance_issues:
                self.log(f"   Performance Issues:")
                for issue in result.performance_issues:
                    self.log(f"     • {issue}")

            if result.screenshot_path:
                self.log(f"   Screenshot: {result.screenshot_path}")

        # JSON Report
        json_report_path = RESULTS_DIR / f"ats_test_report_{TIMESTAMP}.json"
        report_data = {
            "timestamp": TIMESTAMP,
            "base_url": BASE_URL,
            "total_tests": total + skipped,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "success_rate": f"{(passed/total*100):.1f}%" if total > 0 else "0%",
            "results": [r.to_dict() for r in self.results]
        }

        with open(json_report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        self.log(f"\n✓ JSON report saved to: {json_report_path}")

        # HTML Report
        html_report_path = RESULTS_DIR / f"ats_test_report_{TIMESTAMP}.html"
        self._generate_html_report(html_report_path, report_data)
        self.log(f"✓ HTML report saved to: {html_report_path}")

        self.log(f"✓ Screenshots saved to: {SCREENSHOTS_DIR}")

        # Summary
        self.log("\n" + "="*60)
        self.log("TEST SUMMARY")
        self.log("="*60)

        if failed > 0:
            self.log("\nFAILED TESTS:")
            for result in self.results:
                if result.status == "FAIL":
                    self.log(f"\n✗ {result.scenario_name}")
                    self.log(f"  URL: {result.url}")
                    for error in result.errors:
                        self.log(f"  • {error}")

        self.log("\n" + "="*60)
        self.log("RECOMMENDATIONS")
        self.log("="*60)
        self.log("1. Review screenshots in ./ats_test_results/screenshots/")
        self.log("2. Open HTML report for detailed analysis")
        self.log("3. Check console for JavaScript errors")
        self.log("4. Verify all HTMX functionality is working")
        self.log("5. Test drag-and-drop on pipeline board manually")
        self.log("="*60)

    def _generate_html_report(self, output_path: Path, report_data: dict):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ATS Frontend Test Report - {TIMESTAMP}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
        }}
        .stat-card .value {{
            font-size: 32px;
            font-weight: bold;
        }}
        .stat-card.pass .value {{ color: #10b981; }}
        .stat-card.fail .value {{ color: #ef4444; }}
        .stat-card.skip .value {{ color: #f59e0b; }}
        .test-result {{
            background: white;
            margin-bottom: 20px;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .test-result.pass {{
            border-left: 4px solid #10b981;
        }}
        .test-result.fail {{
            border-left: 4px solid #ef4444;
        }}
        .test-result.skip {{
            border-left: 4px solid #f59e0b;
        }}
        .test-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .test-name {{
            font-size: 18px;
            font-weight: bold;
        }}
        .status {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 12px;
        }}
        .status.pass {{
            background: #d1fae5;
            color: #065f46;
        }}
        .status.fail {{
            background: #fee2e2;
            color: #991b1b;
        }}
        .status.skip {{
            background: #fef3c7;
            color: #92400e;
        }}
        .test-meta {{
            color: #666;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .errors, .warnings {{
            margin-top: 10px;
        }}
        .error-item {{
            background: #fee2e2;
            color: #991b1b;
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 4px;
            font-size: 14px;
        }}
        .warning-item {{
            background: #fef3c7;
            color: #92400e;
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 4px;
            font-size: 14px;
        }}
        .screenshot {{
            max-width: 100%;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ATS Frontend Test Report</h1>
        <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Base URL:</strong> {BASE_URL}</p>
    </div>

    <div class="stats">
        <div class="stat-card">
            <h3>Total Tests</h3>
            <div class="value">{report_data['total_tests']}</div>
        </div>
        <div class="stat-card pass">
            <h3>Passed</h3>
            <div class="value">{report_data['passed']}</div>
        </div>
        <div class="stat-card fail">
            <h3>Failed</h3>
            <div class="value">{report_data['failed']}</div>
        </div>
        <div class="stat-card skip">
            <h3>Skipped</h3>
            <div class="value">{report_data['skipped']}</div>
        </div>
        <div class="stat-card">
            <h3>Success Rate</h3>
            <div class="value">{report_data['success_rate']}</div>
        </div>
    </div>

    <h2>Test Results</h2>
"""

        for result in report_data['results']:
            status_class = result['status'].lower()
            html += f"""
    <div class="test-result {status_class}">
        <div class="test-header">
            <div class="test-name">{result['scenario_name']}</div>
            <div class="status {status_class}">{result['status']}</div>
        </div>
        <div class="test-meta">
            <strong>URL:</strong> <a href="{result['url']}" target="_blank">{result['url']}</a><br>
"""
            if result.get('status_code'):
                html += f"            <strong>HTTP Status:</strong> {result['status_code']}<br>\n"
            if result.get('load_time'):
                html += f"            <strong>Load Time:</strong> {result['load_time']:.2f}s<br>\n"

            html += "        </div>\n"

            if result.get('errors'):
                html += "        <div class='errors'>\n"
                html += "            <strong>Errors:</strong>\n"
                for error in result['errors']:
                    html += f"            <div class='error-item'>{error}</div>\n"
                html += "        </div>\n"

            if result.get('warnings'):
                html += "        <div class='warnings'>\n"
                html += "            <strong>Warnings:</strong>\n"
                for warning in result['warnings']:
                    html += f"            <div class='warning-item'>{warning}</div>\n"
                html += "        </div>\n"

            if result.get('screenshot_path'):
                # Convert absolute path to relative for HTML
                screenshot_rel = Path(result['screenshot_path']).relative_to(RESULTS_DIR)
                html += f"        <div><strong>Screenshot:</strong> <a href='{screenshot_rel}' target='_blank'>View Screenshot</a></div>\n"

            html += "    </div>\n"

        html += """
</body>
</html>
"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)


def main():
    """Main execution"""
    print("\n" + "="*60)
    print("ZUMODRA ATS FRONTEND TEST SUITE")
    print("="*60)
    print("\nThis script will test all ATS frontend views including:")
    print("  • Job listings and management")
    print("  • Candidate directory and profiles")
    print("  • Application workflow")
    print("  • Pipeline board (Kanban)")
    print("  • Interview scheduling")
    print("  • Offer management")
    print("\nResults will be saved to: ./ats_test_results/")
    print("="*60 + "\n")

    tester = ATSFrontendTester()
    tester.run_all_tests()

    print("\n" + "="*60)
    print("TESTING COMPLETE")
    print("="*60)
    print("\nNext Steps:")
    print("1. Review the HTML report for detailed visual analysis")
    print("2. Check all screenshots in ./ats_test_results/screenshots/")
    print("3. Address any failed tests")
    print("4. Manually test drag-and-drop on pipeline board")
    print("5. Verify HTMX interactions are working")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
