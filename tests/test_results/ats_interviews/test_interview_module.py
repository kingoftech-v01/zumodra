"""
ATS Interviews Module Testing Script
=====================================

Tests all interview-related URLs and functionality on:
https://demo-company.zumodra.rhematek-solutions.com

CREDENTIALS (from setup_demo_data.py):
- Email: demo@demo.zumodra.rhematek-solutions.com
- Password: demo123!

INTERVIEW URLS TO TEST:
1. /app/ats/interviews/ - Interview list view
2. /app/ats/interviews/<uuid>/ - Interview detail view
3. /app/ats/interviews/<uuid>/reschedule/ - Reschedule form
4. /app/ats/interviews/<uuid>/cancel/ - Cancel interview
5. /app/ats/htmx/interviews/schedule/ - Schedule new interview (HTMX)
6. /app/ats/htmx/interviews/<uuid>/feedback/ - Interview feedback (HTMX)

Created: 2026-01-16
"""

import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add selenium imports
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
except ImportError:
    print("ERROR: Selenium not installed. Install with: pip install selenium")
    # Don't exit - let pytest skip tests that need selenium
    # sys.exit(1)
    pass


class InterviewModuleTester:
    """Comprehensive tester for ATS Interview module."""

    def __init__(self):
        self.base_url = "https://demo-company.zumodra.rhematek-solutions.com"
        self.email = "demo@demo.zumodra.rhematek-solutions.com"
        self.password = "demo123!"
        self.screenshot_dir = Path(__file__).parent
        self.driver: Optional[webdriver.Chrome] = None
        self.session_cookies = None
        self.test_results = []
        self.interview_ids = []

    def setup_driver(self):
        """Initialize Chrome WebDriver with options."""
        print("\n[SETUP] Initializing Chrome WebDriver...")

        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        # Uncomment for headless mode
        # chrome_options.add_argument("--headless")

        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.implicitly_wait(10)
            print("[SETUP] Chrome WebDriver initialized successfully")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to initialize Chrome: {e}")
            return False

    def take_screenshot(self, name: str, description: str = ""):
        """Take and save screenshot with timestamp."""
        if not self.driver:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{name}.png"
        filepath = self.screenshot_dir / filename

        try:
            self.driver.save_screenshot(str(filepath))
            print(f"  📸 Screenshot saved: {filename}")
            if description:
                print(f"     {description}")
            return filepath
        except Exception as e:
            print(f"  ❌ Screenshot failed: {e}")
            return None

    def log_test_result(self, test_name: str, status: str, details: str = "",
                       url: str = "", screenshot: str = ""):
        """Log test result for final report."""
        result = {
            "timestamp": datetime.now().isoformat(),
            "test": test_name,
            "status": status,  # PASS, FAIL, ERROR, SKIP
            "details": details,
            "url": url,
            "screenshot": screenshot
        }
        self.test_results.append(result)

        # Print status with emoji
        emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️", "SKIP": "⏭️"}.get(status, "•")
        print(f"  {emoji} {status}: {test_name}")
        if details:
            print(f"     {details}")

    def login(self) -> bool:
        """Authenticate to the demo tenant."""
        print("\n[TEST 1] Login to Demo Tenant")
        print("=" * 60)

        try:
            # Navigate to login page
            login_url = f"{self.base_url}/accounts/login/"
            print(f"  Navigating to: {login_url}")
            self.driver.get(login_url)
            time.sleep(2)

            # Take screenshot of login page
            self.take_screenshot("01_login_page", "Login page loaded")

            # Find and fill login form
            email_field = self.driver.find_element(By.NAME, "login")
            password_field = self.driver.find_element(By.NAME, "password")

            email_field.clear()
            email_field.send_keys(self.email)
            password_field.clear()
            password_field.send_keys(self.password)

            # Submit form
            submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            submit_button.click()

            # Wait for redirect
            time.sleep(3)

            # Check if login successful
            current_url = self.driver.current_url
            if "login" not in current_url.lower() and "/app/" in current_url:
                self.take_screenshot("02_dashboard_after_login", "Successfully logged in")
                self.log_test_result(
                    "User Login",
                    "PASS",
                    f"Logged in as {self.email}",
                    current_url,
                    "02_dashboard_after_login.png"
                )
                return True
            else:
                self.take_screenshot("02_login_failed", "Login may have failed")
                self.log_test_result(
                    "User Login",
                    "FAIL",
                    f"Still on login page or unexpected redirect: {current_url}",
                    current_url,
                    "02_login_failed.png"
                )
                return False

        except Exception as e:
            self.take_screenshot("error_login", f"Login error: {str(e)}")
            self.log_test_result("User Login", "ERROR", str(e))
            return False

    def test_interview_list(self) -> bool:
        """Test interview list page."""
        print("\n[TEST 2] Interview List Page")
        print("=" * 60)

        try:
            # Navigate to interview list
            url = f"{self.base_url}/app/ats/interviews/"
            print(f"  Navigating to: {url}")
            self.driver.get(url)
            time.sleep(2)

            # Take screenshot
            self.take_screenshot("03_interview_list", "Interview list page")

            # Check page title and content
            page_title = self.driver.title
            page_source = self.driver.page_source.lower()

            # Look for interview-related content
            has_interviews_heading = "interview" in page_source
            has_table_or_list = any(x in page_source for x in ["table", "interview-card", "list"])

            # Try to find interview links/cards
            try:
                # Try multiple selectors
                interview_elements = []
                selectors = [
                    "a[href*='/app/ats/interviews/']",
                    ".interview-card",
                    "tr[data-interview-id]",
                    "[data-testid='interview-item']"
                ]

                for selector in selectors:
                    try:
                        elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                        if elements:
                            interview_elements.extend(elements)
                    except:
                        pass

                # Extract interview IDs from URLs
                for element in interview_elements[:10]:  # Limit to first 10
                    try:
                        href = element.get_attribute("href")
                        if href and "/app/ats/interviews/" in href:
                            # Extract UUID from URL
                            parts = href.split("/app/ats/interviews/")
                            if len(parts) > 1:
                                uuid_part = parts[1].strip("/").split("/")[0]
                                if len(uuid_part) == 36:  # UUID length
                                    self.interview_ids.append(uuid_part)
                    except:
                        pass

                print(f"  Found {len(interview_elements)} interview elements")
                print(f"  Extracted {len(self.interview_ids)} interview IDs")

            except Exception as e:
                print(f"  Note: Could not extract interview elements: {e}")

            # Check for error messages
            error_indicators = ["500", "error", "not found", "forbidden"]
            has_error = any(indicator in page_source for indicator in error_indicators)

            if has_error:
                self.log_test_result(
                    "Interview List Page",
                    "FAIL",
                    "Page contains error indicators",
                    url,
                    "03_interview_list.png"
                )
                return False
            elif has_interviews_heading:
                self.log_test_result(
                    "Interview List Page",
                    "PASS",
                    f"Page loaded successfully. Found {len(self.interview_ids)} interviews",
                    url,
                    "03_interview_list.png"
                )
                return True
            else:
                self.log_test_result(
                    "Interview List Page",
                    "FAIL",
                    "Page loaded but no interview content found",
                    url,
                    "03_interview_list.png"
                )
                return False

        except Exception as e:
            self.take_screenshot("error_interview_list", f"Error: {str(e)}")
            self.log_test_result("Interview List Page", "ERROR", str(e), url)
            return False

    def test_interview_detail(self, interview_id: str, index: int) -> bool:
        """Test individual interview detail page."""
        print(f"\n[TEST 3.{index}] Interview Detail Page (ID: {interview_id[:8]}...)")
        print("=" * 60)

        try:
            # Navigate to interview detail
            url = f"{self.base_url}/app/ats/interviews/{interview_id}/"
            print(f"  Navigating to: {url}")
            self.driver.get(url)
            time.sleep(2)

            # Take screenshot
            screenshot_name = f"04_{index}_interview_detail_{interview_id[:8]}"
            self.take_screenshot(screenshot_name, f"Interview detail page")

            # Check page content
            page_source = self.driver.page_source.lower()

            # Look for interview details
            has_interview_info = any(x in page_source for x in [
                "scheduled", "interviewer", "candidate", "feedback",
                "reschedule", "cancel", "interview type"
            ])

            # Check for specific elements
            has_reschedule_button = "reschedule" in page_source
            has_cancel_button = "cancel" in page_source
            has_feedback_section = "feedback" in page_source

            # Check for errors
            error_indicators = ["500", "404", "not found", "forbidden"]
            has_error = any(indicator in page_source for indicator in error_indicators)

            if has_error:
                self.log_test_result(
                    f"Interview Detail {interview_id[:8]}",
                    "FAIL",
                    "Page shows error",
                    url,
                    f"{screenshot_name}.png"
                )
                return False
            elif has_interview_info:
                details = f"Reschedule: {has_reschedule_button}, Cancel: {has_cancel_button}, Feedback: {has_feedback_section}"
                self.log_test_result(
                    f"Interview Detail {interview_id[:8]}",
                    "PASS",
                    details,
                    url,
                    f"{screenshot_name}.png"
                )
                return True
            else:
                self.log_test_result(
                    f"Interview Detail {interview_id[:8]}",
                    "FAIL",
                    "Page loaded but missing interview information",
                    url,
                    f"{screenshot_name}.png"
                )
                return False

        except Exception as e:
            screenshot_name = f"error_interview_detail_{interview_id[:8]}"
            self.take_screenshot(screenshot_name, f"Error: {str(e)}")
            self.log_test_result(
                f"Interview Detail {interview_id[:8]}",
                "ERROR",
                str(e),
                url
            )
            return False

    def test_interview_reschedule(self, interview_id: str) -> bool:
        """Test interview reschedule page."""
        print(f"\n[TEST 4] Interview Reschedule (ID: {interview_id[:8]}...)")
        print("=" * 60)

        try:
            # Navigate to reschedule page
            url = f"{self.base_url}/app/ats/interviews/{interview_id}/reschedule/"
            print(f"  Navigating to: {url}")
            self.driver.get(url)
            time.sleep(2)

            # Take screenshot
            self.take_screenshot("05_interview_reschedule", "Reschedule page")

            # Check page content
            page_source = self.driver.page_source.lower()

            # Look for reschedule form elements
            has_date_field = any(x in page_source for x in ["date", "scheduled_start", "datetime"])
            has_time_field = any(x in page_source for x in ["time", "scheduled_end"])
            has_submit_button = any(x in page_source for x in ["submit", "reschedule", "save"])

            # Check for errors
            error_indicators = ["500", "404", "not found", "forbidden"]
            has_error = any(indicator in page_source for indicator in error_indicators)

            if has_error:
                self.log_test_result(
                    "Interview Reschedule",
                    "FAIL",
                    "Page shows error",
                    url,
                    "05_interview_reschedule.png"
                )
                return False
            elif has_date_field or has_time_field:
                details = f"Date field: {has_date_field}, Time field: {has_time_field}, Submit: {has_submit_button}"
                self.log_test_result(
                    "Interview Reschedule",
                    "PASS",
                    details,
                    url,
                    "05_interview_reschedule.png"
                )
                return True
            else:
                self.log_test_result(
                    "Interview Reschedule",
                    "FAIL",
                    "Reschedule form elements not found",
                    url,
                    "05_interview_reschedule.png"
                )
                return False

        except Exception as e:
            self.take_screenshot("error_reschedule", f"Error: {str(e)}")
            self.log_test_result("Interview Reschedule", "ERROR", str(e), url)
            return False

    def test_interview_cancel(self, interview_id: str) -> bool:
        """Test interview cancel functionality."""
        print(f"\n[TEST 5] Interview Cancel (ID: {interview_id[:8]}...)")
        print("=" * 60)

        try:
            # Navigate back to detail page first
            detail_url = f"{self.base_url}/app/ats/interviews/{interview_id}/"
            self.driver.get(detail_url)
            time.sleep(2)

            # Look for cancel button/link
            page_source = self.driver.page_source

            # Try to find cancel button
            cancel_found = False
            try:
                cancel_selectors = [
                    "a[href*='/cancel/']",
                    "button[data-action='cancel']",
                    "[hx-post*='/cancel/']",
                    "form[action*='/cancel/']"
                ]

                for selector in cancel_selectors:
                    try:
                        elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                        if elements:
                            cancel_found = True
                            print(f"  Found cancel control: {selector}")
                            break
                    except:
                        pass

            except Exception as e:
                print(f"  Could not locate cancel button: {e}")

            # Take screenshot
            self.take_screenshot("06_interview_cancel_page", "Cancel interface")

            # Try navigating to cancel URL directly
            cancel_url = f"{self.base_url}/app/ats/interviews/{interview_id}/cancel/"
            print(f"  Testing cancel URL: {cancel_url}")
            self.driver.get(cancel_url)
            time.sleep(2)

            self.take_screenshot("06b_interview_cancel_form", "Cancel form/confirmation")

            page_source = self.driver.page_source.lower()

            # Check for cancel-related content
            has_cancel_form = any(x in page_source for x in [
                "cancel", "reason", "confirm", "are you sure"
            ])

            # Check for errors
            error_indicators = ["500", "404", "method not allowed"]
            has_error = any(indicator in page_source for indicator in error_indicators)

            if has_error and "405" in page_source:
                # 405 Method Not Allowed means cancel is POST-only
                self.log_test_result(
                    "Interview Cancel",
                    "PASS",
                    "Cancel endpoint exists (POST-only, cannot GET directly)",
                    cancel_url,
                    "06b_interview_cancel_form.png"
                )
                return True
            elif has_error:
                self.log_test_result(
                    "Interview Cancel",
                    "FAIL",
                    "Cancel page shows error",
                    cancel_url,
                    "06b_interview_cancel_form.png"
                )
                return False
            elif has_cancel_form or cancel_found:
                self.log_test_result(
                    "Interview Cancel",
                    "PASS",
                    "Cancel functionality accessible",
                    cancel_url,
                    "06b_interview_cancel_form.png"
                )
                return True
            else:
                self.log_test_result(
                    "Interview Cancel",
                    "FAIL",
                    "Cancel functionality not found",
                    cancel_url,
                    "06b_interview_cancel_form.png"
                )
                return False

        except Exception as e:
            self.take_screenshot("error_cancel", f"Error: {str(e)}")
            self.log_test_result("Interview Cancel", "ERROR", str(e))
            return False

    def test_interview_feedback(self, interview_id: str) -> bool:
        """Test interview feedback form."""
        print(f"\n[TEST 6] Interview Feedback (ID: {interview_id[:8]}...)")
        print("=" * 60)

        try:
            # Try HTMX endpoint
            url = f"{self.base_url}/app/ats/htmx/interviews/{interview_id}/feedback/"
            print(f"  Navigating to: {url}")
            self.driver.get(url)
            time.sleep(2)

            # Take screenshot
            self.take_screenshot("07_interview_feedback", "Feedback form")

            # Check page content
            page_source = self.driver.page_source.lower()

            # Look for feedback form elements
            has_rating = any(x in page_source for x in ["rating", "score", "stars"])
            has_recommendation = "recommendation" in page_source
            has_feedback_fields = any(x in page_source for x in [
                "strengths", "weaknesses", "notes", "comments", "feedback"
            ])

            # Check for errors
            error_indicators = ["500", "404", "not found", "forbidden"]
            has_error = any(indicator in page_source for indicator in error_indicators)

            if has_error:
                self.log_test_result(
                    "Interview Feedback",
                    "FAIL",
                    "Feedback page shows error",
                    url,
                    "07_interview_feedback.png"
                )
                return False
            elif has_feedback_fields or has_rating:
                details = f"Rating: {has_rating}, Recommendation: {has_recommendation}, Fields: {has_feedback_fields}"
                self.log_test_result(
                    "Interview Feedback",
                    "PASS",
                    details,
                    url,
                    "07_interview_feedback.png"
                )
                return True
            else:
                self.log_test_result(
                    "Interview Feedback",
                    "FAIL",
                    "Feedback form elements not found",
                    url,
                    "07_interview_feedback.png"
                )
                return False

        except Exception as e:
            self.take_screenshot("error_feedback", f"Error: {str(e)}")
            self.log_test_result("Interview Feedback", "ERROR", str(e), url)
            return False

    def test_interview_schedule(self) -> bool:
        """Test interview scheduling form."""
        print(f"\n[TEST 7] Interview Schedule Form")
        print("=" * 60)

        try:
            # Navigate to schedule endpoint
            url = f"{self.base_url}/app/ats/htmx/interviews/schedule/"
            print(f"  Navigating to: {url}")
            self.driver.get(url)
            time.sleep(2)

            # Take screenshot
            self.take_screenshot("08_interview_schedule", "Schedule form")

            # Check page content
            page_source = self.driver.page_source.lower()

            # Look for schedule form elements
            has_form = "form" in page_source
            has_date_time = any(x in page_source for x in ["datetime", "scheduled", "date", "time"])
            has_interviewer = any(x in page_source for x in ["interviewer", "participants"])
            has_interview_type = any(x in page_source for x in ["interview type", "type", "phone", "video"])

            # Check for errors
            error_indicators = ["500", "404", "forbidden"]
            has_error = any(indicator in page_source for indicator in error_indicators)

            if has_error:
                self.log_test_result(
                    "Interview Schedule Form",
                    "FAIL",
                    "Schedule form shows error",
                    url,
                    "08_interview_schedule.png"
                )
                return False
            elif has_form or has_date_time:
                details = f"Form: {has_form}, DateTime: {has_date_time}, Interviewer: {has_interviewer}, Type: {has_interview_type}"
                self.log_test_result(
                    "Interview Schedule Form",
                    "PASS",
                    details,
                    url,
                    "08_interview_schedule.png"
                )
                return True
            else:
                self.log_test_result(
                    "Interview Schedule Form",
                    "FAIL",
                    "Schedule form elements not found",
                    url,
                    "08_interview_schedule.png"
                )
                return False

        except Exception as e:
            self.take_screenshot("error_schedule", f"Error: {str(e)}")
            self.log_test_result("Interview Schedule Form", "ERROR", str(e), url)
            return False

    def generate_report(self):
        """Generate and save test report."""
        print("\n" + "=" * 60)
        print("TEST REPORT GENERATION")
        print("=" * 60)

        # Calculate statistics
        total = len(self.test_results)
        passed = sum(1 for r in self.test_results if r["status"] == "PASS")
        failed = sum(1 for r in self.test_results if r["status"] == "FAIL")
        errors = sum(1 for r in self.test_results if r["status"] == "ERROR")
        skipped = sum(1 for r in self.test_results if r["status"] == "SKIP")

        # Generate markdown report
        report_path = self.screenshot_dir / f"TEST_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# ATS Interviews Module Test Report\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Base URL:** {self.base_url}\n\n")
            f.write(f"**Test User:** {self.email}\n\n")

            f.write("## Summary\n\n")
            f.write(f"- **Total Tests:** {total}\n")
            f.write(f"- **Passed:** {passed} ✅\n")
            f.write(f"- **Failed:** {failed} ❌\n")
            f.write(f"- **Errors:** {errors} ⚠️\n")
            f.write(f"- **Skipped:** {skipped} ⏭️\n")
            f.write(f"- **Success Rate:** {(passed/total*100) if total > 0 else 0:.1f}%\n\n")

            f.write("## Interview IDs Found\n\n")
            if self.interview_ids:
                for interview_id in self.interview_ids[:10]:
                    f.write(f"- `{interview_id}`\n")
            else:
                f.write("No interview IDs extracted from list page.\n")
            f.write("\n")

            f.write("## Detailed Results\n\n")
            for i, result in enumerate(self.test_results, 1):
                status_emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️", "SKIP": "⏭️"}.get(result["status"], "•")
                f.write(f"### {i}. {result['test']} {status_emoji}\n\n")
                f.write(f"- **Status:** {result['status']}\n")
                f.write(f"- **Time:** {result['timestamp']}\n")
                if result['url']:
                    f.write(f"- **URL:** `{result['url']}`\n")
                if result['details']:
                    f.write(f"- **Details:** {result['details']}\n")
                if result['screenshot']:
                    f.write(f"- **Screenshot:** `{result['screenshot']}`\n")
                f.write("\n")

            f.write("## Findings & Issues\n\n")
            f.write("### Errors Found\n\n")
            error_results = [r for r in self.test_results if r["status"] in ["FAIL", "ERROR"]]
            if error_results:
                for result in error_results:
                    f.write(f"- **{result['test']}:** {result['details']}\n")
            else:
                f.write("No errors found! All tests passed. ✅\n")
            f.write("\n")

            f.write("## Recommendations\n\n")
            f.write("1. Review all failed tests and screenshots\n")
            f.write("2. Check server logs for 500 errors\n")
            f.write("3. Verify interview data exists in database\n")
            f.write("4. Test HTMX endpoints with proper headers\n")
            f.write("5. Validate permission checks for all actions\n\n")

            f.write("---\n")
            f.write("*Generated by ATS Interview Module Tester*\n")

        print(f"\n📝 Report saved: {report_path}")

        # Save JSON report
        json_path = self.screenshot_dir / f"TEST_RESULTS_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                "summary": {
                    "total": total,
                    "passed": passed,
                    "failed": failed,
                    "errors": errors,
                    "skipped": skipped,
                    "success_rate": (passed/total*100) if total > 0 else 0
                },
                "interview_ids": self.interview_ids,
                "results": self.test_results
            }, f, indent=2)

        print(f"📊 JSON report saved: {json_path}")

        # Print summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️  Errors: {errors}")
        print(f"⏭️  Skipped: {skipped}")
        print(f"Success Rate: {(passed/total*100) if total > 0 else 0:.1f}%")
        print("=" * 60)

    def run_all_tests(self):
        """Run complete test suite."""
        print("\n" + "=" * 60)
        print("ATS INTERVIEWS MODULE - COMPREHENSIVE TEST SUITE")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print(f"User: {self.email}")
        print(f"Screenshots: {self.screenshot_dir}")
        print("=" * 60)

        try:
            # Setup
            if not self.setup_driver():
                print("\n❌ Failed to initialize WebDriver. Exiting.")
                return

            # Test 1: Login
            if not self.login():
                print("\n❌ Login failed. Cannot proceed with other tests.")
                return

            # Test 2: Interview List
            self.test_interview_list()

            # Test 3: Interview Details (test first 3 interviews found)
            if self.interview_ids:
                for i, interview_id in enumerate(self.interview_ids[:3], 1):
                    self.test_interview_detail(interview_id, i)

                # Test 4-6: Use first interview for detailed tests
                test_interview_id = self.interview_ids[0]
                self.test_interview_reschedule(test_interview_id)
                self.test_interview_cancel(test_interview_id)
                self.test_interview_feedback(test_interview_id)
            else:
                print("\n⚠️  No interview IDs found. Skipping detail tests.")
                self.log_test_result("Interview Details", "SKIP", "No interviews found in list")

            # Test 7: Schedule Form
            self.test_interview_schedule()

            # Generate report
            self.generate_report()

        except KeyboardInterrupt:
            print("\n\n⚠️  Test suite interrupted by user")
            self.generate_report()
        except Exception as e:
            print(f"\n\n❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Cleanup
            if self.driver:
                print("\n[CLEANUP] Closing browser...")
                self.driver.quit()
                print("[CLEANUP] Browser closed")


def main():
    """Main entry point."""
    tester = InterviewModuleTester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
