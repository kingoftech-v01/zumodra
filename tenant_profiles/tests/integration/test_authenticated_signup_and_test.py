#!/usr/bin/env python3
"""
Zumodra Website Testing with User Creation
===========================================

This script:
1. Creates a new test user via signup
2. Logs in with that user
3. Tests all authenticated pages
4. Captures screenshots and documents findings

Test URL: https://demo-company.zumodra.rhematek-solutions.com
"""

import os
import json
import time
from datetime import datetime
from playwright.sync_api import sync_playwright, Page, Browser

# Configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
RESULTS_DIR = "test_results"
SCREENSHOTS_DIR = os.path.join(RESULTS_DIR, "screenshots")
TEST_EMAIL = f"test.user.{int(time.time())}@zumodra-test.com"  # Unique email
TEST_PASSWORD = "TestPass@2024!"
TEST_FIRST_NAME = "Test"
TEST_LAST_NAME = "User"

# Ensure directories exist
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

def log(message):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def save_screenshot(page: Page, name: str):
    """Save screenshot with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{name}_{timestamp}.png"
    filepath = os.path.join(SCREENSHOTS_DIR, filename)
    page.screenshot(path=filepath, full_page=True, timeout=90000)  # Increased timeout to 90s
    log(f"Screenshot saved: {filepath}")
    return filepath

def create_test_user(page: Page):
    """
    Create a new test user via signup page
    Returns: (success: bool, message: str)
    """
    log("\n" + "="*50)
    log("STEP 1: Creating Test User")
    log("="*50)

    try:
        # Navigate to signup page
        signup_url = f"{BASE_URL}/en-us/accounts/signup/"
        log(f"Navigating to signup page: {signup_url}")
        page.goto(signup_url, wait_until="networkidle", timeout=60000)

        save_screenshot(page, "01_signup_page")

        # Fill signup form
        log(f"Filling signup form with email: {TEST_EMAIL}")

        # Try different possible field names for signup
        if page.locator('input[name="email"]').count() > 0:
            page.fill('input[name="email"]', TEST_EMAIL)
        elif page.locator('input[type="email"]').count() > 0:
            page.fill('input[type="email"]', TEST_EMAIL)

        if page.locator('input[name="first_name"]').count() > 0:
            page.fill('input[name="first_name"]', TEST_FIRST_NAME)

        if page.locator('input[name="last_name"]').count() > 0:
            page.fill('input[name="last_name"]', TEST_LAST_NAME)

        if page.locator('input[name="password1"]').count() > 0:
            page.fill('input[name="password1"]', TEST_PASSWORD)
        elif page.locator('input[name="password"]').count() > 0:
            page.fill('input[name="password"]', TEST_PASSWORD)

        if page.locator('input[name="password2"]').count() > 0:
            page.fill('input[name="password2"]', TEST_PASSWORD)

        save_screenshot(page, "02_signup_filled")

        # Submit form
        log("Submitting signup form...")
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle", timeout=30000)

        save_screenshot(page, "03_after_signup")

        current_url = page.url
        log(f"Current URL after signup: {current_url}")

        # Check if signup successful (redirected away from signup page)
        if "/signup/" not in current_url:
            log("[SUCCESS] Signup successful!")
            return True, "User created successfully"
        else:
            # Check for error messages
            error_selector = '.errorlist, .alert-danger, .error, [class*="error"]'
            if page.locator(error_selector).count() > 0:
                error_text = page.locator(error_selector).first.text_content()
                log(f"[ERROR] Signup failed with error: {error_text}")
                return False, f"Signup error: {error_text}"
            else:
                log("[ERROR] Signup failed - no redirect occurred")
                return False, "Signup failed - still on signup page"

    except Exception as e:
        log(f"[ERROR] Exception during signup: {str(e)}")
        save_screenshot(page, "ERROR_signup")
        return False, f"Exception: {str(e)}"

def login_user(page: Page):
    """
    Login with test user credentials
    Returns: (success: bool, message: str)
    """
    log("\n" + "="*50)
    log("STEP 2: Logging In")
    log("="*50)

    try:
        login_url = f"{BASE_URL}/en-us/accounts/login/"
        log(f"Navigating to login page: {login_url}")
        page.goto(login_url, wait_until="networkidle", timeout=60000)

        save_screenshot(page, "04_login_page")

        # Fill login form
        log(f"Filling login credentials for: {TEST_EMAIL}")
        page.fill('input[name="login"]', TEST_EMAIL)
        page.fill('input[name="password"]', TEST_PASSWORD)

        save_screenshot(page, "05_login_filled")

        # Submit
        log("Submitting login form...")
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle", timeout=30000)

        save_screenshot(page, "06_after_login")

        current_url = page.url
        log(f"Current URL after login: {current_url}")

        # Check if login successful
        if "/login/" not in current_url or "/dashboard/" in current_url or "/app/" in current_url:
            log("[OK] Login successful!")
            return True, "Login successful"
        else:
            log("[ERROR] Login failed - still on login page")
            return False, "Login failed"

    except Exception as e:
        log(f"[ERROR] Exception during login: {str(e)}")
        save_screenshot(page, "ERROR_login")
        return False, f"Exception: {str(e)}"

def test_authenticated_pages(page: Page):
    """
    Test all authenticated pages with screenshots
    Returns: list of test results
    """
    log("\n" + "="*50)
    log("STEP 3: Testing Authenticated Pages")
    log("="*50)

    # Pages to test
    pages_to_test = [
        ("Dashboard", "/app/dashboard/"),
        ("ATS - Jobs", "/app/ats/jobs/"),
        ("ATS - Candidates", "/app/ats/candidates/"),
        ("ATS - Pipeline", "/app/ats/pipeline/"),
        ("ATS - Interviews", "/app/ats/interviews/"),
        ("ATS - Applications", "/app/ats/applications/"),
        ("HR - Employees", "/app/hr/employees/"),
        ("HR - Time Off", "/app/hr/time-off/"),
        ("User Profile", "/app/accounts/profile/"),
        ("Services", "/services/"),
    ]

    results = []

    for idx, (page_name, page_url) in enumerate(pages_to_test, start=7):
        log(f"\n--- Testing: {page_name} ---")

        result = {
            "name": page_name,
            "url": page_url,
            "success": False,
            "status_code": None,
            "errors": [],
            "warnings": [],
            "screenshot": None
        }

        try:
            full_url = f"{BASE_URL}{page_url}"
            log(f"Navigating to: {full_url}")

            start_time = time.time()
            response = page.goto(full_url, wait_until="networkidle", timeout=60000)
            load_time = time.time() - start_time

            result["status_code"] = response.status if response else None
            log(f"Status Code: {result['status_code']}")
            log(f"Load Time: {load_time:.2f}s")

            # Save screenshot
            screenshot_name = f"{str(idx).zfill(2)}_{page_name.lower().replace(' ', '_').replace('-', '_')}"
            result["screenshot"] = save_screenshot(page, screenshot_name)

            # Check for errors
            if result["status_code"] == 500:
                result["errors"].append("HTTP 500 Internal Server Error")
                log("[ERROR] HTTP 500 Error!")
            elif result["status_code"] == 404:
                result["errors"].append("HTTP 404 Not Found")
                log("[ERROR] HTTP 404 Error!")
            elif result["status_code"] == 403:
                result["errors"].append("HTTP 403 Forbidden")
                log("[ERROR] HTTP 403 Error - Permission Denied!")
            elif result["status_code"] and result["status_code"] >= 400:
                result["errors"].append(f"HTTP {result['status_code']} Error")
                log(f"[ERROR] HTTP {result['status_code']} Error!")

            # Check for Django error pages
            if "Server Error" in page.content() or "Page not found" in page.content():
                result["errors"].append("Django error page detected")
                log("[ERROR] Django error page detected!")

            # Check if redirected to login (session expired)
            if "/login/" in page.url:
                result["errors"].append("Redirected to login - session expired")
                log("[ERROR] Redirected to login page - session may have expired")

            # If no errors, mark as success
            if not result["errors"]:
                result["success"] = True
                log(f"[OK] Page loaded successfully!")

        except Exception as e:
            result["errors"].append(f"Exception: {str(e)}")
            log(f"[ERROR] Exception: {str(e)}")
            save_screenshot(page, f"ERROR_{page_name.lower().replace(' ', '_')}")

        results.append(result)

    return results

def main():
    """Main test execution"""
    print("="*60)
    print("Zumodra Authenticated Website Testing")
    print("="*60)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Base URL: {BASE_URL}")
    print(f"Test Email: {TEST_EMAIL}")
    print(f"Results Directory: {RESULTS_DIR}")
    print("="*60)

    with sync_playwright() as p:
        log("\nLaunching browser...")
        browser: Browser = p.chromium.launch(headless=True)
        page: Page = browser.new_page()
        page.set_viewport_size({"width": 1920, "height": 1080})

        try:
            # Step 1: Create user
            signup_success, signup_msg = create_test_user(page)

            if not signup_success:
                log(f"\n[ERROR] Cannot proceed - signup failed: {signup_msg}")
                log("\nAttempting to login anyway (user might already exist)...")

            # Step 2: Login
            login_success, login_msg = login_user(page)

            if not login_success:
                log(f"\n[ERROR] Cannot proceed - login failed: {login_msg}")
                log("\n" + "="*60)
                log("Testing aborted - authentication required")
                log("="*60)
                return

            # Step 3: Test authenticated pages
            results = test_authenticated_pages(page)

            # Print summary
            log("\n" + "="*60)
            log("TEST SUMMARY")
            log("="*60)

            total = len(results)
            passed = sum(1 for r in results if r["success"])
            failed = total - passed

            log(f"Total Pages Tested: {total}")
            log(f"Passed: {passed}")
            log(f"Failed: {failed}")

            if failed > 0:
                log("\nFailed Pages:")
                for r in results:
                    if not r["success"]:
                        log(f"  - {r['name']}: {', '.join(r['errors'])}")

            # Save JSON report
            report_path = os.path.join(RESULTS_DIR, f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(report_path, "w") as f:
                json.dump({
                    "test_email": TEST_EMAIL,
                    "timestamp": datetime.now().isoformat(),
                    "total": total,
                    "passed": passed,
                    "failed": failed,
                    "results": results
                }, f, indent=2)
            log(f"\nJSON report saved: {report_path}")

        finally:
            browser.close()

    log("\n" + "="*60)
    log("Testing complete!")
    log("="*60)
    log(f"\nScreenshots: {SCREENSHOTS_DIR}")
    log("Review screenshots for detailed UI analysis")

if __name__ == "__main__":
    main()
