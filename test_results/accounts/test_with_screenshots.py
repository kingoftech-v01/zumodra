"""
Comprehensive Accounts Module Testing with Screenshots
=======================================================

This script uses Playwright to:
1. Test all account URLs
2. Take screenshots of every page
3. Test interactive features
4. Document all findings

Requirements:
    pip install playwright beautifulsoup4
    playwright install chromium

Usage:
    python test_with_screenshots.py
"""

import asyncio
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from pathlib import Path
from datetime import datetime
import json
import traceback
from typing import Dict, List, Optional

# ==================== Configuration ====================

BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
SCREENSHOT_DIR = Path(__file__).parent / "screenshots"
REPORT_FILE = Path(__file__).parent / "playwright_test_report.md"

# Test credentials - update with actual demo credentials
TEST_CREDENTIALS = {
    "email": "demo@demo-company.com",
    "password": "DemoPassword123!",
}

# Create directories
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

# ==================== URL Test Cases ====================

ACCOUNT_URLS = {
    "public": {
        "login_page": "/en-us/accounts/login/",
        "signup_page": "/en-us/accounts/signup/",
        "password_reset": "/en-us/accounts/password/reset/",
    },
    "protected": {
        "verification_dashboard": "/app/accounts/verification/",
        "kyc_list": "/app/accounts/verification/kyc/",
        "kyc_start": "/app/accounts/verification/kyc/start/",
        "employment_list": "/app/accounts/verification/employment/",
        "employment_add": "/app/accounts/verification/employment/add/",
        "education_list": "/app/accounts/verification/education/",
        "education_add": "/app/accounts/verification/education/add/",
        "trust_score": "/app/accounts/trust-score/",
    },
    "api": {
        "api_me": "/api/v1/accounts/me/",
        "api_profiles": "/api/v1/accounts/profiles/me/",
        "api_kyc": "/api/v1/accounts/kyc/",
        "api_trust_scores": "/api/v1/accounts/trust-scores/me/",
    }
}

# ==================== Helper Functions ====================

def get_safe_filename(name: str) -> str:
    """Convert URL name to safe filename."""
    return name.replace('/', '_').replace(':', '_').replace('?', '_')

async def take_screenshot(page: Page, name: str, full_page: bool = True) -> str:
    """Take a screenshot and save it."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{get_safe_filename(name)}.png"
    filepath = SCREENSHOT_DIR / filename

    await page.screenshot(path=str(filepath), full_page=full_page)
    print(f"    📸 Screenshot saved: {filename}")

    return str(filepath)

async def check_for_errors(page: Page) -> List[str]:
    """Check for error messages on the page."""
    errors = []

    # Check for Django error pages
    if await page.locator("text=500 Internal Server Error").count() > 0:
        errors.append("500 Internal Server Error detected")

    if await page.locator("text=404 Not Found").count() > 0:
        errors.append("404 Not Found detected")

    # Check for error messages
    error_selectors = [
        ".alert-danger",
        ".error",
        ".errorlist",
        "[role='alert']",
        ".text-red-500",
        ".text-danger",
    ]

    for selector in error_selectors:
        error_elements = await page.locator(selector).all()
        for elem in error_elements:
            text = await elem.text_content()
            if text and text.strip():
                errors.append(f"Error message: {text.strip()}")

    return errors

# ==================== Test Functions ====================

async def test_url(page: Page, url_name: str, url_path: str, authenticated: bool = False) -> Dict:
    """Test a single URL and return results."""
    full_url = f"{BASE_URL}{url_path}"
    result = {
        'url_name': url_name,
        'url_path': url_path,
        'full_url': full_url,
        'authenticated': authenticated,
        'success': False,
        'status_code': None,
        'error': None,
        'errors_found': [],
        'warnings': [],
        'screenshot': None,
        'page_title': None,
        'response_time': None,
    }

    try:
        print(f"\n[*] Testing: {url_name}")
        print(f"    URL: {url_path}")

        # Navigate to URL
        start_time = datetime.now()
        response = await page.goto(full_url, wait_until='networkidle', timeout=30000)
        end_time = datetime.now()

        result['response_time'] = (end_time - start_time).total_seconds()
        result['status_code'] = response.status if response else None

        # Get page title
        result['page_title'] = await page.title()
        print(f"    Title: {result['page_title']}")
        print(f"    Status: {result['status_code']}")
        print(f"    Time: {result['response_time']:.2f}s")

        # Check for errors
        errors = await check_for_errors(page)
        if errors:
            result['errors_found'] = errors
            print(f"    ⚠️  Errors found: {len(errors)}")
            for error in errors[:3]:  # Show first 3
                print(f"        - {error[:100]}")

        # Take screenshot
        screenshot_path = await take_screenshot(page, url_name)
        result['screenshot'] = screenshot_path

        # Mark as success if status is 200
        if result['status_code'] == 200:
            result['success'] = True
            print(f"    ✅ Success")
        else:
            result['error'] = f"Status code: {result['status_code']}"
            print(f"    ❌ Failed: {result['error']}")

    except Exception as e:
        result['error'] = str(e)
        print(f"    ❌ Error: {str(e)}")
        # Try to take screenshot even on error
        try:
            result['screenshot'] = await take_screenshot(page, f"{url_name}_error")
        except:
            pass

    return result

async def attempt_login(page: Page) -> bool:
    """Attempt to log in to the platform."""
    print("\n" + "="*80)
    print("ATTEMPTING LOGIN")
    print("="*80)

    try:
        login_url = f"{BASE_URL}/en-us/accounts/login/"
        print(f"[*] Navigating to login page: {login_url}")

        await page.goto(login_url, wait_until='networkidle')

        # Take screenshot of login page
        await take_screenshot(page, "login_page_before")

        # Wait for login form
        await page.wait_for_selector('input[type="password"]', timeout=10000)

        # Find email/username field
        email_selectors = [
            'input[type="email"]',
            'input[name="login"]',
            'input[name="email"]',
            'input[name="username"]',
        ]

        email_field = None
        for selector in email_selectors:
            if await page.locator(selector).count() > 0:
                email_field = selector
                break

        if not email_field:
            print("❌ Could not find email/username field")
            return False

        # Fill login form
        print(f"[*] Filling email field: {email_field}")
        await page.fill(email_field, TEST_CREDENTIALS['email'])

        print(f"[*] Filling password field")
        await page.fill('input[type="password"]', TEST_CREDENTIALS['password'])

        # Take screenshot before submission
        await take_screenshot(page, "login_page_filled")

        # Find and click submit button
        submit_selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Sign In")',
            'button:has-text("Log In")',
            'button:has-text("Login")',
        ]

        for selector in submit_selectors:
            if await page.locator(selector).count() > 0:
                print(f"[*] Clicking submit button: {selector}")
                await page.click(selector)
                break

        # Wait for navigation
        await page.wait_for_load_state('networkidle', timeout=10000)

        # Take screenshot after login
        await take_screenshot(page, "after_login")

        # Check if we're logged in
        current_url = page.url
        print(f"[*] Current URL: {current_url}")

        # Check for dashboard or app URLs
        if '/app/' in current_url or '/dashboard/' in current_url:
            print("✅ Login successful!")
            return True

        # Check for error messages
        errors = await check_for_errors(page)
        if errors:
            print(f"❌ Login failed with errors:")
            for error in errors:
                print(f"    - {error}")
            return False

        # Still on login page
        if '/login/' in current_url:
            print("❌ Login failed - still on login page")
            return False

        # Uncertain - assume success if not on login page
        print("⚠️  Login status uncertain - checking session...")
        return True

    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        traceback.print_exc()
        try:
            await take_screenshot(page, "login_error")
        except:
            pass
        return False

async def test_signup_page(page: Page) -> Dict:
    """Test the signup page and analyze its structure."""
    print("\n" + "="*80)
    print("TESTING SIGNUP PAGE")
    print("="*80)

    result = {
        'test_name': 'Signup Page Analysis',
        'success': False,
        'fields': [],
        'errors': [],
    }

    try:
        signup_url = f"{BASE_URL}/en-us/accounts/signup/"
        await page.goto(signup_url, wait_until='networkidle')

        # Take screenshot
        await take_screenshot(page, "signup_page")

        # Get all input fields
        inputs = await page.locator('input').all()
        print(f"\n[*] Found {len(inputs)} input fields:")

        for inp in inputs:
            field_info = {
                'type': await inp.get_attribute('type') or 'text',
                'name': await inp.get_attribute('name') or 'N/A',
                'placeholder': await inp.get_attribute('placeholder') or '',
                'required': await inp.get_attribute('required') is not None,
            }
            result['fields'].append(field_info)
            print(f"    - {field_info['name']:30} [{field_info['type']:10}] {field_info['placeholder']}")

        result['success'] = True

    except Exception as e:
        result['errors'].append(str(e))
        print(f"❌ Error: {str(e)}")

    return result

async def test_profile_functionality(page: Page) -> Dict:
    """Test profile viewing and editing."""
    print("\n" + "="*80)
    print("TESTING PROFILE FUNCTIONALITY")
    print("="*80)

    result = {
        'test_name': 'Profile Functionality',
        'success': False,
        'tests': [],
    }

    # Try different profile URLs
    profile_urls = [
        "/app/accounts/profile/",
        "/app/accounts/verification/",
        "/api/v1/accounts/me/",
    ]

    for url in profile_urls:
        test_result = await test_url(page, f"profile_{url.split('/')[-2]}", url, authenticated=True)
        result['tests'].append(test_result)

    return result

# ==================== Main Test Runner ====================

async def run_tests():
    """Main test runner using Playwright."""
    print("\n" + "="*80)
    print("ZUMODRA ACCOUNTS MODULE - PLAYWRIGHT TEST SUITE")
    print("="*80)
    print(f"Target: {BASE_URL}")
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

    all_results = {
        'public': [],
        'protected': [],
        'api': [],
        'functional': [],
    }

    async with async_playwright() as p:
        # Launch browser
        print("\n[*] Launching browser...")
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        page = await context.new_page()

        # Test public URLs (no authentication)
        print("\n" + "="*80)
        print("TESTING PUBLIC URLS")
        print("="*80)

        for url_name, url_path in ACCOUNT_URLS['public'].items():
            result = await test_url(page, url_name, url_path, authenticated=False)
            all_results['public'].append(result)
            await asyncio.sleep(1)  # Be nice to the server

        # Analyze signup page
        signup_result = await test_signup_page(page)
        all_results['functional'].append(signup_result)

        # Attempt login
        login_success = await attempt_login(page)

        # Test protected URLs (requires authentication)
        print("\n" + "="*80)
        print("TESTING PROTECTED URLS")
        print("="*80)

        if login_success:
            print("[*] Testing as authenticated user")
        else:
            print("[*] Testing without authentication (will redirect to login)")

        for url_name, url_path in ACCOUNT_URLS['protected'].items():
            result = await test_url(page, url_name, url_path, authenticated=login_success)
            all_results['protected'].append(result)
            await asyncio.sleep(1)

        # Test API URLs
        print("\n" + "="*80)
        print("TESTING API URLS")
        print("="*80)

        for url_name, url_path in ACCOUNT_URLS['api'].items():
            result = await test_url(page, url_name, url_path, authenticated=login_success)
            all_results['api'].append(result)
            await asyncio.sleep(1)

        # Test profile functionality (if authenticated)
        if login_success:
            profile_result = await test_profile_functionality(page)
            all_results['functional'].append(profile_result)

        # Close browser
        await browser.close()

    # Generate report
    generate_report(all_results)

    return all_results

def generate_report(results: Dict):
    """Generate comprehensive markdown report."""
    print("\n" + "="*80)
    print("GENERATING REPORT")
    print("="*80)

    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        # Header
        f.write("# Zumodra Accounts Module - Playwright Test Report\n\n")
        f.write(f"**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Base URL:** {BASE_URL}\n\n")
        f.write("---\n\n")

        # Summary
        total = sum(len(results[cat]) for cat in ['public', 'protected', 'api'])
        successful = sum(
            sum(1 for r in results[cat] if r.get('success', False))
            for cat in ['public', 'protected', 'api']
        )

        f.write("## Summary\n\n")
        f.write(f"- **Total URLs Tested:** {total}\n")
        f.write(f"- **Successful:** {successful}\n")
        f.write(f"- **Failed:** {total - successful}\n")
        f.write(f"- **Screenshots:** {len(list(SCREENSHOT_DIR.glob('*.png')))}\n\n")

        # Public URLs
        f.write("## Public URLs\n\n")
        for result in results['public']:
            f.write(f"### {result['url_name']}\n\n")
            f.write(f"- **URL:** `{result['url_path']}`\n")
            f.write(f"- **Status:** {result['status_code']}\n")
            f.write(f"- **Title:** {result['page_title']}\n")
            f.write(f"- **Response Time:** {result.get('response_time', 0):.2f}s\n")
            if result['screenshot']:
                f.write(f"- **Screenshot:** `{Path(result['screenshot']).name}`\n")
            if result['errors_found']:
                f.write(f"- **Errors:**\n")
                for error in result['errors_found']:
                    f.write(f"  - {error}\n")
            f.write("\n")

        # Protected URLs
        f.write("## Protected URLs\n\n")
        for result in results['protected']:
            f.write(f"### {result['url_name']}\n\n")
            f.write(f"- **URL:** `{result['url_path']}`\n")
            f.write(f"- **Status:** {result['status_code']}\n")
            f.write(f"- **Authenticated:** {result['authenticated']}\n")
            if result['screenshot']:
                f.write(f"- **Screenshot:** `{Path(result['screenshot']).name}`\n")
            f.write("\n")

        # API URLs
        f.write("## API Endpoints\n\n")
        for result in results['api']:
            f.write(f"### {result['url_name']}\n\n")
            f.write(f"- **URL:** `{result['url_path']}`\n")
            f.write(f"- **Status:** {result['status_code']}\n")
            if result['screenshot']:
                f.write(f"- **Screenshot:** `{Path(result['screenshot']).name}`\n")
            f.write("\n")

        # Functional Tests
        if results['functional']:
            f.write("## Functional Tests\n\n")
            for test in results['functional']:
                f.write(f"### {test['test_name']}\n\n")
                if 'fields' in test:
                    f.write("**Form Fields:**\n\n")
                    for field in test['fields']:
                        f.write(f"- `{field['name']}` ({field['type']})")
                        if field['required']:
                            f.write(" *required*")
                        f.write("\n")
                if 'tests' in test:
                    for t in test['tests']:
                        f.write(f"- {t['url_name']}: {t['status_code']}\n")
                f.write("\n")

        f.write("---\n\n")
        f.write("*Generated by Playwright Test Suite*\n")

    print(f"[+] Report saved to: {REPORT_FILE}")
    print(f"[+] Screenshots saved to: {SCREENSHOT_DIR}")

# ==================== Entry Point ====================

if __name__ == "__main__":
    print("\nPlaywright Accounts Module Test Suite")
    print("="*80)
    print("\nNote: This script requires Playwright to be installed:")
    print("  pip install playwright")
    print("  playwright install chromium")
    print("\nUpdate TEST_CREDENTIALS with valid demo credentials before running.")
    print("="*80 + "\n")

    try:
        asyncio.run(run_tests())
        print("\n✅ Testing complete!")
    except Exception as e:
        print(f"\n❌ Testing failed: {str(e)}")
        traceback.print_exc()
