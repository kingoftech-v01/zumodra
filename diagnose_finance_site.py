#!/usr/bin/env python3
"""
Quick diagnostic script to check the finance module site status
"""

import sys
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("ERROR: Playwright not installed")
    sys.exit(1)

BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
RESULTS_DIR = Path("./test_results/finance")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def diagnose():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page(viewport={'width': 1920, 'height': 1080})

        print("="*80)
        print("SITE DIAGNOSTIC")
        print("="*80)

        # Test 1: Check if site is accessible
        print("\n[1] Checking site accessibility...")
        try:
            response = page.goto(BASE_URL, wait_until='networkidle', timeout=30000)
            print(f"  ✓ Status: {response.status}")
            print(f"  ✓ URL: {page.url}")

            # Screenshot
            page.screenshot(path=str(RESULTS_DIR / "01_homepage.png"), full_page=True)
            print(f"  ✓ Screenshot saved")

            # Get page title and content snippet
            title = page.title()
            print(f"  ✓ Page title: {title}")

            # Check for error messages
            if '502' in page.content() or 'Bad Gateway' in page.content():
                print("  ✗ 502 Bad Gateway detected")
                return False
            elif '500' in page.content() or 'Server Error' in page.content():
                print("  ✗ 500 Server Error detected")
                return False

        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False

        # Test 2: Check login page
        print("\n[2] Checking login page...")
        try:
            login_url = f"{BASE_URL}/accounts/login/"
            response = page.goto(login_url, wait_until='networkidle', timeout=30000)
            print(f"  ✓ Status: {response.status}")
            print(f"  ✓ URL: {page.url}")

            # Screenshot
            page.screenshot(path=str(RESULTS_DIR / "02_login_page.png"), full_page=True)
            print(f"  ✓ Screenshot saved")

            # Find form fields
            print("\n  Looking for form fields...")

            # Get all input fields
            inputs = page.query_selector_all('input')
            print(f"  Found {len(inputs)} input fields:")
            for inp in inputs:
                name = inp.get_attribute('name') or 'no-name'
                type_attr = inp.get_attribute('type') or 'text'
                id_attr = inp.get_attribute('id') or 'no-id'
                placeholder = inp.get_attribute('placeholder') or ''
                print(f"    - {name} (type={type_attr}, id={id_attr}, placeholder={placeholder})")

            # Get all buttons
            buttons = page.query_selector_all('button')
            print(f"\n  Found {len(buttons)} buttons:")
            for btn in buttons:
                text = btn.text_content()
                type_attr = btn.get_attribute('type') or 'button'
                print(f"    - '{text}' (type={type_attr})")

        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False

        # Test 3: Try direct finance URL (might redirect to login)
        print("\n[3] Checking finance URL (unauthenticated)...")
        try:
            finance_url = f"{BASE_URL}/app/finance/"
            response = page.goto(finance_url, wait_until='networkidle', timeout=30000)
            print(f"  ✓ Status: {response.status}")
            print(f"  ✓ URL: {page.url}")

            # Screenshot
            page.screenshot(path=str(RESULTS_DIR / "03_finance_redirect.png"), full_page=True)
            print(f"  ✓ Screenshot saved")

            # Check if redirected to login
            if 'login' in page.url.lower():
                print("  ✓ Correctly redirects to login (authentication required)")
            else:
                print("  ⚠ Unexpected: did not redirect to login")

        except Exception as e:
            print(f"  ✗ Error: {e}")

        print("\n" + "="*80)
        print("DIAGNOSTIC COMPLETE")
        print("="*80)
        print(f"Screenshots saved to: {RESULTS_DIR}")
        print("\nReview the screenshots to see what's happening.")

        browser.close()

if __name__ == '__main__':
    diagnose()
