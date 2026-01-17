#!/usr/bin/env python3
"""
Investigation Script for Login/Signup Timeout Issues
=====================================================

This script investigates why login and signup pages are timing out
on https://zumodra.rhematek-solutions.com
"""

import sys
import requests
from datetime import datetime

# Set UTF-8 encoding for console output
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    print("ERROR: Playwright is not installed.")
    sys.exit(1)


BASE_URL = "https://zumodra.rhematek-solutions.com"

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(80)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}\n")


def print_success(text):
    print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")


def print_error(text):
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")


def print_info(text):
    print(f"{Colors.OKBLUE}ℹ {text}{Colors.ENDC}")


def test_with_requests():
    """Test URLs with requests library"""
    print_header("HTTP REQUESTS TEST")

    urls = [
        f"{BASE_URL}/accounts/login/",
        f"{BASE_URL}/accounts/signup/",
        f"{BASE_URL}/en/accounts/login/",
        f"{BASE_URL}/en/accounts/signup/",
    ]

    for url in urls:
        print_info(f"Testing: {url}")
        try:
            response = requests.get(url, timeout=30, allow_redirects=True)
            print_success(f"  Status: {response.status_code}")
            print_info(f"  Final URL: {response.url}")
            print_info(f"  Content Length: {len(response.content)} bytes")

            # Check for common auth page indicators
            content_lower = response.text.lower()
            if 'login' in content_lower or 'sign in' in content_lower:
                print_success("  Contains login-related content")
            if 'password' in content_lower:
                print_success("  Contains password field")
            if 'email' in content_lower:
                print_success("  Contains email field")

            print()
        except requests.Timeout:
            print_error(f"  Request timed out after 30 seconds")
        except Exception as e:
            print_error(f"  Error: {str(e)}")
        print()


def test_with_playwright_domcontentloaded():
    """Test with Playwright using domcontentloaded strategy"""
    print_header("PLAYWRIGHT TEST - DOM CONTENT LOADED")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={'width': 1920, 'height': 1080},
        )
        page = context.new_page()

        urls = [
            f"{BASE_URL}/accounts/login/",
            f"{BASE_URL}/accounts/signup/",
        ]

        for url in urls:
            print_info(f"Testing: {url}")
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=60000)
                print_success(f"  Status: {response.status if response else 'N/A'}")
                print_info(f"  Final URL: {page.url}")
                print_info(f"  Title: {page.title()}")

                # Check for form elements
                forms = page.locator('form').count()
                inputs = page.locator('input').count()
                buttons = page.locator('button').count()

                print_info(f"  Forms: {forms}, Inputs: {inputs}, Buttons: {buttons}")

                # Check for specific elements
                if page.locator('input[type="password"]').count() > 0:
                    print_success("  Password field found")
                if page.locator('input[type="email"], input[name="email"], input[name="login"]').count() > 0:
                    print_success("  Email field found")
                if page.locator('button[type="submit"]').count() > 0:
                    print_success("  Submit button found")

            except PlaywrightTimeoutError as e:
                print_error(f"  Timeout: {str(e)}")
            except Exception as e:
                print_error(f"  Error: {str(e)}")
            print()

        context.close()
        browser.close()


def test_with_playwright_load():
    """Test with Playwright using load strategy"""
    print_header("PLAYWRIGHT TEST - LOAD EVENT")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={'width': 1920, 'height': 1080},
        )
        page = context.new_page()

        # Enable console logging
        console_messages = []
        page.on("console", lambda msg: console_messages.append(f"{msg.type}: {msg.text}"))

        # Enable request logging
        network_errors = []
        page.on("requestfailed", lambda request: network_errors.append(
            f"{request.method} {request.url} - {request.failure}"
        ))

        urls = [
            f"{BASE_URL}/accounts/login/",
            f"{BASE_URL}/accounts/signup/",
        ]

        for url in urls:
            print_info(f"Testing: {url}")
            console_messages.clear()
            network_errors.clear()

            try:
                response = page.goto(url, wait_until="load", timeout=60000)
                print_success(f"  Status: {response.status if response else 'N/A'}")
                print_info(f"  Final URL: {page.url}")

                # Wait a bit for any dynamic content
                page.wait_for_timeout(2000)

                # Check console messages
                if console_messages:
                    print_info(f"  Console messages: {len(console_messages)}")
                    for msg in console_messages[:5]:  # Show first 5
                        print(f"    {msg}")

                # Check network errors
                if network_errors:
                    print_error(f"  Network errors: {len(network_errors)}")
                    for error in network_errors[:5]:  # Show first 5
                        print(f"    {error}")

            except PlaywrightTimeoutError as e:
                print_error(f"  Timeout: {str(e)}")

                # Try to get current state
                try:
                    print_info(f"  Current URL when timed out: {page.url}")
                    print_info(f"  Page title when timed out: {page.title()}")
                except:
                    pass

                if console_messages:
                    print_info(f"  Console messages before timeout:")
                    for msg in console_messages[:10]:
                        print(f"    {msg}")

                if network_errors:
                    print_error(f"  Network errors before timeout:")
                    for error in network_errors[:10]:
                        print(f"    {error}")

            except Exception as e:
                print_error(f"  Error: {str(e)}")
            print()

        context.close()
        browser.close()


def check_redirects():
    """Check if URLs redirect"""
    print_header("REDIRECT ANALYSIS")

    urls = [
        f"{BASE_URL}/accounts/login/",
        f"{BASE_URL}/accounts/signup/",
        f"{BASE_URL}/login/",
        f"{BASE_URL}/signup/",
    ]

    for url in urls:
        print_info(f"Checking: {url}")
        try:
            response = requests.get(url, timeout=30, allow_redirects=False)
            print_success(f"  Status: {response.status_code}")

            if response.status_code in [301, 302, 303, 307, 308]:
                print_info(f"  Redirects to: {response.headers.get('Location', 'N/A')}")
            else:
                print_info(f"  No redirect")

        except Exception as e:
            print_error(f"  Error: {str(e)}")
        print()


def main():
    print_header("INVESTIGATING LOGIN/SIGNUP TIMEOUT ISSUES")
    print(f"{Colors.BOLD}Base URL:{Colors.ENDC} {BASE_URL}")
    print(f"{Colors.BOLD}Timestamp:{Colors.ENDC} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Run all tests
    test_with_requests()
    check_redirects()
    test_with_playwright_domcontentloaded()
    test_with_playwright_load()

    print_header("INVESTIGATION COMPLETE")


if __name__ == "__main__":
    main()
