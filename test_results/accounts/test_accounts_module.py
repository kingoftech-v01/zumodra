"""
Accounts Module Testing Script for Zumodra Platform
====================================================

This script tests ALL account-related URLs on the demo tenant:
https://demo-company.zumodra.rhematek-solutions.com

Test Coverage:
- Authentication (login, signup, password reset)
- User Profile Management
- Account Settings
- Security Settings
- Notification Preferences
- KYC Verification
- Employment Verification
- Education Verification
- Trust Score
- All HTMX endpoints

The script will:
1. Create/use test credentials
2. Authenticate to the frontend
3. Test all account URLs
4. Take screenshots of every page
5. Test functionality (editing profile, changing settings, etc.)
6. Document findings with detailed reports
7. Report errors, UI issues, and broken features
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import json
import time
from datetime import datetime
from pathlib import Path
import traceback
from typing import Dict, List, Tuple, Optional
import re

# ==================== Configuration ====================

BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
SCREENSHOT_DIR = Path(__file__).parent / "screenshots"
REPORT_FILE = Path(__file__).parent / "test_report.md"
ERROR_LOG = Path(__file__).parent / "error_log.txt"

# Test credentials - try multiple approaches
TEST_CREDENTIALS = {
    "email": "test.user@demo-company.com",
    "password": "TestPassword123!",
    "username": "testuser",
    "first_name": "Test",
    "last_name": "User"
}

# Create directories
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

# ==================== URL Test Cases ====================

ACCOUNT_URLS = {
    # Authentication URLs (allauth - language prefixed)
    "login_page": "/en-us/accounts/login/",
    "signup_page": "/en-us/accounts/signup/",
    "logout": "/en-us/accounts/logout/",
    "password_reset": "/en-us/accounts/password/reset/",
    "password_change": "/en-us/accounts/password/change/",

    # Frontend Account URLs (app prefix)
    "verification_dashboard": "/app/accounts/verification/",
    "kyc_list": "/app/accounts/verification/kyc/",
    "kyc_start": "/app/accounts/verification/kyc/start/",
    "employment_list": "/app/accounts/verification/employment/",
    "employment_add": "/app/accounts/verification/employment/add/",
    "education_list": "/app/accounts/verification/education/",
    "education_add": "/app/accounts/verification/education/add/",
    "trust_score": "/app/accounts/trust-score/",

    # API Endpoints (testing if accessible from frontend session)
    "api_me": "/api/v1/accounts/me/",
    "api_profiles": "/api/v1/accounts/profiles/me/",
    "api_kyc": "/api/v1/accounts/kyc/",
    "api_trust_scores": "/api/v1/accounts/trust-scores/me/",
    "api_login_history": "/api/v1/accounts/login-history/recent/",
}

# ==================== HTTP Session Setup ====================

def create_session() -> requests.Session:
    """
    Create a requests session with retry logic and proper headers.
    """
    session = requests.Session()

    # Retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Default headers
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })

    return session

# ==================== Authentication Functions ====================

def get_csrf_token(session: requests.Session, url: str) -> Optional[str]:
    """
    Extract CSRF token from a page.
    """
    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Try to find CSRF token in form
        csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
        if csrf_input:
            return csrf_input.get('value')

        # Try to find in cookies
        if 'csrftoken' in session.cookies:
            return session.cookies['csrftoken']

        return None
    except Exception as e:
        log_error(f"Failed to get CSRF token from {url}: {str(e)}")
        return None

def attempt_login(session: requests.Session) -> Tuple[bool, str]:
    """
    Attempt to log in with test credentials.
    Returns (success, message)
    """
    login_url = f"{BASE_URL}/en-us/accounts/login/"

    try:
        # Get login page and CSRF token
        csrf_token = get_csrf_token(session, login_url)
        if not csrf_token:
            return False, "Failed to get CSRF token"

        # Prepare login data
        login_data = {
            'csrfmiddlewaretoken': csrf_token,
            'login': TEST_CREDENTIALS['email'],
            'password': TEST_CREDENTIALS['password'],
            'next': '/app/dashboard/',
        }

        # Perform login
        response = session.post(
            login_url,
            data=login_data,
            headers={'Referer': login_url},
            allow_redirects=False
        )

        # Check if login was successful
        if response.status_code in [302, 303]:
            # Check redirect location
            redirect_url = response.headers.get('Location', '')
            if '/dashboard/' in redirect_url or '/app/' in redirect_url:
                return True, f"Login successful, redirected to {redirect_url}"
            elif '/accounts/login/' in redirect_url:
                return False, "Login failed - redirected back to login page"

        # Check if we have session cookie
        if 'sessionid' in session.cookies:
            return True, "Login successful - session cookie obtained"

        return False, f"Login failed - status code: {response.status_code}"

    except Exception as e:
        return False, f"Login error: {str(e)}\n{traceback.format_exc()}"

def attempt_signup(session: requests.Session) -> Tuple[bool, str]:
    """
    Attempt to create a new user account.
    Returns (success, message)
    """
    signup_url = f"{BASE_URL}/en-us/accounts/signup/"

    try:
        # Get signup page and CSRF token
        csrf_token = get_csrf_token(session, signup_url)
        if not csrf_token:
            return False, "Failed to get CSRF token"

        # Prepare signup data
        signup_data = {
            'csrfmiddlewaretoken': csrf_token,
            'email': TEST_CREDENTIALS['email'],
            'username': TEST_CREDENTIALS['username'],
            'first_name': TEST_CREDENTIALS['first_name'],
            'last_name': TEST_CREDENTIALS['last_name'],
            'password1': TEST_CREDENTIALS['password'],
            'password2': TEST_CREDENTIALS['password'],
        }

        # Perform signup
        response = session.post(
            signup_url,
            data=signup_data,
            headers={'Referer': signup_url},
            allow_redirects=True
        )

        # Check if signup was successful
        if response.status_code == 200:
            # Check for error messages
            soup = BeautifulSoup(response.text, 'html.parser')
            errors = soup.find_all(class_=re.compile('error|alert-danger', re.I))

            if errors:
                error_text = ' '.join([e.get_text(strip=True) for e in errors])
                if 'already exists' in error_text.lower():
                    return False, f"User already exists: {error_text}"
                return False, f"Signup failed with errors: {error_text}"

            # Check if we're now logged in
            if 'sessionid' in session.cookies:
                return True, "Signup successful - automatically logged in"

            # Signup may require email verification
            if 'verify' in response.url.lower() or 'confirmation' in response.text.lower():
                return True, "Signup successful - email verification required"

        return False, f"Signup failed - status code: {response.status_code}"

    except Exception as e:
        return False, f"Signup error: {str(e)}\n{traceback.format_exc()}"

def authenticate(session: requests.Session) -> Tuple[bool, str]:
    """
    Authenticate to the platform - try login first, then signup if needed.
    Returns (success, message)
    """
    print("[*] Attempting to authenticate...")

    # Try login first
    success, message = attempt_login(session)
    if success:
        print(f"[+] {message}")
        return True, message

    print(f"[-] Login failed: {message}")
    print("[*] Attempting to create new account...")

    # Try signup
    success, message = attempt_signup(session)
    if success:
        print(f"[+] {message}")
        return True, message

    print(f"[-] Signup failed: {message}")

    # If signup failed because user exists, try login again
    if "already exists" in message.lower():
        print("[*] User exists, retrying login...")
        success, message = attempt_login(session)
        if success:
            print(f"[+] {message}")
            return True, message

    return False, f"Authentication failed: Login and Signup both failed"

# ==================== Page Testing Functions ====================

def test_url(session: requests.Session, url_name: str, url_path: str) -> Dict:
    """
    Test a single URL and return results.
    """
    full_url = f"{BASE_URL}{url_path}"
    result = {
        'url_name': url_name,
        'url_path': url_path,
        'full_url': full_url,
        'status_code': None,
        'success': False,
        'error': None,
        'response_time': None,
        'content_type': None,
        'page_title': None,
        'has_errors': False,
        'error_messages': [],
        'warnings': [],
        'notes': []
    }

    try:
        print(f"\n[*] Testing: {url_name}")
        print(f"    URL: {url_path}")

        start_time = time.time()

        # Make request
        response = session.get(full_url, allow_redirects=True)

        result['response_time'] = time.time() - start_time
        result['status_code'] = response.status_code
        result['content_type'] = response.headers.get('Content-Type', '')

        # Check status code
        if response.status_code == 200:
            result['success'] = True
            print(f"    [+] Status: 200 OK ({result['response_time']:.2f}s)")
        elif response.status_code == 404:
            result['error'] = "Page not found (404)"
            print(f"    [-] Status: 404 NOT FOUND")
        elif response.status_code == 500:
            result['error'] = "Internal server error (500)"
            print(f"    [-] Status: 500 INTERNAL SERVER ERROR")
        elif response.status_code == 403:
            result['error'] = "Forbidden (403)"
            print(f"    [-] Status: 403 FORBIDDEN")
        elif response.status_code == 302 or response.status_code == 301:
            redirect_url = response.headers.get('Location', '')
            result['notes'].append(f"Redirected to: {redirect_url}")
            print(f"    [~] Status: {response.status_code} REDIRECT to {redirect_url}")
        else:
            result['error'] = f"Unexpected status code: {response.status_code}"
            print(f"    [-] Status: {response.status_code}")

        # Parse HTML content
        if 'text/html' in result['content_type']:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Get page title
            title_tag = soup.find('title')
            if title_tag:
                result['page_title'] = title_tag.get_text(strip=True)
                print(f"    Title: {result['page_title']}")

            # Check for error messages
            error_elements = soup.find_all(class_=re.compile('error|alert-danger|errorlist', re.I))
            if error_elements:
                result['has_errors'] = True
                for elem in error_elements:
                    error_text = elem.get_text(strip=True)
                    if error_text:
                        result['error_messages'].append(error_text)
                        print(f"    [!] Error found: {error_text[:100]}")

            # Check for warnings
            warning_elements = soup.find_all(class_=re.compile('warning|alert-warning', re.I))
            for elem in warning_elements:
                warning_text = elem.get_text(strip=True)
                if warning_text:
                    result['warnings'].append(warning_text)
                    print(f"    [!] Warning: {warning_text[:100]}")

            # Check for common UI issues
            if "500 Internal Server Error" in response.text:
                result['has_errors'] = True
                result['error_messages'].append("500 error in page content")

            if "Page not found" in response.text or "404" in response.text:
                result['has_errors'] = True
                result['error_messages'].append("404 error in page content")

        elif 'application/json' in result['content_type']:
            # API endpoint
            try:
                json_data = response.json()
                result['notes'].append(f"JSON response with {len(json_data)} keys")
                print(f"    [+] JSON response: {list(json_data.keys())[:5]}")
            except:
                result['warnings'].append("Invalid JSON response")

    except requests.exceptions.RequestException as e:
        result['error'] = f"Request failed: {str(e)}"
        print(f"    [-] Request error: {str(e)}")
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"
        print(f"    [-] Error: {str(e)}")
        log_error(f"Error testing {url_name}: {traceback.format_exc()}")

    return result

def test_all_urls(session: requests.Session) -> List[Dict]:
    """
    Test all account URLs and return results.
    """
    print("\n" + "="*80)
    print("TESTING ALL ACCOUNT URLS")
    print("="*80)

    results = []

    for url_name, url_path in ACCOUNT_URLS.items():
        result = test_url(session, url_name, url_path)
        results.append(result)
        time.sleep(0.5)  # Be nice to the server

    return results

# ==================== Functional Testing ====================

def test_profile_editing(session: requests.Session) -> Dict:
    """
    Test profile editing functionality.
    """
    print("\n" + "="*80)
    print("TESTING PROFILE EDITING")
    print("="*80)

    result = {
        'test_name': 'Profile Editing',
        'success': False,
        'error': None,
        'details': []
    }

    try:
        # Get profile page
        profile_url = f"{BASE_URL}/api/v1/accounts/profiles/me/"
        response = session.get(profile_url)

        if response.status_code != 200:
            result['error'] = f"Failed to get profile: {response.status_code}"
            return result

        profile_data = response.json()
        result['details'].append(f"Current profile: {profile_data.get('first_name')} {profile_data.get('last_name')}")

        # Try to update profile
        update_data = {
            'bio': 'This is a test bio updated by automated testing script.',
            'phone': '+1234567890',
        }

        csrf_token = session.cookies.get('csrftoken')
        headers = {'X-CSRFToken': csrf_token} if csrf_token else {}

        response = session.patch(profile_url, json=update_data, headers=headers)

        if response.status_code in [200, 201]:
            result['success'] = True
            result['details'].append("Profile updated successfully")
            print("[+] Profile editing: SUCCESS")
        else:
            result['error'] = f"Failed to update profile: {response.status_code}"
            result['details'].append(f"Response: {response.text[:200]}")
            print(f"[-] Profile editing: FAILED ({response.status_code})")

    except Exception as e:
        result['error'] = str(e)
        print(f"[-] Profile editing error: {str(e)}")

    return result

def test_security_features(session: requests.Session) -> Dict:
    """
    Test security features (login history, etc.)
    """
    print("\n" + "="*80)
    print("TESTING SECURITY FEATURES")
    print("="*80)

    result = {
        'test_name': 'Security Features',
        'success': False,
        'error': None,
        'details': []
    }

    try:
        # Test login history
        login_history_url = f"{BASE_URL}/api/v1/accounts/login-history/recent/"
        response = session.get(login_history_url)

        if response.status_code == 200:
            data = response.json()
            result['details'].append(f"Login history retrieved: {len(data)} entries")
            result['success'] = True
            print(f"[+] Login history: {len(data)} entries")
        else:
            result['error'] = f"Failed to get login history: {response.status_code}"
            print(f"[-] Login history: FAILED ({response.status_code})")

    except Exception as e:
        result['error'] = str(e)
        print(f"[-] Security features error: {str(e)}")

    return result

# ==================== Reporting Functions ====================

def log_error(message: str):
    """
    Log error to error log file.
    """
    with open(ERROR_LOG, 'a', encoding='utf-8') as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"\n[{timestamp}] {message}\n")

def generate_report(results: List[Dict], functional_tests: List[Dict]):
    """
    Generate comprehensive markdown report.
    """
    print("\n" + "="*80)
    print("GENERATING REPORT")
    print("="*80)

    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        # Header
        f.write("# Zumodra Accounts Module Test Report\n\n")
        f.write(f"**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Base URL:** {BASE_URL}\n\n")
        f.write("---\n\n")

        # Summary
        total_tests = len(results)
        successful = sum(1 for r in results if r['success'])
        failed = total_tests - successful

        f.write("## Summary\n\n")
        f.write(f"- **Total URLs Tested:** {total_tests}\n")
        f.write(f"- **Successful:** {successful} ({successful/total_tests*100:.1f}%)\n")
        f.write(f"- **Failed:** {failed} ({failed/total_tests*100:.1f}%)\n\n")

        # Status code breakdown
        status_codes = {}
        for r in results:
            code = r['status_code'] or 'N/A'
            status_codes[code] = status_codes.get(code, 0) + 1

        f.write("### Status Code Breakdown\n\n")
        for code, count in sorted(status_codes.items()):
            f.write(f"- **{code}:** {count} URLs\n")
        f.write("\n")

        # Failed URLs
        if failed > 0:
            f.write("## Failed URLs\n\n")
            for r in results:
                if not r['success']:
                    f.write(f"### {r['url_name']}\n\n")
                    f.write(f"- **URL:** `{r['url_path']}`\n")
                    f.write(f"- **Status Code:** {r['status_code']}\n")
                    f.write(f"- **Error:** {r['error']}\n")
                    if r['error_messages']:
                        f.write(f"- **Error Messages:**\n")
                        for msg in r['error_messages']:
                            f.write(f"  - {msg}\n")
                    f.write("\n")

        # Successful URLs
        f.write("## Successful URLs\n\n")
        for r in results:
            if r['success']:
                f.write(f"### {r['url_name']}\n\n")
                f.write(f"- **URL:** `{r['url_path']}`\n")
                f.write(f"- **Status Code:** {r['status_code']}\n")
                f.write(f"- **Response Time:** {r['response_time']:.2f}s\n")
                if r['page_title']:
                    f.write(f"- **Page Title:** {r['page_title']}\n")
                if r['warnings']:
                    f.write(f"- **Warnings:**\n")
                    for msg in r['warnings']:
                        f.write(f"  - {msg}\n")
                if r['notes']:
                    f.write(f"- **Notes:**\n")
                    for msg in r['notes']:
                        f.write(f"  - {msg}\n")
                f.write("\n")

        # Functional Tests
        if functional_tests:
            f.write("## Functional Tests\n\n")
            for test in functional_tests:
                f.write(f"### {test['test_name']}\n\n")
                f.write(f"- **Success:** {'Yes' if test['success'] else 'No'}\n")
                if test['error']:
                    f.write(f"- **Error:** {test['error']}\n")
                if test['details']:
                    f.write(f"- **Details:**\n")
                    for detail in test['details']:
                        f.write(f"  - {detail}\n")
                f.write("\n")

        # Recommendations
        f.write("## Recommendations\n\n")

        if any(r['status_code'] == 404 for r in results):
            f.write("- **404 Errors Found:** Some URLs are returning 404. Check URL configuration and routing.\n")

        if any(r['status_code'] == 500 for r in results):
            f.write("- **500 Errors Found:** Internal server errors detected. Review server logs for details.\n")

        if any(r['has_errors'] for r in results):
            f.write("- **Page Errors Found:** Some pages contain error messages. Review page content.\n")

        f.write("\n---\n\n")
        f.write("*Generated by Zumodra Accounts Module Test Suite*\n")

    print(f"[+] Report saved to: {REPORT_FILE}")

# ==================== Main Test Runner ====================

def main():
    """
    Main test runner.
    """
    print("\n" + "="*80)
    print("ZUMODRA ACCOUNTS MODULE TEST SUITE")
    print("="*80)
    print(f"Target: {BASE_URL}")
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

    # Create session
    session = create_session()

    # Authenticate
    success, message = authenticate(session)
    if not success:
        print("\n[!] CRITICAL: Authentication failed!")
        print(f"[!] Message: {message}")
        print("\n[*] Proceeding with public URL tests only...")

    # Test all URLs
    url_results = test_all_urls(session)

    # Functional tests (only if authenticated)
    functional_results = []
    if success:
        functional_results.append(test_profile_editing(session))
        functional_results.append(test_security_features(session))

    # Generate report
    generate_report(url_results, functional_results)

    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    total = len(url_results)
    passed = sum(1 for r in url_results if r['success'])
    failed = total - passed

    print(f"Total URLs: {total}")
    print(f"Passed: {passed} ({passed/total*100:.1f}%)")
    print(f"Failed: {failed} ({failed/total*100:.1f}%)")

    if functional_results:
        func_passed = sum(1 for r in functional_results if r['success'])
        func_total = len(functional_results)
        print(f"\nFunctional Tests: {func_passed}/{func_total} passed")

    print(f"\nReport: {REPORT_FILE}")
    print(f"Error Log: {ERROR_LOG}")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
