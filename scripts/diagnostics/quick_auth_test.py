"""
Quick Authentication Test Script for Zumodra
Tests basic connectivity and authentication endpoints
No login credentials required for initial connectivity test
"""

import requests
from datetime import datetime
import json
import sys

# Fix encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE_URL = "https://zumodra.rhematek-solutions.com"

def test_connection():
    """Test basic connectivity to the server."""
    print("\n" + "="*60)
    print("CONNECTIVITY TEST")
    print("="*60)

    try:
        response = requests.get(BASE_URL, timeout=10)
        print(f"✓ Server reachable: {BASE_URL}")
        print(f"  Status Code: {response.status_code}")
        print(f"  Response Time: {response.elapsed.total_seconds():.2f}s")

        if response.status_code == 200:
            print(f"  ✓ Server is UP")
            return True
        else:
            print(f"  ⚠ Unexpected status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"✗ Connection failed: {e}")
        return False


def test_login_page():
    """Test if login page is accessible."""
    print("\n" + "="*60)
    print("LOGIN PAGE TEST")
    print("="*60)

    login_url = f"{BASE_URL}/accounts/login/"

    try:
        response = requests.get(login_url, timeout=10)
        print(f"✓ Login page accessible: {login_url}")
        print(f"  Status Code: {response.status_code}")

        # Check for login form elements
        checks = {
            'login form': 'form' in response.text.lower() and ('login' in response.text.lower() or 'email' in response.text.lower()),
            'CSRF token': 'csrfmiddlewaretoken' in response.text,
            'password field': 'type="password"' in response.text or 'type=password' in response.text,
            'submit button': 'submit' in response.text.lower() or 'sign in' in response.text.lower(),
        }

        print("\n  Form Elements:")
        for check, present in checks.items():
            status = "✓" if present else "✗"
            print(f"    {status} {check}: {'Present' if present else 'Missing'}")

        # Check cookies
        print("\n  Cookies Received:")
        for cookie_name, cookie_value in response.cookies.items():
            print(f"    - {cookie_name}: {cookie_value[:30]}..." if len(cookie_value) > 30 else f"    - {cookie_name}: {cookie_value}")

        if 'csrftoken' in response.cookies:
            print("\n  ✓ CSRF protection active")

        return response.status_code == 200 and checks['CSRF token']

    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to access login page: {e}")
        return False


def test_logout_page():
    """Test if logout page is accessible."""
    print("\n" + "="*60)
    print("LOGOUT PAGE TEST")
    print("="*60)

    logout_url = f"{BASE_URL}/accounts/logout/"

    try:
        response = requests.get(logout_url, timeout=10, allow_redirects=False)
        print(f"✓ Logout endpoint accessible: {logout_url}")
        print(f"  Status Code: {response.status_code}")

        if response.status_code in [200, 302, 405]:  # 405 = Method Not Allowed (GET on POST-only endpoint)
            print(f"  ✓ Logout endpoint exists")
            if response.status_code == 302:
                print(f"  → Redirects to: {response.headers.get('Location', 'Unknown')}")
            return True
        else:
            print(f"  ⚠ Unexpected response")
            return False

    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to access logout endpoint: {e}")
        return False


def test_password_reset_page():
    """Test if password reset page is accessible."""
    print("\n" + "="*60)
    print("PASSWORD RESET PAGE TEST")
    print("="*60)

    reset_url = f"{BASE_URL}/accounts/password/reset/"

    try:
        response = requests.get(reset_url, timeout=10)
        print(f"✓ Password reset page accessible: {reset_url}")
        print(f"  Status Code: {response.status_code}")

        if response.status_code == 200:
            # Check for reset form elements
            has_email_field = 'email' in response.text.lower() and ('input' in response.text.lower() or 'form' in response.text.lower())
            has_csrf = 'csrfmiddlewaretoken' in response.text

            print(f"  {'✓' if has_email_field else '✗'} Email field present: {has_email_field}")
            print(f"  {'✓' if has_csrf else '✗'} CSRF token present: {has_csrf}")
            return has_email_field and has_csrf
        return False

    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to access password reset page: {e}")
        return False


def test_dashboard_protection():
    """Test if dashboard is properly protected (requires authentication)."""
    print("\n" + "="*60)
    print("DASHBOARD PROTECTION TEST")
    print("="*60)

    dashboard_url = f"{BASE_URL}/app/dashboard/"

    try:
        response = requests.get(dashboard_url, timeout=10, allow_redirects=False)
        print(f"✓ Dashboard endpoint tested: {dashboard_url}")
        print(f"  Status Code: {response.status_code}")

        if response.status_code in [302, 301, 303]:  # Redirect
            redirect_location = response.headers.get('Location', '')
            print(f"  ✓ Redirects to: {redirect_location}")

            if 'login' in redirect_location.lower():
                print(f"  ✓ Dashboard is protected (redirects to login)")
                return True
            else:
                print(f"  ⚠ Dashboard redirects but not to login page")
                return True
        elif response.status_code == 403:  # Forbidden
            print(f"  ✓ Dashboard is protected (403 Forbidden)")
            return True
        elif response.status_code == 200:
            # Check if it's actually showing login form
            if 'login' in response.text.lower() and 'password' in response.text.lower():
                print(f"  ✓ Dashboard shows login form")
                return True
            else:
                print(f"  ⚠ Dashboard accessible without auth (SECURITY ISSUE!)")
                return False
        else:
            print(f"  ⚠ Unexpected response: {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to test dashboard: {e}")
        return False


def test_api_endpoints():
    """Test API endpoints availability."""
    print("\n" + "="*60)
    print("API ENDPOINTS TEST")
    print("="*60)

    api_endpoints = [
        ("/api/", "API Root"),
        ("/api/v1/", "API v1"),
        ("/health/", "Health Check"),
        ("/api/schema/", "API Schema"),
    ]

    results = []
    for endpoint, name in api_endpoints:
        url = BASE_URL + endpoint
        try:
            response = requests.get(url, timeout=10)
            status = "✓" if response.status_code == 200 else "⚠"
            print(f"  {status} {name:20} ({endpoint:25}) → {response.status_code}")
            results.append(response.status_code == 200)
        except requests.exceptions.RequestException as e:
            print(f"  ✗ {name:20} ({endpoint:25}) → Error: {e}")
            results.append(False)

    return any(results)  # At least one API endpoint working


def test_security_headers():
    """Test security headers."""
    print("\n" + "="*60)
    print("SECURITY HEADERS TEST")
    print("="*60)

    try:
        response = requests.get(BASE_URL, timeout=10)
        headers = response.headers

        security_headers = {
            'Strict-Transport-Security': 'HSTS (Force HTTPS)',
            'X-Content-Type-Options': 'Prevent MIME sniffing',
            'X-Frame-Options': 'Clickjacking protection',
            'Content-Security-Policy': 'CSP (XSS protection)',
            'X-XSS-Protection': 'XSS filter',
        }

        print("  Security Headers:")
        for header, description in security_headers.items():
            if header in headers:
                value = headers[header]
                print(f"    ✓ {header}")
                print(f"      {description}")
                print(f"      Value: {value[:60]}..." if len(value) > 60 else f"      Value: {value}")
            else:
                print(f"    ⚠ {header} - Not present")
                print(f"      {description}")

        return 'Strict-Transport-Security' in headers  # At least HSTS should be present

    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to check security headers: {e}")
        return False


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("ZUMODRA AUTHENTICATION SYSTEM - QUICK TEST")
    print("="*60)
    print(f"Server: {BASE_URL}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Run tests
    results = {
        'Connection': test_connection(),
        'Login Page': test_login_page(),
        'Logout Page': test_logout_page(),
        'Password Reset': test_password_reset_page(),
        'Dashboard Protection': test_dashboard_protection(),
        'API Endpoints': test_api_endpoints(),
        'Security Headers': test_security_headers(),
    }

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    total = len(results)
    passed = sum(results.values())
    failed = total - passed

    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status:8} | {test_name}")

    print("\n" + "-"*60)
    print(f"  Total:  {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Rate:   {passed/total*100:.1f}%")
    print("="*60)

    # Save results
    report = {
        'timestamp': datetime.now().isoformat(),
        'server': BASE_URL,
        'results': {name: result for name, result in results.items()},
        'summary': {
            'total': total,
            'passed': passed,
            'failed': failed,
            'pass_rate': passed/total*100
        }
    }

    report_file = f"quick_auth_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved to: {report_file}")

    # Next steps
    print("\n" + "="*60)
    print("NEXT STEPS")
    print("="*60)
    print("\nTo test actual login functionality:")
    print("1. Get valid test credentials (email/password)")
    print("2. Edit test_login_session_management.py:")
    print("   - Update TEST_CONFIG['valid_email']")
    print("   - Update TEST_CONFIG['valid_password']")
    print("3. Run: python test_login_session_management.py")
    print("\nFor manual testing, see: AUTHENTICATION_TEST_GUIDE.md")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
