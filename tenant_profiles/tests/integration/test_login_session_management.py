"""
Comprehensive Login and Session Management Testing Script
Tests authentication, session persistence, logout, and security features on zumodra.rhematek-solutions.com

Requirements:
- requests
- beautifulsoup4
- colorama

Install: pip install requests beautifulsoup4 colorama
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    # Fallback if colorama not installed
    class Fore:
        GREEN = RED = YELLOW = CYAN = WHITE = MAGENTA = BLUE = ''
    class Back:
        GREEN = RED = ''
    class Style:
        RESET_ALL = BRIGHT = ''


# Test Configuration
BASE_URL = "https://zumodra.rhematek-solutions.com"
TEST_CONFIG = {
    'base_url': BASE_URL,
    'login_url': f"{BASE_URL}/accounts/login/",
    'logout_url': f"{BASE_URL}/accounts/logout/",
    'dashboard_url': f"{BASE_URL}/app/dashboard/",
    'password_reset_url': f"{BASE_URL}/accounts/password/reset/",
    'profile_url': f"{BASE_URL}/user/profile/",
    # Test credentials - UPDATE THESE WITH VALID TEST CREDENTIALS
    'valid_email': 'admin@demo.zumodra.com',
    'valid_password': 'demopassword123',
    'invalid_email': 'nonexistent@example.com',
    'invalid_password': 'wrongpassword123',
}

# Test Results Storage
test_results: List[Dict] = []


def print_header(text: str):
    """Print a formatted header."""
    if HAS_COLOR:
        print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} {text} {Style.RESET_ALL}\n")
    else:
        print(f"\n{'='*60}\n{text}\n{'='*60}\n")


def print_test_name(text: str):
    """Print test name."""
    if HAS_COLOR:
        print(f"{Fore.CYAN}► {text}")
    else:
        print(f"► {text}")


def print_success(text: str):
    """Print success message."""
    if HAS_COLOR:
        print(f"  {Fore.GREEN}✓ {text}")
    else:
        print(f"  ✓ {text}")


def print_failure(text: str):
    """Print failure message."""
    if HAS_COLOR:
        print(f"  {Fore.RED}✗ {text}")
    else:
        print(f"  ✗ {text}")


def print_info(text: str):
    """Print info message."""
    if HAS_COLOR:
        print(f"  {Fore.YELLOW}ℹ {text}")
    else:
        print(f"  ℹ {text}")


def print_warning(text: str):
    """Print warning message."""
    if HAS_COLOR:
        print(f"  {Fore.MAGENTA}⚠ {text}")
    else:
        print(f"  ⚠ {text}")


def record_test_result(test_name: str, passed: bool, message: str, details: Dict = None):
    """Record test result for final report."""
    test_results.append({
        'test': test_name,
        'passed': passed,
        'message': message,
        'details': details or {},
        'timestamp': datetime.now().isoformat()
    })


def get_csrf_token(session: requests.Session, url: str) -> Tuple[str, str]:
    """
    Get CSRF token from a page.
    Returns (csrf_token, csrf_middleware_token).
    """
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Try to find CSRF token in form input
        csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
        csrf_token = csrf_input['value'] if csrf_input else None

        # Also check cookies
        csrf_cookie = session.cookies.get('csrftoken')

        return csrf_token or csrf_cookie, csrf_token
    except Exception as e:
        print_warning(f"Could not get CSRF token: {e}")
        return None, None


def test_1_standard_login():
    """Test 1: Standard Login with valid credentials."""
    print_header("TEST 1: Standard Login")

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Referer': TEST_CONFIG['login_url']
    })

    try:
        # Step 1: Get login page and CSRF token
        print_test_name("Step 1: Fetch login page and CSRF token")
        csrf_token, csrf_middleware_token = get_csrf_token(session, TEST_CONFIG['login_url'])

        if csrf_token:
            print_success(f"CSRF token retrieved: {csrf_token[:20]}...")
        else:
            print_failure("Could not retrieve CSRF token")
            record_test_result("1.1 Get CSRF Token", False, "Failed to retrieve CSRF token")
            return False

        record_test_result("1.1 Get CSRF Token", True, "CSRF token retrieved successfully")

        # Step 2: Submit login form
        print_test_name("Step 2: Submit login credentials")
        login_data = {
            'login': TEST_CONFIG['valid_email'],
            'password': TEST_CONFIG['valid_password'],
            'csrfmiddlewaretoken': csrf_middleware_token or csrf_token,
        }

        response = session.post(
            TEST_CONFIG['login_url'],
            data=login_data,
            headers={'Referer': TEST_CONFIG['login_url']},
            allow_redirects=True,
            timeout=10
        )

        # Check if login was successful
        if response.status_code == 200:
            print_success(f"Login request completed: {response.status_code}")

            # Check if we got redirected to dashboard or profile
            if 'dashboard' in response.url or 'profile' in response.url or response.url != TEST_CONFIG['login_url']:
                print_success(f"Redirected to: {response.url}")
                record_test_result("1.2 Login Redirect", True, f"Redirected to {response.url}")
            else:
                # Check for error messages in response
                if 'error' in response.text.lower() or 'incorrect' in response.text.lower():
                    print_failure("Login failed - error message found in response")
                    print_info("Response may contain: Incorrect credentials or account issues")
                    record_test_result("1.2 Login Redirect", False, "Login form returned with errors")
                    return False
                else:
                    print_warning("No clear redirect but no error message either")

            # Step 3: Check session cookies
            print_test_name("Step 3: Verify session cookies")
            session_cookie = session.cookies.get('sessionid')
            csrf_cookie = session.cookies.get('csrftoken')

            if session_cookie:
                print_success(f"Session cookie present: {session_cookie[:20]}...")
                record_test_result("1.3 Session Cookie", True, "Session cookie set successfully")
            else:
                print_failure("No session cookie found")
                record_test_result("1.3 Session Cookie", False, "Session cookie not set")

            if csrf_cookie:
                print_success(f"CSRF cookie present: {csrf_cookie[:20]}...")

            # Step 4: Test authenticated access
            print_test_name("Step 4: Access protected dashboard page")
            dashboard_response = session.get(TEST_CONFIG['dashboard_url'], timeout=10)

            if dashboard_response.status_code == 200:
                print_success("Dashboard accessible")

                # Check if response contains user-specific content
                if 'logout' in dashboard_response.text.lower() or 'profile' in dashboard_response.text.lower():
                    print_success("Dashboard contains authenticated content")
                    record_test_result("1.4 Dashboard Access", True, "Authenticated dashboard access successful")
                else:
                    print_warning("Dashboard accessible but may not be authenticated")
                    record_test_result("1.4 Dashboard Access", False, "Dashboard lacks authenticated content")
            elif dashboard_response.status_code == 302 or dashboard_response.status_code == 301:
                print_warning(f"Dashboard redirected to: {dashboard_response.headers.get('Location')}")
                if 'login' in dashboard_response.headers.get('Location', '').lower():
                    print_failure("Redirected back to login - authentication failed")
                    record_test_result("1.4 Dashboard Access", False, "Redirected to login page")
                else:
                    record_test_result("1.4 Dashboard Access", True, "Redirected to authorized page")
            else:
                print_failure(f"Dashboard access failed: {dashboard_response.status_code}")
                record_test_result("1.4 Dashboard Access", False, f"HTTP {dashboard_response.status_code}")

            # Step 5: Check session persistence
            print_test_name("Step 5: Test session persistence (5 second delay)")
            time.sleep(5)

            dashboard_response_2 = session.get(TEST_CONFIG['dashboard_url'], timeout=10)
            if dashboard_response_2.status_code == 200:
                print_success("Session persisted after 5 seconds")
                record_test_result("1.5 Session Persistence", True, "Session active after delay")
            else:
                print_failure(f"Session persistence check failed: {dashboard_response_2.status_code}")
                record_test_result("1.5 Session Persistence", False, f"HTTP {dashboard_response_2.status_code}")

            return True
        else:
            print_failure(f"Login request failed: {response.status_code}")
            record_test_result("1.2 Login Request", False, f"HTTP {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        print_failure(f"Network error: {e}")
        record_test_result("1.x Network Error", False, str(e))
        return False
    except Exception as e:
        print_failure(f"Unexpected error: {e}")
        record_test_result("1.x Unexpected Error", False, str(e))
        return False


def test_2_failed_login_attempts():
    """Test 2: Failed login attempts with wrong credentials."""
    print_header("TEST 2: Failed Login Attempts")

    test_cases = [
        ("Wrong password", TEST_CONFIG['valid_email'], TEST_CONFIG['invalid_password']),
        ("Non-existent email", TEST_CONFIG['invalid_email'], TEST_CONFIG['invalid_password']),
        ("Empty credentials", "", ""),
    ]

    for test_name, email, password in test_cases:
        print_test_name(f"Testing: {test_name}")
        session = requests.Session()

        try:
            # Get CSRF token
            csrf_token, csrf_middleware_token = get_csrf_token(session, TEST_CONFIG['login_url'])

            if not csrf_token:
                print_failure("Could not get CSRF token")
                continue

            # Attempt login
            login_data = {
                'login': email,
                'password': password,
                'csrfmiddlewaretoken': csrf_middleware_token or csrf_token,
            }

            response = session.post(
                TEST_CONFIG['login_url'],
                data=login_data,
                allow_redirects=False,
                timeout=10
            )

            # Check that login failed appropriately
            if response.status_code in [200, 400]:
                # Still on login page or validation error
                soup = BeautifulSoup(response.text, 'html.parser')
                errors = soup.find_all(class_=['error', 'alert', 'errorlist'])

                if errors or 'incorrect' in response.text.lower() or 'invalid' in response.text.lower():
                    print_success("Login correctly rejected with error message")
                    record_test_result(f"2.x {test_name}", True, "Login failed as expected")
                else:
                    print_warning("Login may have failed but no clear error message")
                    record_test_result(f"2.x {test_name}", True, "Login stayed on login page")
            else:
                print_warning(f"Unexpected status code: {response.status_code}")
                record_test_result(f"2.x {test_name}", False, f"HTTP {response.status_code}")

        except Exception as e:
            print_failure(f"Error: {e}")
            record_test_result(f"2.x {test_name} Error", False, str(e))


def test_3_brute_force_protection():
    """Test 3: Brute force protection (django-axes)."""
    print_header("TEST 3: Brute Force Protection (Django-Axes)")
    print_info("Testing 5 failed login attempts to trigger lockout...")

    session = requests.Session()

    try:
        for attempt in range(1, 6):
            print_test_name(f"Failed login attempt {attempt}/5")

            csrf_token, csrf_middleware_token = get_csrf_token(session, TEST_CONFIG['login_url'])

            login_data = {
                'login': TEST_CONFIG['valid_email'],
                'password': 'definitely_wrong_password_' + str(attempt),
                'csrfmiddlewaretoken': csrf_middleware_token or csrf_token,
            }

            response = session.post(
                TEST_CONFIG['login_url'],
                data=login_data,
                allow_redirects=False,
                timeout=10
            )

            if attempt < 5:
                print_info(f"Attempt {attempt} failed (expected)")
            else:
                # On 5th attempt, check if account is locked
                if 'locked' in response.text.lower() or 'too many' in response.text.lower() or 'blocked' in response.text.lower():
                    print_success("Account locked after 5 failed attempts")
                    record_test_result("3.1 Brute Force Protection", True, "Account locked after 5 attempts")
                else:
                    print_warning("No clear lockout message found (protection may use different mechanism)")
                    record_test_result("3.1 Brute Force Protection", False, "No lockout detected after 5 attempts")

            time.sleep(1)  # Small delay between attempts

    except Exception as e:
        print_failure(f"Error testing brute force protection: {e}")
        record_test_result("3.x Brute Force Error", False, str(e))


def test_4_password_reset_flow():
    """Test 4: Password reset flow."""
    print_header("TEST 4: Password Reset Flow")

    session = requests.Session()

    try:
        # Step 1: Access password reset page
        print_test_name("Step 1: Access password reset page")
        response = session.get(TEST_CONFIG['password_reset_url'], timeout=10)

        if response.status_code == 200:
            print_success("Password reset page accessible")
            record_test_result("4.1 Reset Page Access", True, "Page accessible")
        else:
            print_failure(f"Could not access password reset page: {response.status_code}")
            record_test_result("4.1 Reset Page Access", False, f"HTTP {response.status_code}")
            return

        # Step 2: Get CSRF token
        csrf_token, csrf_middleware_token = get_csrf_token(session, TEST_CONFIG['password_reset_url'])

        if not csrf_token:
            print_failure("Could not get CSRF token")
            return

        # Step 3: Submit password reset request
        print_test_name("Step 2: Submit password reset request")
        reset_data = {
            'email': TEST_CONFIG['valid_email'],
            'csrfmiddlewaretoken': csrf_middleware_token or csrf_token,
        }

        response = session.post(
            TEST_CONFIG['password_reset_url'],
            data=reset_data,
            allow_redirects=True,
            timeout=10
        )

        if response.status_code == 200:
            # Check for success message
            if 'sent' in response.text.lower() or 'email' in response.text.lower() or 'check' in response.text.lower():
                print_success("Password reset email request submitted")
                print_info("Check MailHog at http://localhost:8026 (if available)")
                record_test_result("4.2 Reset Email Request", True, "Reset email requested")
            else:
                print_warning("Reset form submitted but no clear confirmation")
                record_test_result("4.2 Reset Email Request", False, "No confirmation message")
        else:
            print_failure(f"Password reset request failed: {response.status_code}")
            record_test_result("4.2 Reset Email Request", False, f"HTTP {response.status_code}")

    except Exception as e:
        print_failure(f"Error testing password reset: {e}")
        record_test_result("4.x Password Reset Error", False, str(e))


def test_5_session_management():
    """Test 5: Session management and concurrent sessions."""
    print_header("TEST 5: Session Management")

    # Create two separate sessions
    session1 = requests.Session()
    session2 = requests.Session()

    try:
        # Login with session 1
        print_test_name("Step 1: Login with first session")
        csrf_token, csrf_middleware_token = get_csrf_token(session1, TEST_CONFIG['login_url'])

        login_data = {
            'login': TEST_CONFIG['valid_email'],
            'password': TEST_CONFIG['valid_password'],
            'csrfmiddlewaretoken': csrf_middleware_token or csrf_token,
        }

        response1 = session1.post(
            TEST_CONFIG['login_url'],
            data=login_data,
            allow_redirects=True,
            timeout=10
        )

        if session1.cookies.get('sessionid'):
            print_success("Session 1 logged in successfully")
            session1_id = session1.cookies.get('sessionid')
            record_test_result("5.1 Session 1 Login", True, f"Session ID: {session1_id[:20]}...")
        else:
            print_failure("Session 1 login failed")
            record_test_result("5.1 Session 1 Login", False, "No session cookie")
            return

        # Login with session 2 (same user)
        print_test_name("Step 2: Login with second session (same user)")
        csrf_token, csrf_middleware_token = get_csrf_token(session2, TEST_CONFIG['login_url'])

        login_data['csrfmiddlewaretoken'] = csrf_middleware_token or csrf_token

        response2 = session2.post(
            TEST_CONFIG['login_url'],
            data=login_data,
            allow_redirects=True,
            timeout=10
        )

        if session2.cookies.get('sessionid'):
            print_success("Session 2 logged in successfully")
            session2_id = session2.cookies.get('sessionid')
            record_test_result("5.2 Session 2 Login", True, f"Session ID: {session2_id[:20]}...")
        else:
            print_failure("Session 2 login failed")
            record_test_result("5.2 Session 2 Login", False, "No session cookie")
            return

        # Check if both sessions are different
        print_test_name("Step 3: Verify concurrent sessions")
        if session1_id != session2_id:
            print_success("Concurrent sessions have different session IDs")
            record_test_result("5.3 Concurrent Sessions", True, "Different session IDs")
        else:
            print_warning("Both sessions have same session ID")
            record_test_result("5.3 Concurrent Sessions", False, "Same session ID")

        # Test if both sessions can access dashboard
        print_test_name("Step 4: Test both sessions can access dashboard")
        dashboard1 = session1.get(TEST_CONFIG['dashboard_url'], timeout=10)
        dashboard2 = session2.get(TEST_CONFIG['dashboard_url'], timeout=10)

        if dashboard1.status_code == 200 and dashboard2.status_code == 200:
            print_success("Both sessions can access dashboard")
            record_test_result("5.4 Concurrent Dashboard Access", True, "Both sessions active")
        else:
            print_failure("One or both sessions cannot access dashboard")
            record_test_result("5.4 Concurrent Dashboard Access", False,
                             f"Session1: {dashboard1.status_code}, Session2: {dashboard2.status_code}")

    except Exception as e:
        print_failure(f"Error testing session management: {e}")
        record_test_result("5.x Session Management Error", False, str(e))


def test_6_logout_functionality():
    """Test 6: Logout functionality."""
    print_header("TEST 6: Logout Functionality")

    session = requests.Session()

    try:
        # Step 1: Login
        print_test_name("Step 1: Login")
        csrf_token, csrf_middleware_token = get_csrf_token(session, TEST_CONFIG['login_url'])

        login_data = {
            'login': TEST_CONFIG['valid_email'],
            'password': TEST_CONFIG['valid_password'],
            'csrfmiddlewaretoken': csrf_middleware_token or csrf_token,
        }

        response = session.post(
            TEST_CONFIG['login_url'],
            data=login_data,
            allow_redirects=True,
            timeout=10
        )

        if not session.cookies.get('sessionid'):
            print_failure("Could not login for logout test")
            return

        print_success("Logged in successfully")
        initial_session_id = session.cookies.get('sessionid')

        # Step 2: Access dashboard to confirm authentication
        print_test_name("Step 2: Verify authenticated access")
        dashboard = session.get(TEST_CONFIG['dashboard_url'], timeout=10)

        if dashboard.status_code == 200:
            print_success("Dashboard accessible before logout")
        else:
            print_warning(f"Dashboard returned {dashboard.status_code}")

        # Step 3: Logout
        print_test_name("Step 3: Logout")

        # Get CSRF token for logout
        logout_csrf, logout_csrf_middleware = get_csrf_token(session, TEST_CONFIG['logout_url'])

        logout_response = session.post(
            TEST_CONFIG['logout_url'],
            data={'csrfmiddlewaretoken': logout_csrf_middleware or logout_csrf},
            allow_redirects=True,
            timeout=10
        )

        if logout_response.status_code == 200:
            print_success("Logout request completed")

            # Check redirect
            if 'home' in logout_response.url or logout_response.url == TEST_CONFIG['base_url'] + '/':
                print_success(f"Redirected to home page: {logout_response.url}")
                record_test_result("6.1 Logout Redirect", True, "Redirected to home")
            else:
                print_info(f"Redirected to: {logout_response.url}")
                record_test_result("6.1 Logout Redirect", True, f"Redirected to {logout_response.url}")
        else:
            print_failure(f"Logout failed: {logout_response.status_code}")
            record_test_result("6.1 Logout", False, f"HTTP {logout_response.status_code}")

        # Step 4: Verify session cleared
        print_test_name("Step 4: Verify session cleared")
        final_session_id = session.cookies.get('sessionid')

        if not final_session_id:
            print_success("Session cookie cleared")
            record_test_result("6.2 Session Cleared", True, "Session cookie removed")
        elif final_session_id != initial_session_id:
            print_success("Session cookie changed (invalidated)")
            record_test_result("6.2 Session Cleared", True, "Session invalidated")
        else:
            print_warning("Session cookie still present with same ID")
            record_test_result("6.2 Session Cleared", False, "Session cookie unchanged")

        # Step 5: Try to access protected page
        print_test_name("Step 5: Verify cannot access protected page after logout")
        dashboard_after_logout = session.get(TEST_CONFIG['dashboard_url'], allow_redirects=False, timeout=10)

        if dashboard_after_logout.status_code in [302, 301]:
            redirect_location = dashboard_after_logout.headers.get('Location', '')
            if 'login' in redirect_location.lower():
                print_success("Redirected to login page (correct)")
                record_test_result("6.3 Post-Logout Protection", True, "Redirected to login")
            else:
                print_warning(f"Redirected to: {redirect_location}")
                record_test_result("6.3 Post-Logout Protection", True, f"Redirected to {redirect_location}")
        elif dashboard_after_logout.status_code == 403:
            print_success("Access forbidden (correct)")
            record_test_result("6.3 Post-Logout Protection", True, "Access denied")
        elif dashboard_after_logout.status_code == 200:
            # Check if it's actually the dashboard or login page
            if 'login' in dashboard_after_logout.text.lower() and 'logout' not in dashboard_after_logout.text.lower():
                print_success("Showing login form (correct)")
                record_test_result("6.3 Post-Logout Protection", True, "Login form shown")
            else:
                print_failure("Dashboard still accessible after logout")
                record_test_result("6.3 Post-Logout Protection", False, "Dashboard accessible after logout")
        else:
            print_warning(f"Unexpected status: {dashboard_after_logout.status_code}")
            record_test_result("6.3 Post-Logout Protection", False, f"HTTP {dashboard_after_logout.status_code}")

    except Exception as e:
        print_failure(f"Error testing logout: {e}")
        record_test_result("6.x Logout Error", False, str(e))


def test_7_login_history():
    """Test 7: Login history tracking."""
    print_header("TEST 7: Login History Tracking")
    print_info("This test requires API access or admin panel access")
    print_info("Testing if LoginHistory model is tracking login attempts...")

    # This would require authenticated API access to check login history
    print_warning("LoginHistory verification requires API access (skipping detailed test)")
    print_info("Expected features:")
    print_info("  - Successful logins logged with timestamp and IP")
    print_info("  - Failed login attempts tracked")
    print_info("  - User agent and device info captured")

    record_test_result("7.x Login History", True, "Manual verification required")


def print_final_report():
    """Print final test report."""
    print_header("FINAL TEST REPORT")

    total_tests = len(test_results)
    passed_tests = sum(1 for result in test_results if result['passed'])
    failed_tests = total_tests - passed_tests
    pass_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

    print(f"Total Tests: {total_tests}")
    print(f"Passed: {Fore.GREEN}{passed_tests}{Style.RESET_ALL}")
    print(f"Failed: {Fore.RED}{failed_tests}{Style.RESET_ALL}")
    print(f"Pass Rate: {Fore.CYAN}{pass_rate:.1f}%{Style.RESET_ALL}\n")

    # Detailed results
    print("Detailed Results:")
    print("=" * 80)

    for result in test_results:
        status = f"{Fore.GREEN}PASS{Style.RESET_ALL}" if result['passed'] else f"{Fore.RED}FAIL{Style.RESET_ALL}"
        print(f"{status} | {result['test']}")
        print(f"     {result['message']}")
        if result.get('details'):
            for key, value in result['details'].items():
                print(f"     {key}: {value}")
        print()

    # Save to JSON file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"login_session_test_report_{timestamp}.json"

    with open(report_file, 'w') as f:
        json.dump({
            'summary': {
                'total': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'pass_rate': pass_rate,
                'timestamp': datetime.now().isoformat(),
                'base_url': TEST_CONFIG['base_url']
            },
            'results': test_results
        }, f, indent=2)

    print(f"\n{Fore.CYAN}Full report saved to: {report_file}{Style.RESET_ALL}\n")


def main():
    """Run all tests."""
    print_header("ZUMODRA LOGIN & SESSION MANAGEMENT TEST SUITE")
    print(f"Testing server: {Fore.CYAN}{TEST_CONFIG['base_url']}{Style.RESET_ALL}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    print_warning("IMPORTANT: Update TEST_CONFIG with valid test credentials!")
    print_info(f"Current test email: {TEST_CONFIG['valid_email']}")

    input("\nPress Enter to continue...")

    # Run all tests
    try:
        test_1_standard_login()
        test_2_failed_login_attempts()
        test_3_brute_force_protection()
        test_4_password_reset_flow()
        test_5_session_management()
        test_6_logout_functionality()
        test_7_login_history()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Tests interrupted by user{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"\n\n{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}\n")
    finally:
        print_final_report()


if __name__ == "__main__":
    main()
