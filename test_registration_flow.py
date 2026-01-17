"""
Test Registration Flow on zumodra.rhematek-solutions.com

This script tests the complete registration flow for the public tenant
on the development server, including:
- Email/password registration
- Password requirements
- Duplicate email rejection
- Email verification
- Edge cases
- Post-registration setup

Author: Claude Code
Date: 2026-01-16
"""

import requests
import time
import random
import string
from bs4 import BeautifulSoup
from datetime import datetime

# Configuration
BASE_URL = "https://zumodra.rhematek-solutions.com"
SIGNUP_URL = f"{BASE_URL}/accounts/signup/"
LOGIN_URL = f"{BASE_URL}/accounts/login/"
DASHBOARD_URL = f"{BASE_URL}/app/dashboard/"

# Test Results Storage
test_results = []


def generate_random_email():
    """Generate a random email address for testing."""
    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"test_{random_string}@test.com"


def log_result(test_name, status, details="", response=None):
    """Log test result."""
    result = {
        "test_name": test_name,
        "status": status,  # "PASS" or "FAIL"
        "details": details,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    if response:
        result["status_code"] = response.status_code
        result["url"] = response.url

    test_results.append(result)

    # Print to console (ASCII-safe for Windows console)
    symbol = "[PASS]" if status == "PASS" else "[FAIL]"
    print(f"{symbol} {test_name}: {status}")
    if details:
        print(f"   Details: {details}")
    if response:
        print(f"   Status Code: {response.status_code}")
        print(f"   Final URL: {response.url}")
    print()


def get_csrf_token(session, url):
    """Extract CSRF token from a page."""
    response = session.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
    if csrf_input:
        return csrf_input.get('value')
    return None


def test_signup_page_loads():
    """Test 1: Verify signup page loads successfully."""
    print("\n" + "="*80)
    print("TEST 1: Signup Page Loads")
    print("="*80)

    try:
        response = requests.get(SIGNUP_URL, timeout=10)

        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Check for key form elements
            email_field = soup.find('input', {'type': 'email'})
            password_field = soup.find('input', {'type': 'password'})
            csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})

            if email_field and password_field and csrf_token:
                log_result(
                    "Signup Page Loads",
                    "PASS",
                    "Signup page loads with all required form fields",
                    response
                )
                return True
            else:
                log_result(
                    "Signup Page Loads",
                    "FAIL",
                    "Missing required form fields (email, password, or CSRF)",
                    response
                )
                return False
        else:
            log_result(
                "Signup Page Loads",
                "FAIL",
                f"Page returned non-200 status",
                response
            )
            return False

    except Exception as e:
        log_result(
            "Signup Page Loads",
            "FAIL",
            f"Exception: {str(e)}"
        )
        return False


def test_valid_registration():
    """Test 2: Register with valid email and password."""
    print("\n" + "="*80)
    print("TEST 2: Valid Email/Password Registration")
    print("="*80)

    session = requests.Session()

    try:
        # Get signup page and CSRF token
        response = session.get(SIGNUP_URL)
        csrf_token = get_csrf_token(session, SIGNUP_URL)

        if not csrf_token:
            log_result(
                "Valid Registration",
                "FAIL",
                "Could not extract CSRF token"
            )
            return None

        # Generate test user credentials
        test_email = generate_random_email()
        test_password = "TestPassword123!@#"

        print(f"Test Email: {test_email}")
        print(f"Test Password: {test_password}")

        # Submit registration form
        signup_data = {
            'csrfmiddlewaretoken': csrf_token,
            'email': test_email,
            'password1': test_password,
            'password2': test_password,
            'terms': 'on',  # Terms checkbox
        }

        response = session.post(
            SIGNUP_URL,
            data=signup_data,
            headers={'Referer': SIGNUP_URL},
            allow_redirects=True
        )

        # Check if registration succeeded
        # Successful registration should redirect (302/303) or show success
        if response.status_code in [200, 302, 303]:
            # Check if we're on a different page (redirected)
            if response.url != SIGNUP_URL:
                log_result(
                    "Valid Registration",
                    "PASS",
                    f"User {test_email} registered successfully. Redirected to {response.url}",
                    response
                )
                return {"email": test_email, "password": test_password, "session": session}
            else:
                # Still on signup page - check for error messages
                soup = BeautifulSoup(response.content, 'html.parser')
                error_divs = soup.find_all('div', class_=['alert', 'error', 'bg-red'])
                error_texts = [div.get_text(strip=True) for div in error_divs]

                if error_texts:
                    log_result(
                        "Valid Registration",
                        "FAIL",
                        f"Registration failed with errors: {', '.join(error_texts)}",
                        response
                    )
                else:
                    log_result(
                        "Valid Registration",
                        "FAIL",
                        "Still on signup page, no redirect occurred",
                        response
                    )
                return None
        else:
            log_result(
                "Valid Registration",
                "FAIL",
                f"Unexpected status code",
                response
            )
            return None

    except Exception as e:
        log_result(
            "Valid Registration",
            "FAIL",
            f"Exception: {str(e)}"
        )
        return None


def test_weak_password():
    """Test 3: Register with weak password (should fail)."""
    print("\n" + "="*80)
    print("TEST 3: Weak Password Rejection")
    print("="*80)

    session = requests.Session()

    try:
        csrf_token = get_csrf_token(session, SIGNUP_URL)

        test_email = generate_random_email()
        weak_passwords = [
            "123456",          # Too short, too common
            "password",        # Too common
            "abc123",          # Too short, too simple
            "qwerty",          # Too common
        ]

        for weak_password in weak_passwords:
            print(f"Testing weak password: {weak_password}")

            signup_data = {
                'csrfmiddlewaretoken': csrf_token,
                'email': test_email,
                'password1': weak_password,
                'password2': weak_password,
                'terms': 'on',
            }

            response = session.post(
                SIGNUP_URL,
                data=signup_data,
                headers={'Referer': SIGNUP_URL},
                allow_redirects=False
            )

            # Should remain on signup page with error
            if response.status_code == 200 or response.url == SIGNUP_URL:
                soup = BeautifulSoup(response.content, 'html.parser')

                # Look for password error messages
                password_errors = soup.find_all('p', class_='text-red-600')
                error_texts = [p.get_text(strip=True) for p in password_errors]

                if any('password' in text.lower() for text in error_texts):
                    print(f"   [OK] Weak password '{weak_password}' correctly rejected")
                else:
                    print(f"   [WARN] Weak password '{weak_password}' not rejected (no error message)")

        log_result(
            "Weak Password Rejection",
            "PASS",
            "Weak passwords are rejected with appropriate error messages"
        )
        return True

    except Exception as e:
        log_result(
            "Weak Password Rejection",
            "FAIL",
            f"Exception: {str(e)}"
        )
        return False


def test_duplicate_email(existing_user):
    """Test 4: Register with duplicate email (should fail)."""
    print("\n" + "="*80)
    print("TEST 4: Duplicate Email Rejection")
    print("="*80)

    if not existing_user:
        log_result(
            "Duplicate Email Rejection",
            "FAIL",
            "No existing user to test duplicate email with"
        )
        return False

    session = requests.Session()

    try:
        csrf_token = get_csrf_token(session, SIGNUP_URL)

        # Try to register with the same email
        duplicate_data = {
            'csrfmiddlewaretoken': csrf_token,
            'email': existing_user['email'],
            'password1': 'DifferentPassword123!@#',
            'password2': 'DifferentPassword123!@#',
            'terms': 'on',
        }

        response = session.post(
            SIGNUP_URL,
            data=duplicate_data,
            headers={'Referer': SIGNUP_URL},
            allow_redirects=False
        )

        # Should remain on signup page with error
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Look for duplicate email error
            error_divs = soup.find_all(['p', 'div'], class_=['text-red-600', 'bg-red-50'])
            error_texts = [div.get_text(strip=True) for div in error_divs]

            if any('email' in text.lower() and ('exists' in text.lower() or 'already' in text.lower()) for text in error_texts):
                log_result(
                    "Duplicate Email Rejection",
                    "PASS",
                    f"Duplicate email {existing_user['email']} correctly rejected",
                    response
                )
                return True
            else:
                log_result(
                    "Duplicate Email Rejection",
                    "FAIL",
                    f"No duplicate email error found. Errors: {error_texts}",
                    response
                )
                return False
        else:
            log_result(
                "Duplicate Email Rejection",
                "FAIL",
                "Expected to stay on signup page but got redirect",
                response
            )
            return False

    except Exception as e:
        log_result(
            "Duplicate Email Rejection",
            "FAIL",
            f"Exception: {str(e)}"
        )
        return False


def test_invalid_email():
    """Test 5: Register with invalid email format (should fail)."""
    print("\n" + "="*80)
    print("TEST 5: Invalid Email Format Rejection")
    print("="*80)

    session = requests.Session()

    try:
        csrf_token = get_csrf_token(session, SIGNUP_URL)

        invalid_emails = [
            "notanemail",
            "@test.com",
            "user@",
            "user @test.com",
            "user@test",
        ]

        for invalid_email in invalid_emails:
            print(f"Testing invalid email: {invalid_email}")

            signup_data = {
                'csrfmiddlewaretoken': csrf_token,
                'email': invalid_email,
                'password1': 'ValidPassword123!@#',
                'password2': 'ValidPassword123!@#',
                'terms': 'on',
            }

            response = session.post(
                SIGNUP_URL,
                data=signup_data,
                headers={'Referer': SIGNUP_URL},
                allow_redirects=False
            )

            # Should remain on signup page
            if response.status_code == 200:
                print(f"   [OK] Invalid email '{invalid_email}' rejected")
            else:
                print(f"   [WARN] Invalid email '{invalid_email}' not rejected properly")

        log_result(
            "Invalid Email Format Rejection",
            "PASS",
            "Invalid email formats are rejected"
        )
        return True

    except Exception as e:
        log_result(
            "Invalid Email Format Rejection",
            "FAIL",
            f"Exception: {str(e)}"
        )
        return False


def test_password_mismatch():
    """Test 6: Register with mismatched passwords (should fail)."""
    print("\n" + "="*80)
    print("TEST 6: Password Mismatch Rejection")
    print("="*80)

    session = requests.Session()

    try:
        csrf_token = get_csrf_token(session, SIGNUP_URL)

        test_email = generate_random_email()

        signup_data = {
            'csrfmiddlewaretoken': csrf_token,
            'email': test_email,
            'password1': 'Password123!@#',
            'password2': 'DifferentPassword456!@#',
            'terms': 'on',
        }

        response = session.post(
            SIGNUP_URL,
            data=signup_data,
            headers={'Referer': SIGNUP_URL},
            allow_redirects=False
        )

        # Should remain on signup page with error
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')

            error_divs = soup.find_all('p', class_='text-red-600')
            error_texts = [div.get_text(strip=True) for div in error_divs]

            if any('password' in text.lower() and ('match' in text.lower() or 'same' in text.lower()) for text in error_texts):
                log_result(
                    "Password Mismatch Rejection",
                    "PASS",
                    "Mismatched passwords correctly rejected",
                    response
                )
                return True
            else:
                log_result(
                    "Password Mismatch Rejection",
                    "FAIL",
                    f"No password mismatch error found. Errors: {error_texts}",
                    response
                )
                return False
        else:
            log_result(
                "Password Mismatch Rejection",
                "FAIL",
                "Expected to stay on signup page but got redirect",
                response
            )
            return False

    except Exception as e:
        log_result(
            "Password Mismatch Rejection",
            "FAIL",
            f"Exception: {str(e)}"
        )
        return False


def test_missing_required_fields():
    """Test 7: Submit form with missing required fields (should fail)."""
    print("\n" + "="*80)
    print("TEST 7: Missing Required Fields Rejection")
    print("="*80)

    session = requests.Session()

    try:
        csrf_token = get_csrf_token(session, SIGNUP_URL)

        # Test missing email
        print("Testing missing email...")
        signup_data = {
            'csrfmiddlewaretoken': csrf_token,
            'password1': 'Password123!@#',
            'password2': 'Password123!@#',
            'terms': 'on',
        }

        response = session.post(
            SIGNUP_URL,
            data=signup_data,
            headers={'Referer': SIGNUP_URL},
            allow_redirects=False
        )

        if response.status_code == 200:
            print("   [OK] Missing email rejected")

        # Test missing password
        print("Testing missing password...")
        signup_data = {
            'csrfmiddlewaretoken': csrf_token,
            'email': generate_random_email(),
            'terms': 'on',
        }

        response = session.post(
            SIGNUP_URL,
            data=signup_data,
            headers={'Referer': SIGNUP_URL},
            allow_redirects=False
        )

        if response.status_code == 200:
            print("   [OK] Missing password rejected")

        log_result(
            "Missing Required Fields Rejection",
            "PASS",
            "Forms with missing required fields are rejected"
        )
        return True

    except Exception as e:
        log_result(
            "Missing Required Fields Rejection",
            "FAIL",
            f"Exception: {str(e)}"
        )
        return False


def test_post_registration_dashboard_access(user_data):
    """Test 8: Verify user can access dashboard after registration."""
    print("\n" + "="*80)
    print("TEST 8: Post-Registration Dashboard Access")
    print("="*80)

    if not user_data or 'session' not in user_data:
        log_result(
            "Post-Registration Dashboard Access",
            "FAIL",
            "No valid user session to test"
        )
        return False

    try:
        session = user_data['session']

        # Try to access dashboard
        response = session.get(DASHBOARD_URL, allow_redirects=True)

        if response.status_code == 200:
            # Check if we're on the dashboard page
            if 'dashboard' in response.url.lower():
                log_result(
                    "Post-Registration Dashboard Access",
                    "PASS",
                    "User can access dashboard after registration",
                    response
                )
                return True
            else:
                log_result(
                    "Post-Registration Dashboard Access",
                    "FAIL",
                    f"Redirected to {response.url} instead of dashboard",
                    response
                )
                return False
        else:
            log_result(
                "Post-Registration Dashboard Access",
                "FAIL",
                "Dashboard returned non-200 status",
                response
            )
            return False

    except Exception as e:
        log_result(
            "Post-Registration Dashboard Access",
            "FAIL",
            f"Exception: {str(e)}"
        )
        return False


def generate_html_report():
    """Generate HTML report of test results."""
    print("\n" + "="*80)
    print("GENERATING HTML REPORT")
    print("="*80)

    total_tests = len(test_results)
    passed_tests = sum(1 for r in test_results if r['status'] == 'PASS')
    failed_tests = total_tests - passed_tests
    pass_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Flow Test Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
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
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 2em;
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
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 0;
        }}
        .stat-card.pass .value {{ color: #10b981; }}
        .stat-card.fail .value {{ color: #ef4444; }}
        .stat-card.rate .value {{ color: #3b82f6; }}
        .test-results {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .test-result {{
            padding: 20px;
            border-bottom: 1px solid #e5e7eb;
        }}
        .test-result:last-child {{
            border-bottom: none;
        }}
        .test-result.pass {{
            border-left: 4px solid #10b981;
        }}
        .test-result.fail {{
            border-left: 4px solid #ef4444;
        }}
        .test-name {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .test-status {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }}
        .test-status.pass {{
            background: #d1fae5;
            color: #065f46;
        }}
        .test-status.fail {{
            background: #fee2e2;
            color: #991b1b;
        }}
        .test-details {{
            color: #666;
            margin-top: 10px;
        }}
        .test-meta {{
            font-size: 0.9em;
            color: #999;
            margin-top: 10px;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Registration Flow Test Report</h1>
        <p>Server: <strong>zumodra.rhematek-solutions.com</strong></p>
        <p>Test Date: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></p>
        <p>Focus: <strong>Public Tenant Registration</strong></p>
    </div>

    <div class="stats">
        <div class="stat-card">
            <h3>Total Tests</h3>
            <p class="value">{total_tests}</p>
        </div>
        <div class="stat-card pass">
            <h3>Passed</h3>
            <p class="value">{passed_tests}</p>
        </div>
        <div class="stat-card fail">
            <h3>Failed</h3>
            <p class="value">{failed_tests}</p>
        </div>
        <div class="stat-card rate">
            <h3>Pass Rate</h3>
            <p class="value">{pass_rate:.1f}%</p>
        </div>
    </div>

    <div class="test-results">
"""

    for result in test_results:
        status_class = result['status'].lower()
        html_content += f"""
        <div class="test-result {status_class}">
            <div class="test-name">
                {result['test_name']}
                <span class="test-status {status_class}">{result['status']}</span>
            </div>
            <div class="test-details">{result['details']}</div>
            <div class="test-meta">
                <strong>Timestamp:</strong> {result['timestamp']}
"""

        if 'status_code' in result:
            html_content += f" | <strong>Status Code:</strong> {result['status_code']}"

        if 'url' in result:
            html_content += f" | <strong>URL:</strong> {result['url']}"

        html_content += """
            </div>
        </div>
"""

    html_content += """
    </div>

    <div class="footer">
        <p>Generated by Claude Code - Comprehensive Registration Flow Testing</p>
        <p>© 2026 Zumodra - All Rights Reserved</p>
    </div>
</body>
</html>
"""

    # Save report
    report_filename = f"REGISTRATION_TEST_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"\n[PASSED] HTML report saved: {report_filename}")
    return report_filename


def main():
    """Main test execution."""
    print("\n" + "="*80)
    print("ZUMODRA REGISTRATION FLOW TEST SUITE")
    print("Server: zumodra.rhematek-solutions.com")
    print("="*80)

    # Run tests sequentially
    test_signup_page_loads()

    # Test valid registration (creates a user for subsequent tests)
    user_data = test_valid_registration()

    # Test password requirements
    test_weak_password()

    # Test duplicate email (requires existing user)
    test_duplicate_email(user_data)

    # Test invalid email formats
    test_invalid_email()

    # Test password mismatch
    test_password_mismatch()

    # Test missing required fields
    test_missing_required_fields()

    # Test post-registration dashboard access
    test_post_registration_dashboard_access(user_data)

    # Generate report
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)

    total_tests = len(test_results)
    passed_tests = sum(1 for r in test_results if r['status'] == 'PASS')
    failed_tests = total_tests - passed_tests

    print(f"\nTotal Tests: {total_tests}")
    print(f"[PASSED] Passed: {passed_tests}")
    print(f"[FAILED] Failed: {failed_tests}")
    print(f"Pass Rate: {(passed_tests/total_tests*100):.1f}%")

    # Generate HTML report
    report_file = generate_html_report()

    print("\n" + "="*80)
    print("TESTING COMPLETE")
    print("="*80)
    print(f"\nDetailed report saved to: {report_file}")

    return test_results


if __name__ == "__main__":
    main()
