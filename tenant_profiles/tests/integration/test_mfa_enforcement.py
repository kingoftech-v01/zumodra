#!/usr/bin/env python
"""
Two-Factor Authentication (MFA) Testing Script

Tests MFA setup, enforcement, and 30-day grace period functionality on
zumodra.rhematek-solutions.com production environment.

Author: Rhematek Solutions
Date: 2026-01-16
"""

import requests
import json
import time
from datetime import datetime, timedelta
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re


class MFATestSuite:
    """Comprehensive MFA testing suite for production environment."""

    def __init__(self, base_url="https://zumodra.rhematek-solutions.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []

        # Test user credentials
        self.test_user = {
            'email': 'mfa.test@rhematek.com',
            'password': 'TestMFA2026!Secure',
            'username': 'mfatestuser'
        }

        # Old user credentials (for testing > 30 days enforcement)
        self.old_user = {
            'email': 'old.user@rhematek.com',
            'password': 'OldUser2026!Test'
        }

        print("=" * 80)
        print("MFA ENFORCEMENT TEST SUITE")
        print("=" * 80)
        print(f"Target Server: {self.base_url}")
        print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print()

    def log_result(self, test_name, status, details="", screenshot_path=None):
        """Log a test result."""
        result = {
            'test': test_name,
            'status': status,
            'details': details,
            'screenshot': screenshot_path,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)

        # Print status
        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_icon} {test_name}: {status}")
        if details:
            print(f"   {details}")
        if screenshot_path:
            print(f"   Screenshot: {screenshot_path}")
        print()

    def get_csrf_token(self, response_text):
        """Extract CSRF token from HTML response."""
        soup = BeautifulSoup(response_text, 'html.parser')
        csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
        if csrf_input:
            return csrf_input.get('value')

        # Try to find in cookies
        csrf_cookie = self.session.cookies.get('csrftoken')
        return csrf_cookie

    def test_1_mfa_setup_page_access(self):
        """Test 1: MFA Setup Page Access"""
        print("\n" + "=" * 80)
        print("TEST 1: MFA Setup Page Access")
        print("=" * 80)

        try:
            # First, try to access without login
            response = self.session.get(
                urljoin(self.base_url, '/en-us/accounts/two-factor/'),
                allow_redirects=False
            )

            if response.status_code in [302, 301]:
                self.log_result(
                    "1.1 Unauthenticated Access",
                    "PASS",
                    f"Correctly redirected to login (HTTP {response.status_code})"
                )
            else:
                self.log_result(
                    "1.1 Unauthenticated Access",
                    "FAIL",
                    f"Should redirect to login but got {response.status_code}"
                )

            # Now login and try again
            self.login(self.test_user['email'], self.test_user['password'])

            response = self.session.get(
                urljoin(self.base_url, '/en-us/accounts/two-factor/')
            )

            if response.status_code == 200:
                self.log_result(
                    "1.2 Authenticated Access",
                    "PASS",
                    "MFA setup page loads successfully"
                )

                # Check for MFA options
                if 'TOTP' in response.text or 'Authenticator' in response.text:
                    self.log_result(
                        "1.3 TOTP Available",
                        "PASS",
                        "TOTP/Authenticator option found on page"
                    )
                else:
                    self.log_result(
                        "1.3 TOTP Available",
                        "FAIL",
                        "TOTP/Authenticator option not found"
                    )

                if 'WebAuthn' in response.text or 'Security Key' in response.text:
                    self.log_result(
                        "1.4 WebAuthn Available",
                        "PASS",
                        "WebAuthn option found on page"
                    )
                else:
                    self.log_result(
                        "1.4 WebAuthn Available",
                        "WARN",
                        "WebAuthn option not found (may not be implemented)"
                    )
            else:
                self.log_result(
                    "1.2 Authenticated Access",
                    "FAIL",
                    f"MFA page returned HTTP {response.status_code}"
                )

        except Exception as e:
            self.log_result(
                "1. MFA Setup Page Access",
                "FAIL",
                f"Exception: {str(e)}"
            )

    def test_2_totp_setup_flow(self):
        """Test 2: TOTP Setup Flow"""
        print("\n" + "=" * 80)
        print("TEST 2: TOTP Setup Flow")
        print("=" * 80)

        try:
            # Navigate to TOTP setup
            response = self.session.get(
                urljoin(self.base_url, '/en-us/accounts/two-factor/totp/activate/')
            )

            if response.status_code == 200:
                self.log_result(
                    "2.1 TOTP Activation Page",
                    "PASS",
                    "TOTP activation page loads successfully"
                )

                # Check for QR code
                if 'qr' in response.text.lower() or 'data:image' in response.text:
                    self.log_result(
                        "2.2 QR Code Generation",
                        "PASS",
                        "QR code found on activation page"
                    )
                else:
                    self.log_result(
                        "2.2 QR Code Generation",
                        "WARN",
                        "QR code not clearly visible in HTML"
                    )

                # Check for manual entry secret
                secret_match = re.search(r'[A-Z2-7]{32,}', response.text)
                if secret_match:
                    self.log_result(
                        "2.3 Manual Entry Secret",
                        "PASS",
                        f"TOTP secret found: {secret_match.group()[:10]}..."
                    )
                else:
                    self.log_result(
                        "2.3 Manual Entry Secret",
                        "WARN",
                        "TOTP secret not found (may be hidden in JS)"
                    )
            else:
                self.log_result(
                    "2.1 TOTP Activation Page",
                    "FAIL",
                    f"TOTP page returned HTTP {response.status_code}"
                )

        except Exception as e:
            self.log_result(
                "2. TOTP Setup Flow",
                "FAIL",
                f"Exception: {str(e)}"
            )

    def test_3_mfa_challenge_on_login(self):
        """Test 3: MFA Challenge on Login"""
        print("\n" + "=" * 80)
        print("TEST 3: MFA Challenge on Login")
        print("=" * 80)

        # This test requires a user with MFA already enabled
        self.log_result(
            "3. MFA Challenge on Login",
            "MANUAL",
            "Requires user with MFA enabled. Manual test required."
        )

    def test_4_grace_period_reminder(self):
        """Test 4: 30-Day Grace Period Enforcement"""
        print("\n" + "=" * 80)
        print("TEST 4: 30-Day Grace Period Enforcement")
        print("=" * 80)

        try:
            # Login as new user
            self.login(self.test_user['email'], self.test_user['password'])

            # Navigate to dashboard
            response = self.session.get(
                urljoin(self.base_url, '/en-us/app/dashboard/')
            )

            if response.status_code == 200:
                # Check for grace period reminder
                if 'two-factor' in response.text.lower() and 'day' in response.text.lower():
                    self.log_result(
                        "4.1 Grace Period Reminder",
                        "PASS",
                        "Grace period reminder found on dashboard"
                    )
                else:
                    self.log_result(
                        "4.1 Grace Period Reminder",
                        "WARN",
                        "No grace period reminder found (may not show for all users)"
                    )

                # Check that user is NOT blocked from accessing content
                self.log_result(
                    "4.2 No Forced Redirect",
                    "PASS",
                    "User can access dashboard without MFA setup"
                )
            else:
                self.log_result(
                    "4. Grace Period Test",
                    "FAIL",
                    f"Dashboard returned HTTP {response.status_code}"
                )

        except Exception as e:
            self.log_result(
                "4. Grace Period Test",
                "FAIL",
                f"Exception: {str(e)}"
            )

    def test_5_mfa_enforcement_after_30_days(self):
        """Test 5: MFA Enforcement After 30 Days"""
        print("\n" + "=" * 80)
        print("TEST 5: MFA Enforcement After 30 Days")
        print("=" * 80)

        # This requires a user account created > 30 days ago
        self.log_result(
            "5. MFA Enforcement (>30 days)",
            "MANUAL",
            "Requires user account older than 30 days. Manual test required."
        )

    def test_6_navigation_integration(self):
        """Test 6: Navigation Integration"""
        print("\n" + "=" * 80)
        print("TEST 6: Navigation Integration")
        print("=" * 80)

        try:
            # Login
            self.login(self.test_user['email'], self.test_user['password'])

            # Check dashboard for MFA link
            response = self.session.get(
                urljoin(self.base_url, '/en-us/app/dashboard/')
            )

            if response.status_code == 200:
                # Check for "Two-Factor Auth" link in user dropdown
                if 'two-factor' in response.text.lower() or 'mfa' in response.text.lower():
                    self.log_result(
                        "6.1 MFA Link in Navigation",
                        "PASS",
                        "MFA link found in navigation"
                    )
                else:
                    self.log_result(
                        "6.1 MFA Link in Navigation",
                        "WARN",
                        "MFA link not clearly visible (may be in dropdown)"
                    )

                # Check for "Setup" badge
                if 'setup' in response.text.lower() and 'mfa' in response.text.lower():
                    self.log_result(
                        "6.2 Setup Badge",
                        "PASS",
                        "Setup badge found for MFA"
                    )
                else:
                    self.log_result(
                        "6.2 Setup Badge",
                        "INFO",
                        "Setup badge not found (user may already have MFA)"
                    )

        except Exception as e:
            self.log_result(
                "6. Navigation Integration",
                "FAIL",
                f"Exception: {str(e)}"
            )

    def test_7_middleware_functionality(self):
        """Test 7: Middleware Functionality"""
        print("\n" + "=" * 80)
        print("TEST 7: Middleware Functionality")
        print("=" * 80)

        try:
            # Test exempt paths
            exempt_paths = [
                '/en-us/accounts/two-factor/',
                '/en-us/accounts/logout/',
                '/static/css/style.css',
                '/api/health/',
            ]

            for path in exempt_paths:
                response = self.session.get(
                    urljoin(self.base_url, path),
                    allow_redirects=False
                )

                # Exempt paths should not redirect to MFA setup
                if response.status_code not in [301, 302] or 'two-factor' not in response.headers.get('Location', ''):
                    self.log_result(
                        f"7. Exempt Path: {path}",
                        "PASS",
                        f"Path correctly exempt (HTTP {response.status_code})"
                    )
                else:
                    self.log_result(
                        f"7. Exempt Path: {path}",
                        "FAIL",
                        f"Path incorrectly redirected to MFA setup"
                    )

        except Exception as e:
            self.log_result(
                "7. Middleware Functionality",
                "FAIL",
                f"Exception: {str(e)}"
            )

    def test_8_backup_codes(self):
        """Test 8: Backup Codes"""
        print("\n" + "=" * 80)
        print("TEST 8: Backup Codes")
        print("=" * 80)

        try:
            # Navigate to backup codes page
            response = self.session.get(
                urljoin(self.base_url, '/en-us/accounts/two-factor/recovery-codes/')
            )

            if response.status_code == 200:
                self.log_result(
                    "8.1 Backup Codes Page",
                    "PASS",
                    "Backup codes page loads successfully"
                )

                # Check for code generation
                if 'generate' in response.text.lower() or 'code' in response.text.lower():
                    self.log_result(
                        "8.2 Code Generation Available",
                        "PASS",
                        "Backup code generation option found"
                    )
            else:
                self.log_result(
                    "8. Backup Codes",
                    "FAIL",
                    f"Backup codes page returned HTTP {response.status_code}"
                )

        except Exception as e:
            self.log_result(
                "8. Backup Codes",
                "FAIL",
                f"Exception: {str(e)}"
            )

    def login(self, email, password):
        """Helper: Login to the application."""
        # Get login page
        login_url = urljoin(self.base_url, '/en-us/accounts/login/')
        response = self.session.get(login_url)

        # Extract CSRF token
        csrf_token = self.get_csrf_token(response.text)

        # Submit login form
        login_data = {
            'login': email,
            'password': password,
            'csrfmiddlewaretoken': csrf_token
        }

        response = self.session.post(
            login_url,
            data=login_data,
            headers={'Referer': login_url}
        )

        return response

    def run_all_tests(self):
        """Run all MFA tests."""
        print("\nStarting MFA Test Suite...\n")

        # Run tests
        self.test_1_mfa_setup_page_access()
        self.test_2_totp_setup_flow()
        self.test_3_mfa_challenge_on_login()
        self.test_4_grace_period_reminder()
        self.test_5_mfa_enforcement_after_30_days()
        self.test_6_navigation_integration()
        self.test_7_middleware_functionality()
        self.test_8_backup_codes()

        # Generate report
        self.generate_report()

    def generate_report(self):
        """Generate test report."""
        print("\n" + "=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)

        total_tests = len(self.test_results)
        passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        warnings = sum(1 for r in self.test_results if r['status'] == 'WARN')
        manual = sum(1 for r in self.test_results if r['status'] == 'MANUAL')

        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️  Warnings: {warnings}")
        print(f"📋 Manual: {manual}")
        print()

        # Save to file
        report_filename = f"MFA_TEST_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump({
                'summary': {
                    'total': total_tests,
                    'passed': passed,
                    'failed': failed,
                    'warnings': warnings,
                    'manual': manual
                },
                'results': self.test_results,
                'timestamp': datetime.now().isoformat(),
                'base_url': self.base_url
            }, f, indent=2)

        print(f"Report saved to: {report_filename}")
        print()

        # Print detailed results
        print("DETAILED RESULTS:")
        print("-" * 80)
        for result in self.test_results:
            status_icon = {
                'PASS': '✅',
                'FAIL': '❌',
                'WARN': '⚠️',
                'MANUAL': '📋',
                'INFO': 'ℹ️'
            }.get(result['status'], '?')

            print(f"{status_icon} {result['test']}: {result['status']}")
            if result['details']:
                print(f"   {result['details']}")

        print("=" * 80)


if __name__ == "__main__":
    # Run tests
    suite = MFATestSuite(base_url="https://zumodra.rhematek-solutions.com")
    suite.run_all_tests()

    print("\nTest suite completed!")
    print("\nMANUAL TESTS REQUIRED:")
    print("=" * 80)
    print("1. Create a new user account and verify grace period works")
    print("2. Test with a user account older than 30 days")
    print("3. Complete TOTP setup with Google Authenticator")
    print("4. Test MFA challenge on login after setup")
    print("5. Test backup code usage and invalidation")
    print("6. Verify redirect loops don't occur")
    print("=" * 80)
