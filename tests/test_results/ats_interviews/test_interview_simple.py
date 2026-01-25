"""
ATS Interviews Module - Simple HTTP Testing Script
===================================================

A lightweight alternative using requests library only.
Tests all interview endpoints without browser automation.

CREDENTIALS:
- Email: demo@demo.zumodra.rhematek-solutions.com
- Password: demo123!

Usage:
    python test_interview_simple.py

Created: 2026-01-16
"""

import requests
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urljoin


class SimpleInterviewTester:
    """Simple HTTP-based tester for interview module."""

    def __init__(self):
        self.base_url = "https://demo-company.zumodra.rhematek-solutions.com"
        self.email = "demo@demo.zumodra.rhematek-solutions.com"
        self.password = "demo123!"
        self.session = requests.Session()
        self.results = []
        self.interview_ids = []

    def log_result(self, test: str, status: str, details: str = "", url: str = ""):
        """Log test result."""
        emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(status, "•")
        result = {
            "test": test,
            "status": status,
            "details": details,
            "url": url,
            "timestamp": datetime.now().isoformat()
        }
        self.results.append(result)
        print(f"  {emoji} {status}: {test}")
        if details:
            print(f"     {details}")

    def login(self) -> bool:
        """Authenticate and get session."""
        print("\n[TEST 1] Authenticating...")
        print("=" * 60)

        try:
            # Get login page to get CSRF token
            login_url = urljoin(self.base_url, "/accounts/login/")
            response = self.session.get(login_url, verify=False, timeout=10)

            if response.status_code != 200:
                self.log_result("Login", "FAIL", f"Login page returned {response.status_code}", login_url)
                return False

            # Extract CSRF token
            csrf_token = None
            csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\'](.+?)["\']', response.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
            else:
                # Try cookie
                csrf_token = self.session.cookies.get('csrftoken')

            if not csrf_token:
                self.log_result("Login", "FAIL", "Could not find CSRF token", login_url)
                return False

            # Submit login form
            login_data = {
                'login': self.email,
                'password': self.password,
                'csrfmiddlewaretoken': csrf_token,
            }

            headers = {
                'Referer': login_url,
                'Content-Type': 'application/x-www-form-urlencoded',
            }

            response = self.session.post(login_url, data=login_data, headers=headers, verify=False, timeout=10)

            # Check if login successful
            if response.status_code in [200, 302] and 'login' not in response.url.lower():
                self.log_result("Login", "PASS", f"Authenticated as {self.email}", response.url)
                return True
            else:
                self.log_result("Login", "FAIL", f"Login failed. Status: {response.status_code}", login_url)
                return False

        except Exception as e:
            self.log_result("Login", "ERROR", str(e), login_url)
            return False

    def test_url(self, name: str, path: str, expected_content: List[str] = None) -> Tuple[bool, int, str]:
        """Test a URL endpoint."""
        url = urljoin(self.base_url, path)

        try:
            response = self.session.get(url, verify=False, timeout=10)
            status_code = response.status_code
            content = response.text.lower()

            # Check for errors
            if status_code == 404:
                self.log_result(name, "FAIL", "404 Not Found", url)
                return False, status_code, content
            elif status_code == 403:
                self.log_result(name, "FAIL", "403 Forbidden - Permission denied", url)
                return False, status_code, content
            elif status_code == 500:
                self.log_result(name, "FAIL", "500 Internal Server Error", url)
                return False, status_code, content
            elif status_code != 200:
                self.log_result(name, "FAIL", f"Status code: {status_code}", url)
                return False, status_code, content

            # Check expected content
            if expected_content:
                found = [phrase for phrase in expected_content if phrase.lower() in content]
                if found:
                    self.log_result(name, "PASS", f"Found: {', '.join(found[:3])}", url)
                    return True, status_code, content
                else:
                    self.log_result(name, "FAIL", "Expected content not found", url)
                    return False, status_code, content
            else:
                self.log_result(name, "PASS", f"Status: {status_code}", url)
                return True, status_code, content

        except requests.exceptions.Timeout:
            self.log_result(name, "ERROR", "Request timeout", url)
            return False, 0, ""
        except Exception as e:
            self.log_result(name, "ERROR", str(e), url)
            return False, 0, ""

    def extract_interview_ids(self, html: str) -> List[str]:
        """Extract interview UUIDs from HTML."""
        # Match UUID pattern in URLs
        pattern = r'/app/ats/interviews/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'
        matches = re.findall(pattern, html, re.IGNORECASE)
        return list(set(matches))  # Remove duplicates

    def run_tests(self):
        """Run all tests."""
        print("\n" + "=" * 60)
        print("ATS INTERVIEWS MODULE - SIMPLE HTTP TEST")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print(f"User: {self.email}")
        print("=" * 60)

        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Step 1: Login
        if not self.login():
            print("\n❌ Authentication failed. Cannot proceed.")
            return

        # Step 2: Test interview list
        print("\n[TEST 2] Interview List Page")
        print("=" * 60)
        success, status, content = self.test_url(
            "Interview List",
            "/app/ats/interviews/",
            ["interview", "scheduled", "candidate"]
        )

        if success:
            # Extract interview IDs
            self.interview_ids = self.extract_interview_ids(content)
            print(f"  Found {len(self.interview_ids)} interview IDs")
            for interview_id in self.interview_ids[:5]:
                print(f"    - {interview_id}")

        # Step 3: Test interview details
        if self.interview_ids:
            print("\n[TEST 3] Interview Detail Pages")
            print("=" * 60)
            for i, interview_id in enumerate(self.interview_ids[:3], 1):
                self.test_url(
                    f"Interview Detail {i}",
                    f"/app/ats/interviews/{interview_id}/",
                    ["interview", "candidate", "scheduled"]
                )

            # Step 4: Test reschedule
            print("\n[TEST 4] Interview Reschedule")
            print("=" * 60)
            test_id = self.interview_ids[0]
            self.test_url(
                "Reschedule Form",
                f"/app/ats/interviews/{test_id}/reschedule/",
                ["reschedule", "date", "time"]
            )

            # Step 5: Test cancel (POST-only, so GET will fail)
            print("\n[TEST 5] Interview Cancel")
            print("=" * 60)
            success, status, content = self.test_url(
                "Cancel Endpoint",
                f"/app/ats/interviews/{test_id}/cancel/",
                []
            )
            if status == 405:
                print("  ℹ️  Note: Cancel is POST-only (405 Method Not Allowed is expected)")
                self.log_result("Cancel Endpoint", "PASS", "Endpoint exists (POST-only)", f"/app/ats/interviews/{test_id}/cancel/")

            # Step 6: Test feedback
            print("\n[TEST 6] Interview Feedback")
            print("=" * 60)
            self.test_url(
                "Feedback Form",
                f"/app/ats/htmx/interviews/{test_id}/feedback/",
                ["feedback", "rating", "recommendation"]
            )

        else:
            print("\n⚠️  No interviews found. Skipping detail tests.")

        # Step 7: Test schedule form
        print("\n[TEST 7] Interview Schedule Form")
        print("=" * 60)
        self.test_url(
            "Schedule Form",
            "/app/ats/htmx/interviews/schedule/",
            ["schedule", "interview", "date"]
        )

        # Generate summary
        self.generate_summary()

    def generate_summary(self):
        """Print and save test summary."""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)

        total = len(self.results)
        passed = sum(1 for r in self.results if r["status"] == "PASS")
        failed = sum(1 for r in self.results if r["status"] == "FAIL")
        errors = sum(1 for r in self.results if r["status"] == "ERROR")

        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️  Errors: {errors}")
        print(f"Success Rate: {(passed/total*100) if total > 0 else 0:.1f}%")

        # Save report
        report_path = Path(__file__).parent / f"SIMPLE_TEST_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump({
                "summary": {
                    "total": total,
                    "passed": passed,
                    "failed": failed,
                    "errors": errors,
                    "success_rate": (passed/total*100) if total > 0 else 0
                },
                "interview_ids": self.interview_ids,
                "results": self.results
            }, f, indent=2)

        print(f"\n📝 Report saved: {report_path}")
        print("=" * 60)

        # Show failed tests
        failed_tests = [r for r in self.results if r["status"] in ["FAIL", "ERROR"]]
        if failed_tests:
            print("\n❌ FAILED TESTS:")
            for test in failed_tests:
                print(f"  - {test['test']}: {test['details']}")
                print(f"    URL: {test['url']}")


def main():
    """Main entry point."""
    tester = SimpleInterviewTester()
    tester.run_tests()


if __name__ == "__main__":
    main()
