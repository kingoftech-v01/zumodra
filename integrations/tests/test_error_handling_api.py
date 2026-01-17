#!/usr/bin/env python
"""
Error Handling API Testing Script
Tests error scenarios via API endpoints without Selenium
"""

import requests
import json
from datetime import datetime
from pathlib import Path


class APIErrorTester:
    def __init__(self):
        self.base_url = "https://demo-company.zumodra.rhematek-solutions.com"
        self.results_dir = Path("test_results/errors")
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.valid_email = "demo@zumodra.com"
        self.valid_password = "Demo123!"

        self.results = {
            "timestamp": datetime.now().isoformat(),
            "base_url": self.base_url,
            "tests": [],
            "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0},
            "security_concerns": []
        }

    def log_test(self, test_name, status, message, details=None):
        """Log test result"""
        result = {
            "test": test_name,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }
        self.results["tests"].append(result)
        self.results["summary"]["total"] += 1

        if status == "PASS":
            self.results["summary"]["passed"] += 1
            print(f"[PASS] {test_name}: {message}")
        elif status == "FAIL":
            self.results["summary"]["failed"] += 1
            print(f"[FAIL] {test_name}: {message}")
        elif status == "WARNING":
            self.results["summary"]["warnings"] += 1
            print(f"[WARN] {test_name}: {message}")

    def add_security_concern(self, concern, severity="MEDIUM"):
        """Add security concern"""
        self.results["security_concerns"].append({
            "concern": concern,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        })
        print(f"  [SECURITY {severity}] {concern}")

    def test_unauthenticated_api_access(self):
        """Test API access without authentication"""
        print("\n" + "="*80)
        print("TEST: UNAUTHENTICATED API ACCESS")
        print("="*80)

        endpoints = [
            "/api/v1/ats/jobs/",
            "/api/v1/ats/candidates/",
            "/api/v1/hr/employees/",
            "/api/v1/dashboard/overview/",
        ]

        for endpoint in endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                response = requests.get(url, timeout=10)

                if response.status_code == 401:
                    self.log_test(
                        f"Unauth API: {endpoint}",
                        "PASS",
                        "Correctly returns 401 Unauthorized",
                        {"status_code": response.status_code}
                    )
                elif response.status_code == 403:
                    self.log_test(
                        f"Unauth API: {endpoint}",
                        "PASS",
                        "Correctly returns 403 Forbidden",
                        {"status_code": response.status_code}
                    )
                elif response.status_code == 200:
                    self.log_test(
                        f"Unauth API: {endpoint}",
                        "FAIL",
                        "API accessible without authentication!",
                        {"status_code": response.status_code}
                    )
                    self.add_security_concern(
                        f"API endpoint {endpoint} accessible without auth",
                        "CRITICAL"
                    )
                else:
                    self.log_test(
                        f"Unauth API: {endpoint}",
                        "WARNING",
                        f"Unexpected status code: {response.status_code}",
                        {"status_code": response.status_code}
                    )

            except requests.exceptions.RequestException as e:
                self.log_test(
                    f"Unauth API: {endpoint}",
                    "FAIL",
                    f"Request failed: {str(e)}"
                )

    def test_404_errors(self):
        """Test non-existent resources"""
        print("\n" + "="*80)
        print("TEST: 404 ERROR RESPONSES")
        print("="*80)

        urls = [
            "/api/v1/ats/jobs/99999/",
            "/api/v1/ats/candidates/99999/",
            "/nonexistent-endpoint",
            "/app/../../../etc/passwd",
        ]

        for url_path in urls:
            try:
                url = f"{self.base_url}{url_path}"
                response = requests.get(url, timeout=10)

                if response.status_code == 404:
                    self.log_test(
                        f"404 Test: {url_path}",
                        "PASS",
                        "Correctly returns 404 Not Found",
                        {"status_code": response.status_code}
                    )
                else:
                    self.log_test(
                        f"404 Test: {url_path}",
                        "WARNING",
                        f"Unexpected status: {response.status_code}",
                        {"status_code": response.status_code}
                    )

            except requests.exceptions.RequestException as e:
                self.log_test(
                    f"404 Test: {url_path}",
                    "FAIL",
                    f"Request failed: {str(e)}"
                )

    def test_csrf_protection(self):
        """Test CSRF protection"""
        print("\n" + "="*80)
        print("TEST: CSRF PROTECTION")
        print("="*80)

        try:
            # Test POST without CSRF token
            response = requests.post(
                f"{self.base_url}/accounts/login/",
                data={"login": self.valid_email, "password": self.valid_password},
                timeout=10,
                allow_redirects=False
            )

            if response.status_code == 403:
                self.log_test(
                    "CSRF Protection",
                    "PASS",
                    "POST rejected without CSRF token (403)",
                    {"status_code": response.status_code}
                )
            elif "csrf" in response.text.lower():
                self.log_test(
                    "CSRF Protection",
                    "PASS",
                    "CSRF error in response",
                    {"status_code": response.status_code}
                )
            else:
                self.log_test(
                    "CSRF Protection",
                    "WARNING",
                    f"Unclear CSRF protection (status: {response.status_code})",
                    {"status_code": response.status_code}
                )

        except requests.exceptions.RequestException as e:
            self.log_test(
                "CSRF Protection",
                "FAIL",
                f"Request failed: {str(e)}"
            )

    def test_malicious_inputs(self):
        """Test injection attempts"""
        print("\n" + "="*80)
        print("TEST: MALICIOUS INPUT HANDLING")
        print("="*80)

        malicious_inputs = [
            {
                "name": "SQL Injection",
                "email": "admin'--",
                "password": "' OR '1'='1"
            },
            {
                "name": "XSS Attempt",
                "email": "<script>alert('xss')</script>@test.com",
                "password": "password"
            },
            {
                "name": "Path Traversal",
                "email": "../../../etc/passwd",
                "password": "password"
            }
        ]

        for test_case in malicious_inputs:
            try:
                # First get the login page to extract CSRF token
                session = requests.Session()
                login_page = session.get(f"{self.base_url}/accounts/login/", timeout=10)

                # Try to extract CSRF token
                csrf_token = None
                if 'csrftoken' in session.cookies:
                    csrf_token = session.cookies['csrftoken']

                # Attempt login with malicious input
                data = {
                    "login": test_case["email"],
                    "password": test_case["password"]
                }
                if csrf_token:
                    data['csrfmiddlewaretoken'] = csrf_token

                response = session.post(
                    f"{self.base_url}/accounts/login/",
                    data=data,
                    timeout=10,
                    allow_redirects=False
                )

                # Check if login was rejected
                if response.status_code in [400, 403]:
                    self.log_test(
                        f"Malicious Input: {test_case['name']}",
                        "PASS",
                        "Input correctly rejected",
                        {"status_code": response.status_code}
                    )
                elif response.status_code == 302:
                    # Check if it's redirecting to dashboard (successful login)
                    if 'dashboard' in response.headers.get('Location', ''):
                        self.log_test(
                            f"Malicious Input: {test_case['name']}",
                            "FAIL",
                            "Malicious input accepted!",
                            {"status_code": response.status_code}
                        )
                        self.add_security_concern(
                            f"Malicious input accepted: {test_case['name']}",
                            "CRITICAL"
                        )
                    else:
                        self.log_test(
                            f"Malicious Input: {test_case['name']}",
                            "PASS",
                            "Login failed as expected",
                            {"status_code": response.status_code}
                        )
                else:
                    self.log_test(
                        f"Malicious Input: {test_case['name']}",
                        "WARNING",
                        f"Unexpected status: {response.status_code}",
                        {"status_code": response.status_code}
                    )

            except requests.exceptions.RequestException as e:
                self.log_test(
                    f"Malicious Input: {test_case['name']}",
                    "FAIL",
                    f"Request failed: {str(e)}"
                )

    def test_rate_limiting(self):
        """Test if rate limiting is in place"""
        print("\n" + "="*80)
        print("TEST: RATE LIMITING")
        print("="*80)

        try:
            # Make multiple rapid requests
            responses = []
            for i in range(20):
                response = requests.get(
                    f"{self.base_url}/accounts/login/",
                    timeout=10
                )
                responses.append(response.status_code)

            # Check if any requests were rate limited (429)
            rate_limited = any(status == 429 for status in responses)

            if rate_limited:
                self.log_test(
                    "Rate Limiting",
                    "PASS",
                    "Rate limiting detected",
                    {"responses": responses}
                )
            else:
                self.log_test(
                    "Rate Limiting",
                    "WARNING",
                    "No rate limiting detected in 20 requests",
                    {"responses": responses}
                )

        except requests.exceptions.RequestException as e:
            self.log_test(
                "Rate Limiting",
                "FAIL",
                f"Request failed: {str(e)}"
            )

    def generate_report(self):
        """Generate test report"""
        print("\n" + "="*80)
        print("GENERATING REPORT")
        print("="*80)

        # JSON report
        json_path = self.results_dir / f"api_error_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nJSON report: {json_path}")

        # Markdown report
        md_path = self.results_dir / f"API_ERROR_TEST_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write("# API Error Handling Test Report\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Base URL:** {self.base_url}\n\n")

            # Summary
            f.write("## Summary\n\n")
            f.write(f"- Total: {self.results['summary']['total']}\n")
            f.write(f"- Passed: {self.results['summary']['passed']}\n")
            f.write(f"- Failed: {self.results['summary']['failed']}\n")
            f.write(f"- Warnings: {self.results['summary']['warnings']}\n\n")

            # Security concerns
            if self.results['security_concerns']:
                f.write("## Security Concerns\n\n")
                for concern in self.results['security_concerns']:
                    f.write(f"- **[{concern['severity']}]** {concern['concern']}\n")
                f.write("\n")

            # Test results
            f.write("## Test Results\n\n")
            for test in self.results['tests']:
                f.write(f"### {test['test']}\n")
                f.write(f"- **Status:** {test['status']}\n")
                f.write(f"- **Message:** {test['message']}\n")
                if test.get('details'):
                    f.write(f"- **Details:** {json.dumps(test['details'])}\n")
                f.write("\n")

        print(f"Markdown report: {md_path}")

        # Print summary
        print("\n" + "="*80)
        print("TEST SUMMARY")
        print("="*80)
        print(f"Total: {self.results['summary']['total']}")
        print(f"Passed: {self.results['summary']['passed']}")
        print(f"Failed: {self.results['summary']['failed']}")
        print(f"Warnings: {self.results['summary']['warnings']}")

        if self.results['security_concerns']:
            print(f"\nSecurity Concerns: {len(self.results['security_concerns'])}")
            for concern in self.results['security_concerns']:
                print(f"  - [{concern['severity']}] {concern['concern']}")

    def run_all_tests(self):
        """Run all tests"""
        print("\n" + "="*80)
        print("STARTING API ERROR HANDLING TESTS")
        print("="*80)

        self.test_unauthenticated_api_access()
        self.test_404_errors()
        self.test_csrf_protection()
        self.test_malicious_inputs()
        self.test_rate_limiting()
        self.generate_report()


if __name__ == "__main__":
    print("""
    ================================================================
           API ERROR HANDLING TEST SUITE
      Testing: demo-company.zumodra.rhematek-solutions.com
    ================================================================
    """)

    tester = APIErrorTester()
    tester.run_all_tests()

    print("\n" + "="*80)
    print("TESTS COMPLETED")
    print("="*80)
