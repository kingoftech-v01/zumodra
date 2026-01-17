#!/usr/bin/env python3
"""
Zumodra API-Based Integration Testing
======================================

Comprehensive API and integration point testing without browser dependencies.
Tests all critical endpoints and integration points.

Domain: https://zumodra.rhematek-solutions.com
Demo Tenant: https://demo-company.zumodra.rhematek-solutions.com
"""

import sys
import json
import time
import requests
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum

# Windows UTF-8 support
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


# Configuration
class Config:
    BASE_URL = "https://zumodra.rhematek-solutions.com"
    DEMO_TENANT_URL = "https://demo-company.zumodra.rhematek-solutions.com"
    API_BASE = f"{BASE_URL}/api/v1"
    DEMO_API_BASE = f"{DEMO_TENANT_URL}/api/v1"

    DEMO_EMAIL = "company.owner@demo.zumodra.rhematek-solutions.com"
    DEMO_PASSWORD = "Demo@2024!"

    TIMEOUT = 15
    RESULTS_DIR = Path("./test_results/api_integration")

    @classmethod
    def setup(cls):
        cls.RESULTS_DIR.mkdir(parents=True, exist_ok=True)


class TestStatus(Enum):
    PASSED = "✅ PASSED"
    FAILED = "❌ FAILED"
    WARNING = "⚠️  WARNING"
    BLOCKED = "🚫 BLOCKED"


@dataclass
class TestResult:
    name: str
    status: TestStatus
    response_time_ms: float = 0.0
    status_code: Optional[int] = None
    message: str = ""
    details: Dict = field(default_factory=dict)


class IntegrationTester:
    def __init__(self):
        Config.setup()
        self.results: List[TestResult] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Zumodra-Integration-Test/1.0',
            'Accept': 'application/json, text/html',
        })
        self.auth_token = None

    def log(self, emoji: str, message: str):
        print(f"{emoji} {message}")

    def test_endpoint(self, name: str, url: str, method: str = "GET",
                     expected_status: int = 200, **kwargs) -> TestResult:
        """Test a single endpoint"""
        self.log("🔍", f"Testing: {name}")

        start = time.time()
        try:
            response = self.session.request(
                method, url, timeout=Config.TIMEOUT, **kwargs
            )
            duration_ms = (time.time() - start) * 1000

            if response.status_code == expected_status:
                status = TestStatus.PASSED
                message = f"OK ({response.status_code})"
            elif 200 <= response.status_code < 300:
                status = TestStatus.WARNING
                message = f"Unexpected success code ({response.status_code})"
            elif response.status_code == 404:
                status = TestStatus.BLOCKED
                message = "Endpoint not found (404)"
            else:
                status = TestStatus.FAILED
                message = f"Status {response.status_code}"

            return TestResult(
                name=name,
                status=status,
                response_time_ms=duration_ms,
                status_code=response.status_code,
                message=message,
                details={
                    'url': url,
                    'method': method,
                    'content_type': response.headers.get('content-type', '')
                }
            )
        except requests.exceptions.Timeout:
            return TestResult(
                name=name,
                status=TestStatus.FAILED,
                message="Timeout exceeded",
                details={'url': url, 'timeout': Config.TIMEOUT}
            )
        except requests.exceptions.ConnectionError as e:
            return TestResult(
                name=name,
                status=TestStatus.FAILED,
                message=f"Connection error: {str(e)[:100]}",
                details={'url': url}
            )
        except Exception as e:
            return TestResult(
                name=name,
                status=TestStatus.FAILED,
                message=f"Error: {str(e)[:100]}",
                details={'url': url}
            )

    # ========================================================================
    # CORE INFRASTRUCTURE TESTS
    # ========================================================================

    def test_core_infrastructure(self):
        """Test core infrastructure endpoints"""
        self.log("🏗️ ", "Testing Core Infrastructure...")

        # Public homepage
        result = self.test_endpoint(
            "Public Homepage",
            Config.BASE_URL,
            expected_status=200
        )
        self.results.append(result)

        # Demo tenant homepage
        result = self.test_endpoint(
            "Demo Tenant Homepage",
            Config.DEMO_TENANT_URL,
            expected_status=200
        )
        self.results.append(result)

        # Login page
        result = self.test_endpoint(
            "Login Page",
            f"{Config.DEMO_TENANT_URL}/accounts/login/",
            expected_status=200
        )
        self.results.append(result)

        # Static files
        result = self.test_endpoint(
            "Static Files (HTMX)",
            f"{Config.BASE_URL}/static/assets/js/vendor/htmx.min.js",
            expected_status=200
        )
        self.results.append(result)

    # ========================================================================
    # AUTHENTICATION TESTS
    # ========================================================================

    def test_authentication(self):
        """Test authentication endpoints"""
        self.log("🔐", "Testing Authentication...")

        # Test login page
        result = self.test_endpoint(
            "Auth: Login Page",
            f"{Config.DEMO_TENANT_URL}/accounts/login/",
            expected_status=200
        )
        self.results.append(result)

        # Test signup page
        result = self.test_endpoint(
            "Auth: Signup Page",
            f"{Config.DEMO_TENANT_URL}/accounts/signup/",
            expected_status=200
        )
        self.results.append(result)

        # Test password reset page
        result = self.test_endpoint(
            "Auth: Password Reset",
            f"{Config.DEMO_TENANT_URL}/accounts/password/reset/",
            expected_status=200
        )
        self.results.append(result)

    # ========================================================================
    # ATS ENDPOINT TESTS
    # ========================================================================

    def test_ats_endpoints(self):
        """Test ATS endpoints"""
        self.log("📋", "Testing ATS Endpoints...")

        # Jobs endpoints
        result = self.test_endpoint(
            "ATS: Jobs List Page",
            f"{Config.DEMO_TENANT_URL}/app/ats/jobs/",
            expected_status=200
        )
        self.results.append(result)

        # Candidates endpoint
        result = self.test_endpoint(
            "ATS: Candidates List Page",
            f"{Config.DEMO_TENANT_URL}/app/ats/candidates/",
            expected_status=200
        )
        self.results.append(result)

        # Applications endpoint
        result = self.test_endpoint(
            "ATS: Applications List Page",
            f"{Config.DEMO_TENANT_URL}/app/ats/applications/",
            expected_status=200
        )
        self.results.append(result)

        # Interviews endpoint
        result = self.test_endpoint(
            "ATS: Interviews List Page",
            f"{Config.DEMO_TENANT_URL}/app/ats/interviews/",
            expected_status=200
        )
        self.results.append(result)

        # Pipeline endpoint
        result = self.test_endpoint(
            "ATS: Pipeline Board",
            f"{Config.DEMO_TENANT_URL}/app/ats/pipeline/",
            expected_status=200
        )
        self.results.append(result)

    # ========================================================================
    # HR ENDPOINT TESTS
    # ========================================================================

    def test_hr_endpoints(self):
        """Test HR endpoints"""
        self.log("👥", "Testing HR Endpoints...")

        # Employees endpoint
        result = self.test_endpoint(
            "HR: Employees List",
            f"{Config.DEMO_TENANT_URL}/app/hr/employees/",
            expected_status=200
        )
        self.results.append(result)

        # Time off endpoint
        result = self.test_endpoint(
            "HR: Time Off Requests",
            f"{Config.DEMO_TENANT_URL}/app/hr/time-off/",
            expected_status=200
        )
        self.results.append(result)

        # Onboarding endpoint
        result = self.test_endpoint(
            "HR: Onboarding",
            f"{Config.DEMO_TENANT_URL}/app/hr/onboarding/",
            expected_status=200
        )
        self.results.append(result)

    # ========================================================================
    # DASHBOARD TESTS
    # ========================================================================

    def test_dashboard_endpoints(self):
        """Test dashboard endpoints"""
        self.log("📊", "Testing Dashboard Endpoints...")

        # Main dashboard
        result = self.test_endpoint(
            "Dashboard: Main",
            f"{Config.DEMO_TENANT_URL}/app/dashboard/",
            expected_status=200
        )
        self.results.append(result)

        # User profile
        result = self.test_endpoint(
            "Dashboard: User Profile",
            f"{Config.DEMO_TENANT_URL}/app/accounts/profile/",
            expected_status=200
        )
        self.results.append(result)

    # ========================================================================
    # API ENDPOINT TESTS
    # ========================================================================

    def test_api_endpoints(self):
        """Test API endpoints"""
        self.log("🔌", "Testing API Endpoints...")

        # API root
        result = self.test_endpoint(
            "API: Root",
            f"{Config.API_BASE}/",
            expected_status=200
        )
        self.results.append(result)

        # API health
        result = self.test_endpoint(
            "API: Health Check",
            f"{Config.API_BASE}/health/",
            expected_status=200
        )
        self.results.append(result)

        # API docs
        result = self.test_endpoint(
            "API: Swagger Docs",
            f"{Config.API_BASE}/docs/",
            expected_status=200
        )
        self.results.append(result)

    # ========================================================================
    # PUBLIC CAREER PAGES
    # ========================================================================

    def test_career_pages(self):
        """Test public career pages"""
        self.log("💼", "Testing Career Pages...")

        # Careers homepage
        result = self.test_endpoint(
            "Careers: Homepage",
            f"{Config.DEMO_TENANT_URL}/careers/",
            expected_status=200
        )
        self.results.append(result)

        # Jobs listing
        result = self.test_endpoint(
            "Careers: Jobs Listing",
            f"{Config.DEMO_TENANT_URL}/careers/jobs/",
            expected_status=200
        )
        self.results.append(result)

    # ========================================================================
    # INTEGRATION POINT TESTS
    # ========================================================================

    def test_security_headers(self):
        """Test security headers"""
        self.log("🔒", "Testing Security Headers...")

        try:
            response = self.session.get(
                Config.DEMO_TENANT_URL,
                timeout=Config.TIMEOUT
            )

            headers = response.headers

            # Check for important security headers
            checks = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            }

            issues = []
            for header, expected in checks.items():
                value = headers.get(header)
                if isinstance(expected, list):
                    if value not in expected:
                        issues.append(f"{header} missing or incorrect")
                elif value != expected:
                    issues.append(f"{header} missing or incorrect")

            if not issues:
                status = TestStatus.PASSED
                message = "All security headers present"
            else:
                status = TestStatus.WARNING
                message = f"Issues: {', '.join(issues)}"

            self.results.append(TestResult(
                name="Security Headers",
                status=status,
                message=message,
                details={'headers': dict(headers)}
            ))

        except Exception as e:
            self.results.append(TestResult(
                name="Security Headers",
                status=TestStatus.FAILED,
                message=f"Error: {str(e)}"
            ))

    def test_ssl_certificate(self):
        """Test SSL certificate"""
        self.log("🔐", "Testing SSL Certificate...")

        try:
            response = self.session.get(
                Config.BASE_URL,
                timeout=Config.TIMEOUT,
                verify=True
            )

            self.results.append(TestResult(
                name="SSL Certificate",
                status=TestStatus.PASSED,
                message="Valid SSL certificate",
                status_code=response.status_code
            ))
        except requests.exceptions.SSLError as e:
            self.results.append(TestResult(
                name="SSL Certificate",
                status=TestStatus.FAILED,
                message=f"SSL Error: {str(e)[:100]}"
            ))
        except Exception as e:
            self.results.append(TestResult(
                name="SSL Certificate",
                status=TestStatus.FAILED,
                message=f"Error: {str(e)[:100]}"
            ))

    # ========================================================================
    # REPORT GENERATION
    # ========================================================================

    def generate_report(self):
        """Generate test report"""
        self.log("📊", "Generating Report...")

        # Count results by status
        passed = sum(1 for r in self.results if r.status == TestStatus.PASSED)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAILED)
        warning = sum(1 for r in self.results if r.status == TestStatus.WARNING)
        blocked = sum(1 for r in self.results if r.status == TestStatus.BLOCKED)
        total = len(self.results)

        # Calculate success rate
        success_rate = (passed / total * 100) if total > 0 else 0

        # Generate report
        report = {
            "timestamp": datetime.now().isoformat(),
            "environment": "Production",
            "base_url": Config.BASE_URL,
            "demo_tenant": Config.DEMO_TENANT_URL,
            "summary": {
                "total_tests": total,
                "passed": passed,
                "failed": failed,
                "warning": warning,
                "blocked": blocked,
                "success_rate": round(success_rate, 2)
            },
            "results": []
        }

        # Add individual results
        for result in self.results:
            report["results"].append({
                "name": result.name,
                "status": result.status.value,
                "response_time_ms": round(result.response_time_ms, 2),
                "status_code": result.status_code,
                "message": result.message,
                "details": result.details
            })

        # Save report
        report_file = Config.RESULTS_DIR / f"api_integration_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        self.log("✅", f"Report saved: {report_file}")

        return report

    def print_summary(self, report: Dict):
        """Print summary to console"""
        print("\n" + "="*80)
        print("ZUMODRA API INTEGRATION TEST SUMMARY")
        print("="*80)

        summary = report["summary"]

        print(f"\n📊 RESULTS:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   ✅ Passed: {summary['passed']}")
        print(f"   ❌ Failed: {summary['failed']}")
        print(f"   ⚠️  Warnings: {summary['warning']}")
        print(f"   🚫 Blocked: {summary['blocked']}")
        print(f"   Success Rate: {summary['success_rate']}%")

        # Show failed tests
        if summary['failed'] > 0:
            print(f"\n❌ FAILED TESTS:")
            for result in self.results:
                if result.status == TestStatus.FAILED:
                    print(f"   - {result.name}: {result.message}")

        # Show blocked tests
        if summary['blocked'] > 0:
            print(f"\n🚫 BLOCKED TESTS:")
            for result in self.results:
                if result.status == TestStatus.BLOCKED:
                    print(f"   - {result.name}: {result.message}")

        # Show warnings
        if summary['warning'] > 0:
            print(f"\n⚠️  WARNINGS:")
            for result in self.results:
                if result.status == TestStatus.WARNING:
                    print(f"   - {result.name}: {result.message}")

        print("\n" + "="*80)

    # ========================================================================
    # MAIN TEST RUNNER
    # ========================================================================

    def run_all_tests(self):
        """Run all integration tests"""
        print("\n" + "="*80)
        print("ZUMODRA API INTEGRATION TEST SUITE")
        print("="*80 + "\n")

        self.log("🚀", "Starting integration tests...")

        # Run all test suites
        self.test_core_infrastructure()
        self.test_authentication()
        self.test_ats_endpoints()
        self.test_hr_endpoints()
        self.test_dashboard_endpoints()
        self.test_api_endpoints()
        self.test_career_pages()
        self.test_security_headers()
        self.test_ssl_certificate()

        # Generate and display report
        report = self.generate_report()
        self.print_summary(report)

        self.log("✅", "All tests completed")

        return report


def main():
    """Main entry point"""
    tester = IntegrationTester()
    report = tester.run_all_tests()

    # Exit with appropriate code
    if report["summary"]["failed"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
