#!/usr/bin/env python
"""
Production API Testing Script for zumodra.rhematek-solutions.com

This script tests all REST API endpoints to verify functionality before tomorrow's demo.
It creates a detailed report of working and broken endpoints.

Usage:
    python test_production_api.py

Requirements:
    pip install requests
"""

import json
import sys
from typing import Dict, List, Tuple, Optional
import requests
from requests.exceptions import RequestException


# Configuration
BASE_URL = "https://zumodra.rhematek-solutions.com"
API_BASE = f"{BASE_URL}/api/v1"

# Test credentials (you'll need to provide valid credentials)
TEST_CREDENTIALS = {
    "email": "",  # Fill in with a valid test user email
    "password": ""  # Fill in with a valid test user password
}


class APITester:
    """API endpoint testing class"""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.api_base = f"{base_url}/api/v1"
        self.session = requests.Session()
        self.access_token = None
        self.refresh_token = None
        self.working_endpoints = []
        self.broken_endpoints = []
        self.sample_responses = {}

    def test_health_check(self) -> Dict:
        """Test the health check endpoint (no auth required)"""
        print("\n" + "="*80)
        print("TESTING HEALTH CHECK ENDPOINTS")
        print("="*80)

        health_endpoints = [
            "/health/",
            "/health/ready/",
            "/health/live/"
        ]

        results = {}
        for endpoint in health_endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                response = self.session.get(url, timeout=10)
                status = "[WORKING]" if response.status_code == 200 else f"[FAILED] ({response.status_code})"
                results[endpoint] = {
                    "status": status,
                    "status_code": response.status_code,
                    "response": response.json() if response.status_code == 200 else None
                }
                print(f"{status} - {endpoint}")
                if response.status_code == 200:
                    self.working_endpoints.append(endpoint)
                    self.sample_responses[endpoint] = response.json()
                else:
                    self.broken_endpoints.append({
                        "endpoint": endpoint,
                        "status_code": response.status_code,
                        "error": response.text
                    })
            except RequestException as e:
                results[endpoint] = {
                    "status": "[ERROR]",
                    "error": str(e)
                }
                print(f"[ERROR] - {endpoint}: {e}")
                self.broken_endpoints.append({
                    "endpoint": endpoint,
                    "error": str(e)
                })

        return results

    def test_api_root(self) -> Dict:
        """Test the API root endpoint"""
        print("\n" + "="*80)
        print("TESTING API ROOT ENDPOINT")
        print("="*80)

        url = f"{self.base_url}/api/"
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                print("[WORKING] - /api/")
                self.working_endpoints.append("/api/")
                self.sample_responses["/api/"] = response.json()
                print("\nAPI Information:")
                print(json.dumps(response.json(), indent=2))
                return {"status": "[WORKING]", "data": response.json()}
            elif response.status_code == 401:
                print("[REQUIRES AUTH] - /api/")
                self.broken_endpoints.append({
                    "endpoint": "/api/",
                    "status_code": 401,
                    "error": "Authentication required"
                })
                return {"status": "[REQUIRES AUTH]", "status_code": 401}
            else:
                print(f"[FAILED] - /api/ ({response.status_code})")
                self.broken_endpoints.append({
                    "endpoint": "/api/",
                    "status_code": response.status_code,
                    "error": response.text
                })
                return {"status": "[FAILED]", "status_code": response.status_code}
        except RequestException as e:
            print(f"[ERROR] - /api/: {e}")
            self.broken_endpoints.append({
                "endpoint": "/api/",
                "error": str(e)
            })
            return {"status": "[ERROR]", "error": str(e)}

    def obtain_jwt_token(self, username: str, password: str) -> bool:
        """Obtain JWT token for authentication"""
        print("\n" + "="*80)
        print("TESTING JWT AUTHENTICATION")
        print("="*80)

        if not username or not password:
            print("[!] SKIPPED - No credentials provided")
            print("Please set TEST_CREDENTIALS in the script to test authenticated endpoints")
            return False

        url = f"{self.api_base}/auth/token/"
        payload = {
            "email": username,
            "password": password
        }

        try:
            response = self.session.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access')
                self.refresh_token = data.get('refresh')
                self.session.headers.update({
                    'Authorization': f'Bearer {self.access_token}'
                })
                print("[OK] WORKING - JWT Token obtained successfully")
                self.working_endpoints.append("/api/v1/auth/token/")
                return True
            else:
                print(f"[X] FAILED - JWT Token ({response.status_code}): {response.text}")
                self.broken_endpoints.append({
                    "endpoint": "/api/v1/auth/token/",
                    "status_code": response.status_code,
                    "error": response.text
                })
                return False
        except RequestException as e:
            print(f"[X] ERROR - JWT Token: {e}")
            self.broken_endpoints.append({
                "endpoint": "/api/v1/auth/token/",
                "error": str(e)
            })
            return False

    def test_endpoint(self, endpoint: str, method: str = "GET",
                     requires_auth: bool = True, description: str = "") -> Dict:
        """Test a single API endpoint"""
        url = f"{self.api_base}{endpoint}"

        if requires_auth and not self.access_token:
            return {
                "status": "[!] SKIPPED",
                "reason": "No authentication token available"
            }

        try:
            if method == "GET":
                response = self.session.get(url, timeout=10)
            elif method == "POST":
                response = self.session.post(url, json={}, timeout=10)
            else:
                return {"status": "[!] SKIPPED", "reason": f"Method {method} not implemented"}

            status_code = response.status_code

            # Success codes
            if status_code in [200, 201]:
                status = "[OK] WORKING"
                self.working_endpoints.append(endpoint)
                try:
                    self.sample_responses[endpoint] = response.json()
                except:
                    self.sample_responses[endpoint] = response.text
            # Empty/No content (also success)
            elif status_code == 204:
                status = "[OK] WORKING (No Content)"
                self.working_endpoints.append(endpoint)
            # Unauthorized (endpoint exists but needs auth or different permissions)
            elif status_code == 401:
                status = "[!] UNAUTHORIZED"
                self.broken_endpoints.append({
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "error": "Authentication required or invalid token"
                })
            # Forbidden (endpoint exists but user lacks permission)
            elif status_code == 403:
                status = "[!] FORBIDDEN"
                self.broken_endpoints.append({
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "error": "Insufficient permissions"
                })
            # Not found (endpoint doesn't exist)
            elif status_code == 404:
                status = "[X] NOT FOUND"
                self.broken_endpoints.append({
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "error": "Endpoint not found"
                })
            # Method not allowed
            elif status_code == 405:
                status = "[!] METHOD NOT ALLOWED"
                self.broken_endpoints.append({
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "error": f"Method {method} not allowed"
                })
            # Server error
            elif status_code >= 500:
                status = "[X] SERVER ERROR"
                self.broken_endpoints.append({
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "error": response.text[:200]
                })
            # Other
            else:
                status = f"[!] UNEXPECTED ({status_code})"
                self.broken_endpoints.append({
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "error": response.text[:200]
                })

            print(f"{status} - {method} {endpoint} {f'({description})' if description else ''}")

            return {
                "status": status,
                "status_code": status_code,
                "description": description
            }

        except RequestException as e:
            print(f"[X] ERROR - {method} {endpoint}: {e}")
            self.broken_endpoints.append({
                "endpoint": endpoint,
                "error": str(e)
            })
            return {
                "status": "[X] ERROR",
                "error": str(e)
            }

    def test_ats_endpoints(self):
        """Test ATS (Applicant Tracking System) endpoints"""
        print("\n" + "="*80)
        print("TESTING ATS ENDPOINTS")
        print("="*80)

        endpoints = [
            ("/ats/jobs/", "GET", "List all jobs"),
            ("/ats/candidates/", "GET", "List all candidates"),
            ("/ats/applications/", "GET", "List all applications"),
            ("/ats/interviews/", "GET", "List all interviews"),
            ("/ats/offers/", "GET", "List all offers"),
            ("/ats/pipelines/", "GET", "List all pipelines"),
            ("/ats/pipeline-stages/", "GET", "List all pipeline stages"),
        ]

        for endpoint, method, description in endpoints:
            self.test_endpoint(endpoint, method, description=description)

    def test_hr_endpoints(self):
        """Test HR (Human Resources) endpoints"""
        print("\n" + "="*80)
        print("TESTING HR ENDPOINTS")
        print("="*80)

        endpoints = [
            ("/hr/employees/", "GET", "List all employees"),
            ("/hr/time-off-requests/", "GET", "List time-off requests"),
            ("/hr/onboarding/", "GET", "List onboarding tasks"),
            ("/hr/departments/", "GET", "List departments"),
            ("/hr/positions/", "GET", "List positions"),
            ("/hr/performance-reviews/", "GET", "List performance reviews"),
        ]

        for endpoint, method, description in endpoints:
            self.test_endpoint(endpoint, method, description=description)

    def test_marketplace_endpoints(self):
        """Test Marketplace endpoints"""
        print("\n" + "="*80)
        print("TESTING MARKETPLACE/SERVICES ENDPOINTS")
        print("="*80)

        endpoints = [
            ("/marketplace/categories/", "GET", "List service categories"),
            ("/marketplace/providers/", "GET", "List service providers"),
            ("/marketplace/services/", "GET", "List services"),
            ("/marketplace/requests/", "GET", "List service requests"),
            ("/marketplace/proposals/", "GET", "List proposals"),
            ("/marketplace/contracts/", "GET", "List contracts"),
            ("/services/categories/", "GET", "List service categories (new API)"),
            ("/services/listings/", "GET", "List service listings"),
        ]

        for endpoint, method, description in endpoints:
            self.test_endpoint(endpoint, method, description=description)

    def test_finance_endpoints(self):
        """Test Finance endpoints"""
        print("\n" + "="*80)
        print("TESTING FINANCE ENDPOINTS")
        print("="*80)

        endpoints = [
            ("/finance/payments/", "GET", "List payments"),
            ("/finance/subscriptions/", "GET", "List subscriptions"),
            ("/finance/invoices/", "GET", "List invoices"),
            ("/finance/escrow/", "GET", "List escrow transactions"),
        ]

        for endpoint, method, description in endpoints:
            self.test_endpoint(endpoint, method, description=description)

    def test_other_endpoints(self):
        """Test other important endpoints"""
        print("\n" + "="*80)
        print("TESTING OTHER ENDPOINTS")
        print("="*80)

        endpoints = [
            ("/notifications/", "GET", "List notifications"),
            ("/messages/conversations/", "GET", "List conversations"),
            ("/dashboard/overview/", "GET", "Dashboard overview"),
            ("/accounts/profile/", "GET", "User profile"),
            ("/tenants/current/", "GET", "Current tenant info"),
            ("/analytics/dashboard/", "GET", "Analytics dashboard"),
        ]

        for endpoint, method, description in endpoints:
            self.test_endpoint(endpoint, method, description=description)

    def test_api_documentation(self):
        """Test API documentation endpoints"""
        print("\n" + "="*80)
        print("TESTING API DOCUMENTATION ENDPOINTS")
        print("="*80)

        doc_endpoints = [
            "/api/schema/",
            "/api/docs/",
            "/api/redoc/"
        ]

        for endpoint in doc_endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                response = self.session.get(url, timeout=10)
                status_code = response.status_code

                if status_code == 200:
                    status = "[OK] WORKING"
                    self.working_endpoints.append(endpoint)
                elif status_code == 401:
                    status = "[!] REQUIRES AUTH"
                    self.broken_endpoints.append({
                        "endpoint": endpoint,
                        "status_code": 401,
                        "error": "Authentication required"
                    })
                else:
                    status = f"[X] FAILED ({status_code})"
                    self.broken_endpoints.append({
                        "endpoint": endpoint,
                        "status_code": status_code,
                        "error": response.text[:200]
                    })

                print(f"{status} - {endpoint}")

            except RequestException as e:
                print(f"[X] ERROR - {endpoint}: {e}")
                self.broken_endpoints.append({
                    "endpoint": endpoint,
                    "error": str(e)
                })

    def generate_report(self) -> str:
        """Generate a comprehensive test report"""
        report = []
        report.append("\n" + "="*80)
        report.append("API TESTING REPORT - zumodra.rhematek-solutions.com")
        report.append("="*80)

        # Summary
        total_tested = len(self.working_endpoints) + len(self.broken_endpoints)
        report.append(f"\n[OK] Total endpoints tested: {total_tested}")
        report.append(f"[OK] Working endpoints: {len(self.working_endpoints)}")
        report.append(f"[X] Broken/Unavailable endpoints: {len(self.broken_endpoints)}")

        # Working endpoints
        if self.working_endpoints:
            report.append("\n" + "-"*80)
            report.append("WORKING ENDPOINTS")
            report.append("-"*80)
            for endpoint in self.working_endpoints:
                report.append(f"[OK] {endpoint}")

        # Broken endpoints
        if self.broken_endpoints:
            report.append("\n" + "-"*80)
            report.append("BROKEN/UNAVAILABLE ENDPOINTS")
            report.append("-"*80)
            for item in self.broken_endpoints:
                endpoint = item.get('endpoint', 'Unknown')
                status_code = item.get('status_code', 'N/A')
                error = item.get('error', 'Unknown error')
                report.append(f"[X] {endpoint} - Status: {status_code}")
                report.append(f"  Error: {error}")
                report.append("")

        # Sample responses
        if self.sample_responses:
            report.append("\n" + "-"*80)
            report.append("SAMPLE API RESPONSES (First 3)")
            report.append("-"*80)
            for i, (endpoint, response) in enumerate(list(self.sample_responses.items())[:3]):
                report.append(f"\n{endpoint}:")
                report.append(json.dumps(response, indent=2)[:500] + "...")
                if i >= 2:
                    break

        # Recommendations
        report.append("\n" + "-"*80)
        report.append("RECOMMENDATIONS FOR DEMO")
        report.append("-"*80)

        if len(self.broken_endpoints) == 0:
            report.append("[OK] All tested endpoints are working! API is ready for demo.")
        elif len(self.broken_endpoints) > len(self.working_endpoints):
            report.append("[!] CRITICAL: Most endpoints are broken or require authentication.")
            report.append("  Action required: Verify authentication system and endpoint configuration.")
        else:
            report.append("[!] Some endpoints need attention before demo:")

            # Count by error type
            auth_errors = sum(1 for e in self.broken_endpoints if e.get('status_code') in [401, 403])
            not_found = sum(1 for e in self.broken_endpoints if e.get('status_code') == 404)
            server_errors = sum(1 for e in self.broken_endpoints if isinstance(e.get('status_code'), int) and e.get('status_code') >= 500)

            if auth_errors > 0:
                report.append(f"  - {auth_errors} endpoints require authentication/permissions")
            if not_found > 0:
                report.append(f"  - {not_found} endpoints not found (may need to be created)")
            if server_errors > 0:
                report.append(f"  - {server_errors} endpoints have server errors (CRITICAL)")

        report.append("\n" + "="*80)

        return "\n".join(report)


def main():
    """Main execution function"""
    print("="*80)
    print("ZUMODRA API TESTING SCRIPT")
    print("="*80)
    print(f"Testing API at: {BASE_URL}")
    print("="*80)

    tester = APITester(BASE_URL)

    # Test health checks (no auth required)
    tester.test_health_check()

    # Test API root
    tester.test_api_root()

    # Test API documentation
    tester.test_api_documentation()

    # Try to authenticate
    if TEST_CREDENTIALS.get("email") and TEST_CREDENTIALS.get("password"):
        authenticated = tester.obtain_jwt_token(
            TEST_CREDENTIALS["email"],
            TEST_CREDENTIALS["password"]
        )
    else:
        print("\n" + "="*80)
        print("[!] AUTHENTICATION SKIPPED")
        print("="*80)
        print("No credentials provided. Only public endpoints will be tested.")
        print("To test authenticated endpoints, edit TEST_CREDENTIALS in this script.")
        authenticated = False

    # Test various endpoint groups
    if authenticated or True:  # Test anyway to see auth requirements
        tester.test_ats_endpoints()
        tester.test_hr_endpoints()
        tester.test_marketplace_endpoints()
        tester.test_finance_endpoints()
        tester.test_other_endpoints()

    # Generate and print report
    report = tester.generate_report()
    print(report)

    # Save report to file
    report_file = "api_test_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\n[OK] Full report saved to: {report_file}")

    # Return exit code based on results
    if len(tester.broken_endpoints) > 0:
        print("\n[!] Warning: Some endpoints need attention")
        return 1
    else:
        print("\n[OK] Success: All tested endpoints are working")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nTesting interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n[X] FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
