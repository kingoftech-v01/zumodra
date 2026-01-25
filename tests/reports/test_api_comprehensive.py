#!/usr/bin/env python3
"""
Comprehensive API Testing Script for Zumodra Platform
Tests all major API endpoints and generates a detailed report
"""

import requests
import json
import sys
from datetime import datetime
from typing import Dict, List, Tuple
from pathlib import Path

# Build paths like Django does: BASE_DIR / 'file.ext'
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Configuration
BASE_URL = "http://localhost:8002"
API_BASE = f"{BASE_URL}/api/v1"

# Test results storage
test_results = {
    "passed": [],
    "failed": [],
    "errors": []
}

def log_result(category: str, endpoint: str, method: str, status_code: int, expected: int, response: dict = None, error: str = None):
    """Log test result"""
    result = {
        "category": category,
        "endpoint": endpoint,
        "method": method,
        "status_code": status_code,
        "expected": expected,
        "timestamp": datetime.now().isoformat(),
        "response_snippet": str(response)[:200] if response else None,
        "error": error
    }

    if error:
        test_results["errors"].append(result)
        print(f"  ❌ ERROR: {method} {endpoint} - {error}")
    elif status_code == expected:
        test_results["passed"].append(result)
        print(f"  ✅ PASS: {method} {endpoint} - {status_code}")
    else:
        test_results["failed"].append(result)
        print(f"  ❌ FAIL: {method} {endpoint} - Expected {expected}, got {status_code}")

def test_endpoint(category: str, endpoint: str, method: str = "GET", expected_status: int = 200,
                 data: dict = None, headers: dict = None, auth_token: str = None):
    """Test a single endpoint"""
    url = f"{API_BASE}{endpoint}"
    headers = headers or {}

    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            headers["Content-Type"] = "application/json"
            response = requests.post(url, json=data, headers=headers, timeout=10)
        elif method == "PUT":
            headers["Content-Type"] = "application/json"
            response = requests.put(url, json=data, headers=headers, timeout=10)
        elif method == "PATCH":
            headers["Content-Type"] = "application/json"
            response = requests.patch(url, json=data, headers=headers, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=10)
        else:
            log_result(category, endpoint, method, 0, expected_status, error=f"Unknown method: {method}")
            return None, None

        try:
            response_json = response.json()
        except:
            response_json = {"raw": response.text[:200]}

        log_result(category, endpoint, method, response.status_code, expected_status, response_json)
        return response.status_code, response_json

    except Exception as e:
        log_result(category, endpoint, method, 0, expected_status, error=str(e))
        return None, None

def test_health_endpoints():
    """Test health check endpoints"""
    print("\n" + "="*80)
    print("Testing HEALTH ENDPOINTS")
    print("="*80)

    # These endpoints don't require API prefix
    health_endpoints = [
        ("/health/", "GET", 200),
        ("/health/ready/", "GET", 200),
        ("/health/live/", "GET", 200),
    ]

    for endpoint, method, expected in health_endpoints:
        url = f"{BASE_URL}{endpoint}"
        try:
            response = requests.get(url, timeout=10)
            response_json = response.json() if response.headers.get('content-type', '').startswith('application/json') else {"raw": response.text[:200]}
            log_result("Health", endpoint, method, response.status_code, expected, response_json)
        except Exception as e:
            log_result("Health", endpoint, method, 0, expected, error=str(e))

def test_authentication():
    """Test authentication endpoints"""
    print("\n" + "="*80)
    print("Testing AUTHENTICATION ENDPOINTS")
    print("="*80)

    # Test endpoints without authentication (should fail with 401/403)
    test_endpoint("Auth", "/ats/jobs/", "GET", 401)
    test_endpoint("Auth", "/hr/employees/", "GET", 401)

    # Try to create a test user via Django admin command
    print("\n  📝 Note: JWT token generation requires existing users")
    print("     Would need to create user via: docker compose exec web python manage.py createsuperuser")

def test_ats_endpoints(auth_token: str = None):
    """Test ATS (Applicant Tracking System) endpoints"""
    print("\n" + "="*80)
    print("Testing ATS ENDPOINTS")
    print("="*80)

    # Jobs
    test_endpoint("ATS", "/ats/jobs/", "GET", 401 if not auth_token else 200, auth_token=auth_token)
    test_endpoint("ATS", "/ats/jobs/", "POST", 401 if not auth_token else 201,
                 data={"title": "Software Engineer", "description": "Test job"}, auth_token=auth_token)

    # Candidates
    test_endpoint("ATS", "/ats/candidates/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Applications
    test_endpoint("ATS", "/ats/applications/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Interviews
    test_endpoint("ATS", "/ats/interviews/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Offers
    test_endpoint("ATS", "/ats/offers/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Pipelines
    test_endpoint("ATS", "/ats/pipelines/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

def test_hr_endpoints(auth_token: str = None):
    """Test HR Core endpoints"""
    print("\n" + "="*80)
    print("Testing HR CORE ENDPOINTS")
    print("="*80)

    # Employees
    test_endpoint("HR", "/hr/employees/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Time Off
    test_endpoint("HR", "/hr/time-off-requests/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Documents
    test_endpoint("HR", "/hr/documents/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Performance Reviews
    test_endpoint("HR", "/hr/performance-reviews/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

def test_services_endpoints(auth_token: str = None):
    """Test Services/Marketplace endpoints"""
    print("\n" + "="*80)
    print("Testing SERVICES/MARKETPLACE ENDPOINTS")
    print("="*80)

    # Services
    test_endpoint("Services", "/services/services/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Providers
    test_endpoint("Services", "/services/providers/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Contracts
    test_endpoint("Services", "/services/contracts/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Reviews
    test_endpoint("Services", "/services/reviews/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

def test_finance_endpoints(auth_token: str = None):
    """Test Finance endpoints"""
    print("\n" + "="*80)
    print("Testing FINANCE ENDPOINTS")
    print("="*80)

    # Transactions
    test_endpoint("Finance", "/finance/transactions/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Subscriptions
    test_endpoint("Finance", "/finance/subscriptions/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Invoices
    test_endpoint("Finance", "/finance/invoices/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

def test_messages_endpoints(auth_token: str = None):
    """Test Messages endpoints"""
    print("\n" + "="*80)
    print("Testing MESSAGES ENDPOINTS")
    print("="*80)

    # Conversations
    test_endpoint("Messages", "/messages/conversations/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Messages
    test_endpoint("Messages", "/messages/messages/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

def test_notifications_endpoints(auth_token: str = None):
    """Test Notifications endpoints"""
    print("\n" + "="*80)
    print("Testing NOTIFICATIONS ENDPOINTS")
    print("="*80)

    # Notifications
    test_endpoint("Notifications", "/notifications/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

    # Notification Preferences
    test_endpoint("Notifications", "/notifications/preferences/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

def test_careers_endpoints():
    """Test Careers (Public) endpoints"""
    print("\n" + "="*80)
    print("Testing CAREERS (PUBLIC) ENDPOINTS")
    print("="*80)

    # These might be public
    test_endpoint("Careers", "/careers/jobs/", "GET", 200)
    test_endpoint("Careers", "/careers/applications/", "GET", 401)

def test_analytics_endpoints(auth_token: str = None):
    """Test Analytics endpoints"""
    print("\n" + "="*80)
    print("Testing ANALYTICS ENDPOINTS")
    print("="*80)

    test_endpoint("Analytics", "/analytics/dashboard/", "GET", 401 if not auth_token else 200, auth_token=auth_token)
    test_endpoint("Analytics", "/analytics/reports/", "GET", 401 if not auth_token else 200, auth_token=auth_token)

def generate_report():
    """Generate comprehensive test report"""
    print("\n" + "="*80)
    print("TEST SUMMARY REPORT")
    print("="*80)

    total_tests = len(test_results["passed"]) + len(test_results["failed"]) + len(test_results["errors"])
    passed = len(test_results["passed"])
    failed = len(test_results["failed"])
    errors = len(test_results["errors"])

    print(f"\n📊 Total Tests: {total_tests}")
    print(f"✅ Passed: {passed} ({passed/total_tests*100:.1f}%)")
    print(f"❌ Failed: {failed} ({failed/total_tests*100:.1f}%)")
    print(f"⚠️  Errors: {errors} ({errors/total_tests*100:.1f}%)")

    # Group by category
    categories = {}
    for result in test_results["passed"] + test_results["failed"] + test_results["errors"]:
        cat = result["category"]
        if cat not in categories:
            categories[cat] = {"passed": 0, "failed": 0, "errors": 0}

        if result in test_results["passed"]:
            categories[cat]["passed"] += 1
        elif result in test_results["failed"]:
            categories[cat]["failed"] += 1
        else:
            categories[cat]["errors"] += 1

    print("\n📋 Results by Category:")
    print("-" * 80)
    for category, stats in sorted(categories.items()):
        total_cat = stats["passed"] + stats["failed"] + stats["errors"]
        print(f"\n{category}:")
        print(f"  ✅ Passed: {stats['passed']}/{total_cat}")
        print(f"  ❌ Failed: {stats['failed']}/{total_cat}")
        print(f"  ⚠️  Errors: {stats['errors']}/{total_cat}")

    # Show failed tests
    if test_results["failed"]:
        print("\n❌ Failed Tests Details:")
        print("-" * 80)
        for result in test_results["failed"]:
            print(f"\n{result['method']} {result['endpoint']}")
            print(f"  Category: {result['category']}")
            print(f"  Expected: {result['expected']}, Got: {result['status_code']}")
            if result['response_snippet']:
                print(f"  Response: {result['response_snippet']}")

    # Show errors
    if test_results["errors"]:
        print("\n⚠️  Error Details:")
        print("-" * 80)
        for result in test_results["errors"]:
            print(f"\n{result['method']} {result['endpoint']}")
            print(f"  Category: {result['category']}")
            print(f"  Error: {result['error']}")

    # Save detailed report to file
    report_file = str(BASE_DIR / 'api_test_report.json')
    with open(report_file, 'w') as f:
        json.dump(test_results, f, indent=2)
    print(f"\n📄 Detailed report saved to: {report_file}")

def main():
    """Main test execution"""
    print("\n" + "="*80)
    print("ZUMODRA API COMPREHENSIVE TEST SUITE")
    print("="*80)
    print(f"Base URL: {BASE_URL}")
    print(f"API Base: {API_BASE}")
    print(f"Start Time: {datetime.now().isoformat()}")

    # Run all tests
    test_health_endpoints()
    test_authentication()
    test_ats_endpoints()
    test_hr_endpoints()
    test_services_endpoints()
    test_finance_endpoints()
    test_messages_endpoints()
    test_notifications_endpoints()
    test_careers_endpoints()
    test_analytics_endpoints()

    # Generate report
    generate_report()

    print(f"\n✨ Test execution completed at: {datetime.now().isoformat()}")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
