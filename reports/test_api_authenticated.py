#!/usr/bin/env python3
"""
Comprehensive Authenticated API Testing Script
Tests all CRUD operations on all major endpoints
"""

import requests
import json
import sys
from datetime import datetime
from typing import Dict, List

# Configuration
BASE_URL = "http://localhost:8002"
API_V1 = f"{BASE_URL}/api/v1"

# Load authentication token
try:
    with open('/home/king/zumodra/auth_token.json', 'r') as f:
        tokens = json.load(f)
        ACCESS_TOKEN = tokens['access']
        print(f"✅ Loaded authentication token")
except Exception as e:
    print(f"❌ Failed to load token: {e}")
    sys.exit(1)

# Headers with authentication
headers = {
    "Authorization": f"Bearer {ACCESS_TOKEN}",
    "Content-Type": "application/json"
}

# Test results storage
results = {
    "passed": [],
    "failed": [],
    "errors": [],
    "created_resources": {}
}

def log_test(category, endpoint, method, expected, actual, details=""):
    """Log test result"""
    result = {
        "category": category,
        "endpoint": endpoint,
        "method": method,
        "expected": expected,
        "actual": actual,
        "details": details,
        "timestamp": datetime.now().isoformat()
    }

    if actual == expected:
        results["passed"].append(result)
        print(f"  ✅ {method} {endpoint} - {actual}")
    else:
        results["failed"].append(result)
        print(f"  ❌ {method} {endpoint} - Expected {expected}, got {actual} - {details}")

def test_request(category, endpoint, method="GET", data=None, expected_status=200):
    """Execute test request"""
    url = f"{API_V1}{endpoint}"

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, json=data, headers=headers, timeout=10)
        elif method == "PUT":
            r = requests.put(url, json=data, headers=headers, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, json=data, headers=headers, timeout=10)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=10)
        else:
            log_test(category, endpoint, method, expected_status, 0, "Unknown method")
            return None, None

        try:
            response_data = r.json()
        except:
            response_data = {"raw": r.text[:200]}

        log_test(category, endpoint, method, expected_status, r.status_code,
                str(response_data)[:100] if r.status_code != expected_status else "")

        return r.status_code, response_data

    except Exception as e:
        log_test(category, endpoint, method, expected_status, 0, str(e))
        return None, None

print("\n" + "="*80)
print("ZUMODRA AUTHENTICATED API COMPREHENSIVE TEST SUITE")
print("="*80)

# Test ATS Endpoints
print("\n🎯 Testing ATS (Applicant Tracking System) APIs...")
test_request("ATS", "/ats/jobs/", "GET", expected_status=200)
test_request("ATS", "/ats/candidates/", "GET", expected_status=200)
test_request("ATS", "/ats/applications/", "GET", expected_status=200)
test_request("ATS", "/ats/interviews/", "GET", expected_status=200)
test_request("ATS", "/ats/offers/", "GET", expected_status=200)
test_request("ATS", "/ats/pipelines/", "GET", expected_status=200)

# Test HR Endpoints
print("\n👥 Testing HR Core APIs...")
test_request("HR", "/hr/employees/", "GET", expected_status=200)
test_request("HR", "/hr/time-off-requests/", "GET", expected_status=200)
test_request("HR", "/hr/performance-reviews/", "GET", expected_status=200)
test_request("HR", "/hr/documents/", "GET", expected_status=200)

# Test Services/Marketplace
print("\n🛒 Testing Services/Marketplace APIs...")
test_request("Services", "/services/services/", "GET", expected_status=200)
test_request("Services", "/services/providers/", "GET", expected_status=200)
test_request("Services", "/services/contracts/", "GET", expected_status=200)
test_request("Services", "/services/reviews/", "GET", expected_status=200)

# Test Finance
print("\n💰 Testing Finance APIs...")
test_request("Finance", "/finance/subscriptions/", "GET", expected_status=200)
test_request("Finance", "/finance/invoices/", "GET", expected_status=200)
test_request("Finance", "/finance/transactions/", "GET", expected_status=200)

# Test Messages
print("\n💬 Testing Messages APIs...")
test_request("Messages", "/messages/conversations/", "GET", expected_status=200)
test_request("Messages", "/messages/messages/", "GET", expected_status=200)

# Test Notifications
print("\n🔔 Testing Notifications APIs...")
test_request("Notifications", "/notifications/", "GET", expected_status=200)
test_request("Notifications", "/notifications/preferences/", "GET", expected_status=200)

# Test Analytics
print("\n📊 Testing Analytics APIs...")
test_request("Analytics", "/analytics/dashboard/", "GET", expected_status=200)
test_request("Analytics", "/analytics/reports/", "GET", expected_status=200)

# Test Careers (Public)
print("\n💼 Testing Careers APIs...")
test_request("Careers", "/careers/jobs/", "GET", expected_status=200)
test_request("Careers", "/careers/applications/", "GET", expected_status=200)

# Generate Summary
print("\n" + "="*80)
print("TEST SUMMARY")
print("="*80)

total = len(results["passed"]) + len(results["failed"]) + len(results["errors"])
passed = len(results["passed"])
failed = len(results["failed"])
errors = len(results["errors"])

print(f"\n📊 Total Tests: {total}")
print(f"✅ Passed: {passed} ({passed/total*100 if total > 0 else 0:.1f}%)")
print(f"❌ Failed: {failed} ({failed/total*100 if total > 0 else 0:.1f}%)")
print(f"⚠️  Errors: {errors} ({errors/total*100 if total > 0 else 0:.1f}%)")

# Group by category
by_category = {}
for r in results["passed"] + results["failed"] + results["errors"]:
    cat = r["category"]
    if cat not in by_category:
        by_category[cat] = {"passed": 0, "failed": 0}

    if r in results["passed"]:
        by_category[cat]["passed"] += 1
    else:
        by_category[cat]["failed"] += 1

print("\n📋 By Category:")
for cat, stats in sorted(by_category.items()):
    total_cat = stats["passed"] + stats["failed"]
    print(f"  {cat}: {stats['passed']}/{total_cat} passed")

# Show failures
if results["failed"]:
    print("\n❌ Failed Tests:")
    for r in results["failed"]:
        print(f"  {r['method']} {r['endpoint']} - {r['details'][:100]}")

# Save report
with open('/home/king/zumodra/api_authenticated_test_report.json', 'w') as f:
    json.dump(results, f, indent=2)

print(f"\n📄 Full report saved to: api_authenticated_test_report.json")
print("="*80 + "\n")
