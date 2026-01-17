#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Comprehensive test script for Public Careers API endpoints.
Tests all public (unauthenticated) endpoints on zumodra.rhematek-solutions.com.
"""

import requests
import json
import time
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Any

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

# Test server URL
BASE_URL = "https://zumodra.rhematek-solutions.com"
API_BASE = f"{BASE_URL}/api/v1/careers"

# Simple text markers (no unicode or colors on Windows)
PASS_MARK = "[PASS]"
FAIL_MARK = "[FAIL]"
INFO_MARK = "[INFO]"

class TestResults:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []

    def add_result(self, name: str, passed: bool, message: str, details: Dict = None):
        """Add a test result"""
        self.tests.append({
            'name': name,
            'passed': passed,
            'message': message,
            'details': details or {}
        })
        if passed:
            self.passed += 1
        else:
            self.failed += 1

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 80)
        print("CAREERS API TEST SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {self.passed + self.failed}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print("=" * 80)

results = TestResults()

def print_test_header(test_name: str):
    """Print test section header"""
    print(f"\n{'=' * 80}")
    print(test_name)
    print('=' * 80)

def print_pass(message: str):
    """Print pass message"""
    print(f"{PASS_MARK}: {message}")

def print_fail(message: str):
    """Print fail message"""
    print(f"{FAIL_MARK}: {message}")

def print_info(message: str):
    """Print info message"""
    print(f"{INFO_MARK}: {message}")

def check_cors_headers(response: requests.Response) -> Tuple[bool, str]:
    """Check if CORS headers are present and correct"""
    cors_headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Requested-With'
    }

    missing = []
    for header, expected in cors_headers.items():
        actual = response.headers.get(header)
        if not actual:
            missing.append(f"{header} (missing)")
        elif expected and expected not in actual:
            missing.append(f"{header} (expected: {expected}, got: {actual})")

    if missing:
        return False, f"Missing/incorrect CORS headers: {', '.join(missing)}"
    return True, "All CORS headers present and correct"

def test_endpoint(
    method: str,
    endpoint: str,
    test_name: str,
    expected_status: int = 200,
    check_cors: bool = True,
    **kwargs
) -> Tuple[bool, requests.Response, str]:
    """Generic endpoint test"""
    url = f"{API_BASE}{endpoint}"
    print_info(f"Testing: {method} {url}")

    try:
        start_time = time.time()
        response = requests.request(method, url, timeout=10, **kwargs)
        elapsed = time.time() - start_time

        print_info(f"Status: {response.status_code}, Time: {elapsed:.2f}s")

        # Check status code
        if response.status_code != expected_status:
            msg = f"Expected status {expected_status}, got {response.status_code}"
            print_fail(msg)
            return False, response, msg

        # Check CORS headers if requested
        if check_cors and method == 'GET':
            cors_ok, cors_msg = check_cors_headers(response)
            if not cors_ok:
                print_fail(cors_msg)
                results.add_result(f"{test_name} - CORS", False, cors_msg)
            else:
                print_pass(cors_msg)
                results.add_result(f"{test_name} - CORS", True, cors_msg)

        # Check if JSON response
        try:
            data = response.json()
            print_info(f"Response keys: {list(data.keys()) if isinstance(data, dict) else 'array'}")
        except:
            if expected_status == 200:
                print_fail("Response is not valid JSON")
                return False, response, "Invalid JSON response"

        print_pass(f"Status code {expected_status}")
        return True, response, "Success"

    except requests.exceptions.RequestException as e:
        msg = f"Request failed: {str(e)}"
        print_fail(msg)
        return False, None, msg

# =============================================================================
# TEST 1: Career Page Configuration
# =============================================================================
def test_career_page():
    print_test_header("TEST 1: GET /api/v1/careers/page/ - Career Page Configuration")

    success, response, msg = test_endpoint('GET', '/page/', 'Career Page')

    if success:
        data = response.json()

        # Check expected fields
        expected_fields = ['id', 'company_name', 'logo', 'tagline', 'is_active']
        missing_fields = [f for f in expected_fields if f not in data]

        if missing_fields:
            msg = f"Missing fields: {', '.join(missing_fields)}"
            print_fail(msg)
            results.add_result('Career Page - Fields', False, msg)
        else:
            print_pass("All expected fields present")
            results.add_result('Career Page - Fields', True, "All fields present")

        # Print sample data
        print_info(f"Company: {data.get('company_name', 'N/A')}")
        print_info(f"Active: {data.get('is_active', 'N/A')}")

        results.add_result('Career Page', True, msg, {'response': data})
    else:
        results.add_result('Career Page', False, msg)

# =============================================================================
# TEST 2: Job Listings
# =============================================================================
def test_job_listings():
    print_test_header("TEST 2: GET /api/v1/careers/jobs/ - List All Jobs")

    success, response, msg = test_endpoint('GET', '/jobs/', 'Job Listings')

    if success:
        data = response.json()

        # Check if paginated or array
        if 'results' in data:
            jobs = data['results']
            print_info(f"Paginated response: {data.get('count', 0)} total jobs")
            print_info(f"Page size: {len(jobs)}")
        elif isinstance(data, list):
            jobs = data
            print_info(f"Array response: {len(jobs)} jobs")
        else:
            jobs = []
            print_fail("Unexpected response format")

        if jobs:
            job = jobs[0]
            print_info(f"Sample job: {job.get('title', 'N/A')}")
            print_info(f"Location: {job.get('location', 'N/A')}")
            print_info(f"Job fields: {list(job.keys())}")

            # Store first job ID and slug for later tests
            global test_job_id, test_job_slug
            test_job_id = job.get('id')
            test_job_slug = job.get('slug') or job.get('custom_slug')

            results.add_result('Job Listings', True, f"Found {len(jobs)} jobs", {'sample': job})
        else:
            print_info("No jobs found in database")
            results.add_result('Job Listings', True, "API works but no jobs available")
    else:
        results.add_result('Job Listings', False, msg)

# =============================================================================
# TEST 3: Job Listings with Filters
# =============================================================================
def test_job_filters():
    print_test_header("TEST 3: Job Listings with Filters")

    # Test search filter
    print_info("Testing search filter...")
    success, response, msg = test_endpoint('GET', '/jobs/?search=developer', 'Job Search Filter')
    if success:
        data = response.json()
        jobs = data.get('results', data) if isinstance(data, dict) else data
        print_pass(f"Search filter works: {len(jobs)} results")
        results.add_result('Job Search Filter', True, f"{len(jobs)} results")
    else:
        results.add_result('Job Search Filter', False, msg)

    # Test remote filter
    print_info("Testing remote filter...")
    success, response, msg = test_endpoint('GET', '/jobs/?remote=true', 'Job Remote Filter')
    if success:
        data = response.json()
        jobs = data.get('results', data) if isinstance(data, dict) else data
        print_pass(f"Remote filter works: {len(jobs)} results")
        results.add_result('Job Remote Filter', True, f"{len(jobs)} results")
    else:
        results.add_result('Job Remote Filter', False, msg)

    # Test job_type filter
    print_info("Testing job_type filter...")
    success, response, msg = test_endpoint('GET', '/jobs/?job_type=full_time', 'Job Type Filter')
    if success:
        data = response.json()
        jobs = data.get('results', data) if isinstance(data, dict) else data
        print_pass(f"Job type filter works: {len(jobs)} results")
        results.add_result('Job Type Filter', True, f"{len(jobs)} results")
    else:
        results.add_result('Job Type Filter', False, msg)

    # Test featured filter
    print_info("Testing featured filter...")
    success, response, msg = test_endpoint('GET', '/jobs/?featured=true', 'Job Featured Filter')
    if success:
        data = response.json()
        jobs = data.get('results', data) if isinstance(data, dict) else data
        print_pass(f"Featured filter works: {len(jobs)} results")
        results.add_result('Job Featured Filter', True, f"{len(jobs)} results")
    else:
        results.add_result('Job Featured Filter', False, msg)

# =============================================================================
# TEST 4: Job Detail by ID
# =============================================================================
def test_job_detail():
    print_test_header("TEST 4: GET /api/v1/careers/jobs/<id>/ - Job Detail")

    if not test_job_id:
        print_fail("No job ID available from previous test")
        results.add_result('Job Detail by ID', False, "No job ID available")
        return

    success, response, msg = test_endpoint('GET', f'/jobs/{test_job_id}/', 'Job Detail by ID')

    if success:
        data = response.json()
        print_info(f"Job title: {data.get('title', 'N/A')}")
        print_info(f"Description length: {len(data.get('description', ''))} chars")
        print_info(f"View count: {data.get('view_count', 0)}")

        # Check for detailed fields
        expected_fields = ['title', 'description', 'location', 'job_type', 'view_count']
        present_fields = [f for f in expected_fields if f in data]
        print_info(f"Present fields: {', '.join(present_fields)}")

        results.add_result('Job Detail by ID', True, msg, {'job': data})
    else:
        results.add_result('Job Detail by ID', False, msg)

# =============================================================================
# TEST 5: Job Detail by Slug
# =============================================================================
def test_job_detail_by_slug():
    print_test_header("TEST 5: GET /api/v1/careers/jobs/slug/<slug>/ - Job Detail by Slug")

    if not test_job_slug:
        print_fail("No job slug available from previous test")
        results.add_result('Job Detail by Slug', False, "No job slug available")
        return

    success, response, msg = test_endpoint('GET', f'/jobs/slug/{test_job_slug}/', 'Job Detail by Slug')

    if success:
        data = response.json()
        print_info(f"Job title: {data.get('title', 'N/A')}")
        print_pass("Job retrieved successfully by slug")
        results.add_result('Job Detail by Slug', True, msg)
    else:
        results.add_result('Job Detail by Slug', False, msg)

# =============================================================================
# TEST 6: Job Categories
# =============================================================================
def test_categories():
    print_test_header("TEST 6: GET /api/v1/careers/categories/ - Job Categories")

    success, response, msg = test_endpoint('GET', '/categories/', 'Job Categories')

    if success:
        data = response.json()

        if isinstance(data, list):
            print_pass(f"Found {len(data)} categories")
            if data:
                print_info(f"Sample categories: {[c.get('name', c) for c in data[:3]]}")
        elif isinstance(data, dict) and 'results' in data:
            categories = data['results']
            print_pass(f"Found {len(categories)} categories")
            if categories:
                print_info(f"Sample categories: {[c.get('name', c) for c in categories[:3]]}")
        else:
            print_info(f"Response format: {type(data)}")

        results.add_result('Job Categories', True, msg, {'data': data})
    else:
        results.add_result('Job Categories', False, msg)

# =============================================================================
# TEST 7: Job Locations
# =============================================================================
def test_locations():
    print_test_header("TEST 7: GET /api/v1/careers/locations/ - Job Locations")

    success, response, msg = test_endpoint('GET', '/locations/', 'Job Locations')

    if success:
        data = response.json()

        if isinstance(data, dict) and 'locations' in data:
            locations = data['locations']
            print_pass(f"Found {len(locations)} locations")
            if locations:
                print_info(f"Sample locations: {locations[:5]}")
        elif isinstance(data, list):
            print_pass(f"Found {len(data)} locations")
            if data:
                print_info(f"Sample locations: {data[:5]}")

        results.add_result('Job Locations', True, msg, {'data': data})
    else:
        results.add_result('Job Locations', False, msg)

# =============================================================================
# TEST 8: Career Stats
# =============================================================================
def test_stats():
    print_test_header("TEST 8: GET /api/v1/careers/stats/ - Career Page Stats")

    success, response, msg = test_endpoint('GET', '/stats/', 'Career Stats')

    if success:
        data = response.json()
        print_info(f"Stats keys: {list(data.keys())}")

        if 'open_positions' in data:
            print_info(f"Open positions: {data['open_positions']}")
        if 'top_categories' in data:
            print_info(f"Top categories: {data['top_categories']}")
        if 'locations' in data:
            print_info(f"Locations count: {len(data.get('locations', []))}")

        results.add_result('Career Stats', True, msg, {'stats': data})
    else:
        results.add_result('Career Stats', False, msg)

# =============================================================================
# TEST 9: Error Handling
# =============================================================================
def test_error_handling():
    print_test_header("TEST 9: Error Handling - Non-existent Resources")

    # Test non-existent job ID
    print_info("Testing non-existent job ID...")
    success, response, msg = test_endpoint(
        'GET', '/jobs/99999999/',
        'Non-existent Job',
        expected_status=404,
        check_cors=False
    )
    if success:
        data = response.json()
        if 'error' in data or 'detail' in data:
            print_pass("Returns proper error message")
            results.add_result('Error Handling - 404', True, "Proper 404 response")
        else:
            print_fail("No error message in response")
            results.add_result('Error Handling - 404', False, "No error message")
    else:
        results.add_result('Error Handling - 404', False, msg)

    # Test invalid slug
    print_info("Testing invalid job slug...")
    success, response, msg = test_endpoint(
        'GET', '/jobs/slug/invalid-nonexistent-slug-12345/',
        'Invalid Slug',
        expected_status=404,
        check_cors=False
    )
    if success:
        print_pass("Returns 404 for invalid slug")
        results.add_result('Error Handling - Invalid Slug', True, "Proper 404 for invalid slug")
    else:
        results.add_result('Error Handling - Invalid Slug', False, msg)

    # Test invalid query parameters
    print_info("Testing invalid query parameters...")
    success, response, msg = test_endpoint(
        'GET', '/jobs/?page=999999',
        'Invalid Query Params'
    )
    if response and response.status_code in [200, 404]:
        print_pass("Handles invalid query params gracefully")
        results.add_result('Error Handling - Query Params', True, "Graceful handling")
    else:
        results.add_result('Error Handling - Query Params', False, "Did not handle gracefully")

# =============================================================================
# TEST 10: OPTIONS (CORS Preflight)
# =============================================================================
def test_options_preflight():
    print_test_header("TEST 10: OPTIONS Requests - CORS Preflight")

    endpoints = ['/page/', '/jobs/', '/categories/', '/locations/']

    for endpoint in endpoints:
        url = f"{API_BASE}{endpoint}"
        print_info(f"Testing OPTIONS {url}")

        try:
            response = requests.options(url, timeout=5)
            print_info(f"Status: {response.status_code}")

            if response.status_code in [200, 204]:
                cors_ok, cors_msg = check_cors_headers(response)
                if cors_ok:
                    print_pass(f"OPTIONS {endpoint} - CORS headers correct")
                    results.add_result(f'OPTIONS {endpoint}', True, "CORS preflight works")
                else:
                    print_fail(f"OPTIONS {endpoint} - {cors_msg}")
                    results.add_result(f'OPTIONS {endpoint}', False, cors_msg)
            else:
                print_info(f"OPTIONS not supported on {endpoint} (status {response.status_code})")
        except Exception as e:
            print_fail(f"OPTIONS {endpoint} failed: {str(e)}")

# =============================================================================
# TEST 11: Response Time
# =============================================================================
def test_response_times():
    print_test_header("TEST 11: Response Time Performance")

    endpoints = [
        ('/page/', 'Career Page'),
        ('/jobs/', 'Job List'),
        ('/categories/', 'Categories'),
        ('/locations/', 'Locations'),
        ('/stats/', 'Stats'),
    ]

    for endpoint, name in endpoints:
        url = f"{API_BASE}{endpoint}"
        try:
            start = time.time()
            response = requests.get(url, timeout=10)
            elapsed = time.time() - start

            if elapsed < 1.0:
                print_pass(f"{name}: {elapsed:.3f}s (excellent)")
                results.add_result(f'Response Time - {name}', True, f"{elapsed:.3f}s")
            elif elapsed < 3.0:
                print_info(f"{name}: {elapsed:.3f}s (acceptable)")
                results.add_result(f'Response Time - {name}', True, f"{elapsed:.3f}s")
            else:
                print_fail(f"{name}: {elapsed:.3f}s (slow)")
                results.add_result(f'Response Time - {name}', False, f"{elapsed:.3f}s - too slow")
        except Exception as e:
            print_fail(f"{name}: {str(e)}")
            results.add_result(f'Response Time - {name}', False, str(e))

# =============================================================================
# MAIN TEST RUNNER
# =============================================================================
def main():
    print('=' * 80)
    print("ZUMODRA PUBLIC CAREERS API TEST SUITE")
    print('=' * 80)
    print(f"Server: {BASE_URL}")
    print(f"API Base: {API_BASE}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print('=' * 80 + '\n')

    # Initialize global variables
    global test_job_id, test_job_slug
    test_job_id = None
    test_job_slug = None

    # Run all tests
    test_career_page()
    test_job_listings()
    test_job_filters()
    test_job_detail()
    test_job_detail_by_slug()
    test_categories()
    test_locations()
    test_stats()
    test_error_handling()
    test_options_preflight()
    test_response_times()

    # Print summary
    results.print_summary()

    # Write detailed results to file
    output_file = f"careers_api_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'server': BASE_URL,
            'total_tests': results.passed + results.failed,
            'passed': results.passed,
            'failed': results.failed,
            'tests': results.tests
        }, f, indent=2)

    print(f"\nDetailed results saved to: {output_file}")

    # Exit with proper code
    return 0 if results.failed == 0 else 1

if __name__ == '__main__':
    exit(main())
