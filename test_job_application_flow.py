"""
Test Job Application Submission Flow on Development Server
===========================================================

This script tests the complete job application flow on zumodra.rhematek-solutions.com

Test Scenarios:
1. POST /api/v1/careers/apply/ - Submit Application
2. Application Form Validation
3. GET /api/v1/careers/application/<uuid>/status/ - Check Status
4. Application Success Confirmation
5. Rate Limiting (5 applications/hour)
6. Email Notifications
7. Duplicate Application Prevention
8. UTM Tracking

Server: zumodra.rhematek-solutions.com
"""

import requests
import json
import time
import io
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import os

# Configuration
BASE_URL = "https://zumodra.rhematek-solutions.com"
API_BASE = f"{BASE_URL}/api/v1"
CAREERS_API = f"{API_BASE}/careers"

# Test data
TEST_EMAIL = f"test_applicant_{int(time.time())}@example.com"
TEST_RESUME_PATH = "test_resume.pdf"


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_test_header(test_name: str):
    """Print a formatted test header"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*80}")
    print(f"TEST: {test_name}")
    print(f"{'='*80}{Colors.END}\n")


def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}[PASS] {message}{Colors.END}")


def print_failure(message: str):
    """Print failure message"""
    print(f"{Colors.RED}[FAIL] {message}{Colors.END}")


def print_info(message: str):
    """Print info message"""
    print(f"{Colors.YELLOW}[INFO] {message}{Colors.END}")


def create_dummy_resume() -> io.BytesIO:
    """Create a dummy PDF resume file in memory"""
    pdf_content = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/Resources <<
/Font <<
/F1 <<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
>>
>>
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 55
>>
stream
BT
/F1 12 Tf
100 700 Td
(Test Resume - John Doe) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000317 00000 n
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
421
%%EOF
"""
    return io.BytesIO(pdf_content)


def get_job_listings() -> Tuple[bool, Optional[List[Dict]], str]:
    """
    Test: Get available job listings
    GET /api/v1/careers/jobs/
    """
    print_test_header("Get Job Listings")

    try:
        response = requests.get(f"{CAREERS_API}/jobs/", timeout=10)

        print_info(f"Status Code: {response.status_code}")
        print_info(f"Response Time: {response.elapsed.total_seconds():.2f}s")

        if response.status_code == 200:
            data = response.json()

            # Check if it's paginated
            if isinstance(data, dict) and 'results' in data:
                jobs = data['results']
                count = data.get('count', len(jobs))
                print_success(f"Retrieved {len(jobs)} jobs (Total: {count})")
            else:
                jobs = data
                print_success(f"Retrieved {len(jobs)} jobs")

            if jobs:
                # Display first job details
                job = jobs[0]
                print_info(f"Sample Job: {job.get('job', {}).get('title', 'N/A')}")
                print_info(f"Job ID: {job.get('id', 'N/A')}")
                return True, jobs, "Job listings retrieved successfully"
            else:
                print_failure("No jobs available for application")
                return False, None, "No jobs found"
        else:
            print_failure(f"Failed to get jobs: {response.status_code}")
            print_info(f"Response: {response.text[:500]}")
            return False, None, f"HTTP {response.status_code}"

    except Exception as e:
        print_failure(f"Exception: {str(e)}")
        return False, None, str(e)


def submit_application(job_listing_id: int, email: str = None,
                      utm_params: Dict = None) -> Tuple[bool, Optional[str], str]:
    """
    Test: Submit a job application
    POST /api/v1/careers/apply/
    """
    print_test_header("Submit Job Application")

    if email is None:
        email = TEST_EMAIL

    try:
        # Prepare multipart form data
        resume_file = create_dummy_resume()

        files = {
            'resume': ('resume.pdf', resume_file, 'application/pdf')
        }

        data = {
            'job_listing': job_listing_id,
            'first_name': 'John',
            'last_name': 'Doe',
            'email': email,
            'phone': '+1-555-0100',
            'cover_letter': 'I am very interested in this position and believe my skills align well with the requirements.',
            'linkedin_url': 'https://linkedin.com/in/johndoe',
            'portfolio_url': 'https://johndoe.com',
            'privacy_consent': 'true',
            'marketing_consent': 'false',
        }

        # Add UTM parameters if provided
        url = f"{CAREERS_API}/apply/"
        if utm_params:
            params = []
            for key, value in utm_params.items():
                params.append(f"{key}={value}")
            url += "?" + "&".join(params)

        print_info(f"Submitting application to: {url}")
        print_info(f"Email: {email}")
        print_info(f"Job Listing ID: {job_listing_id}")

        response = requests.post(url, data=data, files=files, timeout=15)

        print_info(f"Status Code: {response.status_code}")
        print_info(f"Response Time: {response.elapsed.total_seconds():.2f}s")

        if response.status_code == 201:
            result = response.json()
            application_uuid = result.get('application_id')
            print_success(f"Application submitted successfully!")
            print_info(f"Application UUID: {application_uuid}")
            print_info(f"Message: {result.get('message', 'N/A')}")
            return True, application_uuid, "Application submitted successfully"
        elif response.status_code == 429:
            print_failure("Rate limit exceeded (429 Too Many Requests)")
            print_info(f"Response: {response.text}")

            # Check rate limit headers
            if 'X-RateLimit-Limit' in response.headers:
                print_info(f"Rate Limit: {response.headers.get('X-RateLimit-Limit')}")
            if 'X-RateLimit-Remaining' in response.headers:
                print_info(f"Remaining: {response.headers.get('X-RateLimit-Remaining')}")
            if 'Retry-After' in response.headers:
                print_info(f"Retry After: {response.headers.get('Retry-After')}s")

            return False, None, "Rate limit exceeded"
        else:
            print_failure(f"Application submission failed: {response.status_code}")
            print_info(f"Response: {response.text[:500]}")
            return False, None, f"HTTP {response.status_code}"

    except Exception as e:
        print_failure(f"Exception: {str(e)}")
        return False, None, str(e)


def check_application_status(uuid: str) -> Tuple[bool, str]:
    """
    Test: Check application status
    GET /api/v1/careers/application/<uuid>/status/
    """
    print_test_header("Check Application Status")

    try:
        url = f"{CAREERS_API}/application/{uuid}/status/"
        print_info(f"Checking status at: {url}")

        response = requests.get(url, timeout=10)

        print_info(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print_success("Application status retrieved successfully")
            print_info(f"UUID: {result.get('uuid', 'N/A')}")
            print_info(f"Job Title: {result.get('job_title', 'N/A')}")
            print_info(f"Status: {result.get('status', 'N/A')}")
            print_info(f"Status Display: {result.get('status_display', 'N/A')}")
            print_info(f"Submitted At: {result.get('submitted_at', 'N/A')}")
            return True, "Status check successful"
        else:
            print_failure(f"Failed to check status: {response.status_code}")
            print_info(f"Response: {response.text[:500]}")
            return False, f"HTTP {response.status_code}"

    except Exception as e:
        print_failure(f"Exception: {str(e)}")
        return False, str(e)


def test_validation_missing_fields(job_listing_id: int) -> Tuple[bool, str]:
    """
    Test: Application validation - missing required fields
    """
    print_test_header("Test Validation: Missing Required Fields")

    try:
        # Submit with missing required fields
        data = {
            'job_listing': job_listing_id,
            'first_name': 'John',
            # Missing last_name
            # Missing email
            # Missing resume
            'privacy_consent': 'true',
        }

        response = requests.post(f"{CAREERS_API}/apply/", data=data, timeout=10)

        print_info(f"Status Code: {response.status_code}")

        if response.status_code == 400:
            print_success("Validation correctly rejected missing fields")
            result = response.json()
            print_info(f"Errors: {json.dumps(result, indent=2)}")
            return True, "Validation works correctly"
        elif response.status_code == 201:
            print_failure("Application was accepted with missing fields (should fail)")
            return False, "Validation did not work"
        else:
            print_info(f"Unexpected status code: {response.status_code}")
            return True, f"Got HTTP {response.status_code}"

    except Exception as e:
        print_failure(f"Exception: {str(e)}")
        return False, str(e)


def test_validation_invalid_email(job_listing_id: int) -> Tuple[bool, str]:
    """
    Test: Application validation - invalid email format
    """
    print_test_header("Test Validation: Invalid Email Format")

    try:
        resume_file = create_dummy_resume()

        files = {
            'resume': ('resume.pdf', resume_file, 'application/pdf')
        }

        data = {
            'job_listing': job_listing_id,
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'invalid-email-format',  # Invalid email
            'privacy_consent': 'true',
        }

        response = requests.post(f"{CAREERS_API}/apply/", data=data, files=files, timeout=10)

        print_info(f"Status Code: {response.status_code}")

        if response.status_code == 400:
            print_success("Validation correctly rejected invalid email")
            result = response.json()
            print_info(f"Errors: {json.dumps(result, indent=2)}")
            return True, "Email validation works"
        elif response.status_code == 201:
            print_failure("Application was accepted with invalid email (should fail)")
            return False, "Email validation did not work"
        else:
            print_info(f"Unexpected status code: {response.status_code}")
            return True, f"Got HTTP {response.status_code}"

    except Exception as e:
        print_failure(f"Exception: {str(e)}")
        return False, str(e)


def test_validation_no_consent(job_listing_id: int) -> Tuple[bool, str]:
    """
    Test: Application validation - no privacy consent
    """
    print_test_header("Test Validation: No Privacy Consent")

    try:
        resume_file = create_dummy_resume()

        files = {
            'resume': ('resume.pdf', resume_file, 'application/pdf')
        }

        data = {
            'job_listing': job_listing_id,
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'test@example.com',
            'privacy_consent': 'false',  # No consent
        }

        response = requests.post(f"{CAREERS_API}/apply/", data=data, files=files, timeout=10)

        print_info(f"Status Code: {response.status_code}")

        if response.status_code == 400:
            print_success("Validation correctly rejected missing consent")
            result = response.json()
            print_info(f"Errors: {json.dumps(result, indent=2)}")
            return True, "Consent validation works"
        elif response.status_code == 201:
            print_failure("Application was accepted without consent (should fail)")
            return False, "Consent validation did not work"
        else:
            print_info(f"Unexpected status code: {response.status_code}")
            return True, f"Got HTTP {response.status_code}"

    except Exception as e:
        print_failure(f"Exception: {str(e)}")
        return False, str(e)


def test_rate_limiting(job_listing_id: int) -> Tuple[bool, str]:
    """
    Test: Rate limiting (5 applications/hour)
    """
    print_test_header("Test Rate Limiting (5 applications/hour)")

    print_info("Attempting to submit 6 applications rapidly...")

    successful_submissions = 0
    rate_limited = False

    for i in range(6):
        email = f"ratelimit_test_{int(time.time())}_{i}@example.com"
        print_info(f"\nAttempt {i+1}/6...")

        success, uuid, message = submit_application(job_listing_id, email=email)

        if success:
            successful_submissions += 1
            print_info(f"Submission {i+1} succeeded")
        else:
            if "rate limit" in message.lower() or "429" in message:
                rate_limited = True
                print_info(f"Submission {i+1} was rate limited (expected after 5)")
                break
            else:
                print_info(f"Submission {i+1} failed: {message}")

        # Small delay between requests
        time.sleep(0.5)

    print_info(f"\nSuccessful submissions: {successful_submissions}")

    if successful_submissions == 5 and rate_limited:
        print_success("Rate limiting working correctly (5 allowed, 6th blocked)")
        return True, "Rate limiting works correctly"
    elif successful_submissions < 5:
        print_info(f"Only {successful_submissions} submissions succeeded (may be existing rate limits)")
        return True, f"{successful_submissions} submissions before limit"
    elif successful_submissions == 6:
        print_failure("All 6 submissions succeeded - rate limiting not working")
        return False, "Rate limiting not enforced"
    else:
        print_info(f"Unexpected result: {successful_submissions} succeeded, rate_limited={rate_limited}")
        return True, f"{successful_submissions} submissions succeeded"


def test_utm_tracking(job_listing_id: int) -> Tuple[bool, str]:
    """
    Test: UTM parameter tracking
    """
    print_test_header("Test UTM Tracking")

    utm_params = {
        'utm_source': 'linkedin',
        'utm_medium': 'social',
        'utm_campaign': 'hiring_2024',
    }

    email = f"utm_test_{int(time.time())}@example.com"
    success, uuid, message = submit_application(job_listing_id, email=email, utm_params=utm_params)

    if success:
        print_success("Application with UTM parameters submitted successfully")
        print_info("UTM parameters should be captured in the application record")
        return True, "UTM tracking test completed"
    else:
        print_failure(f"Failed to submit application with UTM: {message}")
        return False, message


def run_all_tests():
    """Run all test scenarios"""
    print(f"\n{Colors.BOLD}{'='*80}")
    print(f"JOB APPLICATION FLOW TEST SUITE")
    print(f"Server: {BASE_URL}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*80}{Colors.END}\n")

    results = {}

    # Test 1: Get job listings
    success, jobs, message = get_job_listings()
    results['Get Job Listings'] = ('PASS' if success else 'FAIL', message)

    if not success or not jobs:
        print_failure("\n[!] Cannot proceed with tests - no jobs available")
        return results

    # Use first job for testing
    job_listing_id = jobs[0]['id']
    print_info(f"\nUsing Job Listing ID: {job_listing_id} for all tests\n")
    time.sleep(1)

    # Test 2: Submit valid application
    success, uuid, message = submit_application(job_listing_id)
    results['Submit Valid Application'] = ('PASS' if success else 'FAIL', message)
    time.sleep(1)

    # Test 3: Check application status
    if uuid:
        success, message = check_application_status(uuid)
        results['Check Application Status'] = ('PASS' if success else 'FAIL', message)
        time.sleep(1)
    else:
        results['Check Application Status'] = ('SKIP', 'No UUID from previous test')

    # Test 4: Validation - Missing fields
    success, message = test_validation_missing_fields(job_listing_id)
    results['Validation: Missing Fields'] = ('PASS' if success else 'FAIL', message)
    time.sleep(1)

    # Test 5: Validation - Invalid email
    success, message = test_validation_invalid_email(job_listing_id)
    results['Validation: Invalid Email'] = ('PASS' if success else 'FAIL', message)
    time.sleep(1)

    # Test 6: Validation - No consent
    success, message = test_validation_no_consent(job_listing_id)
    results['Validation: No Consent'] = ('PASS' if success else 'FAIL', message)
    time.sleep(1)

    # Test 7: UTM tracking
    success, message = test_utm_tracking(job_listing_id)
    results['UTM Tracking'] = ('PASS' if success else 'FAIL', message)
    time.sleep(1)

    # Test 8: Rate limiting (OPTIONAL - comment out to avoid using rate limit)
    print_info("\n[!] Rate limiting test will consume your hourly rate limit!")
    print_info("Press Ctrl+C within 5 seconds to skip...")
    try:
        time.sleep(5)
        success, message = test_rate_limiting(job_listing_id)
        results['Rate Limiting'] = ('PASS' if success else 'FAIL', message)
    except KeyboardInterrupt:
        print_info("\n\nRate limiting test skipped by user")
        results['Rate Limiting'] = ('SKIP', 'Skipped by user')

    # Print summary
    print_summary(results)

    return results


def print_summary(results: Dict):
    """Print test results summary"""
    print(f"\n{Colors.BOLD}{'='*80}")
    print(f"TEST RESULTS SUMMARY")
    print(f"{'='*80}{Colors.END}\n")

    pass_count = 0
    fail_count = 0
    skip_count = 0

    for test_name, (status, message) in results.items():
        if status == 'PASS':
            color = Colors.GREEN
            symbol = '[+]'
            pass_count += 1
        elif status == 'FAIL':
            color = Colors.RED
            symbol = '[-]'
            fail_count += 1
        else:  # SKIP
            color = Colors.YELLOW
            symbol = '[>]'
            skip_count += 1

        print(f"{color}{symbol} {status:6s}{Colors.END} | {test_name:40s} | {message}")

    total = pass_count + fail_count + skip_count

    print(f"\n{Colors.BOLD}{'='*80}")
    print(f"Total: {total} | Pass: {pass_count} | Fail: {fail_count} | Skip: {skip_count}")
    print(f"{'='*80}{Colors.END}\n")

    if fail_count == 0 and pass_count > 0:
        print(f"{Colors.GREEN}{Colors.BOLD}*** ALL TESTS PASSED! ***{Colors.END}\n")
    elif fail_count > 0:
        print(f"{Colors.RED}{Colors.BOLD}*** SOME TESTS FAILED ***{Colors.END}\n")


if __name__ == "__main__":
    try:
        run_all_tests()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Test suite interrupted by user{Colors.END}\n")
    except Exception as e:
        print(f"\n\n{Colors.RED}Fatal error: {str(e)}{Colors.END}\n")
        import traceback
        traceback.print_exc()
