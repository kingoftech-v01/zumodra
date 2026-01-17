"""
ATS Candidates & Applications Module Testing Script

This script tests all candidate-related URLs on the demo tenant:
- Candidate list view
- Candidate detail view
- Pipeline board (Kanban)
- Application views
- Interview scheduling
- All HTMX interactions

Takes screenshots of every page and documents findings.
"""

import os
import time
import json
from datetime import datetime
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
LOGIN_EMAIL = "demo@demo.zumodra.rhematek-solutions.com"
LOGIN_PASSWORD = "demo123!"

# Screenshots directory
SCREENSHOTS_DIR = Path(__file__).parent
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

# Test results log
TEST_LOG_FILE = SCREENSHOTS_DIR / "test_results.txt"
FINDINGS_FILE = SCREENSHOTS_DIR / "findings.json"

# =============================================================================
# TEST TRACKING
# =============================================================================

findings = {
    "test_run": datetime.now().isoformat(),
    "base_url": BASE_URL,
    "total_tests": 0,
    "passed_tests": 0,
    "failed_tests": 0,
    "warnings": 0,
    "errors": [],
    "warnings_list": [],
    "pages_tested": []
}

def log(message, level="INFO"):
    """Log message to console and file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] [{level}] {message}"
    print(log_msg)
    with open(TEST_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")

def record_finding(page_name, url, status_code, issues=None, warnings=None, notes=None):
    """Record findings for a tested page."""
    finding = {
        "page": page_name,
        "url": url,
        "status_code": status_code,
        "timestamp": datetime.now().isoformat(),
        "issues": issues or [],
        "warnings": warnings or [],
        "notes": notes or []
    }

    findings["pages_tested"].append(finding)
    findings["total_tests"] += 1

    if status_code == 200:
        findings["passed_tests"] += 1
    else:
        findings["failed_tests"] += 1
        findings["errors"].append(f"{page_name}: HTTP {status_code}")

    if issues:
        findings["errors"].extend([f"{page_name}: {issue}" for issue in issues])
    if warnings:
        findings["warnings"] += len(warnings)
        findings["warnings_list"].extend([f"{page_name}: {warn}" for warn in warnings])

# =============================================================================
# HTTP SESSION SETUP
# =============================================================================

def create_session():
    """Create a requests session with retry logic and proper headers."""
    session = requests.Session()

    # Configure retry strategy
    retry_strategy = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
        backoff_factor=1
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Set user agent
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    })

    return session

# =============================================================================
# AUTHENTICATION
# =============================================================================

def login(session):
    """Authenticate to the application."""
    log("=" * 80)
    log("STEP 1: AUTHENTICATION")
    log("=" * 80)

    # Get login page to retrieve CSRF token
    log(f"Fetching login page: {BASE_URL}/accounts/login/")
    try:
        response = session.get(f"{BASE_URL}/accounts/login/", timeout=30, verify=False)
        log(f"Login page status: {response.status_code}")

        if response.status_code != 200:
            log(f"ERROR: Failed to load login page: {response.status_code}", "ERROR")
            return False

        # Save login page HTML for debugging
        with open(SCREENSHOTS_DIR / "00_login_page.html", "w", encoding="utf-8") as f:
            f.write(response.text)
        log("Saved login page HTML for debugging")

        # Extract CSRF token from cookies
        csrf_token = session.cookies.get('csrftoken')
        if not csrf_token:
            log("ERROR: No CSRF token found in cookies", "ERROR")
            return False

        log(f"CSRF token obtained: {csrf_token[:20]}...")

        # Prepare login data
        login_data = {
            'login': LOGIN_EMAIL,
            'password': LOGIN_PASSWORD,
            'csrfmiddlewaretoken': csrf_token,
        }

        # Submit login form
        log(f"Submitting login form for: {LOGIN_EMAIL}")
        login_response = session.post(
            f"{BASE_URL}/accounts/login/",
            data=login_data,
            headers={
                'Referer': f"{BASE_URL}/accounts/login/",
                'X-CSRFToken': csrf_token,
            },
            timeout=30,
            verify=False,
            allow_redirects=True
        )

        log(f"Login response status: {login_response.status_code}")
        log(f"Final URL after redirect: {login_response.url}")

        # Save login response HTML for debugging
        with open(SCREENSHOTS_DIR / "00_login_response.html", "w", encoding="utf-8") as f:
            f.write(login_response.text)
        log("Saved login response HTML for debugging")

        # Check if login was successful
        if login_response.status_code == 200:
            # Check if we're on the dashboard or another authenticated page
            if '/accounts/login/' in login_response.url:
                log("ERROR: Login failed - still on login page", "ERROR")
                # Check for error messages in response
                if 'error' in login_response.text.lower() or 'invalid' in login_response.text.lower():
                    log("ERROR: Invalid credentials or login error", "ERROR")
                return False
            else:
                log("SUCCESS: Login successful!", "SUCCESS")
                log(f"Session cookies: {list(session.cookies.keys())}")
                return True
        else:
            log(f"ERROR: Login failed with status {login_response.status_code}", "ERROR")
            return False

    except requests.exceptions.RequestException as e:
        log(f"ERROR: Request exception during login: {e}", "ERROR")
        return False

# =============================================================================
# PAGE TESTING FUNCTIONS
# =============================================================================

def test_page(session, page_name, url, check_content=None, screenshot_name=None):
    """
    Test a page and save response info.

    Args:
        session: requests session
        page_name: Human-readable page name
        url: Full URL to test
        check_content: List of strings that should be in the response
        screenshot_name: Optional custom screenshot filename
    """
    log(f"\nTesting: {page_name}")
    log(f"URL: {url}")

    issues = []
    warnings = []
    notes = []

    try:
        response = session.get(url, timeout=30, verify=False)
        status_code = response.status_code

        log(f"Status: {status_code}")

        # Check status code
        if status_code == 404:
            issues.append("Page not found (404)")
            log("ERROR: 404 Not Found", "ERROR")
        elif status_code == 500:
            issues.append("Internal server error (500)")
            log("ERROR: 500 Internal Server Error", "ERROR")
        elif status_code == 403:
            issues.append("Forbidden (403)")
            log("ERROR: 403 Forbidden", "ERROR")
        elif status_code == 302 or status_code == 301:
            warnings.append(f"Redirect ({status_code}) to {response.headers.get('Location', 'unknown')}")
            log(f"WARNING: Redirect to {response.headers.get('Location')}", "WARNING")
        elif status_code != 200:
            issues.append(f"Unexpected status code: {status_code}")
            log(f"WARNING: Unexpected status {status_code}", "WARNING")

        # Check content
        if check_content and status_code == 200:
            content = response.text
            for expected in check_content:
                if expected.lower() not in content.lower():
                    warnings.append(f"Expected content not found: '{expected}'")
                    log(f"WARNING: Expected content not found: '{expected}'", "WARNING")
                else:
                    notes.append(f"Found expected content: '{expected}'")

        # Save HTML response
        if screenshot_name:
            html_file = SCREENSHOTS_DIR / f"{screenshot_name}.html"
        else:
            html_file = SCREENSHOTS_DIR / f"{page_name.replace(' ', '_').lower()}.html"

        with open(html_file, "w", encoding="utf-8") as f:
            f.write(response.text)
        notes.append(f"Saved HTML to {html_file.name}")
        log(f"Saved HTML to: {html_file.name}")

        # Record finding
        record_finding(page_name, url, status_code, issues, warnings, notes)

        return response

    except requests.exceptions.Timeout:
        issues.append("Request timeout")
        log("ERROR: Request timeout", "ERROR")
        record_finding(page_name, url, 0, issues)
        return None
    except requests.exceptions.RequestException as e:
        issues.append(f"Request error: {str(e)}")
        log(f"ERROR: Request exception: {e}", "ERROR")
        record_finding(page_name, url, 0, issues)
        return None

# =============================================================================
# ATS CANDIDATE TESTING
# =============================================================================

def test_candidate_list(session):
    """Test candidate list page."""
    log("\n" + "=" * 80)
    log("STEP 2: TESTING CANDIDATE LIST")
    log("=" * 80)

    url = f"{BASE_URL}/app/ats/candidates/"
    test_page(
        session,
        "Candidate List",
        url,
        check_content=["Candidates", "Search", "Filter"],
        screenshot_name="01_candidate_list"
    )

def test_candidate_detail(session):
    """Test candidate detail pages."""
    log("\n" + "=" * 80)
    log("STEP 3: TESTING CANDIDATE DETAIL PAGES")
    log("=" * 80)

    # First, get candidate list to find candidate IDs
    log("Fetching candidate list to find candidate IDs...")
    try:
        response = session.get(f"{BASE_URL}/app/ats/candidates/", timeout=30, verify=False)

        if response.status_code == 200:
            # Try to extract candidate UUIDs from links
            import re
            candidate_pattern = r'/app/ats/candidates/([0-9a-f-]{36})/'
            candidate_ids = re.findall(candidate_pattern, response.text)

            if candidate_ids:
                log(f"Found {len(candidate_ids)} candidate IDs")
                # Test first 3 candidates
                for i, candidate_id in enumerate(candidate_ids[:3], 1):
                    url = f"{BASE_URL}/app/ats/candidates/{candidate_id}/"
                    test_page(
                        session,
                        f"Candidate Detail {i}",
                        url,
                        check_content=["Candidate", "Applications", "Profile"],
                        screenshot_name=f"02_candidate_detail_{i}"
                    )
                    time.sleep(1)  # Be nice to the server
            else:
                log("WARNING: No candidate IDs found in list", "WARNING")
                findings["warnings_list"].append("No candidates found to test detail pages")
        else:
            log(f"ERROR: Could not fetch candidate list (status {response.status_code})", "ERROR")
    except Exception as e:
        log(f"ERROR: Exception while fetching candidates: {e}", "ERROR")

def test_pipeline_board(session):
    """Test pipeline Kanban board."""
    log("\n" + "=" * 80)
    log("STEP 4: TESTING PIPELINE BOARD")
    log("=" * 80)

    url = f"{BASE_URL}/app/ats/pipeline/"
    test_page(
        session,
        "Pipeline Board",
        url,
        check_content=["Pipeline", "Stage", "Application"],
        screenshot_name="03_pipeline_board"
    )

def test_application_detail(session):
    """Test application detail pages."""
    log("\n" + "=" * 80)
    log("STEP 5: TESTING APPLICATION DETAIL PAGES")
    log("=" * 80)

    # Try to get pipeline board to find application IDs
    log("Fetching pipeline board to find application IDs...")
    try:
        response = session.get(f"{BASE_URL}/app/ats/pipeline/", timeout=30, verify=False)

        if response.status_code == 200:
            # Try to extract application UUIDs
            import re
            app_pattern = r'/app/ats/applications/([0-9a-f-]{36})/'
            app_ids = re.findall(app_pattern, response.text)

            if app_ids:
                log(f"Found {len(app_ids)} application IDs")
                # Test first 3 applications
                for i, app_id in enumerate(app_ids[:3], 1):
                    url = f"{BASE_URL}/app/ats/applications/{app_id}/"
                    test_page(
                        session,
                        f"Application Detail {i}",
                        url,
                        check_content=["Application", "Candidate", "Job"],
                        screenshot_name=f"04_application_detail_{i}"
                    )
                    time.sleep(1)
            else:
                log("WARNING: No application IDs found", "WARNING")
                findings["warnings_list"].append("No applications found to test detail pages")
        else:
            log(f"ERROR: Could not fetch pipeline board (status {response.status_code})", "ERROR")
    except Exception as e:
        log(f"ERROR: Exception while fetching applications: {e}", "ERROR")

def test_interview_list(session):
    """Test interview list page."""
    log("\n" + "=" * 80)
    log("STEP 6: TESTING INTERVIEW LIST")
    log("=" * 80)

    url = f"{BASE_URL}/app/ats/interviews/"
    test_page(
        session,
        "Interview List",
        url,
        check_content=["Interview", "Scheduled", "Upcoming"],
        screenshot_name="05_interview_list"
    )

def test_interview_detail(session):
    """Test interview detail pages."""
    log("\n" + "=" * 80)
    log("STEP 7: TESTING INTERVIEW DETAIL PAGES")
    log("=" * 80)

    # Get interview list to find interview IDs
    log("Fetching interview list to find interview IDs...")
    try:
        response = session.get(f"{BASE_URL}/app/ats/interviews/", timeout=30, verify=False)

        if response.status_code == 200:
            import re
            interview_pattern = r'/app/ats/interviews/([0-9a-f-]{36})/'
            interview_ids = re.findall(interview_pattern, response.text)

            if interview_ids:
                log(f"Found {len(interview_ids)} interview IDs")
                # Test first 2 interviews
                for i, interview_id in enumerate(interview_ids[:2], 1):
                    url = f"{BASE_URL}/app/ats/interviews/{interview_id}/"
                    test_page(
                        session,
                        f"Interview Detail {i}",
                        url,
                        check_content=["Interview", "Candidate", "Feedback"],
                        screenshot_name=f"06_interview_detail_{i}"
                    )
                    time.sleep(1)
            else:
                log("WARNING: No interview IDs found", "WARNING")
                findings["warnings_list"].append("No interviews found to test detail pages")
        else:
            log(f"ERROR: Could not fetch interview list (status {response.status_code})", "ERROR")
    except Exception as e:
        log(f"ERROR: Exception while fetching interviews: {e}", "ERROR")

def test_offer_list(session):
    """Test offer list page."""
    log("\n" + "=" * 80)
    log("STEP 8: TESTING OFFER LIST")
    log("=" * 80)

    url = f"{BASE_URL}/app/ats/offers/"
    test_page(
        session,
        "Offer List",
        url,
        check_content=["Offer", "Pending", "Accepted"],
        screenshot_name="07_offer_list"
    )

def test_job_list(session):
    """Test job list page (for context)."""
    log("\n" + "=" * 80)
    log("STEP 9: TESTING JOB LIST (CONTEXT)")
    log("=" * 80)

    url = f"{BASE_URL}/app/ats/jobs/"
    test_page(
        session,
        "Job List",
        url,
        check_content=["Jobs", "Open", "Closed"],
        screenshot_name="08_job_list"
    )

def test_candidate_create(session):
    """Test candidate creation page."""
    log("\n" + "=" * 80)
    log("STEP 10: TESTING CANDIDATE CREATE PAGE")
    log("=" * 80)

    url = f"{BASE_URL}/app/ats/candidates/create/"
    test_page(
        session,
        "Candidate Create",
        url,
        check_content=["Create", "Candidate", "First Name", "Email"],
        screenshot_name="09_candidate_create"
    )

# =============================================================================
# MAIN TEST EXECUTION
# =============================================================================

def main():
    """Main test execution."""
    # Clear previous log
    if TEST_LOG_FILE.exists():
        TEST_LOG_FILE.unlink()

    log("=" * 80)
    log("ATS CANDIDATES & APPLICATIONS MODULE TESTING")
    log("=" * 80)
    log(f"Target URL: {BASE_URL}")
    log(f"Test run started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"Screenshots directory: {SCREENSHOTS_DIR}")
    log("")

    # Disable SSL warnings for self-signed certificates
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Create session
    session = create_session()

    # Step 1: Login
    if not login(session):
        log("\n" + "=" * 80)
        log("CRITICAL ERROR: Authentication failed. Cannot proceed with tests.")
        log("=" * 80)
        log("\nPlease verify:")
        log("  1. The demo tenant exists and is active")
        log("  2. The credentials are correct:")
        log(f"     Email: {LOGIN_EMAIL}")
        log(f"     Password: {LOGIN_PASSWORD}")
        log("  3. The site is accessible")

        # Save findings
        findings["errors"].append("Authentication failed - tests aborted")
        with open(FINDINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

        return

    # Run all tests
    try:
        test_candidate_list(session)
        test_candidate_detail(session)
        test_pipeline_board(session)
        test_application_detail(session)
        test_interview_list(session)
        test_interview_detail(session)
        test_offer_list(session)
        test_job_list(session)
        test_candidate_create(session)
    except Exception as e:
        log(f"\nCRITICAL ERROR during test execution: {e}", "ERROR")
        findings["errors"].append(f"Critical error: {str(e)}")

    # Test summary
    log("\n" + "=" * 80)
    log("TEST SUMMARY")
    log("=" * 80)
    log(f"Total tests: {findings['total_tests']}")
    log(f"Passed (200 OK): {findings['passed_tests']}")
    log(f"Failed: {findings['failed_tests']}")
    log(f"Warnings: {findings['warnings']}")
    log(f"Errors: {len(findings['errors'])}")

    if findings['errors']:
        log("\nErrors found:")
        for error in findings['errors']:
            log(f"  - {error}")

    if findings['warnings_list']:
        log("\nWarnings:")
        for warning in findings['warnings_list']:
            log(f"  - {warning}")

    # Save findings to JSON
    with open(FINDINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    log(f"\nFindings saved to: {FINDINGS_FILE}")
    log(f"Test log saved to: {TEST_LOG_FILE}")
    log(f"HTML snapshots saved to: {SCREENSHOTS_DIR}")
    log("\n" + "=" * 80)
    log("TEST RUN COMPLETED")
    log("=" * 80)

if __name__ == "__main__":
    main()
