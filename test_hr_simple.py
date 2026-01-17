"""
Simple HR Employees Module Testing Script (without Selenium)

Tests all employee-related URLs on the demo site using requests library.
This is a lighter-weight alternative that doesn't require browser automation.
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
SCREENSHOTS_DIR = Path("test_results/hr_employees")
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(SCREENSHOTS_DIR / 'test_log.txt', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"

# Test results tracking
test_results = {
    'total': 0,
    'passed': 0,
    'failed': 0,
    'errors': [],
    'warnings': [],
    'url_tests': []
}


class HREmployeeTester:
    """Test class for HR Employee module functionality."""

    def __init__(self):
        """Initialize the tester with requests session."""
        self.session = requests.Session()
        # Add retry logic
        retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        # Disable SSL verification for demo sites
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

        self.authenticated = False
        self.csrf_token = None
        self.test_employee_id = None

    def get_csrf_token(self, response):
        """Extract CSRF token from response."""
        if 'csrftoken' in self.session.cookies:
            return self.session.cookies['csrftoken']
        # Try to extract from HTML
        if 'csrf' in response.text.lower():
            import re
            match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']', response.text)
            if match:
                return match.group(1)
        return None

    def authenticate(self):
        """Authenticate to the demo site."""
        logger.info("=" * 80)
        logger.info("AUTHENTICATION")
        logger.info("=" * 80)

        test_results['total'] += 1

        try:
            # Try common demo credentials
            credentials = [
                ('admin@demo-company.com', 'password123'),
                ('demo@demo-company.com', 'demo123'),
                ('hr@demo-company.com', 'password'),
                ('test@demo-company.com', 'test123'),
            ]

            login_url = urljoin(BASE_URL, '/accounts/login/')

            # First, get the login page to get CSRF token
            logger.info(f"Getting login page: {login_url}")
            response = self.session.get(login_url, timeout=30)

            if response.status_code != 200:
                logger.error(f"Failed to load login page: {response.status_code}")
                test_results['failed'] += 1
                test_results['errors'].append(f"Login page returned {response.status_code}")
                return False

            csrf_token = self.get_csrf_token(response)
            logger.info(f"CSRF token obtained: {csrf_token[:10] if csrf_token else 'None'}...")

            for email, password in credentials:
                logger.info(f"Attempting login with {email}...")

                # Prepare login data
                login_data = {
                    'email': email,
                    'password': password,
                }

                if csrf_token:
                    login_data['csrfmiddlewaretoken'] = csrf_token

                # Submit login
                response = self.session.post(
                    login_url,
                    data=login_data,
                    allow_redirects=True,
                    timeout=30
                )

                # Check if login was successful
                if response.status_code == 200:
                    # Check for success indicators
                    if '/dashboard/' in response.url or '/app/' in response.url or 'logout' in response.text.lower():
                        logger.info(f"[PASS] Successfully authenticated as {email}")
                        self.authenticated = True
                        test_results['passed'] += 1
                        return True
                    elif 'invalid' in response.text.lower() or 'incorrect' in response.text.lower():
                        logger.debug(f"Invalid credentials for {email}")
                        continue
                else:
                    logger.debug(f"Login returned {response.status_code} for {email}")

            # If we get here, no credentials worked
            logger.error("[FAIL] Failed to authenticate with any test credentials")
            test_results['failed'] += 1
            test_results['errors'].append("Authentication failed - no valid credentials found")
            return False

        except Exception as e:
            logger.error(f"[FAIL] Authentication error: {e}")
            test_results['failed'] += 1
            test_results['errors'].append(f"Authentication exception: {str(e)}")
            return False

    def test_url(self, url, name, expected_content=None):
        """Test a single URL."""
        logger.info("-" * 80)
        logger.info(f"Testing: {name}")
        logger.info(f"URL: {url}")

        test_results['total'] += 1
        result = {
            'name': name,
            'url': url,
            'status_code': None,
            'success': False,
            'errors': [],
            'warnings': [],
            'checks': []
        }

        try:
            response = self.session.get(url, timeout=30)
            result['status_code'] = response.status_code

            logger.info(f"Status Code: {response.status_code}")
            logger.info(f"Final URL: {response.url}")

            # Check status code
            if response.status_code == 200:
                result['checks'].append("[PASS] HTTP 200 OK")
                logger.info("[PASS] HTTP 200 OK")
            elif response.status_code == 404:
                result['errors'].append("[FAIL] 404 Not Found")
                logger.error("[FAIL] 404 Not Found - URL does not exist")
                test_results['errors'].append(f"{name}: 404 Not Found")
            elif response.status_code == 403:
                result['errors'].append("[FAIL] 403 Forbidden")
                logger.error("[FAIL] 403 Forbidden - Access denied")
                test_results['errors'].append(f"{name}: 403 Forbidden")
            elif response.status_code == 500:
                result['errors'].append("[FAIL] 500 Server Error")
                logger.error("[FAIL] 500 Server Error")
                test_results['errors'].append(f"{name}: 500 Server Error")
            else:
                result['warnings'].append(f"[WARN] Unexpected status code: {response.status_code}")
                logger.warning(f"[WARN] Unexpected status code: {response.status_code}")

            # Check content
            if response.status_code == 200:
                content_length = len(response.text)
                result['checks'].append(f"[PASS] Content length: {content_length} bytes")
                logger.info(f"[PASS] Content length: {content_length} bytes")

                if content_length < 500:
                    result['warnings'].append("[WARN] Page content is very short (< 500 bytes)")
                    logger.warning("[WARN] Page content is very short (< 500 bytes)")

                # Check for error indicators in content
                content_lower = response.text.lower()

                if 'error' in content_lower and 'server error' in content_lower:
                    result['errors'].append("[FAIL] Server error message in page content")
                    logger.error("[FAIL] Server error message found in page")
                    test_results['errors'].append(f"{name}: Server error message in content")

                if 'exception' in content_lower and 'traceback' in content_lower:
                    result['errors'].append("[FAIL] Python exception/traceback in page")
                    logger.error("[FAIL] Python exception/traceback found in page")
                    test_results['errors'].append(f"{name}: Exception in content")

                # Check for expected content
                if expected_content:
                    for content_item in expected_content:
                        if content_item.lower() in content_lower:
                            result['checks'].append(f"[PASS] Found expected content: '{content_item}'")
                            logger.info(f"[PASS] Found expected content: '{content_item}'")
                        else:
                            result['warnings'].append(f"[WARN] Expected content not found: '{content_item}'")
                            logger.warning(f"[WARN] Expected content not found: '{content_item}'")

                # Check for common page elements
                if '<title>' in response.text:
                    import re
                    title_match = re.search(r'<title>([^<]+)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()
                        result['checks'].append(f"[PASS] Page title: {title}")
                        logger.info(f"[PASS] Page title: {title}")

                # Check for login redirect (indicates not authenticated for this page)
                if '/login' in response.url.lower() or 'sign in' in content_lower:
                    result['warnings'].append("[WARN] Page may require authentication")
                    logger.warning("[WARN] Redirected to login or login prompt found")

            # Determine success
            if response.status_code == 200 and not result['errors']:
                result['success'] = True
                test_results['passed'] += 1
                logger.info(f"[PASS] {name} test PASSED")
            else:
                test_results['failed'] += 1
                logger.error(f"[FAIL] {name} test FAILED")

        except requests.exceptions.Timeout:
            result['errors'].append("[FAIL] Request timeout")
            logger.error("[FAIL] Request timeout (30s)")
            test_results['failed'] += 1
            test_results['errors'].append(f"{name}: Request timeout")
        except requests.exceptions.ConnectionError as e:
            result['errors'].append(f"[FAIL] Connection error: {str(e)}")
            logger.error(f"[FAIL] Connection error: {e}")
            test_results['failed'] += 1
            test_results['errors'].append(f"{name}: Connection error")
        except Exception as e:
            result['errors'].append(f"[FAIL] Unexpected error: {str(e)}")
            logger.error(f"[FAIL] Unexpected error: {e}")
            test_results['failed'] += 1
            test_results['errors'].append(f"{name}: {str(e)}")

        test_results['url_tests'].append(result)
        test_results['warnings'].extend(result['warnings'])

        return result['success']

    def run_all_tests(self):
        """Run all HR employee tests."""
        logger.info("=" * 80)
        logger.info("HR EMPLOYEES MODULE TESTING")
        logger.info("=" * 80)
        logger.info(f"Base URL: {BASE_URL}")
        logger.info(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 80)
        logger.info("")

        try:
            # Step 1: Authentication
            if not self.authenticate():
                logger.error("Authentication failed - proceeding with tests anyway (may get 403/redirects)")

            logger.info("")
            logger.info("=" * 80)
            logger.info("URL TESTS")
            logger.info("=" * 80)
            logger.info("")

            # Step 2: Test employee directory
            self.test_url(
                urljoin(BASE_URL, '/app/hr/employees/'),
                'Employee Directory',
                expected_content=['employee', 'name', 'department']
            )

            # Step 3: Test employee detail (with placeholder ID)
            # Try to extract employee ID from directory if possible
            try:
                response = self.session.get(urljoin(BASE_URL, '/app/hr/employees/'))
                if response.status_code == 200:
                    import re
                    # Look for UUID pattern in hrefs
                    uuid_pattern = r'/employees/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
                    match = re.search(uuid_pattern, response.text, re.IGNORECASE)
                    if match:
                        self.test_employee_id = match.group(1)
                        logger.info(f"Found employee ID: {self.test_employee_id}")
            except:
                pass

            if self.test_employee_id:
                self.test_url(
                    urljoin(BASE_URL, f'/app/hr/employees/{self.test_employee_id}/'),
                    'Employee Detail',
                    expected_content=['employee', 'job title', 'department']
                )
            else:
                logger.warning("Could not extract employee ID for detail test")
                test_results['warnings'].append("Employee detail test skipped - no ID found")

            # Step 4: Test employee create
            self.test_url(
                urljoin(BASE_URL, '/app/hr/employees/create/'),
                'Employee Create',
                expected_content=['form', 'create', 'employee']
            )

            # Step 5: Test employee edit
            if self.test_employee_id:
                self.test_url(
                    urljoin(BASE_URL, f'/app/hr/employees/{self.test_employee_id}/edit/'),
                    'Employee Edit',
                    expected_content=['form', 'edit', 'employee']
                )
            else:
                logger.warning("Could not test employee edit - no ID found")
                test_results['warnings'].append("Employee edit test skipped - no ID found")

            # Step 6: Test org chart
            self.test_url(
                urljoin(BASE_URL, '/app/hr/org-chart/'),
                'Organization Chart',
                expected_content=['organization', 'chart', 'employee']
            )

            # Step 7: Test org chart data API
            self.test_url(
                urljoin(BASE_URL, '/app/hr/org-chart/data/'),
                'Organization Chart Data API',
                expected_content=['employees']
            )

            # Generate report
            self.generate_report()

        except Exception as e:
            logger.error(f"Fatal error during testing: {e}")
            test_results['errors'].append(f"Fatal error: {str(e)}")

        logger.info("")
        logger.info("=" * 80)
        logger.info("Testing complete!")
        logger.info("=" * 80)

        return test_results

    def generate_report(self):
        """Generate a comprehensive test report."""
        logger.info("")
        logger.info("=" * 80)
        logger.info("TEST REPORT")
        logger.info("=" * 80)

        report = []
        report.append("=" * 80)
        report.append("HR EMPLOYEES MODULE TEST REPORT")
        report.append(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Base URL: {BASE_URL}")
        report.append("=" * 80)
        report.append("")

        report.append("SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Tests: {test_results['total']}")
        report.append(f"Passed: {test_results['passed']}")
        report.append(f"Failed: {test_results['failed']}")
        pass_rate = (test_results['passed'] / test_results['total'] * 100) if test_results['total'] > 0 else 0
        report.append(f"Pass Rate: {pass_rate:.1f}%")
        report.append("")

        report.append("URL TEST RESULTS")
        report.append("-" * 80)
        for test in test_results['url_tests']:
            status = "[PASS] PASS" if test['success'] else "[FAIL] FAIL"
            report.append(f"{status} | {test['name']}")
            report.append(f"       URL: {test['url']}")
            report.append(f"       Status: {test['status_code']}")
            if test['errors']:
                for error in test['errors']:
                    report.append(f"       {error}")
            if test['checks']:
                for check in test['checks'][:3]:  # Show first 3 checks
                    report.append(f"       {check}")
            report.append("")

        if test_results['errors']:
            report.append("ERRORS")
            report.append("-" * 80)
            for error in test_results['errors']:
                report.append(f"  [FAIL] {error}")
            report.append("")

        if test_results['warnings']:
            report.append("WARNINGS")
            report.append("-" * 80)
            for warning in list(set(test_results['warnings']))[:20]:  # Dedupe and limit
                report.append(f"  [WARN] {warning}")
            report.append("")

        report.append("TESTED URLS")
        report.append("-" * 80)
        report.append(f"  • Employee Directory: {BASE_URL}/app/hr/employees/")
        report.append(f"  • Employee Detail: {BASE_URL}/app/hr/employees/<id>/")
        report.append(f"  • Employee Create: {BASE_URL}/app/hr/employees/create/")
        report.append(f"  • Employee Edit: {BASE_URL}/app/hr/employees/<id>/edit/")
        report.append(f"  • Organization Chart: {BASE_URL}/app/hr/org-chart/")
        report.append(f"  • Org Chart Data API: {BASE_URL}/app/hr/org-chart/data/")
        report.append("")

        report.append("=" * 80)

        # Print report
        report_text = "\n".join(report)
        print("\n" + report_text)

        for line in report:
            logger.info(line)

        # Save report to file
        report_file = SCREENSHOTS_DIR / "test_report.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
        logger.info(f"\nReport saved to: {report_file}")

        # Save JSON report
        json_file = SCREENSHOTS_DIR / "test_results.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(test_results, f, indent=2)
        logger.info(f"JSON results saved to: {json_file}")

        return report_text


def main():
    """Main entry point for the test script."""
    print("=" * 80)
    print("HR EMPLOYEES MODULE TESTING")
    print("=" * 80)
    print()
    print(f"Target: {BASE_URL}")
    print(f"Output: {SCREENSHOTS_DIR}")
    print()
    print("This script will:")
    print("  1. Authenticate to the demo site")
    print("  2. Test all employee-related URLs")
    print("  3. Check for errors and issues")
    print("  4. Generate detailed report")
    print()
    print("=" * 80)
    print()

    tester = HREmployeeTester()
    results = tester.run_all_tests()

    # Exit with appropriate code
    if results['failed'] > 0:
        print(f"\n[WARN] Testing completed with {results['failed']} failures")
        sys.exit(1)
    else:
        print(f"\n[PASS] All {results['passed']} tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
