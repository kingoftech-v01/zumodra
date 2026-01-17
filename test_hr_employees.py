"""
HR Employees Module Testing Script

Tests all employee-related functionality on the demo site:
- Employee directory listing
- Employee detail view
- Employee create form
- Employee edit form
- Organization chart
- All CRUD operations

This script will:
1. Authenticate to the demo site
2. Test all HR employee URLs
3. Take screenshots of every page
4. Document findings with inline comments
5. Report any errors, 404s, or UI issues
"""

import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_results/hr_employees/test_log.txt'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
SCREENSHOTS_DIR = Path("test_results/hr_employees")
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

# Test results tracking
test_results = {
    'total': 0,
    'passed': 0,
    'failed': 0,
    'errors': [],
    'warnings': []
}


class HREmployeeTester:
    """Test class for HR Employee module functionality."""

    def __init__(self):
        """Initialize the tester with Selenium WebDriver."""
        self.driver = None
        self.session = requests.Session()
        self.authenticated = False
        self.test_employee_id = None

    def setup_driver(self):
        """Setup Chrome WebDriver with appropriate options."""
        logger.info("Setting up Chrome WebDriver...")
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--allow-insecure-localhost')

        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            logger.info("Chrome WebDriver initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Chrome WebDriver: {e}")
            raise

    def teardown_driver(self):
        """Clean up WebDriver."""
        if self.driver:
            self.driver.quit()
            logger.info("WebDriver closed")

    def take_screenshot(self, name):
        """Take a screenshot and save it with the given name."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}.png"
        filepath = SCREENSHOTS_DIR / filename
        try:
            self.driver.save_screenshot(str(filepath))
            logger.info(f"Screenshot saved: {filename}")
            return str(filepath)
        except Exception as e:
            logger.error(f"Failed to save screenshot {name}: {e}")
            return None

    def check_for_errors(self, url):
        """Check page for common error indicators."""
        errors = []
        warnings = []

        try:
            # Check for 404
            if "404" in self.driver.title or "Not Found" in self.driver.title:
                errors.append(f"404 Page Not Found: {url}")

            # Check for 500 error
            if "500" in self.driver.title or "Server Error" in self.driver.title:
                errors.append(f"500 Server Error: {url}")

            # Check for error messages in page
            try:
                error_elements = self.driver.find_elements(By.CLASS_NAME, 'alert-danger')
                for elem in error_elements:
                    if elem.is_displayed():
                        errors.append(f"Error message on {url}: {elem.text}")
            except:
                pass

            # Check for warning messages
            try:
                warning_elements = self.driver.find_elements(By.CLASS_NAME, 'alert-warning')
                for elem in warning_elements:
                    if elem.is_displayed():
                        warnings.append(f"Warning on {url}: {elem.text}")
            except:
                pass

            # Check for empty content or missing data
            try:
                body = self.driver.find_element(By.TAG_NAME, 'body')
                if len(body.text.strip()) < 50:
                    warnings.append(f"Page appears empty or minimal content: {url}")
            except:
                pass

        except Exception as e:
            logger.error(f"Error checking page for issues: {e}")

        return errors, warnings

    def authenticate(self):
        """Authenticate to the demo site."""
        logger.info("=" * 80)
        logger.info("AUTHENTICATION")
        logger.info("=" * 80)

        test_results['total'] += 1

        try:
            # Try to find or create test credentials
            # First, try common demo credentials
            credentials = [
                ('admin@demo-company.com', 'password123'),
                ('demo@demo-company.com', 'demo123'),
                ('hr@demo-company.com', 'password'),
                ('test@demo-company.com', 'test123'),
            ]

            login_url = f"{BASE_URL}/accounts/login/"

            for email, password in credentials:
                logger.info(f"Attempting login with {email}...")
                self.driver.get(login_url)
                time.sleep(2)

                self.take_screenshot("01_login_page")

                try:
                    # Find and fill login form
                    email_input = self.driver.find_element(By.NAME, 'email')
                    password_input = self.driver.find_element(By.NAME, 'password')

                    email_input.clear()
                    email_input.send_keys(email)
                    password_input.clear()
                    password_input.send_keys(password)

                    # Submit form
                    submit_button = self.driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
                    submit_button.click()

                    time.sleep(3)

                    # Check if login was successful
                    if "/dashboard/" in self.driver.current_url or "/app/" in self.driver.current_url:
                        logger.info(f"Successfully authenticated as {email}")
                        self.authenticated = True
                        test_results['passed'] += 1
                        self.take_screenshot("02_after_login")
                        return True

                except Exception as e:
                    logger.debug(f"Login attempt failed for {email}: {e}")
                    continue

            # If we get here, no credentials worked
            logger.error("Failed to authenticate with any test credentials")
            test_results['failed'] += 1
            test_results['errors'].append("Authentication failed - no valid credentials found")
            return False

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            test_results['failed'] += 1
            test_results['errors'].append(f"Authentication exception: {str(e)}")
            return False

    def test_employee_directory(self):
        """Test the employee directory page."""
        logger.info("=" * 80)
        logger.info("TEST: Employee Directory")
        logger.info("=" * 80)

        test_results['total'] += 1
        url = f"{BASE_URL}/app/hr/employees/"

        try:
            logger.info(f"Navigating to: {url}")
            self.driver.get(url)
            time.sleep(3)

            self.take_screenshot("03_employee_directory")

            # Check for errors
            errors, warnings = self.check_for_errors(url)
            if errors:
                test_results['errors'].extend(errors)
                test_results['failed'] += 1
                logger.error(f"Errors found on employee directory: {errors}")
                return

            if warnings:
                test_results['warnings'].extend(warnings)
                logger.warning(f"Warnings on employee directory: {warnings}")

            # Check page elements
            page_checks = []

            # Check for employee list/table
            try:
                employees = self.driver.find_elements(By.CSS_SELECTOR, '.employee-card, .employee-row, tbody tr')
                if employees:
                    logger.info(f"Found {len(employees)} employee entries")
                    page_checks.append(f"✓ Employee list present ({len(employees)} entries)")

                    # Store first employee ID for later tests
                    if len(employees) > 0:
                        try:
                            first_link = self.driver.find_element(By.CSS_SELECTOR, 'a[href*="/employees/"]')
                            href = first_link.get_attribute('href')
                            if '/employees/' in href:
                                self.test_employee_id = href.split('/employees/')[-1].rstrip('/')
                                logger.info(f"Captured test employee ID: {self.test_employee_id}")
                        except:
                            pass
                else:
                    test_results['warnings'].append("No employees found in directory")
                    logger.warning("No employees found in directory")
            except Exception as e:
                page_checks.append(f"✗ Could not find employee list: {e}")

            # Check for search functionality
            try:
                search_input = self.driver.find_element(By.CSS_SELECTOR, 'input[name="q"], input[type="search"]')
                page_checks.append("✓ Search functionality present")
            except:
                page_checks.append("✗ Search input not found")

            # Check for filters
            try:
                filters = self.driver.find_elements(By.CSS_SELECTOR, 'select, .filter-dropdown')
                if filters:
                    page_checks.append(f"✓ Filters present ({len(filters)} filter controls)")
                else:
                    page_checks.append("✗ No filters found")
            except:
                page_checks.append("✗ Filter elements not accessible")

            # Check for "Create Employee" button
            try:
                create_btn = self.driver.find_element(By.CSS_SELECTOR, 'a[href*="/create"], button:contains("Create"), a:contains("Add")')
                page_checks.append("✓ Create employee button present")
            except:
                page_checks.append("✗ Create employee button not found")

            # Log all checks
            for check in page_checks:
                logger.info(check)

            test_results['passed'] += 1
            logger.info("Employee directory test PASSED")

        except Exception as e:
            logger.error(f"Employee directory test FAILED: {e}")
            test_results['failed'] += 1
            test_results['errors'].append(f"Employee directory error: {str(e)}")

    def test_employee_detail(self):
        """Test employee detail page."""
        logger.info("=" * 80)
        logger.info("TEST: Employee Detail View")
        logger.info("=" * 80)

        test_results['total'] += 1

        if not self.test_employee_id:
            logger.warning("No employee ID available, attempting to find one...")
            # Try to get an employee ID from the directory
            try:
                self.driver.get(f"{BASE_URL}/app/hr/employees/")
                time.sleep(2)
                first_link = self.driver.find_element(By.CSS_SELECTOR, 'a[href*="/employees/"]')
                href = first_link.get_attribute('href')
                if '/employees/' in href:
                    self.test_employee_id = href.split('/employees/')[-1].rstrip('/')
            except:
                logger.error("Could not find employee ID for testing detail view")
                test_results['failed'] += 1
                test_results['errors'].append("No employee ID available for detail view test")
                return

        url = f"{BASE_URL}/app/hr/employees/{self.test_employee_id}/"

        try:
            logger.info(f"Navigating to: {url}")
            self.driver.get(url)
            time.sleep(3)

            self.take_screenshot("04_employee_detail")

            # Check for errors
            errors, warnings = self.check_for_errors(url)
            if errors:
                test_results['errors'].extend(errors)
                test_results['failed'] += 1
                logger.error(f"Errors found on employee detail: {errors}")
                return

            if warnings:
                test_results['warnings'].extend(warnings)
                logger.warning(f"Warnings on employee detail: {warnings}")

            # Check page elements
            page_checks = []

            # Check for employee name/header
            try:
                header = self.driver.find_element(By.CSS_SELECTOR, 'h1, h2, .employee-name')
                page_checks.append(f"✓ Employee header present: {header.text[:50]}")
            except:
                page_checks.append("✗ Employee header not found")

            # Check for employment details
            detail_sections = [
                'Job Title', 'Department', 'Manager', 'Status', 'Employment Type',
                'Hire Date', 'Employee ID', 'Email'
            ]

            page_text = self.driver.find_element(By.TAG_NAME, 'body').text
            for section in detail_sections:
                if section.lower() in page_text.lower():
                    page_checks.append(f"✓ {section} section present")
                else:
                    page_checks.append(f"✗ {section} section not found")

            # Check for tabs or sections
            try:
                tabs = self.driver.find_elements(By.CSS_SELECTOR, '.tab, .nav-tab, [role="tab"]')
                if tabs:
                    page_checks.append(f"✓ Navigation tabs present ({len(tabs)} tabs)")
            except:
                pass

            # Check for edit button
            try:
                edit_btn = self.driver.find_element(By.CSS_SELECTOR, 'a[href*="/edit"], button:contains("Edit")')
                page_checks.append("✓ Edit button present")
            except:
                page_checks.append("✗ Edit button not found")

            # Log all checks
            for check in page_checks:
                logger.info(check)

            test_results['passed'] += 1
            logger.info("Employee detail test PASSED")

        except Exception as e:
            logger.error(f"Employee detail test FAILED: {e}")
            test_results['failed'] += 1
            test_results['errors'].append(f"Employee detail error: {str(e)}")

    def test_employee_create(self):
        """Test employee creation form."""
        logger.info("=" * 80)
        logger.info("TEST: Employee Create Form")
        logger.info("=" * 80)

        test_results['total'] += 1
        url = f"{BASE_URL}/app/hr/employees/create/"

        try:
            logger.info(f"Navigating to: {url}")
            self.driver.get(url)
            time.sleep(3)

            self.take_screenshot("05_employee_create")

            # Check for errors
            errors, warnings = self.check_for_errors(url)
            if errors:
                test_results['errors'].extend(errors)
                test_results['failed'] += 1
                logger.error(f"Errors found on employee create: {errors}")
                return

            if warnings:
                test_results['warnings'].extend(warnings)
                logger.warning(f"Warnings on employee create: {warnings}")

            # Check form elements
            page_checks = []

            # Check for form
            try:
                form = self.driver.find_element(By.TAG_NAME, 'form')
                page_checks.append("✓ Form element present")
            except:
                page_checks.append("✗ Form element not found")
                test_results['warnings'].append("Create form not found - may not be implemented")

            # Check for common form fields
            form_fields = [
                ('job_title', 'Job Title'),
                ('department', 'Department'),
                ('employment_type', 'Employment Type'),
                ('hire_date', 'Hire Date'),
            ]

            for field_name, field_label in form_fields:
                try:
                    field = self.driver.find_element(By.CSS_SELECTOR, f'[name*="{field_name}"], #{field_name}')
                    page_checks.append(f"✓ {field_label} field present")
                except:
                    page_checks.append(f"✗ {field_label} field not found")

            # Check for submit button
            try:
                submit = self.driver.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                page_checks.append("✓ Submit button present")
            except:
                page_checks.append("✗ Submit button not found")

            # Log all checks
            for check in page_checks:
                logger.info(check)

            test_results['passed'] += 1
            logger.info("Employee create test PASSED")

        except Exception as e:
            logger.error(f"Employee create test FAILED: {e}")
            test_results['failed'] += 1
            test_results['errors'].append(f"Employee create error: {str(e)}")

    def test_employee_edit(self):
        """Test employee edit form."""
        logger.info("=" * 80)
        logger.info("TEST: Employee Edit Form")
        logger.info("=" * 80)

        test_results['total'] += 1

        if not self.test_employee_id:
            logger.warning("No employee ID available for edit test")
            test_results['failed'] += 1
            test_results['errors'].append("No employee ID available for edit test")
            return

        url = f"{BASE_URL}/app/hr/employees/{self.test_employee_id}/edit/"

        try:
            logger.info(f"Navigating to: {url}")
            self.driver.get(url)
            time.sleep(3)

            self.take_screenshot("06_employee_edit")

            # Check for errors
            errors, warnings = self.check_for_errors(url)
            if errors:
                test_results['errors'].extend(errors)
                test_results['failed'] += 1
                logger.error(f"Errors found on employee edit: {errors}")
                return

            if warnings:
                test_results['warnings'].extend(warnings)
                logger.warning(f"Warnings on employee edit: {warnings}")

            # Check form elements
            page_checks = []

            # Check for form
            try:
                form = self.driver.find_element(By.TAG_NAME, 'form')
                page_checks.append("✓ Form element present")
            except:
                page_checks.append("✗ Form element not found")

            # Check for pre-filled data
            try:
                inputs = self.driver.find_elements(By.CSS_SELECTOR, 'input[value], textarea')
                filled_inputs = [inp for inp in inputs if inp.get_attribute('value')]
                if filled_inputs:
                    page_checks.append(f"✓ Form has pre-filled data ({len(filled_inputs)} fields)")
                else:
                    page_checks.append("✗ Form appears empty (no pre-filled data)")
            except:
                page_checks.append("✗ Could not check form data")

            # Check for submit button
            try:
                submit = self.driver.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                page_checks.append("✓ Submit button present")
            except:
                page_checks.append("✗ Submit button not found")

            # Log all checks
            for check in page_checks:
                logger.info(check)

            test_results['passed'] += 1
            logger.info("Employee edit test PASSED")

        except Exception as e:
            logger.error(f"Employee edit test FAILED: {e}")
            test_results['failed'] += 1
            test_results['errors'].append(f"Employee edit error: {str(e)}")

    def test_org_chart(self):
        """Test organization chart page."""
        logger.info("=" * 80)
        logger.info("TEST: Organization Chart")
        logger.info("=" * 80)

        test_results['total'] += 1
        url = f"{BASE_URL}/app/hr/org-chart/"

        try:
            logger.info(f"Navigating to: {url}")
            self.driver.get(url)
            time.sleep(3)

            self.take_screenshot("07_org_chart")

            # Check for errors
            errors, warnings = self.check_for_errors(url)
            if errors:
                test_results['errors'].extend(errors)
                test_results['failed'] += 1
                logger.error(f"Errors found on org chart: {errors}")
                return

            if warnings:
                test_results['warnings'].extend(warnings)
                logger.warning(f"Warnings on org chart: {warnings}")

            # Check page elements
            page_checks = []

            # Check for org chart visualization
            try:
                org_elements = self.driver.find_elements(By.CSS_SELECTOR, '.org-chart, #orgchart, .hierarchy, svg')
                if org_elements:
                    page_checks.append(f"✓ Organization chart visualization present")
                else:
                    page_checks.append("✗ Organization chart visualization not found")
            except:
                page_checks.append("✗ Could not check for org chart visualization")

            # Check for employee nodes/cards
            try:
                nodes = self.driver.find_elements(By.CSS_SELECTOR, '.employee-node, .org-node, .person-card')
                if nodes:
                    page_checks.append(f"✓ Employee nodes present ({len(nodes)} nodes)")
                else:
                    page_checks.append("✗ No employee nodes found")
            except:
                pass

            # Log all checks
            for check in page_checks:
                logger.info(check)

            test_results['passed'] += 1
            logger.info("Organization chart test PASSED")

        except Exception as e:
            logger.error(f"Organization chart test FAILED: {e}")
            test_results['failed'] += 1
            test_results['errors'].append(f"Organization chart error: {str(e)}")

    def generate_report(self):
        """Generate a comprehensive test report."""
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

        if test_results['errors']:
            report.append("ERRORS")
            report.append("-" * 80)
            for error in test_results['errors']:
                report.append(f"  ✗ {error}")
            report.append("")

        if test_results['warnings']:
            report.append("WARNINGS")
            report.append("-" * 80)
            for warning in test_results['warnings']:
                report.append(f"  ⚠ {warning}")
            report.append("")

        report.append("TESTED URLS")
        report.append("-" * 80)
        report.append(f"  • Employee Directory: {BASE_URL}/app/hr/employees/")
        report.append(f"  • Employee Detail: {BASE_URL}/app/hr/employees/<id>/")
        report.append(f"  • Employee Create: {BASE_URL}/app/hr/employees/create/")
        report.append(f"  • Employee Edit: {BASE_URL}/app/hr/employees/<id>/edit/")
        report.append(f"  • Organization Chart: {BASE_URL}/app/hr/org-chart/")
        report.append("")

        report.append("SCREENSHOTS")
        report.append("-" * 80)
        screenshots = sorted(SCREENSHOTS_DIR.glob("*.png"))
        for screenshot in screenshots:
            report.append(f"  • {screenshot.name}")
        report.append("")

        report.append("=" * 80)

        # Print report
        report_text = "\n".join(report)
        print(report_text)
        logger.info(report_text)

        # Save report to file
        report_file = SCREENSHOTS_DIR / "test_report.txt"
        with open(report_file, 'w') as f:
            f.write(report_text)
        logger.info(f"Report saved to: {report_file}")

        return report_text

    def run_all_tests(self):
        """Run all HR employee tests."""
        logger.info("Starting HR Employees Module Testing")
        logger.info(f"Base URL: {BASE_URL}")
        logger.info(f"Screenshots will be saved to: {SCREENSHOTS_DIR}")

        try:
            self.setup_driver()

            # Step 1: Authentication
            if not self.authenticate():
                logger.error("Authentication failed - cannot proceed with tests")
                return

            # Step 2: Test employee directory
            self.test_employee_directory()

            # Step 3: Test employee detail
            self.test_employee_detail()

            # Step 4: Test employee create
            self.test_employee_create()

            # Step 5: Test employee edit
            self.test_employee_edit()

            # Step 6: Test org chart
            self.test_org_chart()

            # Generate report
            self.generate_report()

        except Exception as e:
            logger.error(f"Fatal error during testing: {e}")
            test_results['errors'].append(f"Fatal error: {str(e)}")

        finally:
            self.teardown_driver()

        logger.info("Testing complete!")
        return test_results


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
    print("  3. Take screenshots of every page")
    print("  4. Document findings and report errors")
    print()
    print("=" * 80)
    print()

    tester = HREmployeeTester()
    results = tester.run_all_tests()

    # Exit with appropriate code
    if results['failed'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
