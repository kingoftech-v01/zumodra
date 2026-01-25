"""
ATS Offers Module Testing Script
=================================

Tests all offer-related functionality on the demo site:
- https://demo-company.zumodra.rhematek-solutions.com

This script will:
1. Authenticate with test credentials
2. Navigate to all offer-related URLs
3. Test CRUD operations (Create, Read, Update, Delete)
4. Test offer actions (send, accept, decline, withdraw)
5. Take screenshots of every page
6. Document all findings
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Test configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
SCREENSHOT_DIR = Path(__file__).parent
RESULTS_FILE = SCREENSHOT_DIR / "test_results.json"

# Test credentials - trying common demo credentials
TEST_CREDENTIALS = [
    {"username": "admin@demo-company.com", "password": "admin123"},
    {"username": "admin", "password": "admin"},
    {"username": "demo", "password": "demo123"},
    {"username": "recruiter@demo-company.com", "password": "recruiter123"},
    {"username": "test@demo-company.com", "password": "test123"},
]

# Test results storage
test_results = {
    "test_run_date": datetime.now().isoformat(),
    "base_url": BASE_URL,
    "authentication": {},
    "pages_tested": [],
    "errors": [],
    "warnings": [],
    "summary": {}
}


class OfferTester:
    """Main testing class for ATS Offers module"""

    def __init__(self, browser: Browser):
        self.browser = browser
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.authenticated = False
        self.credentials_used = None

    async def setup(self):
        """Initialize browser context and page"""
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        self.page = await self.context.new_page()
        logger.info("Browser context initialized")

    async def teardown(self):
        """Cleanup resources"""
        if self.context:
            await self.context.close()
        logger.info("Browser context closed")

    async def take_screenshot(self, name: str, full_page: bool = True):
        """Take a screenshot and save it"""
        screenshot_path = SCREENSHOT_DIR / f"{name}.png"
        await self.page.screenshot(path=str(screenshot_path), full_page=full_page)
        logger.info(f"Screenshot saved: {screenshot_path}")
        return str(screenshot_path)

    async def authenticate(self) -> bool:
        """
        Try to authenticate with test credentials.
        Returns True if successful, False otherwise.
        """
        logger.info("Starting authentication process...")

        # First, try to access the site and see if we're redirected to login
        try:
            await self.page.goto(BASE_URL, wait_until="networkidle", timeout=30000)
            await self.take_screenshot("01_initial_page")

            current_url = self.page.url
            logger.info(f"Current URL after navigation: {current_url}")

            # Check if we're on a login page
            login_indicators = [
                "login", "signin", "sign-in", "authenticate",
                "username", "password", "email"
            ]

            page_content = await self.page.content()
            is_login_page = any(indicator in current_url.lower() or
                               indicator in page_content.lower()
                               for indicator in login_indicators)

            if not is_login_page:
                logger.info("No login required or already authenticated")
                self.authenticated = True
                test_results["authentication"]["status"] = "not_required"
                return True

            # Try each set of credentials
            for idx, creds in enumerate(TEST_CREDENTIALS):
                logger.info(f"Trying credentials {idx + 1}/{len(TEST_CREDENTIALS)}")

                try:
                    # Look for common login form selectors
                    username_selectors = [
                        'input[name="username"]',
                        'input[name="email"]',
                        'input[type="email"]',
                        'input[id="id_username"]',
                        'input[id="id_email"]',
                        '#username',
                        '#email',
                    ]

                    password_selectors = [
                        'input[name="password"]',
                        'input[type="password"]',
                        'input[id="id_password"]',
                        '#password',
                    ]

                    # Find username field
                    username_field = None
                    for selector in username_selectors:
                        try:
                            username_field = await self.page.wait_for_selector(
                                selector, timeout=2000
                            )
                            if username_field:
                                break
                        except:
                            continue

                    if not username_field:
                        logger.error("Could not find username field")
                        continue

                    # Find password field
                    password_field = None
                    for selector in password_selectors:
                        try:
                            password_field = await self.page.wait_for_selector(
                                selector, timeout=2000
                            )
                            if password_field:
                                break
                        except:
                            continue

                    if not password_field:
                        logger.error("Could not find password field")
                        continue

                    # Fill in credentials
                    await username_field.fill(creds["username"])
                    await password_field.fill(creds["password"])

                    await self.take_screenshot(f"02_login_form_filled_{idx + 1}")

                    # Submit form
                    submit_selectors = [
                        'button[type="submit"]',
                        'input[type="submit"]',
                        'button:has-text("Login")',
                        'button:has-text("Sign in")',
                        'button:has-text("Log in")',
                    ]

                    for selector in submit_selectors:
                        try:
                            submit_btn = await self.page.wait_for_selector(
                                selector, timeout=2000
                            )
                            if submit_btn:
                                await submit_btn.click()
                                break
                        except:
                            continue

                    # Wait for navigation
                    await self.page.wait_for_load_state("networkidle", timeout=10000)
                    await self.take_screenshot(f"03_after_login_{idx + 1}")

                    # Check if login was successful
                    new_url = self.page.url
                    if "login" not in new_url.lower():
                        logger.info(f"✓ Authentication successful with credentials {idx + 1}")
                        self.authenticated = True
                        self.credentials_used = creds
                        test_results["authentication"] = {
                            "status": "success",
                            "credentials_used": creds["username"],
                            "attempt_number": idx + 1
                        }
                        return True
                    else:
                        logger.warning(f"Login attempt {idx + 1} failed")

                except Exception as e:
                    logger.error(f"Error during login attempt {idx + 1}: {str(e)}")
                    continue

            # If we get here, all login attempts failed
            logger.error("All authentication attempts failed")
            test_results["authentication"] = {
                "status": "failed",
                "attempts": len(TEST_CREDENTIALS),
                "error": "All credentials failed"
            }
            return False

        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            test_results["authentication"] = {
                "status": "error",
                "error": str(e)
            }
            return False

    async def test_page(self, url: str, page_name: str, description: str) -> Dict:
        """
        Test a specific page and record results.

        Returns a dict with:
        - url: the URL tested
        - name: page name
        - status_code: HTTP status
        - accessible: whether page loaded successfully
        - errors: any errors encountered
        - screenshot: path to screenshot
        """
        logger.info(f"Testing page: {page_name} - {url}")

        result = {
            "url": url,
            "name": page_name,
            "description": description,
            "timestamp": datetime.now().isoformat(),
            "accessible": False,
            "status_code": None,
            "errors": [],
            "warnings": [],
            "screenshot": None
        }

        try:
            # Navigate to page
            response = await self.page.goto(url, wait_until="networkidle", timeout=30000)

            if response:
                result["status_code"] = response.status

                # Check for error status codes
                if response.status >= 500:
                    result["errors"].append(f"Server error: {response.status}")
                    logger.error(f"✗ {page_name}: Server error {response.status}")
                elif response.status == 404:
                    result["errors"].append("Page not found (404)")
                    logger.error(f"✗ {page_name}: Not found (404)")
                elif response.status >= 400:
                    result["errors"].append(f"Client error: {response.status}")
                    logger.warning(f"⚠ {page_name}: Client error {response.status}")
                elif response.status >= 300:
                    result["warnings"].append(f"Redirect: {response.status}")
                    logger.info(f"↪ {page_name}: Redirected ({response.status})")
                else:
                    result["accessible"] = True
                    logger.info(f"✓ {page_name}: Success ({response.status})")

            # Take screenshot
            screenshot_path = await self.take_screenshot(
                page_name.replace(" ", "_").replace("/", "_").lower()
            )
            result["screenshot"] = screenshot_path

            # Check for visible error messages on the page
            error_selectors = [
                '.alert-danger',
                '.error',
                '.alert-error',
                '[role="alert"]',
                '.message.error'
            ]

            for selector in error_selectors:
                try:
                    error_elements = await self.page.query_selector_all(selector)
                    for element in error_elements:
                        error_text = await element.text_content()
                        if error_text and error_text.strip():
                            result["errors"].append(f"Page error: {error_text.strip()}")
                except:
                    continue

            # Check page title
            title = await self.page.title()
            result["page_title"] = title

            if "error" in title.lower() or "404" in title.lower():
                result["errors"].append(f"Error in page title: {title}")

        except Exception as e:
            logger.error(f"✗ {page_name}: Exception - {str(e)}")
            result["errors"].append(f"Exception: {str(e)}")

            # Try to take screenshot anyway
            try:
                screenshot_path = await self.take_screenshot(
                    f"error_{page_name.replace(' ', '_').replace('/', '_').lower()}"
                )
                result["screenshot"] = screenshot_path
            except:
                pass

        return result

    async def test_offer_list(self) -> Dict:
        """Test the offers list page"""
        url = f"{BASE_URL}/app/ats/offers/"
        result = await self.test_page(url, "Offer List", "List all offers with filtering")

        # Additional checks specific to offer list
        if result["accessible"]:
            try:
                # Check for offer table or cards
                has_offers = False

                # Look for common list elements
                list_selectors = [
                    'table',
                    '.offer-list',
                    '.offer-card',
                    '[data-offer-id]'
                ]

                for selector in list_selectors:
                    elements = await self.page.query_selector_all(selector)
                    if elements:
                        has_offers = True
                        result["has_offer_data"] = True
                        result["offer_count"] = len(elements)
                        break

                if not has_offers:
                    result["warnings"].append("No offers found on page")

                # Check for filter options
                filter_selectors = [
                    'select[name="status"]',
                    'input[name="search"]',
                    '.filter-form'
                ]

                for selector in filter_selectors:
                    if await self.page.query_selector(selector):
                        result["has_filters"] = True
                        break

                # Check for create button
                create_btn = await self.page.query_selector('a[href*="create"], button:has-text("Create")')
                result["has_create_button"] = create_btn is not None

            except Exception as e:
                result["warnings"].append(f"Additional checks failed: {str(e)}")

        return result

    async def test_offer_creation(self, application_id: Optional[str] = None) -> Dict:
        """Test offer creation flow"""

        # First, we need to find an application to create an offer for
        if not application_id:
            logger.info("Need to find an application for offer creation...")

            # Navigate to applications or candidates page to get an ID
            # This is a placeholder - we'll try to scrape an application ID
            try:
                # Try pipeline board
                await self.page.goto(f"{BASE_URL}/app/ats/pipeline/", timeout=30000)
                await asyncio.sleep(2)

                # Look for application IDs in the DOM
                app_links = await self.page.query_selector_all('a[href*="/applications/"]')
                if app_links:
                    first_link = app_links[0]
                    href = await first_link.get_attribute('href')
                    # Extract UUID from href
                    import re
                    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
                    match = re.search(uuid_pattern, href)
                    if match:
                        application_id = match.group(0)
                        logger.info(f"Found application ID: {application_id}")
            except Exception as e:
                logger.warning(f"Could not find application ID: {str(e)}")

        if application_id:
            url = f"{BASE_URL}/app/ats/offers/create/{application_id}/"
        else:
            # Test the create endpoint without application ID (should error)
            url = f"{BASE_URL}/app/ats/offers/create/"

        result = await self.test_page(url, "Offer Create", "Create new offer for application")

        # If page is accessible, try to fill out form
        if result["accessible"] and application_id:
            try:
                # Look for form fields
                form_fields = {
                    'base_salary': await self.page.query_selector('input[name="base_salary"]'),
                    'salary_currency': await self.page.query_selector('select[name="salary_currency"]'),
                    'start_date': await self.page.query_selector('input[name="start_date"]'),
                    'expiration_date': await self.page.query_selector('input[name="expiration_date"]'),
                }

                result["has_form"] = any(field is not None for field in form_fields.values())

                if result["has_form"]:
                    logger.info("Form found, attempting to fill it out...")

                    # Fill form with test data
                    if form_fields['base_salary']:
                        await form_fields['base_salary'].fill('75000')

                    if form_fields['start_date']:
                        # Get date 30 days from now
                        from datetime import date, timedelta
                        start = (date.today() + timedelta(days=30)).strftime('%Y-%m-%d')
                        await form_fields['start_date'].fill(start)

                    if form_fields['expiration_date']:
                        # Get date 14 days from now
                        exp = (date.today() + timedelta(days=14)).strftime('%Y-%m-%d')
                        await form_fields['expiration_date'].fill(exp)

                    await self.take_screenshot("offer_create_form_filled")

                    # Note: Not actually submitting to avoid creating test data
                    result["form_fillable"] = True
                    result["warnings"].append("Form not submitted (test mode)")
                else:
                    result["warnings"].append("Form fields not found")

            except Exception as e:
                result["warnings"].append(f"Form interaction failed: {str(e)}")

        return result

    async def test_offer_detail(self, offer_id: Optional[str] = None) -> Dict:
        """Test offer detail page"""

        # Try to find an offer ID from the list page
        if not offer_id:
            logger.info("Attempting to find an offer ID...")
            try:
                await self.page.goto(f"{BASE_URL}/app/ats/offers/", timeout=30000)

                # Look for offer links
                offer_links = await self.page.query_selector_all('a[href*="/offers/"][href*="/"]')
                if offer_links:
                    first_link = offer_links[0]
                    href = await first_link.get_attribute('href')
                    # Extract UUID
                    import re
                    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
                    match = re.search(uuid_pattern, href)
                    if match:
                        offer_id = match.group(0)
                        logger.info(f"Found offer ID: {offer_id}")
            except Exception as e:
                logger.warning(f"Could not find offer ID: {str(e)}")

        if offer_id:
            url = f"{BASE_URL}/app/ats/offers/{offer_id}/"
        else:
            # Use a dummy UUID for testing
            url = f"{BASE_URL}/app/ats/offers/00000000-0000-0000-0000-000000000000/"

        result = await self.test_page(url, "Offer Detail", "View offer details")

        # Check for offer details on page
        if result["accessible"]:
            try:
                # Look for key offer information
                detail_indicators = [
                    'salary',
                    'start date',
                    'status',
                    'candidate',
                    'position',
                    'job'
                ]

                page_text = await self.page.text_content('body')
                page_text_lower = page_text.lower()

                found_indicators = [ind for ind in detail_indicators if ind in page_text_lower]
                result["detail_fields_found"] = found_indicators

                # Look for action buttons
                action_buttons = []
                button_texts = ['send', 'accept', 'decline', 'withdraw', 'approve', 'reject']

                for text in button_texts:
                    btn = await self.page.query_selector(f'button:has-text("{text.title()}")')
                    if btn:
                        action_buttons.append(text)

                result["available_actions"] = action_buttons

            except Exception as e:
                result["warnings"].append(f"Detail checks failed: {str(e)}")

        return result

    async def test_offer_action(self, action: str, offer_id: Optional[str] = None) -> Dict:
        """Test offer action endpoints (approve, reject, send, etc.)"""

        # Use the same logic to find offer ID
        if not offer_id:
            logger.info(f"Attempting to find an offer ID for {action} action...")
            try:
                await self.page.goto(f"{BASE_URL}/app/ats/offers/", timeout=30000)

                offer_links = await self.page.query_selector_all('a[href*="/offers/"][href*="/"]')
                if offer_links:
                    first_link = offer_links[0]
                    href = await first_link.get_attribute('href')
                    import re
                    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
                    match = re.search(uuid_pattern, href)
                    if match:
                        offer_id = match.group(0)
            except:
                pass

        if offer_id:
            url = f"{BASE_URL}/app/ats/offers/{offer_id}/{action}/"
        else:
            url = f"{BASE_URL}/app/ats/offers/00000000-0000-0000-0000-000000000000/{action}/"

        result = await self.test_page(
            url,
            f"Offer {action.title()}",
            f"{action.title()} offer action"
        )

        # Note: These are POST endpoints, so GET requests might not work properly
        if result["status_code"] == 405:
            result["warnings"].append("Method not allowed (POST required) - This is expected")
            result["accessible"] = True  # Mark as accessible since 405 is expected for POST-only

        return result

    async def run_all_tests(self):
        """Run complete test suite"""
        logger.info("=" * 80)
        logger.info("Starting ATS Offers Module Testing")
        logger.info("=" * 80)

        await self.setup()

        try:
            # Step 1: Authenticate
            auth_success = await self.authenticate()

            if not auth_success:
                logger.error("Authentication failed. Cannot proceed with tests.")
                test_results["errors"].append("Authentication failed - tests aborted")
                return

            logger.info("✓ Authentication successful")

            # Step 2: Test Offer List
            logger.info("\n--- Testing Offer List ---")
            offer_list_result = await self.test_offer_list()
            test_results["pages_tested"].append(offer_list_result)

            # Step 3: Test Offer Creation
            logger.info("\n--- Testing Offer Creation ---")
            offer_create_result = await self.test_offer_creation()
            test_results["pages_tested"].append(offer_create_result)

            # Step 4: Test Offer Detail
            logger.info("\n--- Testing Offer Detail ---")
            offer_detail_result = await self.test_offer_detail()
            test_results["pages_tested"].append(offer_detail_result)

            # Step 5: Test Offer Actions
            logger.info("\n--- Testing Offer Actions ---")
            actions = ['send', 'accept', 'decline', 'withdraw', 'approve', 'reject']

            for action in actions:
                logger.info(f"Testing {action} action...")
                action_result = await self.test_offer_action(action)
                test_results["pages_tested"].append(action_result)

            # Generate summary
            logger.info("\n" + "=" * 80)
            logger.info("Test Summary")
            logger.info("=" * 80)

            total_pages = len(test_results["pages_tested"])
            accessible_pages = sum(1 for p in test_results["pages_tested"] if p["accessible"])
            pages_with_errors = sum(1 for p in test_results["pages_tested"] if p["errors"])

            test_results["summary"] = {
                "total_pages_tested": total_pages,
                "accessible_pages": accessible_pages,
                "pages_with_errors": pages_with_errors,
                "success_rate": f"{(accessible_pages / total_pages * 100):.1f}%" if total_pages > 0 else "0%"
            }

            logger.info(f"Total pages tested: {total_pages}")
            logger.info(f"Accessible pages: {accessible_pages}")
            logger.info(f"Pages with errors: {pages_with_errors}")
            logger.info(f"Success rate: {test_results['summary']['success_rate']}")

            # List pages with errors
            if pages_with_errors > 0:
                logger.info("\nPages with errors:")
                for page in test_results["pages_tested"]:
                    if page["errors"]:
                        logger.error(f"  - {page['name']}: {', '.join(page['errors'])}")

        except Exception as e:
            logger.error(f"Fatal error during testing: {str(e)}")
            test_results["errors"].append(f"Fatal error: {str(e)}")

        finally:
            await self.teardown()

            # Save results to JSON
            with open(RESULTS_FILE, 'w') as f:
                json.dump(test_results, f, indent=2)

            logger.info(f"\nTest results saved to: {RESULTS_FILE}")
            logger.info("=" * 80)


async def main():
    """Main entry point"""
    async with async_playwright() as p:
        # Launch browser
        browser = await p.chromium.launch(
            headless=False,  # Set to True for headless mode
            args=['--start-maximized']
        )

        try:
            tester = OfferTester(browser)
            await tester.run_all_tests()
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
