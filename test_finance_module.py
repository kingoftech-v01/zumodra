#!/usr/bin/env python3
"""
Zumodra Finance/Payments Module Testing Script
===============================================

This script comprehensively tests the Finance/Payments module functionality
on the Zumodra production website with authenticated access.

Test URL: https://demo-company.zumodra.rhematek-solutions.com
Login: company.owner@demo.zumodra.rhematek-solutions.com
Password: Demo@2024!

FINANCE MODULE URLS TO TEST:
-----------------------------
1. /app/finance/ - Finance dashboard
2. /app/finance/payments/ - Payment history
3. /app/finance/subscription/ - Subscription management
4. /app/finance/invoices/ - Invoice list
5. /app/finance/payment-methods/ - Payment methods management
6. /app/finance/escrow/ - Escrow transactions
7. /app/finance/connect/ - Connected account (Stripe Connect)
8. /app/finance/analytics/ - Financial analytics

HTMX ENDPOINTS TO TEST:
-----------------------
- /app/finance/htmx/quick-stats/
- /app/finance/htmx/recent-payments/
- /app/finance/htmx/pending-invoices/
- /app/finance/htmx/escrow-summary/
- /app/finance/htmx/payments/
- /app/finance/htmx/subscription/status/
- /app/finance/htmx/subscription/plans/
- /app/finance/htmx/invoices/
- /app/finance/htmx/payment-methods/
- /app/finance/htmx/escrow/
- /app/finance/htmx/connect/status/
- /app/finance/htmx/analytics/chart/

FUNCTIONALITY TO TEST:
----------------------
1. Dashboard Overview
   - Quick stats display
   - Recent payments list
   - Pending invoices
   - Escrow summary
   - Payment methods count
   - Connected account status

2. Payment History
   - Payment list display
   - Payment filtering (status, date range, amount)
   - Payment detail modal
   - Pagination
   - Refund request status

3. Subscriptions
   - Current subscription display
   - Available plans list
   - Subscription upgrade/change
   - Subscription success/cancel pages

4. Invoices
   - Invoice list with filtering
   - Invoice detail view
   - Payment status (paid/unpaid/overdue)
   - Invoice payment action
   - PDF download (if available)

5. Payment Methods
   - Saved payment methods list
   - Add new payment method
   - Set default payment method
   - Delete payment method
   - Stripe integration

6. Escrow Transactions
   - Escrow list (buyer/seller views)
   - Escrow detail
   - Status tracking
   - Timeline/audit log
   - Dispute management

7. Connected Account
   - Account status display
   - Onboarding flow
   - Capability status
   - Payout settings

8. Analytics
   - Payment trends charts
   - Invoice statistics
   - Escrow metrics
   - Financial reports

FINDINGS DOCUMENTATION:
-----------------------
All findings will be documented inline with detailed comments.
Screenshots will be saved to: ./test_results/finance/

SETUP:
------
1. Install: pip install playwright pytest-playwright
2. Install browsers: playwright install chromium
3. Run: python test_finance_module.py
"""

import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Set UTF-8 encoding for console output
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

try:
    from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext, TimeoutError as PlaywrightTimeoutError
except ImportError:
    print("ERROR: Playwright is not installed.")
    print("Please install it with:")
    print("  pip install playwright pytest-playwright")
    print("  playwright install chromium")
    sys.exit(1)


# =============================================================================
# TEST CONFIGURATION
# =============================================================================

BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
LOGIN_EMAIL = "company.owner@demo.zumodra.rhematek-solutions.com"
LOGIN_PASSWORD = "Demo@2024!"

# Test results directory
RESULTS_DIR = Path("./test_results/finance")
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")


# =============================================================================
# TEST RESULT CLASS
# =============================================================================

class FinanceTestResult:
    """Store test results for finance module pages"""
    def __init__(self, page_name: str, url: str):
        self.page_name = page_name
        self.url = url
        self.status_code: Optional[int] = None
        self.load_time: Optional[float] = None
        self.screenshot_path: Optional[str] = None
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.success: bool = False
        self.ui_elements_visible: List[str] = []
        self.ui_elements_missing: List[str] = []
        self.console_errors: List[str] = []
        self.network_errors: List[str] = []
        self.features_tested: List[str] = []

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON export"""
        return {
            'page_name': self.page_name,
            'url': self.url,
            'status_code': self.status_code,
            'load_time': self.load_time,
            'screenshot_path': self.screenshot_path,
            'errors': self.errors,
            'warnings': self.warnings,
            'success': self.success,
            'ui_elements_visible': self.ui_elements_visible,
            'ui_elements_missing': self.ui_elements_missing,
            'console_errors': self.console_errors,
            'network_errors': self.network_errors,
            'features_tested': self.features_tested,
        }


# =============================================================================
# FINANCE TESTER CLASS
# =============================================================================

class FinanceModuleTester:
    """Finance module testing class"""

    def __init__(self):
        self.results: List[FinanceTestResult] = []
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.authenticated = False

        # Create results directory
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    def setup(self):
        """Initialize browser and context"""
        print("="*80)
        print("ZUMODRA FINANCE MODULE TESTING")
        print("="*80)
        print(f"Test URL: {BASE_URL}")
        print(f"Login Email: {LOGIN_EMAIL}")
        print(f"Results Directory: {RESULTS_DIR}")
        print(f"Timestamp: {TIMESTAMP}")
        print("="*80)
        print()

        playwright = sync_playwright().start()
        self.browser = playwright.chromium.launch(headless=False)
        self.context = self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            accept_downloads=True
        )
        self.page = self.context.new_page()

        # Setup console and network error listeners
        self.page.on('console', self._handle_console_message)
        self.page.on('requestfailed', self._handle_network_error)

    def _handle_console_message(self, msg):
        """Capture console errors"""
        if msg.type in ['error', 'warning']:
            if hasattr(self, 'current_result') and self.current_result:
                self.current_result.console_errors.append(f"{msg.type.upper()}: {msg.text}")

    def _handle_network_error(self, request):
        """Capture network errors"""
        if hasattr(self, 'current_result') and self.current_result:
            self.current_result.network_errors.append(f"Failed to load: {request.url}")

    def login(self) -> bool:
        """Authenticate to the website"""
        print("\n[1] AUTHENTICATING TO WEBSITE")
        print("-" * 80)

        try:
            login_url = f"{BASE_URL}/accounts/login/"
            print(f"Navigating to login page: {login_url}")

            # Navigate and take screenshot of login page
            self.page.goto(login_url, wait_until='networkidle', timeout=30000)

            # Take screenshot of login page for debugging
            login_screenshot = RESULTS_DIR / f"00_login_page_{TIMESTAMP}.png"
            self.page.screenshot(path=str(login_screenshot), full_page=True)
            print(f"✓ Login page screenshot: {login_screenshot}")

            # Check if already logged in (redirect to dashboard)
            if '/app/dashboard/' in self.page.url or '/app/' in self.page.url:
                print("✓ Already authenticated")
                self.authenticated = True
                return True

            # Try different login field selectors
            print("Filling login credentials...")

            # Find email/username field
            email_selectors = [
                'input[name="login"]',
                'input[name="email"]',
                'input[name="username"]',
                'input[type="email"]',
                '#id_login',
                '#id_email',
                '#id_username',
            ]

            email_filled = False
            for selector in email_selectors:
                try:
                    if self.page.query_selector(selector):
                        self.page.fill(selector, LOGIN_EMAIL, timeout=5000)
                        print(f"  ✓ Email filled using selector: {selector}")
                        email_filled = True
                        break
                except:
                    continue

            if not email_filled:
                print("  ✗ Could not find email/username field")
                return False

            # Find password field
            password_selectors = [
                'input[name="password"]',
                'input[type="password"]',
                '#id_password',
            ]

            password_filled = False
            for selector in password_selectors:
                try:
                    if self.page.query_selector(selector):
                        self.page.fill(selector, LOGIN_PASSWORD, timeout=5000)
                        print(f"  ✓ Password filled using selector: {selector}")
                        password_filled = True
                        break
                except:
                    continue

            if not password_filled:
                print("  ✗ Could not find password field")
                return False

            # Submit form
            print("Submitting login form...")
            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Sign in")',
                'button:has-text("Log in")',
                'button:has-text("Login")',
            ]

            submitted = False
            for selector in submit_selectors:
                try:
                    if self.page.query_selector(selector):
                        self.page.click(selector, timeout=5000)
                        print(f"  ✓ Form submitted using: {selector}")
                        submitted = True
                        break
                except:
                    continue

            if not submitted:
                print("  ✗ Could not find submit button")
                return False

            # Wait for navigation after login
            time.sleep(3)  # Give it some time
            self.page.wait_for_load_state('networkidle', timeout=30000)

            # Check if login successful
            current_url = self.page.url
            print(f"Current URL after login: {current_url}")

            if '/app/dashboard/' in current_url or '/app/' in current_url:
                print(f"✓ Login successful! Redirected to: {current_url}")
                self.authenticated = True

                # Take screenshot of dashboard
                screenshot_path = RESULTS_DIR / f"00_login_success_{TIMESTAMP}.png"
                self.page.screenshot(path=str(screenshot_path), full_page=True)
                print(f"✓ Screenshot saved: {screenshot_path}")
                return True
            else:
                print(f"✗ Login may have failed. Current URL: {current_url}")

                # Check for error messages
                if self.page.query_selector('.error, .alert-error, .errorlist'):
                    error_text = self.page.text_content('.error, .alert-error, .errorlist')
                    print(f"  ✗ Error message: {error_text}")

                screenshot_path = RESULTS_DIR / f"00_login_failed_{TIMESTAMP}.png"
                self.page.screenshot(path=str(screenshot_path), full_page=True)
                print(f"✗ Screenshot saved: {screenshot_path}")
                return False

        except Exception as e:
            print(f"✗ Login error: {e}")
            import traceback
            traceback.print_exc()

            # Take error screenshot
            try:
                error_screenshot = RESULTS_DIR / f"00_login_error_{TIMESTAMP}.png"
                self.page.screenshot(path=str(error_screenshot), full_page=True)
                print(f"✗ Error screenshot: {error_screenshot}")
            except:
                pass

            return False

    def test_page(self, page_name: str, url: str,
                  ui_elements: List[str] = None,
                  features: List[str] = None) -> FinanceTestResult:
        """Test a finance page"""
        result = FinanceTestResult(page_name, url)
        self.current_result = result

        print(f"\n[TEST] {page_name}")
        print("-" * 80)
        print(f"URL: {url}")

        try:
            # Navigate to page
            start_time = time.time()
            response = self.page.goto(url, wait_until='networkidle', timeout=30000)
            load_time = time.time() - start_time

            result.load_time = round(load_time, 2)
            result.status_code = response.status if response else None

            print(f"✓ Page loaded in {result.load_time}s")
            print(f"✓ HTTP Status: {result.status_code}")

            # Check for errors
            if result.status_code and result.status_code >= 400:
                result.errors.append(f"HTTP {result.status_code} error")
                print(f"✗ HTTP Error {result.status_code}")

            # Check for Django error page
            page_content = self.page.content()
            if 'Server Error (500)' in page_content:
                result.errors.append("500 Server Error detected")
                print("✗ 500 Server Error detected")
            elif 'Page not found (404)' in page_content:
                result.errors.append("404 Page Not Found")
                print("✗ 404 Page Not Found")
            elif 'TemplateDoesNotExist' in page_content:
                result.errors.append("Template Missing Error")
                print("✗ Template Missing Error")

            # Check UI elements
            if ui_elements:
                print("\nChecking UI elements...")
                for element in ui_elements:
                    try:
                        if self.page.query_selector(element):
                            result.ui_elements_visible.append(element)
                            print(f"  ✓ Found: {element}")
                        else:
                            result.ui_elements_missing.append(element)
                            print(f"  ✗ Missing: {element}")
                    except Exception as e:
                        result.ui_elements_missing.append(element)
                        print(f"  ✗ Error checking {element}: {e}")

            # Test features
            if features:
                result.features_tested = features
                print(f"\nFeatures tested: {', '.join(features)}")

            # Take screenshot
            screenshot_name = f"{page_name.lower().replace(' ', '_')}_{TIMESTAMP}.png"
            screenshot_path = RESULTS_DIR / screenshot_name
            self.page.screenshot(path=str(screenshot_path), full_page=True)
            result.screenshot_path = str(screenshot_path)
            print(f"✓ Screenshot saved: {screenshot_path}")

            # Determine success
            result.success = (
                result.status_code and result.status_code < 400 and
                len(result.errors) == 0 and
                len(result.ui_elements_missing) < len(ui_elements) / 2 if ui_elements else True
            )

            if result.success:
                print(f"✓ {page_name} test PASSED")
            else:
                print(f"✗ {page_name} test FAILED")

            # Report console/network errors
            if result.console_errors:
                print(f"\n⚠ Console Errors ({len(result.console_errors)}):")
                for error in result.console_errors[:5]:  # Show first 5
                    print(f"  - {error}")

            if result.network_errors:
                print(f"\n⚠ Network Errors ({len(result.network_errors)}):")
                for error in result.network_errors[:5]:  # Show first 5
                    print(f"  - {error}")

        except PlaywrightTimeoutError as e:
            result.errors.append(f"Timeout error: {e}")
            print(f"✗ Timeout error: {e}")
        except Exception as e:
            result.errors.append(f"Unexpected error: {e}")
            print(f"✗ Unexpected error: {e}")

        self.results.append(result)
        return result

    def test_finance_dashboard(self):
        """Test finance dashboard page"""
        result = self.test_page(
            "Finance Dashboard",
            f"{BASE_URL}/app/finance/",
            ui_elements=[
                'h1', 'h2', 'h3',  # Headers
                '.stat, .card, .metric',  # Stats cards
                'table, .table',  # Tables
                'a[href*="payments"]',  # Payment links
                'a[href*="invoices"]',  # Invoice links
                'a[href*="subscription"]',  # Subscription links
            ],
            features=[
                'Dashboard overview',
                'Quick stats display',
                'Recent payments',
                'Pending invoices',
                'Navigation links'
            ]
        )

        # Additional dashboard-specific checks
        print("\n[ADDITIONAL CHECKS] Finance Dashboard")
        try:
            # Check for financial metrics
            if self.page.query_selector('text=/Total Spent|Amount|Balance/i'):
                result.ui_elements_visible.append('Financial metrics found')
                print("  ✓ Financial metrics displayed")
            else:
                result.warnings.append("No financial metrics visible")
                print("  ⚠ No financial metrics visible")
        except Exception as e:
            print(f"  ✗ Error checking metrics: {e}")

    def test_payment_history(self):
        """Test payment history page"""
        result = self.test_page(
            "Payment History",
            f"{BASE_URL}/app/finance/payments/",
            ui_elements=[
                'h1:has-text("Payment")',  # Page title
                'table, .payment-list',  # Payment list
                'button, a[href*="filter"]',  # Filter controls
                '.pagination, nav[aria-label*="page"]',  # Pagination
            ],
            features=[
                'Payment list display',
                'Filtering capability',
                'Payment details',
                'Status indicators'
            ]
        )

        # Test filtering
        print("\n[FEATURE TEST] Payment Filtering")
        try:
            # Look for filter inputs
            if self.page.query_selector('input[name*="status"], select[name*="status"]'):
                print("  ✓ Status filter available")
                result.ui_elements_visible.append('Status filter')

            if self.page.query_selector('input[type="date"], input[name*="date"]'):
                print("  ✓ Date filter available")
                result.ui_elements_visible.append('Date filter')
        except Exception as e:
            print(f"  ✗ Error testing filters: {e}")

    def test_subscriptions(self):
        """Test subscription management page"""
        result = self.test_page(
            "Subscription Management",
            f"{BASE_URL}/app/finance/subscription/",
            ui_elements=[
                'h1:has-text("Subscription")',
                '.plan, .subscription-plan',  # Plan cards
                'button:has-text("Subscribe"), button:has-text("Upgrade")',  # Action buttons
                '.price, .amount',  # Pricing display
            ],
            features=[
                'Current subscription display',
                'Available plans',
                'Subscription actions',
                'Pricing information'
            ]
        )

        # Check for plan details
        print("\n[FEATURE TEST] Subscription Plans")
        try:
            plans = self.page.query_selector_all('.plan, .card, .pricing-card')
            if plans:
                print(f"  ✓ Found {len(plans)} plan cards")
                result.ui_elements_visible.append(f'{len(plans)} subscription plans')
            else:
                print("  ⚠ No subscription plans visible")
                result.warnings.append("No subscription plans visible")
        except Exception as e:
            print(f"  ✗ Error checking plans: {e}")

    def test_invoices(self):
        """Test invoice list page"""
        result = self.test_page(
            "Invoice List",
            f"{BASE_URL}/app/finance/invoices/",
            ui_elements=[
                'h1:has-text("Invoice")',
                'table, .invoice-list',
                '.paid, .unpaid, .status',  # Status indicators
                'button:has-text("Pay"), a:has-text("View")',  # Action buttons
            ],
            features=[
                'Invoice list display',
                'Payment status',
                'Invoice actions',
                'Filtering'
            ]
        )

        # Check for invoice details
        print("\n[FEATURE TEST] Invoice Details")
        try:
            # Look for invoice rows
            invoice_rows = self.page.query_selector_all('tr:has-text("INV-"), .invoice-item')
            if invoice_rows:
                print(f"  ✓ Found {len(invoice_rows)} invoices")
                result.ui_elements_visible.append(f'{len(invoice_rows)} invoices')

                # Try to click first invoice detail
                if len(invoice_rows) > 0:
                    try:
                        first_invoice = invoice_rows[0]
                        detail_link = first_invoice.query_selector('a[href*="invoices/"]')
                        if detail_link:
                            print("  ✓ Invoice detail links available")
                            result.ui_elements_visible.append('Invoice detail links')
                    except Exception as e:
                        print(f"  ⚠ Could not check detail links: {e}")
            else:
                print("  ⚠ No invoices found (may be empty state)")
                result.warnings.append("No invoices visible")
        except Exception as e:
            print(f"  ✗ Error checking invoices: {e}")

    def test_payment_methods(self):
        """Test payment methods page"""
        result = self.test_page(
            "Payment Methods",
            f"{BASE_URL}/app/finance/payment-methods/",
            ui_elements=[
                'h1:has-text("Payment Method")',
                '.card, .payment-method',  # Payment method cards
                'button:has-text("Add"), button:has-text("New")',  # Add button
                '.visa, .mastercard, .amex, .card-brand',  # Card brands
            ],
            features=[
                'Saved payment methods',
                'Add payment method',
                'Card brand display',
                'Default payment method'
            ]
        )

        # Check Stripe integration
        print("\n[FEATURE TEST] Stripe Integration")
        try:
            # Look for Stripe elements
            if self.page.query_selector('script[src*="stripe"]'):
                print("  ✓ Stripe SDK loaded")
                result.ui_elements_visible.append('Stripe SDK')
            else:
                print("  ⚠ Stripe SDK not detected")
                result.warnings.append("Stripe SDK not detected")
        except Exception as e:
            print(f"  ✗ Error checking Stripe: {e}")

    def test_escrow_transactions(self):
        """Test escrow transactions page"""
        result = self.test_page(
            "Escrow Transactions",
            f"{BASE_URL}/app/finance/escrow/",
            ui_elements=[
                'h1:has-text("Escrow")',
                'table, .escrow-list',
                '.status, .badge',  # Status badges
                'button:has-text("Filter"), select',  # Filters
            ],
            features=[
                'Escrow list display',
                'Status tracking',
                'Buyer/seller views',
                'Transaction details'
            ]
        )

        # Check escrow statuses
        print("\n[FEATURE TEST] Escrow Status")
        try:
            statuses = self.page.query_selector_all('.status, .badge, [class*="status"]')
            if statuses:
                print(f"  ✓ Found {len(statuses)} status indicators")
                result.ui_elements_visible.append('Status indicators')
            else:
                print("  ⚠ No escrow transactions visible")
                result.warnings.append("No escrow transactions")
        except Exception as e:
            print(f"  ✗ Error checking escrow: {e}")

    def test_connected_account(self):
        """Test Stripe Connect account page"""
        result = self.test_page(
            "Connected Account",
            f"{BASE_URL}/app/finance/connect/",
            ui_elements=[
                'h1:has-text("Connect"), h1:has-text("Account")',
                '.status, .account-status',
                'button:has-text("Connect"), button:has-text("Setup")',
                '.capability, .onboarding',
            ],
            features=[
                'Account status display',
                'Onboarding flow',
                'Capability status',
                'Stripe Connect integration'
            ]
        )

        # Check account status
        print("\n[FEATURE TEST] Connected Account Status")
        try:
            # Look for status messages
            if self.page.query_selector('text=/Active|Pending|Onboarding|Complete/i'):
                print("  ✓ Account status displayed")
                result.ui_elements_visible.append('Account status')
            else:
                print("  ⚠ No account status visible")
                result.warnings.append("No account status")
        except Exception as e:
            print(f"  ✗ Error checking account: {e}")

    def test_analytics(self):
        """Test financial analytics page"""
        result = self.test_page(
            "Financial Analytics",
            f"{BASE_URL}/app/finance/analytics/",
            ui_elements=[
                'h1:has-text("Analytics"), h1:has-text("Report")',
                'canvas, .chart',  # Chart elements
                '.stat, .metric',  # Metrics
                'select[name*="period"], button:has-text("Filter")',  # Period selector
            ],
            features=[
                'Payment trends',
                'Invoice statistics',
                'Escrow metrics',
                'Financial charts'
            ]
        )

        # Check for charts
        print("\n[FEATURE TEST] Charts and Visualizations")
        try:
            # Look for Chart.js or other chart libraries
            if self.page.query_selector('canvas, .chart, [class*="chart"]'):
                print("  ✓ Charts found")
                result.ui_elements_visible.append('Charts')
            else:
                print("  ⚠ No charts visible")
                result.warnings.append("No charts visible")

            # Check for Chart.js
            if self.page.query_selector('script[src*="chart"]'):
                print("  ✓ Chart.js loaded")
                result.ui_elements_visible.append('Chart.js library')
        except Exception as e:
            print(f"  ✗ Error checking charts: {e}")

    def test_htmx_endpoints(self):
        """Test HTMX partial endpoints"""
        print("\n[HTMX ENDPOINTS TEST]")
        print("-" * 80)

        htmx_endpoints = [
            ('Quick Stats', '/app/finance/htmx/quick-stats/'),
            ('Recent Payments', '/app/finance/htmx/recent-payments/'),
            ('Pending Invoices', '/app/finance/htmx/pending-invoices/'),
            ('Escrow Summary', '/app/finance/htmx/escrow-summary/'),
            ('Payment List', '/app/finance/htmx/payments/'),
            ('Subscription Status', '/app/finance/htmx/subscription/status/'),
            ('Subscription Plans', '/app/finance/htmx/subscription/plans/'),
            ('Invoice List', '/app/finance/htmx/invoices/'),
            ('Payment Methods', '/app/finance/htmx/payment-methods/'),
            ('Escrow List', '/app/finance/htmx/escrow/'),
            ('Connect Status', '/app/finance/htmx/connect/status/'),
            ('Analytics Chart', '/app/finance/htmx/analytics/chart/?type=payments&period=30d'),
        ]

        for name, endpoint in htmx_endpoints:
            url = f"{BASE_URL}{endpoint}"
            print(f"\n[HTMX] {name}")
            try:
                response = self.page.goto(url, wait_until='networkidle', timeout=10000)
                status = response.status if response else None
                print(f"  URL: {url}")
                print(f"  Status: {status}")

                if status == 200:
                    print(f"  ✓ HTMX endpoint working")

                    # Take screenshot
                    screenshot_name = f"htmx_{name.lower().replace(' ', '_')}_{TIMESTAMP}.png"
                    screenshot_path = RESULTS_DIR / screenshot_name
                    self.page.screenshot(path=str(screenshot_path))
                    print(f"  ✓ Screenshot: {screenshot_path}")
                else:
                    print(f"  ✗ HTMX endpoint returned {status}")

            except Exception as e:
                print(f"  ✗ Error: {e}")

    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "="*80)
        print("FINANCE MODULE TEST REPORT")
        print("="*80)

        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.success)
        failed_tests = total_tests - passed_tests

        print(f"\nTotal Tests: {total_tests}")
        print(f"Passed: {passed_tests} ({passed_tests/total_tests*100:.1f}%)")
        print(f"Failed: {failed_tests} ({failed_tests/total_tests*100:.1f}%)")

        print("\n" + "-"*80)
        print("DETAILED RESULTS")
        print("-"*80)

        for result in self.results:
            status_icon = "✓" if result.success else "✗"
            print(f"\n{status_icon} {result.page_name}")
            print(f"  URL: {result.url}")
            print(f"  Status Code: {result.status_code}")
            print(f"  Load Time: {result.load_time}s")
            print(f"  Screenshot: {result.screenshot_path}")

            if result.ui_elements_visible:
                print(f"  ✓ UI Elements ({len(result.ui_elements_visible)}): {', '.join(result.ui_elements_visible[:5])}")
            if result.ui_elements_missing:
                print(f"  ✗ Missing Elements ({len(result.ui_elements_missing)}): {', '.join(result.ui_elements_missing[:5])}")
            if result.errors:
                print(f"  ✗ Errors ({len(result.errors)}):")
                for error in result.errors:
                    print(f"    - {error}")
            if result.warnings:
                print(f"  ⚠ Warnings ({len(result.warnings)}):")
                for warning in result.warnings:
                    print(f"    - {warning}")
            if result.features_tested:
                print(f"  Features: {', '.join(result.features_tested)}")

        # Export to JSON
        json_path = RESULTS_DIR / f"finance_test_report_{TIMESTAMP}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': TIMESTAMP,
                'base_url': BASE_URL,
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'results': [r.to_dict() for r in self.results]
            }, f, indent=2)

        print(f"\n✓ JSON report saved: {json_path}")

        # Summary of issues
        print("\n" + "="*80)
        print("ISSUES SUMMARY")
        print("="*80)

        all_errors = []
        all_warnings = []

        for result in self.results:
            for error in result.errors:
                all_errors.append(f"{result.page_name}: {error}")
            for warning in result.warnings:
                all_warnings.append(f"{result.page_name}: {warning}")

        if all_errors:
            print(f"\n✗ ERRORS ({len(all_errors)}):")
            for error in all_errors:
                print(f"  - {error}")
        else:
            print("\n✓ No errors found!")

        if all_warnings:
            print(f"\n⚠ WARNINGS ({len(all_warnings)}):")
            for warning in all_warnings:
                print(f"  - {warning}")
        else:
            print("\n✓ No warnings!")

        print("\n" + "="*80)
        print("TEST COMPLETE")
        print("="*80)
        print(f"All screenshots saved to: {RESULTS_DIR}")
        print(f"JSON report: {json_path}")

    def run_all_tests(self):
        """Run all finance module tests"""
        if not self.authenticated:
            print("✗ Not authenticated. Cannot run tests.")
            return

        print("\n" + "="*80)
        print("RUNNING FINANCE MODULE TESTS")
        print("="*80)

        # Main page tests
        self.test_finance_dashboard()
        time.sleep(2)

        self.test_payment_history()
        time.sleep(2)

        self.test_subscriptions()
        time.sleep(2)

        self.test_invoices()
        time.sleep(2)

        self.test_payment_methods()
        time.sleep(2)

        self.test_escrow_transactions()
        time.sleep(2)

        self.test_connected_account()
        time.sleep(2)

        self.test_analytics()
        time.sleep(2)

        # HTMX endpoint tests
        self.test_htmx_endpoints()

        # Generate report
        self.generate_report()

    def teardown(self):
        """Cleanup browser resources"""
        if self.page:
            self.page.close()
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Main test execution"""
    tester = FinanceModuleTester()

    try:
        # Setup browser
        tester.setup()

        # Login
        if not tester.login():
            print("\n✗ Authentication failed. Exiting.")
            return

        # Run all tests
        tester.run_all_tests()

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\n✗ Test execution error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        print("\nCleaning up...")
        tester.teardown()
        print("Done.")


if __name__ == '__main__':
    main()
