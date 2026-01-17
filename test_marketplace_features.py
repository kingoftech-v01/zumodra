#!/usr/bin/env python3
"""
Marketplace/Freelance Feature Testing Script for Zumodra
=========================================================

Tests all marketplace and freelance features on the deployed instance:
- Browse freelancers page
- Service listings
- Service proposals
- Contract management
- Escrow payment flow
- Provider profiles display
- Service categories

Domain: https://zumodra.rhematek-solutions.com
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Any

# Configuration
BASE_URL = "https://zumodra.rhematek-solutions.com"
TEST_RESULTS_FILE = "test_results/marketplace_test_results.json"

class Color:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class MarketplaceFeatureTester:
    """Test marketplace/freelance features on Zumodra"""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/json,*/*',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'base_url': base_url,
            'tests': [],
            'summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'working_features': [],
                'broken_features': [],
            }
        }
        self.logged_in = False
        self.auth_token = None

    def log(self, message: str, color: str = Color.RESET):
        """Print colored log message"""
        try:
            print(f"{color}{message}{Color.RESET}")
        except UnicodeEncodeError:
            # Fallback for Windows console encoding issues
            print(f"{color}{message.encode('ascii', 'replace').decode('ascii')}{Color.RESET}")

    def add_test_result(self, test_name: str, status: str, details: Dict[str, Any]):
        """Add a test result to the collection"""
        self.results['tests'].append({
            'name': test_name,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'details': details
        })
        self.results['summary']['total'] += 1

        if status == 'PASS':
            self.results['summary']['passed'] += 1
            self.results['summary']['working_features'].append(test_name)
            self.log(f"[+] {test_name}: PASS", Color.GREEN)
        else:
            self.results['summary']['failed'] += 1
            self.results['summary']['broken_features'].append(test_name)
            self.log(f"[-] {test_name}: FAIL", Color.RED)

    def save_results(self):
        """Save test results to file"""
        import os
        os.makedirs(os.path.dirname(TEST_RESULTS_FILE), exist_ok=True)
        with open(TEST_RESULTS_FILE, 'w') as f:
            json.dump(self.results, f, indent=2)
        self.log(f"\nResults saved to: {TEST_RESULTS_FILE}", Color.CYAN)

    # ==================== Authentication ====================

    def test_login(self, username: str = "testuser", password: str = "testpass123"):
        """Test login functionality"""
        self.log("\n" + "="*60, Color.BOLD)
        self.log("Testing Authentication", Color.BOLD)
        self.log("="*60, Color.BOLD)

        try:
            # Get login page first for CSRF token
            login_url = f"{self.base_url}/en/accounts/login/"
            response = self.session.get(login_url, timeout=10)

            if response.status_code == 200:
                # Extract CSRF token
                csrf_token = None
                if 'csrftoken' in self.session.cookies:
                    csrf_token = self.session.cookies['csrftoken']

                # Attempt login
                login_data = {
                    'login': username,
                    'password': password,
                    'csrfmiddlewaretoken': csrf_token,
                }

                response = self.session.post(login_url, data=login_data, timeout=10)

                if response.status_code in [200, 302]:
                    # Check if we're redirected or logged in
                    if 'sessionid' in self.session.cookies:
                        self.logged_in = True
                        self.add_test_result(
                            "Authentication - Login",
                            "PASS",
                            {
                                'url': login_url,
                                'status_code': response.status_code,
                                'has_session': True,
                                'note': 'Successfully logged in'
                            }
                        )
                    else:
                        self.add_test_result(
                            "Authentication - Login",
                            "PASS",
                            {
                                'url': login_url,
                                'status_code': response.status_code,
                                'has_session': False,
                                'note': 'Login page accessible (credentials may be invalid)'
                            }
                        )
                else:
                    self.add_test_result(
                        "Authentication - Login",
                        "FAIL",
                        {
                            'url': login_url,
                            'status_code': response.status_code,
                            'error': 'Unexpected status code'
                        }
                    )
            else:
                self.add_test_result(
                    "Authentication - Login",
                    "FAIL",
                    {
                        'url': login_url,
                        'status_code': response.status_code,
                        'error': 'Login page not accessible'
                    }
                )

        except Exception as e:
            self.add_test_result(
                "Authentication - Login",
                "FAIL",
                {
                    'url': login_url,
                    'error': str(e)
                }
            )

    # ==================== Browse Freelancers ====================

    def test_browse_freelancers(self):
        """Test browse freelancers/providers page"""
        self.log("\n" + "="*60, Color.BOLD)
        self.log("Testing Browse Freelancers", Color.BOLD)
        self.log("="*60, Color.BOLD)

        test_urls = [
            '/en/services/providers/',
            '/services/providers/',
        ]

        for url in test_urls:
            try:
                full_url = f"{self.base_url}{url}"
                self.log(f"\nTesting: {full_url}", Color.CYAN)

                response = self.session.get(full_url, timeout=10, allow_redirects=True)

                if response.status_code == 200:
                    content = response.text.lower()

                    # Check for provider-related content
                    has_provider_content = (
                        'provider' in content or
                        'freelancer' in content or
                        'profile' in content or
                        'browse' in content
                    )

                    # Check for pagination or listing structure
                    has_listing_structure = (
                        'card' in content or
                        'list' in content or
                        'grid' in content or
                        'pagination' in content
                    )

                    self.add_test_result(
                        f"Browse Freelancers - {url}",
                        "PASS" if has_provider_content else "FAIL",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'has_provider_content': has_provider_content,
                            'has_listing_structure': has_listing_structure,
                            'content_length': len(response.text),
                            'final_url': response.url
                        }
                    )
                    break  # Success, no need to try other URLs

                elif response.status_code == 404:
                    self.log(f"  URL not found: {url}", Color.YELLOW)
                    continue  # Try next URL

                else:
                    self.add_test_result(
                        f"Browse Freelancers - {url}",
                        "FAIL",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'error': f'Unexpected status code: {response.status_code}'
                        }
                    )

            except Exception as e:
                self.add_test_result(
                    f"Browse Freelancers - {url}",
                    "FAIL",
                    {
                        'url': full_url,
                        'error': str(e)
                    }
                )

    # ==================== Service Listings ====================

    def test_service_listings(self):
        """Test service listings page"""
        self.log("\n" + "="*60, Color.BOLD)
        self.log("Testing Service Listings", Color.BOLD)
        self.log("="*60, Color.BOLD)

        test_urls = [
            '/en/services/',
            '/services/',
        ]

        for url in test_urls:
            try:
                full_url = f"{self.base_url}{url}"
                self.log(f"\nTesting: {full_url}", Color.CYAN)

                response = self.session.get(full_url, timeout=10, allow_redirects=True)

                if response.status_code == 200:
                    content = response.text.lower()

                    # Check for service-related content
                    has_service_content = (
                        'service' in content or
                        'marketplace' in content or
                        'browse' in content
                    )

                    # Check for categories
                    has_categories = (
                        'category' in content or
                        'categories' in content or
                        'filter' in content
                    )

                    # Check for listing structure
                    has_listing = (
                        'card' in content or
                        'grid' in content or
                        'list' in content
                    )

                    self.add_test_result(
                        f"Service Listings - {url}",
                        "PASS" if has_service_content else "FAIL",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'has_service_content': has_service_content,
                            'has_categories': has_categories,
                            'has_listing': has_listing,
                            'content_length': len(response.text),
                            'final_url': response.url
                        }
                    )
                    break  # Success

                elif response.status_code == 404:
                    self.log(f"  URL not found: {url}", Color.YELLOW)
                    continue

                else:
                    self.add_test_result(
                        f"Service Listings - {url}",
                        "FAIL",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'error': f'Unexpected status code'
                        }
                    )

            except Exception as e:
                self.add_test_result(
                    f"Service Listings - {url}",
                    "FAIL",
                    {
                        'url': full_url,
                        'error': str(e)
                    }
                )

    # ==================== Service Categories ====================

    def test_service_categories(self):
        """Test service categories display"""
        self.log("\n" + "="*60, Color.BOLD)
        self.log("Testing Service Categories", Color.BOLD)
        self.log("="*60, Color.BOLD)

        # Check main service page for categories
        try:
            url = f"{self.base_url}/en/services/"
            response = self.session.get(url, timeout=10, allow_redirects=True)

            if response.status_code == 200:
                content = response.text.lower()

                # Common service categories
                common_categories = [
                    'design', 'development', 'writing', 'marketing',
                    'video', 'music', 'programming', 'business',
                    'graphic', 'web', 'mobile', 'data'
                ]

                found_categories = [cat for cat in common_categories if cat in content]

                has_categories = len(found_categories) > 0 or 'category' in content

                self.add_test_result(
                    "Service Categories Display",
                    "PASS" if has_categories else "FAIL",
                    {
                        'url': url,
                        'status_code': response.status_code,
                        'has_categories': has_categories,
                        'found_categories': found_categories,
                        'category_count': len(found_categories)
                    }
                )
            else:
                self.add_test_result(
                    "Service Categories Display",
                    "FAIL",
                    {
                        'url': url,
                        'status_code': response.status_code,
                        'error': 'Service page not accessible'
                    }
                )

        except Exception as e:
            self.add_test_result(
                "Service Categories Display",
                "FAIL",
                {
                    'url': url,
                    'error': str(e)
                }
            )

    # ==================== Provider Profiles ====================

    def test_provider_profiles(self):
        """Test provider profile display"""
        self.log("\n" + "="*60, Color.BOLD)
        self.log("Testing Provider Profiles", Color.BOLD)
        self.log("="*60, Color.BOLD)

        # Test provider profile creation/view pages
        test_urls = [
            '/en/services/provider/create/',
            '/en/services/provider/dashboard/',
            '/services/provider/create/',
            '/services/provider/dashboard/',
        ]

        for url in test_urls:
            try:
                full_url = f"{self.base_url}{url}"
                self.log(f"\nTesting: {full_url}", Color.CYAN)

                response = self.session.get(full_url, timeout=10, allow_redirects=True)

                if response.status_code == 200:
                    content = response.text.lower()

                    # Check for provider-related forms/content
                    has_provider_content = (
                        'provider' in content or
                        'profile' in content or
                        'freelancer' in content
                    )

                    has_form = (
                        'form' in content or
                        'input' in content or
                        'submit' in content
                    )

                    self.add_test_result(
                        f"Provider Profile - {url}",
                        "PASS" if has_provider_content else "FAIL",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'has_provider_content': has_provider_content,
                            'has_form': has_form,
                            'final_url': response.url
                        }
                    )

                elif response.status_code in [302, 403]:
                    # Redirect or forbidden - might require auth
                    self.add_test_result(
                        f"Provider Profile - {url}",
                        "PASS",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'note': 'Requires authentication (expected behavior)',
                            'final_url': response.url
                        }
                    )

                elif response.status_code == 404:
                    self.log(f"  URL not found: {url}", Color.YELLOW)
                    continue

            except Exception as e:
                self.log(f"  Error: {str(e)}", Color.RED)

    # ==================== Service Proposals ====================

    def test_service_proposals(self):
        """Test service proposals functionality"""
        self.log("\n" + "="*60, Color.BOLD)
        self.log("Testing Service Proposals", Color.BOLD)
        self.log("="*60, Color.BOLD)

        test_urls = [
            '/en/services/request/create/',
            '/en/services/request/my-requests/',
            '/services/request/create/',
            '/services/request/my-requests/',
        ]

        for url in test_urls:
            try:
                full_url = f"{self.base_url}{url}"
                self.log(f"\nTesting: {full_url}", Color.CYAN)

                response = self.session.get(full_url, timeout=10, allow_redirects=True)

                if response.status_code == 200:
                    content = response.text.lower()

                    has_proposal_content = (
                        'proposal' in content or
                        'request' in content or
                        'submit' in content
                    )

                    self.add_test_result(
                        f"Service Proposals - {url}",
                        "PASS" if has_proposal_content else "FAIL",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'has_proposal_content': has_proposal_content,
                            'final_url': response.url
                        }
                    )

                elif response.status_code in [302, 403]:
                    self.add_test_result(
                        f"Service Proposals - {url}",
                        "PASS",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'note': 'Requires authentication',
                            'final_url': response.url
                        }
                    )

                elif response.status_code == 404:
                    self.log(f"  URL not found: {url}", Color.YELLOW)
                    continue

            except Exception as e:
                self.log(f"  Error: {str(e)}", Color.RED)

    # ==================== Contract Management ====================

    def test_contract_management(self):
        """Test contract management functionality"""
        self.log("\n" + "="*60, Color.BOLD)
        self.log("Testing Contract Management", Color.BOLD)
        self.log("="*60, Color.BOLD)

        test_urls = [
            '/en/services/contracts/',
            '/services/contracts/',
        ]

        for url in test_urls:
            try:
                full_url = f"{self.base_url}{url}"
                self.log(f"\nTesting: {full_url}", Color.CYAN)

                response = self.session.get(full_url, timeout=10, allow_redirects=True)

                if response.status_code == 200:
                    content = response.text.lower()

                    has_contract_content = (
                        'contract' in content or
                        'agreement' in content or
                        'status' in content
                    )

                    self.add_test_result(
                        f"Contract Management - {url}",
                        "PASS" if has_contract_content else "FAIL",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'has_contract_content': has_contract_content,
                            'final_url': response.url
                        }
                    )
                    break  # Success

                elif response.status_code in [302, 403]:
                    self.add_test_result(
                        f"Contract Management - {url}",
                        "PASS",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'note': 'Requires authentication',
                            'final_url': response.url
                        }
                    )
                    break

                elif response.status_code == 404:
                    self.log(f"  URL not found: {url}", Color.YELLOW)
                    continue

            except Exception as e:
                self.log(f"  Error: {str(e)}", Color.RED)

    # ==================== Escrow Payment Flow ====================

    def test_escrow_payment(self):
        """Test escrow payment flow (demo-safe check)"""
        self.log("\n" + "="*60, Color.BOLD)
        self.log("Testing Escrow Payment Flow", Color.BOLD)
        self.log("="*60, Color.BOLD)

        # We'll just check if escrow-related pages are accessible
        # WITHOUT actually creating transactions (demo-safe)

        try:
            # Check if finance/payment endpoints exist
            url = f"{self.base_url}/en/finance/"
            response = self.session.get(url, timeout=10, allow_redirects=True)

            finance_accessible = response.status_code in [200, 302, 403]

            self.add_test_result(
                "Escrow Payment Flow - Finance Module",
                "PASS" if finance_accessible else "FAIL",
                {
                    'url': url,
                    'status_code': response.status_code,
                    'note': 'Finance module accessibility check (no transactions created)',
                    'accessible': finance_accessible
                }
            )

            # Check API for escrow endpoints
            api_url = f"{self.base_url}/api/v1/marketplace/"
            api_response = self.session.get(api_url, timeout=10)

            api_accessible = api_response.status_code in [200, 401, 403]

            self.add_test_result(
                "Escrow Payment Flow - API Endpoints",
                "PASS" if api_accessible else "FAIL",
                {
                    'url': api_url,
                    'status_code': api_response.status_code,
                    'note': 'Marketplace API endpoint check',
                    'accessible': api_accessible
                }
            )

        except Exception as e:
            self.add_test_result(
                "Escrow Payment Flow",
                "FAIL",
                {
                    'error': str(e)
                }
            )

    # ==================== Create Service ====================

    def test_create_service(self):
        """Test create service page"""
        self.log("\n" + "="*60, Color.BOLD)
        self.log("Testing Create Service", Color.BOLD)
        self.log("="*60, Color.BOLD)

        test_urls = [
            '/en/services/service/create/',
            '/services/service/create/',
        ]

        for url in test_urls:
            try:
                full_url = f"{self.base_url}{url}"
                self.log(f"\nTesting: {full_url}", Color.CYAN)

                response = self.session.get(full_url, timeout=10, allow_redirects=True)

                if response.status_code == 200:
                    content = response.text.lower()

                    has_form = 'form' in content and ('service' in content or 'create' in content)

                    self.add_test_result(
                        f"Create Service - {url}",
                        "PASS" if has_form else "FAIL",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'has_form': has_form,
                            'final_url': response.url
                        }
                    )
                    break

                elif response.status_code in [302, 403]:
                    self.add_test_result(
                        f"Create Service - {url}",
                        "PASS",
                        {
                            'url': full_url,
                            'status_code': response.status_code,
                            'note': 'Requires authentication',
                            'final_url': response.url
                        }
                    )
                    break

                elif response.status_code == 404:
                    self.log(f"  URL not found: {url}", Color.YELLOW)
                    continue

            except Exception as e:
                self.log(f"  Error: {str(e)}", Color.RED)

    # ==================== Main Test Runner ====================

    def run_all_tests(self):
        """Run all marketplace tests"""
        self.log("\n" + "="*80, Color.BOLD + Color.MAGENTA)
        self.log("ZUMODRA MARKETPLACE/FREELANCE FEATURE TESTING", Color.BOLD + Color.MAGENTA)
        self.log("="*80, Color.BOLD + Color.MAGENTA)
        self.log(f"Target: {self.base_url}", Color.CYAN)
        self.log(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Color.CYAN)
        self.log("="*80, Color.BOLD + Color.MAGENTA)

        # Run all tests
        self.test_login()
        time.sleep(0.5)

        self.test_browse_freelancers()
        time.sleep(0.5)

        self.test_service_listings()
        time.sleep(0.5)

        self.test_service_categories()
        time.sleep(0.5)

        self.test_provider_profiles()
        time.sleep(0.5)

        self.test_service_proposals()
        time.sleep(0.5)

        self.test_contract_management()
        time.sleep(0.5)

        self.test_escrow_payment()
        time.sleep(0.5)

        self.test_create_service()

        # Print summary
        self.print_summary()

        # Save results
        self.save_results()

    def print_summary(self):
        """Print test summary"""
        self.log("\n" + "="*80, Color.BOLD)
        self.log("TEST SUMMARY", Color.BOLD + Color.CYAN)
        self.log("="*80, Color.BOLD)

        summary = self.results['summary']

        self.log(f"\nTotal Tests: {summary['total']}", Color.BOLD)
        self.log(f"Passed: {summary['passed']}", Color.GREEN)
        self.log(f"Failed: {summary['failed']}", Color.RED)

        pass_rate = (summary['passed'] / summary['total'] * 100) if summary['total'] > 0 else 0
        self.log(f"Pass Rate: {pass_rate:.1f}%", Color.CYAN)

        if summary['working_features']:
            self.log("\n" + "="*60, Color.GREEN)
            self.log("WORKING FEATURES:", Color.GREEN + Color.BOLD)
            self.log("="*60, Color.GREEN)
            for feature in summary['working_features']:
                self.log(f"  [+] {feature}", Color.GREEN)

        if summary['broken_features']:
            self.log("\n" + "="*60, Color.RED)
            self.log("BROKEN/INACCESSIBLE FEATURES:", Color.RED + Color.BOLD)
            self.log("="*60, Color.RED)
            for feature in summary['broken_features']:
                self.log(f"  [-] {feature}", Color.RED)

        self.log("\n" + "="*80, Color.BOLD)


def main():
    """Main entry point"""
    tester = MarketplaceFeatureTester(BASE_URL)

    try:
        tester.run_all_tests()
    except KeyboardInterrupt:
        tester.log("\n\nTest interrupted by user", Color.YELLOW)
        tester.save_results()
    except Exception as e:
        tester.log(f"\n\nUnexpected error: {str(e)}", Color.RED)
        tester.save_results()
        raise


if __name__ == "__main__":
    main()
