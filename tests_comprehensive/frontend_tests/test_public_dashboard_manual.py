"""
Manual Test Script for Public User Dashboard
Tests the live server at zumodra.rhematek-solutions.com

Run with: python test_public_dashboard_manual.py
"""

import requests
from datetime import datetime
import json

# Configuration
BASE_URL = "https://zumodra.rhematek-solutions.com"
LOGIN_URL = f"{BASE_URL}/accounts/login/"
DASHBOARD_URL = f"{BASE_URL}/app/dashboard/"

# Test Credentials
# You need to provide credentials for:
# 1. A public user without tenant membership and WITHOUT MFA
# 2. A public user with MFA enabled
# 3. A public user with complete profile

TEST_USERS = {
    'public_no_mfa': {
        'username': 'publicuser',  # Replace with actual test user
        'password': 'testpass123',  # Replace with actual password
        'expected_mfa': False,
    },
    'public_with_mfa': {
        'username': 'mfauser',  # Replace with actual test user
        'password': 'testpass123',  # Replace with actual password
        'expected_mfa': True,
    },
}


class DashboardTester:
    """Test harness for public user dashboard."""

    def __init__(self):
        self.session = requests.Session()
        self.results = []

    def log_test(self, name, passed, details=""):
        """Log test result."""
        status = "✅ PASS" if passed else "❌ FAIL"
        result = {
            'name': name,
            'status': status,
            'passed': passed,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.results.append(result)
        print(f"{status}: {name}")
        if details:
            print(f"  Details: {details}")
        return passed

    def login(self, username, password):
        """Login to the application."""
        print(f"\n🔐 Logging in as {username}...")

        # Get login page to obtain CSRF token
        response = self.session.get(LOGIN_URL)
        if response.status_code != 200:
            self.log_test("Login page accessible", False, f"Status: {response.status_code}")
            return False

        # Extract CSRF token
        csrf_token = None
        if 'csrftoken' in self.session.cookies:
            csrf_token = self.session.cookies['csrftoken']

        # Perform login
        login_data = {
            'login': username,
            'password': password,
            'csrfmiddlewaretoken': csrf_token,
        }

        response = self.session.post(LOGIN_URL, data=login_data, allow_redirects=True)

        if response.status_code == 200 and 'Welcome' in response.text:
            self.log_test(f"Login successful for {username}", True)
            return True
        else:
            self.log_test(f"Login successful for {username}", False,
                         f"Status: {response.status_code}")
            return False

    def test_dashboard_access(self):
        """Test 1: Dashboard Access."""
        print("\n📋 Testing Dashboard Access...")

        response = self.session.get(DASHBOARD_URL)
        passed = response.status_code == 200
        self.log_test("Dashboard page loads", passed, f"Status: {response.status_code}")

        if passed:
            # Check if public user dashboard template is used
            is_public = 'public-user-dashboard' in response.text.lower() or \
                       'is_public_user' in response.text.lower()
            self.log_test("Public user dashboard template used", is_public)

        return passed

    def test_welcome_banner(self):
        """Test 2: Welcome Banner."""
        print("\n👋 Testing Welcome Banner...")

        response = self.session.get(DASHBOARD_URL)
        content = response.text

        # Check welcome message
        has_welcome = 'Welcome' in content
        self.log_test("Welcome banner displays", has_welcome)

        # Check gradient styling
        has_gradient = 'gradient' in content.lower() and 'blue' in content.lower()
        self.log_test("Welcome banner has gradient styling", has_gradient)

        # Check "Complete your profile" message
        has_profile_msg = 'Complete your profile' in content
        self.log_test("Profile completion message displays", has_profile_msg)

    def test_mfa_warning(self, expect_mfa_enabled=False):
        """Test 3: MFA Warning Banner."""
        print("\n🛡️ Testing MFA Warning Banner...")

        response = self.session.get(DASHBOARD_URL)
        content = response.text

        has_security_notice = 'Security Notice' in content
        has_mfa_warning = 'Two-factor authentication' in content

        if expect_mfa_enabled:
            # MFA enabled - banner should NOT appear
            banner_absent = not (has_security_notice and has_mfa_warning)
            self.log_test("MFA banner does NOT show (MFA enabled)", banner_absent)
        else:
            # MFA not enabled - banner SHOULD appear
            self.log_test("MFA warning banner displays", has_security_notice)
            self.log_test("MFA warning message shows", has_mfa_warning)

            # Check for "Set it up now" link
            has_setup_link = 'Set it up now' in content or 'two-factor' in content.lower()
            self.log_test("MFA setup link present", has_setup_link)

    def test_profile_completion(self):
        """Test 4: Profile Completion Widget."""
        print("\n📊 Testing Profile Completion Widget...")

        response = self.session.get(DASHBOARD_URL)
        content = response.text

        has_widget = 'Profile Completion' in content
        self.log_test("Profile completion widget displays", has_widget)

        # Check for percentage display
        has_percentage = '%' in content and ('0%' in content or any(f'{i}%' in content for i in range(1, 101)))
        self.log_test("Profile completion percentage shows", has_percentage)

        # Check for progress bar
        has_progress_bar = 'progress' in content.lower() or 'bg-blue-600' in content
        self.log_test("Progress bar renders", has_progress_bar)

        # Check for profile link
        has_profile_link = 'Complete your profile' in content or '/profile/' in content
        self.log_test("Profile completion link present", has_profile_link)

    def test_quick_actions(self):
        """Test 5: Quick Actions Cards."""
        print("\n⚡ Testing Quick Actions Cards...")

        response = self.session.get(DASHBOARD_URL)
        content = response.text

        # Check all 3 cards
        has_browse_jobs = 'Browse Jobs' in content
        self.log_test("Browse Jobs card displays", has_browse_jobs)

        has_browse_services = 'Browse Services' in content
        self.log_test("Browse Services card displays", has_browse_services)

        has_enable_2fa = 'Enable 2FA' in content or 'Secure your account' in content
        self.log_test("Enable 2FA card displays", has_enable_2fa)

        # Check for icons (Phosphor icons)
        has_icons = 'ph-briefcase' in content or 'ph-storefront' in content or 'ph-shield' in content
        self.log_test("Quick action icons display", has_icons)

        # Check for hover effects
        has_hover = 'hover:' in content
        self.log_test("Hover effects present", has_hover)

        # Check responsive grid
        has_grid = 'grid' in content and 'md:grid-cols-3' in content
        self.log_test("Responsive grid layout used", has_grid)

    def test_recommended_jobs(self):
        """Test 6: Recommended Jobs Section."""
        print("\n💼 Testing Recommended Jobs Section...")

        response = self.session.get(DASHBOARD_URL)
        content = response.text

        has_jobs_section = 'Recommended Jobs' in content or 'No jobs available' in content
        self.log_test("Jobs section displays", has_jobs_section)

        if 'Recommended Jobs' in content:
            # Jobs are available
            self.log_test("Recommended jobs found", True, "Jobs section populated")

            # Check for job details
            has_company = 'company' in content.lower()
            self.log_test("Job cards show company name", has_company)

            has_location = 'ph-map-pin' in content or 'location' in content.lower()
            self.log_test("Job cards show location", has_location)

            # Check for "View all jobs" link
            has_view_all = 'View all jobs' in content or '/careers/' in content
            self.log_test("View all jobs link present", has_view_all)

        else:
            # Empty state
            self.log_test("Empty state displays", 'No jobs available' in content)
            has_empty_icon = 'ph-briefcase' in content
            self.log_test("Empty state icon shows", has_empty_icon)

    def test_join_organization_cta(self):
        """Test 7: Join Organization CTA."""
        print("\n🏢 Testing Join Organization CTA...")

        response = self.session.get(DASHBOARD_URL)
        content = response.text

        has_cta = 'Ready to do more?' in content
        self.log_test("Join organization CTA displays", has_cta)

        has_explanation = 'Join an organization' in content
        self.log_test("CTA explanation text present", has_explanation)

        # Check for gradient styling
        has_gradient = 'gradient' in content.lower() and 'purple' in content.lower()
        self.log_test("CTA has gradient styling", has_gradient)

        # Check for action buttons
        has_join_btn = 'Join Organization' in content
        self.log_test("Join Organization button present", has_join_btn)

        has_create_btn = 'Create Organization' in content
        self.log_test("Create Organization button present", has_create_btn)

    def test_dark_mode_support(self):
        """Test 8: Dark Mode Support."""
        print("\n🌙 Testing Dark Mode Support...")

        response = self.session.get(DASHBOARD_URL)
        content = response.text

        # Check for dark mode classes
        has_dark_bg = 'dark:bg-gray-800' in content
        self.log_test("Dark mode background classes present", has_dark_bg)

        has_dark_text = 'dark:text-white' in content or 'dark:text-gray' in content
        self.log_test("Dark mode text classes present", has_dark_text)

    def test_responsive_design(self):
        """Test 9: Responsive Design."""
        print("\n📱 Testing Responsive Design...")

        response = self.session.get(DASHBOARD_URL)
        content = response.text

        # Check container
        has_container = 'container' in content and 'mx-auto' in content
        self.log_test("Responsive container used", has_container)

        # Check max width
        has_max_width = 'max-w' in content
        self.log_test("Max width constraint applied", has_max_width)

        # Check grid responsiveness
        has_responsive_grid = 'grid-cols-1' in content and 'md:grid-cols' in content
        self.log_test("Grid adapts to screen size", has_responsive_grid)

    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*60)
        print("📊 TEST SUMMARY")
        print("="*60)

        total = len(self.results)
        passed = sum(1 for r in self.results if r['passed'])
        failed = total - passed

        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"Success Rate: {(passed/total*100):.1f}%")

        if failed > 0:
            print("\n❌ Failed Tests:")
            for result in self.results:
                if not result['passed']:
                    print(f"  - {result['name']}")
                    if result['details']:
                        print(f"    {result['details']}")

        # Save results to JSON
        with open('public_dashboard_test_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n💾 Results saved to: public_dashboard_test_results.json")

    def run_all_tests(self, username, password, expect_mfa=False):
        """Run all tests for a user."""
        print("\n" + "="*60)
        print(f"🚀 TESTING PUBLIC USER DASHBOARD")
        print(f"Server: {BASE_URL}")
        print(f"User: {username}")
        print("="*60)

        # Login
        if not self.login(username, password):
            print("\n❌ Login failed. Cannot proceed with tests.")
            return

        # Run all tests
        self.test_dashboard_access()
        self.test_welcome_banner()
        self.test_mfa_warning(expect_mfa)
        self.test_profile_completion()
        self.test_quick_actions()
        self.test_recommended_jobs()
        self.test_join_organization_cta()
        self.test_dark_mode_support()
        self.test_responsive_design()

        # Summary
        self.print_summary()


def main():
    """Main test runner."""
    print("="*60)
    print("PUBLIC USER DASHBOARD TEST SUITE")
    print("="*60)
    print(f"Target Server: {BASE_URL}")
    print(f"Dashboard URL: {DASHBOARD_URL}")
    print("\n⚠️  IMPORTANT: Update TEST_USERS with actual credentials!")
    print("="*60)

    # Ask for credentials
    print("\n📝 Enter test user credentials:")
    username = input("Username (or press Enter to skip): ").strip()

    if not username:
        print("\n❌ No username provided. Exiting.")
        print("\n💡 To run tests, edit TEST_USERS in this script with valid credentials,")
        print("   or enter credentials when prompted.")
        return

    password = input("Password: ").strip()

    # Run tests
    tester = DashboardTester()
    tester.run_all_tests(username, password, expect_mfa=False)

    print("\n" + "="*60)
    print("✅ Testing Complete!")
    print("="*60)


if __name__ == '__main__':
    main()
