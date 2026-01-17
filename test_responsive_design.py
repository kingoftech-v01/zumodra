"""
Zumodra Responsive Design Testing Script
Tests mobile/tablet/desktop responsiveness across all major pages
"""

import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

# Fix Windows console encoding for emojis
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

try:
    from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("⚠️  Playwright not installed. Run: pip install playwright && playwright install")

# Test Configuration
TEST_CONFIG = {
    'base_url': 'https://demo-company.zumodra.rhematek-solutions.com',
    'test_user': {
        'email': 'admin@demo.zumodra.rhematek-solutions.com',
        'password': 'Demo@2024!',
    },
    'viewports': {
        'mobile': {'width': 375, 'height': 812, 'name': 'Mobile (iPhone 13)'},
        'tablet': {'width': 768, 'height': 1024, 'name': 'Tablet (iPad)'},
        'desktop': {'width': 1920, 'height': 1080, 'name': 'Desktop (Full HD)'},
    },
    'pages_to_test': [
        {'name': 'Homepage', 'url': '/', 'requires_auth': False},
        {'name': 'Login', 'url': '/accounts/login/', 'requires_auth': False},
        {'name': 'Dashboard', 'url': '/app/dashboard/', 'requires_auth': True},
        {'name': 'ATS Jobs List', 'url': '/app/ats/jobs/', 'requires_auth': True},
        {'name': 'ATS Pipeline Board', 'url': '/app/ats/pipeline/', 'requires_auth': True},
        {'name': 'ATS Candidates', 'url': '/app/ats/candidates/', 'requires_auth': True},
        {'name': 'HR Employees', 'url': '/app/hr/employees/', 'requires_auth': True},
        {'name': 'Services Marketplace', 'url': '/app/services/', 'requires_auth': True},
        {'name': 'User Profile', 'url': '/app/profile/', 'requires_auth': True},
    ],
    'screenshot_dir': Path(__file__).parent / 'test_results' / 'responsive',
    'timeout': 10000,  # 10 seconds
    'slow_mo': 500,  # Slow down by 500ms for better observation
}

# Issue tracking
issues_found = []


class ResponsiveTestRunner:
    """Automated responsive design testing"""

    def __init__(self, config: Dict):
        self.config = config
        self.browser = None
        self.context = None
        self.page = None
        self.test_results = {
            'start_time': datetime.now().isoformat(),
            'base_url': config['base_url'],
            'tests': [],
            'issues': [],
            'summary': {}
        }

    def setup_browser(self) -> Browser:
        """Initialize Playwright browser"""
        print("🚀 Launching browser...")
        playwright = sync_playwright().start()
        self.browser = playwright.chromium.launch(
            headless=False,  # Set to True for CI/CD
            slow_mo=self.config['slow_mo']
        )
        return self.browser

    def create_context(self, viewport: Dict) -> BrowserContext:
        """Create browser context with specific viewport"""
        return self.browser.new_context(
            viewport={'width': viewport['width'], 'height': viewport['height']},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )

    def login(self, page: Page) -> bool:
        """Login to the application"""
        try:
            print(f"  🔐 Logging in as {self.config['test_user']['email']}...")

            # Navigate to login page
            page.goto(f"{self.config['base_url']}/accounts/login/", timeout=self.config['timeout'])
            page.wait_for_load_state('networkidle')

            # Fill login form
            page.fill('input[name="login"]', self.config['test_user']['email'])
            page.fill('input[name="password"]', self.config['test_user']['password'])

            # Submit form
            page.click('button[type="submit"]')

            # Wait for redirect to dashboard or profile
            page.wait_for_load_state('networkidle', timeout=self.config['timeout'])

            # Check if login successful (should redirect away from login page)
            current_url = page.url
            if '/login' not in current_url:
                print(f"  ✅ Login successful - redirected to {current_url}")
                return True
            else:
                print(f"  ❌ Login failed - still on login page")
                return False

        except Exception as e:
            print(f"  ❌ Login error: {str(e)}")
            return False

    def check_responsive_issues(self, page: Page, page_name: str, viewport_name: str) -> List[Dict]:
        """Check for common responsive design issues"""
        issues = []

        try:
            # Check for horizontal scrollbar (overflow)
            body_width = page.evaluate("document.body.scrollWidth")
            window_width = page.evaluate("window.innerWidth")

            if body_width > window_width:
                issues.append({
                    'page': page_name,
                    'viewport': viewport_name,
                    'type': 'horizontal_overflow',
                    'severity': 'high',
                    'description': f'Content overflows horizontally ({body_width}px > {window_width}px)',
                })

            # Check for tiny font sizes (less than 12px on mobile)
            small_fonts = page.evaluate("""
                () => {
                    const elements = document.querySelectorAll('*');
                    const smallFonts = [];
                    elements.forEach(el => {
                        const fontSize = parseFloat(window.getComputedStyle(el).fontSize);
                        if (fontSize < 12 && fontSize > 0) {
                            smallFonts.push({
                                tag: el.tagName,
                                fontSize: fontSize,
                                text: el.innerText ? el.innerText.substring(0, 50) : ''
                            });
                        }
                    });
                    return smallFonts.slice(0, 5);  // Return first 5
                }
            """)

            if small_fonts and viewport_name == 'Mobile (iPhone 13)':
                issues.append({
                    'page': page_name,
                    'viewport': viewport_name,
                    'type': 'small_fonts',
                    'severity': 'medium',
                    'description': f'Found {len(small_fonts)} elements with font size < 12px',
                    'examples': small_fonts,
                })

            # Check for overlapping elements
            overlaps = page.evaluate("""
                () => {
                    const checkOverlap = (el1, el2) => {
                        const rect1 = el1.getBoundingClientRect();
                        const rect2 = el2.getBoundingClientRect();
                        return !(rect1.right < rect2.left ||
                                rect1.left > rect2.right ||
                                rect1.bottom < rect2.top ||
                                rect1.top > rect2.bottom);
                    };

                    const elements = Array.from(document.querySelectorAll('button, a, input, .card, .panel'));
                    let overlapCount = 0;

                    for (let i = 0; i < elements.length; i++) {
                        for (let j = i + 1; j < elements.length; j++) {
                            if (checkOverlap(elements[i], elements[j])) {
                                overlapCount++;
                            }
                        }
                    }

                    return overlapCount;
                }
            """)

            if overlaps > 0:
                issues.append({
                    'page': page_name,
                    'viewport': viewport_name,
                    'type': 'overlapping_elements',
                    'severity': 'high',
                    'description': f'Found {overlaps} potentially overlapping interactive elements',
                })

            # Check if navigation menu is accessible
            nav_visible = page.evaluate("""
                () => {
                    const nav = document.querySelector('nav, [role="navigation"], .navbar, .menu');
                    if (!nav) return false;
                    const style = window.getComputedStyle(nav);
                    return style.display !== 'none' && style.visibility !== 'hidden';
                }
            """)

            if not nav_visible:
                issues.append({
                    'page': page_name,
                    'viewport': viewport_name,
                    'type': 'navigation_hidden',
                    'severity': 'high',
                    'description': 'Navigation menu not visible',
                })

            # Check for clickable elements too small (< 44x44px on mobile - WCAG guideline)
            if viewport_name == 'Mobile (iPhone 13)':
                small_buttons = page.evaluate("""
                    () => {
                        const buttons = document.querySelectorAll('button, a, input[type="submit"], input[type="button"]');
                        const tooSmall = [];
                        buttons.forEach(btn => {
                            const rect = btn.getBoundingClientRect();
                            if ((rect.width < 44 || rect.height < 44) && rect.width > 0 && rect.height > 0) {
                                tooSmall.push({
                                    tag: btn.tagName,
                                    width: Math.round(rect.width),
                                    height: Math.round(rect.height),
                                    text: btn.innerText ? btn.innerText.substring(0, 30) : ''
                                });
                            }
                        });
                        return tooSmall.slice(0, 5);  // First 5
                    }
                """)

                if small_buttons:
                    issues.append({
                        'page': page_name,
                        'viewport': viewport_name,
                        'type': 'small_touch_targets',
                        'severity': 'medium',
                        'description': f'Found {len(small_buttons)} buttons/links smaller than 44x44px (WCAG minimum)',
                        'examples': small_buttons,
                    })

            # Check for images without responsive sizing
            unresponsive_images = page.evaluate("""
                () => {
                    const images = document.querySelectorAll('img');
                    const unresponsive = [];
                    images.forEach(img => {
                        const hasMaxWidth = window.getComputedStyle(img).maxWidth !== 'none';
                        const hasWidth100 = window.getComputedStyle(img).width === '100%';
                        if (!hasMaxWidth && !hasWidth100 && img.width > 0) {
                            unresponsive.push({
                                src: img.src.substring(0, 50),
                                width: img.width,
                                height: img.height
                            });
                        }
                    });
                    return unresponsive.slice(0, 3);
                }
            """)

            if unresponsive_images:
                issues.append({
                    'page': page_name,
                    'viewport': viewport_name,
                    'type': 'unresponsive_images',
                    'severity': 'low',
                    'description': f'Found {len(unresponsive_images)} images without responsive sizing',
                    'examples': unresponsive_images,
                })

        except Exception as e:
            print(f"    ⚠️  Error checking responsive issues: {str(e)}")

        return issues

    def take_screenshot(self, page: Page, page_name: str, viewport_name: str) -> str:
        """Take and save screenshot"""
        # Clean names for filename
        clean_page = page_name.lower().replace(' ', '_')
        clean_viewport = viewport_name.lower().replace(' ', '_').replace('(', '').replace(')', '')

        filename = f"{clean_page}_{clean_viewport}.png"
        filepath = self.config['screenshot_dir'] / filename

        # Ensure directory exists
        filepath.parent.mkdir(parents=True, exist_ok=True)

        # Take full page screenshot
        page.screenshot(path=str(filepath), full_page=True)

        return str(filepath)

    def test_page(self, page: Page, page_config: Dict, viewport_name: str) -> Dict:
        """Test a single page at a specific viewport"""
        page_name = page_config['name']
        url = f"{self.config['base_url']}{page_config['url']}"

        print(f"  📄 Testing {page_name} at {viewport_name}...")

        result = {
            'page': page_name,
            'url': url,
            'viewport': viewport_name,
            'status': 'unknown',
            'issues': [],
            'screenshot': None,
            'timestamp': datetime.now().isoformat(),
        }

        try:
            # Navigate to page
            response = page.goto(url, timeout=self.config['timeout'])
            page.wait_for_load_state('networkidle')

            # Check if page loaded successfully
            if response and response.status == 200:
                result['status'] = 'loaded'
            elif response:
                result['status'] = f'error_{response.status}'
                result['issues'].append({
                    'type': 'http_error',
                    'severity': 'high',
                    'description': f'HTTP {response.status} error',
                })
                return result

            # Wait a bit for dynamic content
            time.sleep(2)

            # Check for responsive issues
            issues = self.check_responsive_issues(page, page_name, viewport_name)
            result['issues'] = issues

            # Take screenshot
            screenshot_path = self.take_screenshot(page, page_name, viewport_name)
            result['screenshot'] = screenshot_path

            # Update status
            if issues:
                result['status'] = 'issues_found'
                print(f"    ⚠️  Found {len(issues)} issue(s)")
            else:
                result['status'] = 'passed'
                print(f"    ✅ No issues detected")

        except Exception as e:
            result['status'] = 'error'
            result['issues'].append({
                'type': 'test_error',
                'severity': 'critical',
                'description': f'Test error: {str(e)}',
            })
            print(f"    ❌ Error: {str(e)}")

        return result

    def run_tests(self):
        """Run all responsive tests"""
        if not PLAYWRIGHT_AVAILABLE:
            print("❌ Playwright is not installed. Please install it first:")
            print("   pip install playwright")
            print("   playwright install")
            return

        print("\n" + "="*70)
        print("🧪 ZUMODRA RESPONSIVE DESIGN TESTING")
        print("="*70)
        print(f"📍 Target: {self.config['base_url']}")
        print(f"📱 Viewports: {', '.join(self.config['viewports'].keys())}")
        print(f"📄 Pages: {len(self.config['pages_to_test'])}")
        print(f"💾 Screenshots: {self.config['screenshot_dir']}")
        print("="*70 + "\n")

        # Setup browser
        self.setup_browser()

        # Test each viewport
        for viewport_key, viewport_config in self.config['viewports'].items():
            viewport_name = viewport_config['name']
            print(f"\n{'='*70}")
            print(f"📱 TESTING {viewport_name.upper()} ({viewport_config['width']}x{viewport_config['height']})")
            print(f"{'='*70}\n")

            # Create context with viewport
            self.context = self.create_context(viewport_config)
            self.page = self.context.new_page()

            # Login if needed (once per viewport)
            auth_required = any(p['requires_auth'] for p in self.config['pages_to_test'])
            logged_in = False

            if auth_required:
                logged_in = self.login(self.page)
                if not logged_in:
                    print(f"  ⚠️  Login failed - skipping authenticated pages")

            # Test each page
            for page_config in self.config['pages_to_test']:
                # Skip auth-required pages if not logged in
                if page_config['requires_auth'] and not logged_in:
                    print(f"  ⏭️  Skipping {page_config['name']} (requires authentication)")
                    continue

                # Run test
                result = self.test_page(self.page, page_config, viewport_name)
                self.test_results['tests'].append(result)

                # Add issues to global list
                for issue in result.get('issues', []):
                    self.test_results['issues'].append({
                        **issue,
                        'page': page_config['name'],
                        'viewport': viewport_name,
                    })

                # Small delay between pages
                time.sleep(1)

            # Cleanup context
            self.context.close()

        # Cleanup browser
        self.browser.close()

        # Generate summary
        self.generate_summary()

        # Save results
        self.save_results()

        # Print summary
        self.print_summary()

    def generate_summary(self):
        """Generate test summary statistics"""
        total_tests = len(self.test_results['tests'])
        passed = sum(1 for t in self.test_results['tests'] if t['status'] == 'passed')
        issues_found = sum(1 for t in self.test_results['tests'] if t['status'] == 'issues_found')
        errors = sum(1 for t in self.test_results['tests'] if t['status'] in ['error', 'error_404', 'error_500'])

        total_issues = len(self.test_results['issues'])
        critical = sum(1 for i in self.test_results['issues'] if i.get('severity') == 'critical')
        high = sum(1 for i in self.test_results['issues'] if i.get('severity') == 'high')
        medium = sum(1 for i in self.test_results['issues'] if i.get('severity') == 'medium')
        low = sum(1 for i in self.test_results['issues'] if i.get('severity') == 'low')

        self.test_results['summary'] = {
            'total_tests': total_tests,
            'passed': passed,
            'issues_found': issues_found,
            'errors': errors,
            'total_issues': total_issues,
            'issues_by_severity': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
            },
            'pass_rate': f"{(passed / total_tests * 100):.1f}%" if total_tests > 0 else "0%",
        }

        self.test_results['end_time'] = datetime.now().isoformat()

    def save_results(self):
        """Save test results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"responsive_test_results_{timestamp}.json"
        filepath = self.config['screenshot_dir'] / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.test_results, f, indent=2, ensure_ascii=False)

        print(f"\n💾 Results saved to: {filepath}")

    def print_summary(self):
        """Print test summary to console"""
        summary = self.test_results['summary']

        print("\n" + "="*70)
        print("📊 TEST SUMMARY")
        print("="*70)
        print(f"Total Tests: {summary['total_tests']}")
        print(f"  ✅ Passed: {summary['passed']}")
        print(f"  ⚠️  Issues Found: {summary['issues_found']}")
        print(f"  ❌ Errors: {summary['errors']}")
        print(f"  📈 Pass Rate: {summary['pass_rate']}")
        print()
        print(f"Total Issues: {summary['total_issues']}")
        print(f"  🔴 Critical: {summary['issues_by_severity']['critical']}")
        print(f"  🟠 High: {summary['issues_by_severity']['high']}")
        print(f"  🟡 Medium: {summary['issues_by_severity']['medium']}")
        print(f"  🟢 Low: {summary['issues_by_severity']['low']}")
        print("="*70)

        # Print top issues
        if self.test_results['issues']:
            print("\n🔍 TOP ISSUES FOUND:\n")

            # Group issues by type
            issues_by_type = {}
            for issue in self.test_results['issues']:
                issue_type = issue.get('type', 'unknown')
                if issue_type not in issues_by_type:
                    issues_by_type[issue_type] = []
                issues_by_type[issue_type].append(issue)

            # Print grouped issues
            for issue_type, issues_list in sorted(issues_by_type.items()):
                print(f"  • {issue_type.replace('_', ' ').title()}: {len(issues_list)} occurrence(s)")
                # Show first example
                if issues_list:
                    example = issues_list[0]
                    print(f"    → {example['page']} @ {example['viewport']}")
                    print(f"      {example['description']}")
                print()


def main():
    """Main entry point"""
    runner = ResponsiveTestRunner(TEST_CONFIG)
    runner.run_tests()


if __name__ == '__main__':
    main()
