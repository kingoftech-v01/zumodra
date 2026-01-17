"""
ATS Jobs Module Testing Helper Script

This script provides utilities for manual testing of the ATS Jobs module.
It does NOT automate the actual testing but provides helpers for:
- Generating test data
- Checking URLs
- Validating responses
- Documenting test results

Usage:
    python test_helper.py --check-urls
    python test_helper.py --generate-test-data
    python test_helper.py --validate-job <job-uuid>
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urljoin

# Test environment configuration
BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"
TEST_DATE = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# URL patterns from ats/urls_frontend.py
JOB_URLS = {
    "job_list": "/app/ats/jobs/",
    "job_create": "/app/ats/jobs/create/",
    "job_detail": "/app/ats/jobs/{uuid}/",
    "job_edit": "/app/ats/jobs/{uuid}/edit/",
    "job_publish": "/app/ats/jobs/{uuid}/publish/",
    "job_close": "/app/ats/jobs/{uuid}/close/",
    "job_duplicate": "/app/ats/jobs/{uuid}/duplicate/",
    "job_delete": "/app/ats/jobs/{uuid}/delete/",
}


class TestResult:
    """Structure for test results."""

    def __init__(self, test_name: str):
        self.test_name = test_name
        self.url = ""
        self.status = "PENDING"  # PENDING, PASS, FAIL, SKIP
        self.expected = ""
        self.actual = ""
        self.screenshot = ""
        self.errors = []
        self.notes = []
        self.timestamp = TEST_DATE

    def to_dict(self) -> Dict:
        return {
            "test_name": self.test_name,
            "url": self.url,
            "status": self.status,
            "expected": self.expected,
            "actual": self.actual,
            "screenshot": self.screenshot,
            "errors": self.errors,
            "notes": self.notes,
            "timestamp": self.timestamp,
        }

    def to_markdown(self) -> str:
        """Convert result to markdown format."""
        status_emoji = {
            "PASS": "✅",
            "FAIL": "❌",
            "SKIP": "⏭️",
            "PENDING": "⏳",
        }

        md = f"### {status_emoji.get(self.status, '❓')} {self.test_name}\n\n"
        md += f"**URL:** {self.url}\n\n"
        md += f"**Status:** {self.status}\n\n"
        md += f"**Expected:** {self.expected}\n\n"
        md += f"**Actual:** {self.actual}\n\n"

        if self.screenshot:
            md += f"**Screenshot:** `{self.screenshot}`\n\n"

        if self.errors:
            md += "**Errors:**\n"
            for error in self.errors:
                md += f"- {error}\n"
            md += "\n"

        if self.notes:
            md += "**Notes:**\n"
            for note in self.notes:
                md += f"- {note}\n"
            md += "\n"

        md += f"**Tested:** {self.timestamp}\n\n"
        md += "---\n\n"

        return md


class TestSession:
    """Manages a testing session."""

    def __init__(self):
        self.results: List[TestResult] = []
        self.session_start = datetime.now()

    def add_result(self, result: TestResult):
        self.results.append(result)

    def generate_report(self, output_file: str = "TEST_REPORT.md"):
        """Generate markdown test report."""
        pass_count = sum(1 for r in self.results if r.status == "PASS")
        fail_count = sum(1 for r in self.results if r.status == "FAIL")
        skip_count = sum(1 for r in self.results if r.status == "SKIP")
        total_count = len(self.results)

        report = "# ATS Jobs Module - Test Report\n\n"
        report += f"**Test Date:** {TEST_DATE}\n\n"
        report += f"**Environment:** {BASE_URL}\n\n"
        report += f"**Duration:** {(datetime.now() - self.session_start).seconds} seconds\n\n"
        report += "## Summary\n\n"
        report += f"- **Total Tests:** {total_count}\n"
        report += f"- **Passed:** ✅ {pass_count}\n"
        report += f"- **Failed:** ❌ {fail_count}\n"
        report += f"- **Skipped:** ⏭️ {skip_count}\n"

        if total_count > 0:
            pass_rate = (pass_count / total_count) * 100
            report += f"- **Pass Rate:** {pass_rate:.1f}%\n"

        report += "\n---\n\n"
        report += "## Detailed Results\n\n"

        for result in self.results:
            report += result.to_markdown()

        # Write report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)

        print(f"✅ Test report generated: {output_file}")
        return report

    def export_json(self, output_file: str = "test_results.json"):
        """Export results as JSON."""
        data = {
            "session_start": self.session_start.isoformat(),
            "test_date": TEST_DATE,
            "base_url": BASE_URL,
            "results": [r.to_dict() for r in self.results],
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        print(f"✅ Test results exported: {output_file}")


def check_urls(job_uuid: Optional[str] = None):
    """Print all job-related URLs for testing."""
    print("\n" + "="*80)
    print("ATS Jobs Module - URL Reference")
    print("="*80 + "\n")

    if not job_uuid:
        job_uuid = "<job-uuid>"
        print("⚠️  No job UUID provided. Using placeholder.")
        print("   To test with real UUID, run: python test_helper.py --check-urls <uuid>\n")

    print(f"Base URL: {BASE_URL}\n")
    print("Job URLs to Test:\n")

    for name, path in JOB_URLS.items():
        full_url = urljoin(BASE_URL, path.format(uuid=job_uuid))
        method = "POST" if name in ["job_publish", "job_close", "job_duplicate"] else "GET"
        method = "DELETE" if name == "job_delete" else method

        print(f"  {name:20} [{method:6}] {full_url}")

    print("\n" + "="*80 + "\n")


def generate_test_data():
    """Generate sample test data for job creation."""
    test_job = {
        "title": "Senior Python Developer - TEST",
        "description": "Test job posting for QA validation. This is a comprehensive test of the ATS job creation functionality.",
        "requirements": "• 5+ years Python experience\n• Django framework expertise\n• PostgreSQL database skills\n• REST API development\n• Git version control",
        "responsibilities": "• Design and develop backend services\n• Write clean, maintainable code\n• Collaborate with frontend team\n• Review pull requests\n• Mentor junior developers",
        "location": "Remote",
        "job_type": "full_time",
        "experience_level": "senior",
        "remote_type": "fully_remote",
        "salary_min": 80000,
        "salary_max": 120000,
        "salary_currency": "USD",
        "benefits": "• Health insurance\n• 401(k) matching\n• Unlimited PTO\n• Remote work\n• Professional development budget",
    }

    print("\n" + "="*80)
    print("Sample Test Data for Job Creation")
    print("="*80 + "\n")

    print("Copy and paste these values into the job creation form:\n")

    for field, value in test_job.items():
        print(f"{field.upper()}:")
        if isinstance(value, str) and '\n' in value:
            print(value)
        else:
            print(f"  {value}")
        print()

    print("="*80 + "\n")

    # Save to JSON
    with open("test_job_data.json", 'w', encoding='utf-8') as f:
        json.dump(test_job, f, indent=2)

    print("✅ Test data saved to: test_job_data.json\n")


def validate_job_uuid(uuid: str) -> bool:
    """Validate UUID format."""
    import re
    uuid_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(uuid_pattern.match(uuid))


def create_test_checklist():
    """Generate a test checklist in markdown."""
    checklist = """# ATS Jobs Module - Test Checklist

**Tester:** _______________
**Date:** _______________
**Environment:** https://demo-company.zumodra.rhematek-solutions.com

## Pre-Test Setup

- [ ] Browser DevTools open (F12)
- [ ] Screenshot tool ready
- [ ] Test credentials verified
- [ ] Logged into demo tenant

---

## Test Scenarios

### 1. Authentication
- [ ] Login page loads
- [ ] Can log in with test credentials
- [ ] Redirect to dashboard successful
- [ ] Screenshot: `01_login_page.png`
- [ ] Screenshot: `02_dashboard_after_login.png`

### 2. Job List Page (`/app/ats/jobs/`)
- [ ] Page loads without errors
- [ ] Jobs display correctly
- [ ] Filters work (status, category, job_type)
- [ ] Search functionality works
- [ ] Stats dashboard shows correct counts
- [ ] Pagination works (if applicable)
- [ ] "Create Job" button visible
- [ ] Screenshot: `03_job_list_page.png`
- [ ] Screenshot: `04_job_list_filtered.png`

### 3. Job Creation (`/app/ats/jobs/create/`)
- [ ] Form loads correctly
- [ ] All fields visible
- [ ] Category dropdown populated
- [ ] Pipeline dropdown populated
- [ ] Form validation works
- [ ] Can submit form
- [ ] Success message displays
- [ ] Redirects to job detail
- [ ] Job UUID: ________________
- [ ] Screenshot: `05_job_create_form.png`
- [ ] Screenshot: `06_job_created_success.png`
- [ ] Screenshot: `07_new_job_detail.png`

### 4. Job Detail (`/app/ats/jobs/<uuid>/`)
- [ ] Page loads with job UUID
- [ ] All job details visible
- [ ] Status badge shows "Draft"
- [ ] Action buttons visible (Edit, Publish, Duplicate, Delete)
- [ ] Applications section visible
- [ ] Pipeline stages visible
- [ ] Stats show zeros for new job
- [ ] Screenshot: `08_job_detail_page.png`

### 5. Job Editing (`/app/ats/jobs/<uuid>/edit/`)
- [ ] Edit form loads
- [ ] Form pre-populated with existing data
- [ ] Can modify fields
- [ ] Changes save successfully
- [ ] Success message displays
- [ ] Redirects to job detail
- [ ] Updated values visible
- [ ] Screenshot: `09_job_edit_form.png`
- [ ] Screenshot: `10_job_edited_success.png`
- [ ] Screenshot: `11_job_detail_after_edit.png`

### 6. Job Publishing (`/app/ats/jobs/<uuid>/publish/`)
- [ ] Publish button visible on draft job
- [ ] Can click publish
- [ ] Status changes to "Open"
- [ ] Success message displays
- [ ] published_at timestamp set
- [ ] Screenshot: `12_job_before_publish.png`
- [ ] Screenshot: `13_job_after_publish.png`

### 7. Job Closing (`/app/ats/jobs/<uuid>/close/`)
- [ ] Close button visible on open job
- [ ] Can click close
- [ ] Status changes to "Closed"
- [ ] Success message displays
- [ ] closed_at timestamp set
- [ ] Screenshot: `14_job_before_close.png`
- [ ] Screenshot: `15_job_after_close.png`

### 8. Job Duplication (`/app/ats/jobs/<uuid>/duplicate/`)
- [ ] Duplicate button works
- [ ] Creates new job
- [ ] Title has " (Copy)" suffix
- [ ] New job status = "draft"
- [ ] All fields copied
- [ ] New UUID generated
- [ ] Applications NOT copied
- [ ] Redirects to new job detail
- [ ] New Job UUID: ________________
- [ ] Screenshot: `16_job_duplicate_action.png`
- [ ] Screenshot: `17_duplicated_job_detail.png`

### 9. Job Deletion (`/app/ats/jobs/<uuid>/delete/`)
- [ ] Delete button visible
- [ ] Confirmation required
- [ ] Soft delete performed
- [ ] Success message displays
- [ ] Redirects to job list
- [ ] Job not in active listings
- [ ] Screenshot: `18_job_delete_confirmation.png`
- [ ] Screenshot: `19_job_list_after_delete.png`

---

## Additional Checks

### HTMX Functionality
- [ ] Job list filters update without page reload
- [ ] Network tab shows HX-Request header
- [ ] Partial HTML responses (not full page)
- [ ] URL updates without full reload

### Error Handling
- [ ] Invalid UUID returns 404
- [ ] Missing required fields show validation errors
- [ ] Permission denied handled gracefully
- [ ] Network errors handled

### Browser Compatibility
- [ ] Chrome (latest)
- [ ] Firefox (latest)
- [ ] Edge (latest)
- [ ] Mobile responsive

### Security
- [ ] CSRF token present in forms
- [ ] XSS prevented (test with `<script>` in title)
- [ ] SQL injection prevented
- [ ] Tenant isolation enforced

### Performance
- [ ] Page load < 2 seconds
- [ ] API response < 500ms
- [ ] No memory leaks
- [ ] No unnecessary requests

---

## Issues Found

| # | Issue | URL | Severity | Screenshot |
|---|-------|-----|----------|-----------|
| 1 |       |     |          |            |
| 2 |       |     |          |            |
| 3 |       |     |          |            |

---

## Notes

_Add any additional observations here:_

---

## Sign-off

- [ ] All tests completed
- [ ] Screenshots saved
- [ ] Issues documented
- [ ] Test report generated

**Tester Signature:** _______________  **Date:** _______________

"""

    with open("TEST_CHECKLIST.md", 'w', encoding='utf-8') as f:
        f.write(checklist)

    print("✅ Test checklist generated: TEST_CHECKLIST.md\n")


def main():
    parser = argparse.ArgumentParser(
        description="ATS Jobs Module Testing Helper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_helper.py --check-urls
  python test_helper.py --check-urls a1b2c3d4-e5f6-7890-abcd-ef1234567890
  python test_helper.py --generate-test-data
  python test_helper.py --create-checklist
  python test_helper.py --all
        """
    )

    parser.add_argument(
        '--check-urls',
        nargs='?',
        const=True,
        metavar='JOB_UUID',
        help='Print all job-related URLs (optionally with job UUID)'
    )
    parser.add_argument(
        '--generate-test-data',
        action='store_true',
        help='Generate sample test data for job creation'
    )
    parser.add_argument(
        '--create-checklist',
        action='store_true',
        help='Generate test checklist markdown file'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all helper functions'
    )

    args = parser.parse_args()

    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        return

    # Run requested functions
    if args.all or args.check_urls:
        job_uuid = args.check_urls if isinstance(args.check_urls, str) else None
        check_urls(job_uuid)

    if args.all or args.generate_test_data:
        generate_test_data()

    if args.all or args.create_checklist:
        create_test_checklist()

    print("✅ Testing helper completed!\n")


if __name__ == "__main__":
    main()
