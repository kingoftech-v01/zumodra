# ATS Frontend Testing Suite

Complete testing suite for the Zumodra Jobs & Recruitment frontend on **zumodra.rhematek-solutions.com**.

## 📚 Documentation

| Document | Purpose | Audience |
|----------|---------|----------|
| **ATS_TEST_README.md** (this file) | Quick start and overview | Everyone |
| **ATS_TESTING_SUMMARY.md** | Comprehensive testing summary | Project managers, QA leads |
| **ATS_FRONTEND_TEST_GUIDE.md** | Detailed test scenarios and instructions | QA testers, developers |
| **ATS_TEST_QUICK_REFERENCE.md** | Checklist and quick reference | Testers during execution |
| **test_ats_frontend.py** | Automated test script | QA automation |

## 🚀 Quick Start (5 Minutes)

### Step 1: Install Requirements

```bash
pip install playwright pytest-playwright
playwright install chromium
```

### Step 2: Run Tests

```bash
python test_ats_frontend.py
```

### Step 3: View Results

```bash
# Open HTML report in browser
open ats_test_results/ats_test_report_*.html

# Or view in default browser (Windows)
start ats_test_results/ats_test_report_*.html

# Or view in default browser (Linux/Mac)
xdg-open ats_test_results/ats_test_report_*.html
```

### Step 4: Review Screenshots

All screenshots are saved in: `ats_test_results/screenshots/`

## 🎯 What Gets Tested

### Core ATS Views (8 scenarios)

1. ✅ **Job Listing** - View all jobs with search and filters
2. ✅ **Candidate List** - Browse talent pool
3. ✅ **Pipeline Board** - Kanban board with drag-and-drop
4. ✅ **Application Detail** - Full applicant information
5. ✅ **Interview List** - Manage interviews
6. ✅ **Job Creation** - Create new job postings
7. ✅ **Interview Scheduling** - Schedule candidate interviews
8. ✅ **Offer Management** - Create and track employment offers

### Additional Tests (10+ scenarios)

- Job detail view
- Candidate profile
- Job editing/duplication/deletion
- Interview rescheduling/cancellation
- Interview feedback
- Offer creation and actions

## 🔑 Test Server & Credentials

```
Server: https://demo-company.zumodra.rhematek-solutions.com
Email: company.owner@demo.zumodra.rhematek-solutions.com
Password: Demo@2024!
```

**Note:** Must be authenticated user with company tenant membership.

## 📊 Test Results

After running tests, you'll get:

### HTML Report
Beautiful visual report with:
- Test statistics
- Pass/fail status for each scenario
- Screenshots
- Error details
- Performance metrics

### JSON Report
Machine-readable results for:
- CI/CD integration
- Automated reporting
- Trend analysis

### Screenshots
Full-page screenshots of:
- Every tested page
- Login flow
- Error states
- UI elements

## 🎨 Example Results

```
ATS Frontend Test Results
==========================
Total Tests: 10
Passed: 9 ✓
Failed: 1 ✗
Success Rate: 90.0%

Critical Features:
✓ Job Listing - PASS
✓ Candidate List - PASS
✓ Pipeline Board - PASS
✓ Application Detail - PASS
✓ Interview List - PASS
✓ Job Creation - PASS
✓ Interview Scheduling - PASS
✓ Offer List - PASS
✗ Job Detail - FAIL (404 Not Found)
✓ Candidate Detail - PASS
```

## 🔍 What to Look For

### ✅ Success Indicators
- HTTP 200 status codes
- All UI elements visible
- Fast page loads (< 3 seconds)
- No JavaScript errors
- Smooth drag-and-drop
- Forms work correctly

### ❌ Failure Indicators
- 404 or 500 errors
- Missing UI elements
- JavaScript console errors
- Broken drag-and-drop
- Non-functional forms
- Redirect to login when authenticated

## 🐛 Critical Feature: Pipeline Drag-and-Drop

**THE MOST IMPORTANT FEATURE TO TEST**

The pipeline board must allow drag-and-drop of application cards between stages.

**Manual Test:**
1. Go to `/en-us/app/jobs/pipeline/`
2. Find an application card
3. Drag it to a different column
4. Verify it moves smoothly
5. Check that the change is saved

This is the core workflow for recruiters and MUST work perfectly.

## 📋 Test Priorities

### P0 - Critical (Must Pass)
- Pipeline board loads
- Drag-and-drop works
- Can view applications
- Can create jobs
- Authentication works

### P1 - High Priority
- Search functionality
- Filters work
- Forms submit
- Notes can be added
- Interviews can be scheduled

### P2 - Medium Priority
- Performance (load times)
- Layout consistency
- Optional features
- Minor UI issues

### P3 - Low Priority
- Cosmetic improvements
- Enhancement suggestions
- Documentation updates

## 🎓 Testing Workflow

### For Quick Testing (30 minutes)

1. Read: `ATS_TEST_QUICK_REFERENCE.md`
2. Run: `python test_ats_frontend.py`
3. Review: HTML report
4. Manually test: Pipeline drag-and-drop
5. Document: Critical issues

### For Comprehensive Testing (2-3 hours)

1. Read: `ATS_FRONTEND_TEST_GUIDE.md`
2. Run: Automated tests
3. Review: All screenshots
4. Test: Each scenario manually
5. Verify: HTMX functionality
6. Check: Console for errors
7. Test: Multiple browsers
8. Document: All findings
9. Create: Bug tickets
10. Write: Summary report

## 🛠️ Customization

### Running Specific Tests

Edit `test_ats_frontend.py` and comment out tests you don't need:

```python
def run_all_tests(self):
    # ... authentication ...

    # Test 1: Job Listing
    self.test_job_listing_view()

    # Test 2: Candidate List
    self.test_candidate_list_view()

    # Comment out tests you don't want to run
    # self.test_pipeline_board_view()
```

### Adjusting Timeouts

If tests timeout, increase timeout values:

```python
# In setup_browser method
self.context.set_default_timeout(60000)  # 60 seconds
```

### Headless vs Visible

To see browser while testing:

```python
# In setup_browser method
self.browser = playwright.chromium.launch(
    headless=False,  # Set to False to see browser
    slow_mo=50,
)
```

## 📊 Performance Benchmarks

| Page | Target | Max Acceptable |
|------|--------|----------------|
| Job List | < 2s | 3s |
| Candidate List | < 2s | 3s |
| Pipeline Board | < 3s | 5s |
| Application Detail | < 2s | 3s |
| Interview List | < 2s | 3s |

## 🔧 Troubleshooting

### "Playwright not found"
```bash
pip install playwright pytest-playwright
playwright install chromium
```

### "Authentication failed"
- Check credentials are correct
- Try logging in manually first
- Verify account is not locked

### "Tests timing out"
- Increase timeout values in script
- Check internet connection
- Test during off-peak hours

### "Screenshots not saving"
- Check directory permissions
- Ensure disk space available
- Use absolute paths

### "Drag-and-drop not testing"
This requires manual testing as automated testing of drag-and-drop is complex.

## 📞 Getting Help

### Documentation
- Start with `ATS_TEST_QUICK_REFERENCE.md` for quick help
- Read `ATS_FRONTEND_TEST_GUIDE.md` for detailed guidance
- Check `ATS_TESTING_SUMMARY.md` for complete overview

### Code
- Main script: `test_ats_frontend.py`
- ATS views: `ats/template_views.py`
- ATS URLs: `ats/urls_frontend.py`
- Templates: `templates/jobs/*.html`

## 🎯 Success Criteria

Tests are successful when:

✅ All 8 core scenarios pass (HTTP 200)
✅ No JavaScript console errors
✅ All expected UI elements visible
✅ Forms functional and validate correctly
✅ Drag-and-drop works smoothly
✅ Load times under 3 seconds
✅ Data persists after actions
✅ No broken links or navigation issues

## 📈 Continuous Testing

### CI/CD Integration

Add to your CI pipeline:

```yaml
# .github/workflows/ats-frontend-tests.yml
name: ATS Frontend Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - run: pip install playwright pytest-playwright
      - run: playwright install chromium
      - run: python test_ats_frontend.py
      - uses: actions/upload-artifact@v2
        with:
          name: test-results
          path: ats_test_results/
```

### Scheduled Testing

Run tests daily/weekly to catch regressions:

```bash
# Add to crontab (Linux/Mac)
0 9 * * * cd /path/to/zumodra && python test_ats_frontend.py

# Add to Task Scheduler (Windows)
schtasks /create /tn "ATS Tests" /tr "python C:\path\to\test_ats_frontend.py" /sc daily /st 09:00
```

## 📝 Reporting Issues

When reporting issues, include:

1. **Scenario name** (e.g., "Pipeline Board View")
2. **URL** (full URL tested)
3. **Expected behavior** (what should happen)
4. **Actual behavior** (what actually happened)
5. **Screenshot** (attach screenshot)
6. **Console errors** (any JavaScript errors)
7. **Steps to reproduce**
8. **Browser/OS** (which browser and version)
9. **Severity** (P0/P1/P2/P3)

## 🎉 You're Ready!

Everything you need is in this folder:

```
zumodra/
├── ATS_TEST_README.md          ← You are here
├── ATS_TESTING_SUMMARY.md      ← Complete overview
├── ATS_FRONTEND_TEST_GUIDE.md  ← Detailed scenarios
├── ATS_TEST_QUICK_REFERENCE.md ← Quick checklist
├── test_ats_frontend.py        ← Automation script
└── ats_test_results/           ← Results (after running)
    ├── screenshots/
    ├── ats_test_report_*.html
    └── ats_test_report_*.json
```

### Next Steps

1. **First-time testers:** Read `ATS_TEST_QUICK_REFERENCE.md`
2. **Run tests:** `python test_ats_frontend.py`
3. **Review results:** Open HTML report
4. **Manual testing:** Test drag-and-drop manually
5. **Document:** Note all issues
6. **Report:** Share results with team

---

**Ready to ensure a great recruiting experience? Start testing now!** 🚀

```bash
python test_ats_frontend.py
```

**Questions?** Check the comprehensive guide or quick reference card.

**Last Updated:** 2024-01-16
**Version:** 1.0.0
