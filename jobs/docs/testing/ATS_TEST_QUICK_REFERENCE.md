# ATS Frontend Testing - Quick Reference Card

## 🚀 Quick Start

```bash
# Install requirements
pip install playwright pytest-playwright
playwright install chromium

# Run tests
python test_ats_frontend.py

# View results
open ats_test_results/ats_test_report_*.html
```

## 🔑 Test Credentials

- **URL:** https://demo-company.zumodra.rhematek-solutions.com
- **Email:** company.owner@demo.zumodra.rhematek-solutions.com
- **Password:** Demo@2024!

## 📋 Test Scenarios Checklist

| # | Scenario | URL | Status |
|---|----------|-----|--------|
| 1 | Job Listing | `/en-us/app/jobs/jobs/` | ⬜ |
| 2 | Candidate List | `/en-us/app/jobs/candidates/` | ⬜ |
| 3 | Application Detail | `/en-us/app/jobs/applications/[id]/` | ⬜ |
| 4 | Interview List | `/en-us/app/jobs/interviews/` | ⬜ |
| 5 | Pipeline Board | `/en-us/app/jobs/pipeline/` | ⬜ |
| 6 | Job Creation | `/en-us/app/jobs/jobs/create/` | ⬜ |
| 7 | Interview Scheduling | `/en-us/app/jobs/interviews/schedule/` | ⬜ |
| 8 | Offer List | `/en-us/app/jobs/offers/` | ⬜ |

## ⚡ Critical Features to Test

### 1. Job List View ⭐⭐⭐⭐⭐
- [ ] Jobs display in grid/table
- [ ] Search by title works
- [ ] Filters work (status, category, type)
- [ ] Create button visible
- [ ] Click job opens detail page

### 2. Candidate List ⭐⭐⭐⭐⭐
- [ ] Candidates display with name, email
- [ ] Search works instantly
- [ ] Filters apply correctly
- [ ] Click candidate opens profile

### 3. Application Detail ⭐⭐⭐⭐⭐
- [ ] Applicant info visible
- [ ] Resume download works
- [ ] Can add notes
- [ ] Status change works
- [ ] Timeline shows activities

### 4. Pipeline Board (CRITICAL) ⭐⭐⭐⭐⭐
- [ ] All columns visible (Applied, Screening, Interview, Offer, Hired, Rejected)
- [ ] Application cards in columns
- [ ] **Drag-and-drop works** 🔥
- [ ] Job filter works
- [ ] Column counts accurate

### 5. Interview List ⭐⭐⭐⭐
- [ ] Interviews display
- [ ] Filter tabs work (Upcoming, Past)
- [ ] Interview details visible
- [ ] Can schedule new interview

### 6. Job Creation ⭐⭐⭐⭐
- [ ] Form displays all fields
- [ ] Validation works
- [ ] Can create job
- [ ] Redirects to job detail

### 7. Interview Scheduling ⭐⭐⭐⭐
- [ ] Date/time picker works
- [ ] Can select interviewers
- [ ] Can add location/link
- [ ] Form submits successfully

### 8. Offer Management ⭐⭐⭐
- [ ] Offers display
- [ ] Can create offer
- [ ] Offer actions work (send, accept, decline)

## 🎯 What to Look For

### ✅ Success Indicators
- HTTP 200 status codes
- No JavaScript console errors
- All UI elements visible
- Fast page loads (< 3 seconds)
- Smooth animations
- Clear navigation
- Proper error messages

### ❌ Failure Indicators
- 404 or 500 errors
- JavaScript errors in console
- Missing UI elements
- Slow page loads (> 5 seconds)
- Broken links
- Non-functional buttons
- Redirect to login when authenticated
- Empty or broken layouts

### ⚠️ Warning Signs
- Long load times (3-5 seconds)
- Missing optional features
- Inconsistent styling
- Poor mobile responsiveness
- Unclear error messages

## 🐛 Common Issues to Check

### Authentication
- [ ] Login successful
- [ ] Session persists
- [ ] No unexpected logouts

### Navigation
- [ ] All links work
- [ ] Breadcrumbs correct
- [ ] Back button works

### Forms
- [ ] Validation messages clear
- [ ] Required fields marked
- [ ] Submit buttons work
- [ ] Cancel returns correctly

### HTMX Features
- [ ] Filters apply without page reload
- [ ] Modals open/close properly
- [ ] Inline editing works
- [ ] Drag-and-drop smooth

### Data Display
- [ ] Tables render correctly
- [ ] Cards show all info
- [ ] Stats accurate
- [ ] Dates formatted properly

## 📊 Performance Benchmarks

| Page | Target Load Time | Max Acceptable |
|------|------------------|----------------|
| Job List | < 2s | 3s |
| Candidate List | < 2s | 3s |
| Pipeline Board | < 3s | 5s |
| Application Detail | < 2s | 3s |
| Interview List | < 2s | 3s |

## 🔍 Browser Console Checks

Open Developer Tools (F12) and check:

### Console Tab
Look for errors (red text):
```
❌ TypeError: Cannot read property...
❌ 404 Not Found
❌ 500 Internal Server Error
```

### Network Tab
Check for failed requests:
- Red status codes (4xx, 5xx)
- Long loading times
- Failed HTMX requests

### Performance Tab
Check for:
- Long script execution
- Layout shifts
- Memory leaks

## 📸 Screenshot Checklist

Take screenshots of:
- [ ] Login page
- [ ] Job listing (full page)
- [ ] Candidate listing (full page)
- [ ] Pipeline board (full width)
- [ ] Application detail (full page)
- [ ] Interview list
- [ ] Job creation form
- [ ] Interview scheduling modal
- [ ] Any errors encountered

## 🎨 UI/UX Checklist

### Layout
- [ ] Responsive design works
- [ ] No overlapping elements
- [ ] Proper spacing
- [ ] Aligned elements

### Typography
- [ ] Fonts load correctly
- [ ] Text readable
- [ ] Proper hierarchy
- [ ] No truncated text

### Colors
- [ ] Status badges colored correctly
  - Green = Success/Hired
  - Blue = In Progress
  - Yellow = Warning/Pending
  - Red = Error/Rejected
  - Gray = Draft/Inactive

### Icons
- [ ] Icons load
- [ ] Semantically correct
- [ ] Consistent style

## 🚨 Report These Immediately

### Critical Issues (P0)
- ❌ Pipeline drag-and-drop not working
- ❌ Cannot create jobs
- ❌ Cannot view applications
- ❌ Authentication broken
- ❌ Major layout broken
- ❌ Critical features missing

### High Priority (P1)
- ❌ Search not working
- ❌ Filters not working
- ❌ Cannot add notes
- ❌ Cannot schedule interviews
- ❌ Status changes don't save

### Medium Priority (P2)
- ⚠️ Slow page loads
- ⚠️ Minor layout issues
- ⚠️ Inconsistent styling
- ⚠️ Missing optional fields

### Low Priority (P3)
- ℹ️ Cosmetic issues
- ℹ️ Enhancement suggestions
- ℹ️ Documentation updates

## 📝 Quick Bug Report Template

```markdown
**Issue:** [Brief description]
**Severity:** P0/P1/P2/P3
**Page:** [URL]
**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected:** [What should happen]
**Actual:** [What actually happens]
**Screenshot:** [Attach screenshot]
**Console Errors:** [Any errors]
**Browser:** [Browser and version]
```

## 🎓 Testing Tips

1. **Clear Browser Cache** before testing
2. **Use Incognito Mode** for clean tests
3. **Test Multiple Browsers** (Chrome, Firefox, Safari)
4. **Check Mobile View** (responsive design)
5. **Document Everything** with screenshots
6. **Test Edge Cases** (empty lists, long text)
7. **Verify Data Persistence** (refresh page)
8. **Test Network Conditions** (slow connection)

## 🔄 After Testing

1. [ ] Review all screenshots
2. [ ] Check HTML report
3. [ ] Document all issues
4. [ ] Create tickets for bugs
5. [ ] Share report with team
6. [ ] Schedule retesting

## 📞 Need Help?

If tests fail or you're stuck:

1. Check `ATS_FRONTEND_TEST_GUIDE.md` for detailed instructions
2. Review screenshots in `./ats_test_results/screenshots/`
3. Check JSON report for error details
4. Look at browser console for errors
5. Try manual testing to confirm

## ✨ Success Criteria

Tests are successful when:

- ✅ All 8 core scenarios pass
- ✅ No critical bugs (P0/P1)
- ✅ Load times under 3 seconds
- ✅ No JavaScript errors
- ✅ Drag-and-drop works smoothly
- ✅ All forms functional
- ✅ Data displays correctly
- ✅ Navigation works properly

---

**Remember:** The goal is to ensure a smooth user experience for recruiters using the ATS system. Focus on critical workflows: viewing jobs, reviewing applications, moving candidates through pipeline, and scheduling interviews.

**Good luck testing! 🧪✨**
