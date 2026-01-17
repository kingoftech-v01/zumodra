# ATS Frontend Testing Guide

## Overview

This guide provides comprehensive instructions for testing the Applicant Tracking System (ATS) frontend views on the Zumodra production server: **zumodra.rhematek-solutions.com**

## Server Information

- **URL:** https://demo-company.zumodra.rhematek-solutions.com
- **Test Account:** company.owner@demo.zumodra.rhematek-solutions.com
- **Password:** Demo@2024!
- **Requirements:** Must be authenticated user with tenant membership (company tenant)

## Test Script

An automated test script is provided: `test_ats_frontend.py`

### Installation

```bash
# Install Playwright
pip install playwright pytest-playwright

# Install browser drivers
playwright install chromium
```

### Running Tests

```bash
python test_ats_frontend.py
```

### Results Location

- **Screenshots:** `./ats_test_results/screenshots/`
- **JSON Report:** `./ats_test_results/ats_test_report_*.json`
- **HTML Report:** `./ats_test_results/ats_test_report_*.html`

---

## Test Scenarios

### Test 1: Job Listing View

**URL:** `/en-us/app/ats/jobs/`

**Expected Elements:**
- ✅ Page title (h1 or .page-title)
- ✅ Job cards or table showing job listings
- ✅ Search functionality (input with search or filter)
- ✅ Filter dropdowns (status, category, job type, date)
- ✅ Sort options (by date, status, applicants)
- ✅ "Create Job" button
- ✅ Job cards display:
  - Job title
  - Status badge (Open, Closed, Draft, On Hold)
  - Applicant count
  - Date posted
  - Location
  - Job type

**Features to Test:**
1. Search by job title
2. Filter by status (Open, Closed, Draft, On Hold)
3. Filter by category
4. Filter by job type (Full-time, Part-time, Contract, Freelance)
5. Click on a job card to view details
6. Pagination (if more than 20 jobs)

**Expected Status:** ✓ PASS
**HTTP Status Code:** 200

**What to Report:**
- Screenshot of job listing page
- Are all jobs displaying correctly?
- Does search work?
- Do filters work?
- Is pagination working?
- Any broken links?

---

### Test 2: Candidate List View

**URL:** `/en-us/app/ats/candidates/`

**Expected Elements:**
- ✅ Page title
- ✅ Candidate cards or table
- ✅ Search box (search by name, email)
- ✅ Filter options (status, source, location, skills)
- ✅ Candidate cards display:
  - Name
  - Email
  - Phone (optional)
  - Status
  - Source (where they came from)
  - Application count
  - Profile picture or avatar

**Features to Test:**
1. Search by candidate name
2. Search by email
3. Filter by status
4. Filter by source (LinkedIn, Job Board, Referral, etc.)
5. Click on candidate to view profile
6. Pagination (25 per page)

**Expected Status:** ✓ PASS
**HTTP Status Code:** 200

**What to Report:**
- Screenshot of candidate list
- Are candidates displayed correctly?
- Does search work instantly?
- Do filters apply correctly?
- Can you click through to candidate details?

---

### Test 3: Application Detail View

**URL:** `/en-us/app/ats/applications/[uuid]/`

**Expected Elements:**
- ✅ Applicant information section
  - Candidate name
  - Email, phone
  - Current position/company
- ✅ Job information
  - Job title
  - Applied date
  - Current stage
- ✅ Resume/CV download link
- ✅ Cover letter section (if provided)
- ✅ Status change dropdown
- ✅ Notes section
  - Add note button
  - Existing notes with author and timestamp
- ✅ Activity timeline
  - Status changes
  - Notes added
  - Interviews scheduled
  - Stage movements
- ✅ Action buttons
  - Schedule Interview
  - Move to Stage
  - Reject Application
  - Send Email
  - Add Note

**Features to Test:**
1. Change application status
2. Add a note
3. Download resume (if available)
4. View cover letter
5. View activity timeline
6. Click "Schedule Interview" button

**Expected Status:** ✓ PASS
**HTTP Status Code:** 200

**What to Report:**
- Screenshot of application detail page
- Is all applicant information visible?
- Can you download the resume?
- Does the status change work?
- Can you add notes?
- Is the timeline showing all activities?

---

### Test 4: Interview List View

**URL:** `/en-us/app/ats/interviews/`

**Expected Elements:**
- ✅ Page title
- ✅ Interview cards or calendar view
- ✅ Filter tabs:
  - Upcoming
  - Today
  - Past
  - Completed
  - Cancelled
- ✅ Interview details:
  - Candidate name
  - Job title
  - Interview type (Phone, Video, In-person)
  - Date and time
  - Interviewer(s)
  - Status badge
- ✅ Action buttons:
  - View Details
  - Reschedule
  - Cancel
  - Add Feedback

**Features to Test:**
1. Switch between filter tabs (Upcoming, Past, etc.)
2. Click on interview to view details
3. Check if calendar view is available
4. Filter by date range

**Expected Status:** ✓ PASS
**HTTP Status Code:** 200

**What to Report:**
- Screenshot of interview list
- Are interviews organized properly?
- Do filters work?
- Can you see all interview details?
- Is calendar view available?

---

### Test 5: Pipeline Board View (Kanban)

**URL:** `/en-us/app/ats/pipeline/`

**Expected Elements:**
- ✅ Page title
- ✅ Kanban board columns:
  - Applied (New)
  - Screening
  - Interview
  - Offer
  - Hired
  - Rejected
- ✅ Application cards in each column with:
  - Candidate name
  - Job title
  - Application date
  - Priority indicator (optional)
- ✅ Drag-and-drop functionality
- ✅ Job filter dropdown
- ✅ Column counts (number of applications per stage)
- ✅ Bulk actions
- ✅ Quick actions on cards:
  - View details
  - Schedule interview
  - Send email

**Features to Test:**
1. View pipeline board layout
2. **Drag application card to different stage** (KEY FEATURE)
3. Filter by specific job
4. Click on application card to view details
5. Check column counts
6. Try bulk selection (if available)

**Expected Status:** ✓ PASS
**HTTP Status Code:** 200

**Critical Feature:** Drag-and-drop between columns

**What to Report:**
- Screenshot of pipeline board
- Are all columns visible?
- Are application cards displayed correctly?
- **Does drag-and-drop work?** (CRITICAL)
- Are column counts accurate?
- Does filtering by job work?
- Any JavaScript errors in console?

---

### Test 6: Job Creation Form

**URL:** `/en-us/app/ats/jobs/create/`

**Expected Elements:**
- ✅ Form title
- ✅ Form fields:
  - Job Title (required)
  - Category dropdown
  - Job Type (Full-time, Part-time, etc.)
  - Experience Level
  - Location
  - Remote Type (On-site, Remote, Hybrid)
  - Description (rich text or textarea)
  - Requirements (textarea)
  - Responsibilities (textarea)
  - Salary Min/Max
  - Salary Currency
  - Benefits (textarea)
  - Pipeline selection
  - Recruiter selection
  - Hiring Manager selection
- ✅ Submit button
- ✅ Cancel button
- ✅ Form validation

**Features to Test:**
1. Fill out form fields
2. Test form validation (submit empty form)
3. Select dropdowns
4. Submit form
5. Cancel form

**Expected Status:** ✓ PASS
**HTTP Status Code:** 200

**What to Report:**
- Screenshot of job creation form
- Are all form fields visible?
- Does validation work?
- Can you select from dropdowns?
- Does the form submit successfully?

---

### Test 7: Job Editing

**URL:** `/en-us/app/ats/jobs/[uuid]/edit/`

**Expected Elements:**
- ✅ Pre-filled form with existing job data
- ✅ All fields from creation form
- ✅ Save button
- ✅ Cancel button

**Features to Test:**
1. Verify all fields are pre-filled
2. Edit job title
3. Save changes
4. Verify changes are reflected

**What to Report:**
- Screenshot of job edit form
- Are fields pre-filled correctly?
- Can you save changes?

---

### Test 8: Job Duplication

**Action:** Click "Duplicate" button on job detail page

**Expected Behavior:**
- Creates a copy of the job with "(Copy)" appended to title
- Sets status to "Draft"
- Redirects to new job detail page

**What to Report:**
- Does duplication work?
- Is the new job created correctly?

---

### Test 9: Job Deletion

**Action:** Click "Delete" button on job detail page

**Expected Behavior:**
- Shows confirmation dialog
- On confirm, soft deletes the job
- Redirects to job list

**What to Report:**
- Does deletion require confirmation?
- Is job removed from list?

---

### Test 10: Interview Scheduling Form

**URL:** `/en-us/app/ats/interviews/schedule/` or via modal from application detail

**Expected Elements:**
- ✅ Application/Candidate selection (if not pre-selected)
- ✅ Interview type dropdown (Phone, Video, In-person, Panel)
- ✅ Date picker
- ✅ Start time
- ✅ End time
- ✅ Interviewer selection (multi-select)
- ✅ Location field (for in-person)
- ✅ Meeting link field (for video)
- ✅ Notes/Agenda textarea
- ✅ Schedule button

**Features to Test:**
1. Select interview type
2. Choose date and time
3. Select interviewer(s)
4. Add location or meeting link
5. Submit form

**Expected Status:** ✓ PASS

**What to Report:**
- Screenshot of scheduling form
- Can you select date/time?
- Can you select multiple interviewers?
- Does form submit successfully?

---

### Test 11: Interview Rescheduling

**URL:** `/en-us/app/ats/interviews/[uuid]/reschedule/`

**Expected Elements:**
- ✅ Current interview details displayed
- ✅ New date picker
- ✅ New time picker
- ✅ Reason for rescheduling (optional)
- ✅ Reschedule button

**Features to Test:**
1. View current interview details
2. Select new date/time
3. Submit reschedule

**What to Report:**
- Can you reschedule an interview?
- Are notifications sent? (check if mentioned)

---

### Test 12: Interview Cancellation

**Action:** Click "Cancel" button on interview detail page

**Expected Elements:**
- ✅ Confirmation dialog
- ✅ Cancellation reason field
- ✅ Confirm button

**What to Report:**
- Does cancellation require confirmation?
- Can you provide a reason?

---

### Test 13: Interview Feedback

**URL:** `/en-us/app/ats/interviews/[uuid]/feedback/`

**Expected Elements:**
- ✅ Rating system (1-5 stars or 1-10)
- ✅ Recommendation dropdown (Strong Yes, Yes, Maybe, No, Strong No)
- ✅ Strengths textarea
- ✅ Weaknesses textarea
- ✅ Notes textarea
- ✅ Submit button

**Features to Test:**
1. Select rating
2. Choose recommendation
3. Fill in feedback fields
4. Submit feedback

**What to Report:**
- Screenshot of feedback form
- Can you submit feedback?
- Is feedback recorded in application timeline?

---

### Test 14: Offer List View

**URL:** `/en-us/app/ats/offers/`

**Expected Elements:**
- ✅ Page title
- ✅ Offer cards or table
- ✅ Filter by status (Draft, Sent, Accepted, Declined, Withdrawn)
- ✅ Offer details:
  - Candidate name
  - Job title
  - Salary amount
  - Status
  - Created date
  - Expiration date

**What to Report:**
- Screenshot of offer list
- Are offers displayed correctly?
- Do filters work?

---

### Test 15: Offer Creation

**URL:** `/en-us/app/ats/offers/create/[application_uuid]/`

**Expected Elements:**
- ✅ Candidate and job information (read-only)
- ✅ Base salary input
- ✅ Salary currency dropdown
- ✅ Salary period (Annual, Monthly)
- ✅ Bonus field
- ✅ Equity field
- ✅ Benefits textarea
- ✅ Start date picker
- ✅ Expiration date picker
- ✅ Notes textarea
- ✅ "Send Immediately" checkbox
- ✅ Create/Save button

**Features to Test:**
1. Fill in offer details
2. Set salary and benefits
3. Choose dates
4. Create offer

**What to Report:**
- Screenshot of offer form
- Can you create an offer?
- Does "Send Immediately" work?

---

### Test 16: Offer Actions

**Actions available on offer detail page:**
- Send (for draft offers)
- Accept (simulate candidate acceptance)
- Decline (simulate candidate decline)
- Withdraw (company withdraws offer)

**What to Report:**
- Are all actions available?
- Do actions update offer status correctly?

---

### Test 17: Candidate Profile/Detail View

**URL:** `/en-us/app/ats/candidates/[uuid]/`

**Expected Elements:**
- ✅ Candidate information
  - Name, email, phone
  - Current title/company
  - Location
  - Skills
  - Source
- ✅ Resume/CV section
- ✅ Application history
  - Jobs applied to
  - Application status
  - Application date
- ✅ Activity timeline
  - All interactions
  - Notes
  - Status changes
- ✅ Upcoming interviews
- ✅ Action buttons:
  - Add to Job
  - Add Note
  - Edit Profile

**What to Report:**
- Screenshot of candidate profile
- Is all information displayed correctly?
- Can you view application history?
- Is timeline showing all activities?

---

### Test 18: Job Detail View

**URL:** `/en-us/app/ats/jobs/[uuid]/`

**Expected Elements:**
- ✅ Job information
  - Title
  - Status badge
  - Category
  - Location
  - Job type
  - Posted date
- ✅ Job description
- ✅ Requirements
- ✅ Responsibilities
- ✅ Salary range
- ✅ Benefits
- ✅ Assigned recruiter and hiring manager
- ✅ Application statistics
  - Total applications
  - New
  - In Review
  - Interviewing
  - Offer
  - Hired
  - Rejected
- ✅ Recent applications list
- ✅ Pipeline view (applications by stage)
- ✅ Action buttons:
  - Edit Job
  - Duplicate Job
  - Publish (if draft)
  - Close (if open)
  - Delete

**What to Report:**
- Screenshot of job detail page
- Is all job information visible?
- Are application statistics accurate?
- Can you see recent applications?
- Are action buttons working?

---

## Performance Testing

### Load Time Benchmarks

- **Expected Load Times:**
  - Job List: < 2 seconds
  - Candidate List: < 2 seconds
  - Pipeline Board: < 3 seconds (more complex)
  - Application Detail: < 2 seconds
  - Interview List: < 2 seconds

### What to Report:
- Pages loading slower than expected
- Any timeout errors
- Network errors in browser console

---

## JavaScript Functionality Testing

### HTMX Features to Test

1. **Dynamic Loading:**
   - Does pagination load without full page refresh?
   - Do filters apply instantly?
   - Does search show results dynamically?

2. **Modals:**
   - Does interview scheduling modal open?
   - Do confirmation dialogs appear?
   - Can you close modals properly?

3. **Inline Editing:**
   - Can you add notes without page refresh?
   - Does status change update immediately?

4. **Drag and Drop:**
   - Pipeline board drag-and-drop (CRITICAL)
   - Do cards move smoothly?
   - Does position update in database?

### What to Report:
- Any JavaScript errors in browser console
- HTMX requests failing (check Network tab)
- Features not working as expected
- Broken animations or transitions

---

## UI/UX Testing

### Visual Elements to Check

1. **Responsive Design:**
   - Does page layout work at different widths?
   - Are elements properly aligned?
   - Is text readable?

2. **Typography:**
   - Are fonts loading correctly?
   - Is text hierarchy clear?
   - Are sizes appropriate?

3. **Colors and Branding:**
   - Is color scheme consistent?
   - Are status badges using correct colors?
   - Is branding visible?

4. **Icons:**
   - Are icons loading?
   - Are they semantically correct?
   - Are they consistent?

5. **Forms:**
   - Are labels clear?
   - Is validation feedback visible?
   - Are required fields marked?

### What to Report:
- Layout issues
- Missing icons or images
- Inconsistent styling
- Accessibility issues
- Missing labels

---

## Error Handling Testing

### Scenarios to Test

1. **404 Errors:**
   - Access non-existent job ID
   - Access deleted candidate
   - Expected: Beautiful 404 page

2. **403 Errors:**
   - Try to access restricted page
   - Expected: Permission denied message

3. **Validation Errors:**
   - Submit empty form
   - Enter invalid data
   - Expected: Clear error messages

### What to Report:
- How errors are displayed
- Are error messages helpful?
- Can users recover from errors?

---

## Security Testing

### Items to Verify

1. **Authentication:**
   - Are you redirected to login when not authenticated?
   - Does session persist correctly?

2. **Authorization:**
   - Can you only see your tenant's data?
   - Are actions restricted by role?

3. **CSRF Protection:**
   - Are forms protected?
   - Are tokens present?

### What to Report:
- Any security concerns
- Unprotected endpoints
- Data leakage

---

## Reporting Format

For each test scenario, provide:

### Test Result Template

```markdown
## Test: [Scenario Name]

**Status:** ✅ PASS / ❌ FAIL / ⚠️ WARNING

**URL:** [Full URL tested]

**HTTP Status Code:** [200/404/500/etc.]

**Load Time:** [X.XX seconds]

**Screenshot:** [Path or embed]

**Findings:**
- ✅ [What worked correctly]
- ❌ [What failed]
- ⚠️ [Warnings or concerns]

**UI Elements:**
- ✅ [Elements found]
- ❌ [Elements missing]

**Console Errors:**
- [List any JavaScript errors]

**Performance:**
- [Any performance issues]

**Notes:**
- [Additional observations]
```

---

## Summary Report Template

After completing all tests, provide:

### Executive Summary

```markdown
# ATS Frontend Test Report

**Date:** [Date]
**Tester:** [Name]
**Server:** zumodra.rhematek-solutions.com
**Total Tests:** [X]
**Passed:** [X] ✅
**Failed:** [X] ❌
**Warnings:** [X] ⚠️

## Overall Assessment

[Brief summary of findings]

## Critical Issues

1. [Issue 1]
2. [Issue 2]

## High Priority Issues

1. [Issue 1]
2. [Issue 2]

## Medium Priority Issues

1. [Issue 1]
2. [Issue 2]

## Low Priority Issues / Enhancements

1. [Issue 1]
2. [Issue 2]

## Performance Summary

- Average Load Time: [X.XX seconds]
- Slowest Page: [Page name] ([X.XX seconds])
- JavaScript Errors: [X]

## Browser Compatibility

Tested on:
- Browser: [Chrome/Firefox/Safari]
- Version: [X.X.X]
- OS: [Windows/Mac/Linux]

## Recommendations

1. [Recommendation 1]
2. [Recommendation 2]

## Next Steps

1. [Action item 1]
2. [Action item 2]
```

---

## Quick Start Checklist

- [ ] Install Playwright: `pip install playwright pytest-playwright`
- [ ] Install browser: `playwright install chromium`
- [ ] Run test script: `python test_ats_frontend.py`
- [ ] Review HTML report in browser
- [ ] Check all screenshots
- [ ] Document findings using template above
- [ ] Create issue tickets for failures
- [ ] Retest after fixes

---

## Support

If you encounter issues running the test script:

1. Check Python version: `python --version` (should be 3.8+)
2. Check Playwright installation: `playwright --version`
3. Try running in non-headless mode (set `headless=False` in script)
4. Check network connectivity to zumodra.rhematek-solutions.com
5. Verify credentials are correct

---

## Additional Manual Tests

Some features require manual testing:

1. **Drag and Drop:**
   - Manually drag application cards between pipeline stages
   - Verify smooth animation
   - Check database update

2. **File Upload:**
   - Upload candidate resume
   - Verify file is stored
   - Check download works

3. **Email Functionality:**
   - Send email to candidate
   - Check if email is queued/sent

4. **Calendar Integration:**
   - Check if interviews appear in calendar
   - Verify ICS file generation

5. **Notification System:**
   - Check if notifications appear
   - Verify notification links work

---

**Happy Testing! 🧪**
