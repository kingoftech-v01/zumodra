# ATS Jobs Module Testing Guide

**Test Environment:** https://demo-company.zumodra.rhematek-solutions.com
**Date:** 2026-01-16
**Module:** ATS Jobs (Applicant Tracking System - Jobs/Positions)

## Overview

This guide provides comprehensive manual testing instructions for the ATS Jobs module. The module handles job posting creation, management, editing, duplication, and deletion.

---

## Pre-Test Setup

### 1. Test User Credentials

You will need credentials with one of these roles:
- **Recruiter** (view, create, edit jobs)
- **Hiring Manager** (view, create, edit jobs)
- **HR Manager** (view, create, edit, delete jobs)
- **Admin/PDG** (full access)

**Default Demo Credentials (if available):**
- Email: `admin@demo-company.com` or `recruiter@demo-company.com`
- Password: `testpass123` (or check with deployment team)

### 2. Browser Setup

- Use Chrome, Firefox, or Edge (latest version)
- Enable browser DevTools (F12) to monitor:
  - Network tab (check for 500 errors, 404s)
  - Console tab (check for JavaScript errors)
- Clear browser cache before starting

### 3. Screenshot Tool

- Windows: Snipping Tool (Win + Shift + S)
- Save all screenshots to: `test_results/ats_jobs/`

---

## URL Structure Analysis

Based on code review of `ats/urls_frontend.py` and `ats/template_views.py`:

### Core Job URLs (namespace: `frontend:ats:*`)

| URL Pattern | View Class | Purpose | HTTP Methods |
|-------------|------------|---------|--------------|
| `/app/jobs/jobs/` | `JobListView` | List all jobs | GET |
| `/app/jobs/jobs/create/` | `JobCreateView` | Create new job | GET, POST |
| `/app/jobs/jobs/<uuid>/` | `JobDetailView` | View job details | GET |
| `/app/jobs/jobs/<uuid>/edit/` | `JobEditView` | Edit existing job | GET, POST |
| `/app/jobs/jobs/<uuid>/publish/` | `JobPublishView` | Publish draft job | POST |
| `/app/jobs/jobs/<uuid>/close/` | `JobCloseView` | Close open job | POST |
| `/app/jobs/jobs/<uuid>/duplicate/` | `JobDuplicateView` | Duplicate job | POST |
| `/app/jobs/jobs/<uuid>/delete/` | `JobDeleteView` | Soft delete job | DELETE |

### Key Features from Code Analysis

**JobListView (Lines 117-207)**
- Supports HTMX partial rendering
- Filters: status, category, job_type, search query
- Pagination: 20 items per page
- Stats dashboard: open, closed, draft, on_hold counts
- Search fields: title, description, location

**JobDetailView (Lines 209-268)**
- Shows job details with applications
- Displays application stats by stage
- Recent applications list (last 10)
- Pipeline visualization

**JobCreateView (Lines 271-306)**
- Required fields: title, category, job_type, experience_level, location
- Optional: salary_min, salary_max, benefits, pipeline, recruiter, hiring_manager
- Default status: 'draft'
- Redirects to job detail on success

**JobEditView (Lines 1618-1668)**
- Updates: title, description, department, location, job_type, experience_level
- Updates salary if provided
- Requires 'edit' permission

**JobDuplicateView (Lines 1670-1699)**
- Creates copy with " (Copy)" suffix
- Sets status to 'draft'
- Copies all fields except applications

**JobDeleteView (Lines 1702-1724)**
- Soft delete (sets is_deleted=True, deleted_at=timestamp)
- Requires 'delete' permission
- Uses DELETE HTTP method
- Returns HX-Trigger: 'jobDeleted'

---

## Test Scenarios

### TEST 1: Authentication & Access

**URL:** https://demo-company.zumodra.rhematek-solutions.com/accounts/login/

**Steps:**
1. Navigate to login page
2. Take screenshot: `01_login_page.png`
3. Enter test credentials
4. Submit form
5. Verify successful redirect to dashboard
6. Take screenshot: `02_dashboard_after_login.png`

**Expected Result:**
- ✅ Login form displays correctly
- ✅ CSRF token present
- ✅ No console errors
- ✅ Redirect to dashboard after login

**Error Indicators:**
- ❌ 500 Internal Server Error
- ❌ CSRF token missing
- ❌ Invalid credentials message
- ❌ Redirect loop

---

### TEST 2: Job List Page

**URL:** https://demo-company.zumodra.rhematek-solutions.com/app/jobs/jobs/

**Steps:**
1. Navigate to job list URL
2. Take screenshot: `03_job_list_page.png`
3. Check page elements:
   - Job cards/table
   - Filter sidebar (status, category, job_type)
   - Search bar
   - "Create Job" button
   - Stats dashboard (open, closed, draft, on_hold counts)
4. Test search functionality
5. Test filters (each one individually)
6. Take screenshot after each filter: `04_job_list_filtered.png`

**Expected Result:**
- ✅ Jobs display in grid/list format
- ✅ Pagination works (if > 20 jobs)
- ✅ Filters update results without full page reload (HTMX)
- ✅ Search returns relevant results
- ✅ Stats counts accurate

**Error Indicators:**
- ❌ 404 Not Found
- ❌ Empty list with "No jobs found" when jobs exist
- ❌ Filter dropdowns empty
- ❌ JavaScript errors in console
- ❌ Broken pagination

**Code Reference:**
```python
# template_views.py:117-207
# Filters applied:
# - status (draft, open, closed, on_hold)
# - category (from JobCategory)
# - job_type (full_time, part_time, contract, etc.)
# - q (search in title, description, location)
```

---

### TEST 3: Job Creation

**URL:** https://demo-company.zumodra.rhematek-solutions.com/app/jobs/jobs/create/

**Steps:**
1. Click "Create Job" button or navigate directly
2. Take screenshot: `05_job_create_form.png`
3. Fill out form with test data:
   - **Title:** "Senior Python Developer - TEST"
   - **Category:** Select any available
   - **Job Type:** "Full-time"
   - **Experience Level:** "Senior"
   - **Location:** "Remote"
   - **Remote Type:** "Fully Remote"
   - **Description:** "Test job posting for QA validation"
   - **Requirements:** "Python, Django, PostgreSQL"
   - **Responsibilities:** "Develop and maintain applications"
   - **Salary Min:** 80000
   - **Salary Max:** 120000
   - **Currency:** USD
4. Submit form
5. Take screenshot of success message: `06_job_created_success.png`
6. Verify redirect to job detail page
7. Take screenshot: `07_new_job_detail.png`
8. **Record the Job UUID** from URL for subsequent tests

**Expected Result:**
- ✅ Form displays all fields
- ✅ Category dropdown populated
- ✅ Pipeline dropdown populated
- ✅ Form validation works (required fields)
- ✅ Success message after creation
- ✅ Redirect to job detail page
- ✅ Job status = 'draft'

**Error Indicators:**
- ❌ 500 error on form submission
- ❌ Form doesn't submit
- ❌ Validation errors on valid data
- ❌ No redirect after success
- ❌ Empty dropdown fields

**Code Reference:**
```python
# template_views.py:271-306
# Default status: 'draft'
# Success URL: reverse('ats:job-detail', kwargs={'pk': self.object.pk})
```

---

### TEST 4: Job Detail Page

**URL:** https://demo-company.zumodra.rhematek-solutions.com/app/jobs/jobs/`<uuid>`/

**Steps:**
1. Navigate to job detail page (from created job)
2. Take screenshot: `08_job_detail_page.png`
3. Verify displayed information:
   - Job title, description, requirements
   - Salary range
   - Status badge (should be "Draft")
   - Action buttons (Edit, Publish, Duplicate, Delete)
   - Applications section (empty for new job)
   - Pipeline stages (if pipeline assigned)
   - Application stats (all zeros for new job)
4. Check for recruiter/hiring manager info
5. Check for created_by timestamp

**Expected Result:**
- ✅ All job details display correctly
- ✅ Action buttons visible and enabled
- ✅ Pipeline visualization (if assigned)
- ✅ Application stats show zeros
- ✅ No JavaScript errors

**Error Indicators:**
- ❌ 404 Not Found
- ❌ Missing job details
- ❌ Action buttons not visible
- ❌ Template rendering errors
- ❌ Stats calculation errors

**Code Reference:**
```python
# template_views.py:209-268
# Shows: job details, applications by stage, recent applications
# Stats: total, new, in_review, interviewing, offer, hired, rejected
```

---

### TEST 5: Job Editing

**URL:** https://demo-company.zumodra.rhematek-solutions.com/app/jobs/jobs/`<uuid>`/edit/

**Steps:**
1. From job detail page, click "Edit" button
2. Take screenshot: `09_job_edit_form.png`
3. Verify form pre-populated with existing data
4. Modify fields:
   - **Title:** Change to "Senior Python Developer - EDITED"
   - **Location:** Change to "New York, NY"
   - **Salary Max:** Change to 130000
5. Submit form
6. Take screenshot: `10_job_edited_success.png`
7. Verify redirect to job detail
8. Confirm changes saved
9. Take screenshot: `11_job_detail_after_edit.png`

**Expected Result:**
- ✅ Form pre-populated correctly
- ✅ All fields editable
- ✅ Changes save successfully
- ✅ Success message displays
- ✅ Redirect to job detail
- ✅ Updated values visible

**Error Indicators:**
- ❌ Form fields empty
- ❌ Changes don't save
- ❌ 500 error on submission
- ❌ Validation errors on valid data
- ❌ No success feedback

**Code Reference:**
```python
# template_views.py:1618-1668
# Updates fields, redirects to job detail
# URL name: 'frontend:jobs:job_detail'
```

---

### TEST 6: Job Publishing

**URL:** https://demo-company.zumodra.rhematek-solutions.com/app/jobs/jobs/`<uuid>`/publish/

**Steps:**
1. From job detail page (draft status), click "Publish" button
2. Take screenshot before: `12_job_before_publish.png`
3. Click confirm (if modal appears)
4. Verify status change to "Open"
5. Take screenshot after: `13_job_after_publish.png`
6. Check published_at timestamp set

**Expected Result:**
- ✅ Status changes from "draft" to "open"
- ✅ Success message displays
- ✅ published_at timestamp set
- ✅ Status badge updates
- ✅ Job now visible in public listings (if applicable)

**Error Indicators:**
- ❌ Status doesn't change
- ❌ Error message
- ❌ Can't publish already published job

**Code Reference:**
```python
# template_views.py:1273-1298
# POST only, changes status to 'open', sets published_at
```

---

### TEST 7: Job Closing

**URL:** https://demo-company.zumodra.rhematek-solutions.com/app/jobs/jobs/`<uuid>`/close/

**Steps:**
1. From open job detail page, click "Close" button
2. Take screenshot before: `14_job_before_close.png`
3. Click confirm
4. Verify status change to "Closed"
5. Take screenshot after: `15_job_after_close.png`

**Expected Result:**
- ✅ Status changes to "closed"
- ✅ closed_at timestamp set
- ✅ Success message
- ✅ Job no longer in open listings

**Error Indicators:**
- ❌ Can't close draft jobs (expected behavior)
- ❌ Status doesn't change

**Code Reference:**
```python
# template_views.py:1301-1326
# POST only, requires status in ['open', 'on_hold']
```

---

### TEST 8: Job Duplication

**URL:** https://demo-company.zumodra.rhematek-solutions.com/app/jobs/jobs/`<uuid>`/duplicate/

**Steps:**
1. From job detail page, click "Duplicate" button
2. Take screenshot: `16_job_duplicate_action.png`
3. Verify redirect to new job detail page
4. Check duplicated job:
   - Title has " (Copy)" suffix
   - Status = "draft"
   - All other fields copied
   - New UUID generated
   - Applications NOT copied
5. Take screenshot: `17_duplicated_job_detail.png`

**Expected Result:**
- ✅ New job created
- ✅ Title includes " (Copy)"
- ✅ Status = "draft"
- ✅ All fields copied except ID/UUID
- ✅ No applications on duplicate
- ✅ Redirect to new job detail

**Error Indicators:**
- ❌ 500 error
- ❌ Original job modified
- ❌ Fields not copied correctly
- ❌ Applications copied (shouldn't happen)

**Code Reference:**
```python
# template_views.py:1670-1699
# Creates new JobPosting with " (Copy)" suffix
# Status always 'draft', created_by = current user
```

---

### TEST 9: Job Deletion

**URL:** https://demo-company.zumodra.rhematek-solutions.com/app/jobs/jobs/`<uuid>`/delete/

**Steps:**
1. From job detail page, click "Delete" button
2. Take screenshot: `18_job_delete_confirmation.png`
3. Confirm deletion (modal or form)
4. Verify soft delete:
   - Job marked as deleted
   - Redirect to job list
   - Job not visible in list
5. Take screenshot: `19_job_list_after_delete.png`
6. Check database (if accessible) for is_deleted=True flag

**Expected Result:**
- ✅ Confirmation required before delete
- ✅ Soft delete (not permanently removed)
- ✅ Success message
- ✅ Redirect to job list
- ✅ Job not in active listings
- ✅ is_deleted=True, deleted_at timestamp set

**Error Indicators:**
- ❌ Hard delete (permanent removal)
- ❌ No confirmation
- ❌ Can't delete with applications (check if enforced)
- ❌ 403 Forbidden (permission issue)

**Code Reference:**
```python
# template_views.py:1702-1724
# Soft delete: sets is_deleted=True, deleted_at=timezone.now()
# Requires 'delete' permission (HR, Admin, PDG roles)
# Uses DELETE HTTP method
```

---

## Additional Tests

### TEST 10: Permissions

Test access with different user roles:

| Role | View | Create | Edit | Delete |
|------|------|--------|------|--------|
| Viewer | ✅ | ❌ | ❌ | ❌ |
| Recruiter | ✅ | ✅ | ✅ | ❌ |
| Hiring Manager | ✅ | ✅ | ✅ | ❌ |
| HR Manager | ✅ | ✅ | ✅ | ✅ |
| Admin/PDG | ✅ | ✅ | ✅ | ✅ |

**Code Reference:**
```python
# template_views.py:83-111 (ATSPermissionMixin)
# Permission checks by role
```

---

### TEST 11: HTMX Functionality

The job list uses HTMX for dynamic updates:

1. Open DevTools Network tab
2. Apply a filter on job list page
3. Verify:
   - Request has `HX-Request` header
   - Response returns partial HTML (not full page)
   - URL updates without full reload
   - No page flicker

**Code Reference:**
```python
# template_views.py:46-80 (HTMXMixin)
# Checks HX-Request header, returns partial template
```

---

### TEST 12: Error Handling

Test error scenarios:

1. **Invalid UUID:** Try accessing `/app/jobs/jobs/invalid-uuid/`
   - Expected: 404 page
   - Screenshot: `20_404_error.png`

2. **Missing Required Fields:** Submit job creation form without title
   - Expected: Validation error message
   - Screenshot: `21_validation_error.png`

3. **Permission Denied:** Try delete action with Recruiter role
   - Expected: 403 Forbidden or error message
   - Screenshot: `22_permission_denied.png`

4. **Network Error:** Disconnect internet, try form submission
   - Expected: Network error message
   - Screenshot: `23_network_error.png`

---

## Browser Compatibility

Test in multiple browsers:

- [ ] Chrome (latest)
- [ ] Firefox (latest)
- [ ] Edge (latest)
- [ ] Safari (if available)

**Focus on:**
- Form rendering
- HTMX interactions
- Modal dialogs
- Responsive design (mobile/tablet)

---

## Performance Checks

Monitor in DevTools:

1. **Page Load Time:** Should be < 2 seconds
2. **API Response Time:** Should be < 500ms
3. **Memory Usage:** Check for memory leaks
4. **Network Requests:** Check for unnecessary requests

---

## Security Checks

1. **CSRF Protection:** Verify CSRF token in all POST forms
2. **XSS Prevention:** Try injecting `<script>alert('XSS')</script>` in title field
3. **SQL Injection:** Try `' OR '1'='1` in search field
4. **Authorization:** Try accessing other tenant's job (different subdomain)

**Code Reference:**
```python
# All views use LoginRequiredMixin and TenantViewMixin
# @require_tenant_type('company') decorator enforces tenant type
# Input sanitized with bleach/nh3
```

---

## Known Issues from Code Review

### Potential Issues Found:

1. **JobDetailView (line 305):**
   - Success URL uses `'ats:job-detail'` but should be `'frontend:jobs:job_detail'`
   - This may cause 404 on redirect after job creation
   - **VERIFY:** Check if redirect works correctly

2. **JobEditView (line 1667):**
   - Uses `'frontend:jobs:job_detail'` (correct namespace)
   - **VERIFY:** Confirm this redirects properly

3. **Interview/Application References:**
   - Some code uses `job_posting` (lines 1345, 1396)
   - Some code uses `job` (lines 1803, 1824)
   - **VERIFY:** Check if relationships are consistent

4. **Soft Delete Implementation:**
   - is_deleted field set but no is_active filter on queryset
   - **VERIFY:** Deleted jobs should not appear in listings

---

## Test Data Requirements

For comprehensive testing, ensure test database has:

- [ ] At least 3 job categories
- [ ] At least 1 pipeline with stages
- [ ] At least 25 jobs (to test pagination)
- [ ] Jobs in each status (draft, open, closed, on_hold)
- [ ] Jobs with and without applications
- [ ] Jobs with salary ranges
- [ ] Jobs with different job types

---

## Reporting Issues

For each issue found, document:

1. **Issue Title:** Brief description
2. **URL:** Full URL where issue occurs
3. **Steps to Reproduce:** Detailed steps
4. **Expected Result:** What should happen
5. **Actual Result:** What actually happens
6. **Screenshot:** Visual evidence
7. **Browser:** Browser name and version
8. **Console Errors:** JavaScript/Network errors
9. **Severity:** Critical / High / Medium / Low
10. **Code Reference:** File and line number (if known)

---

## Test Completion Checklist

- [ ] All test scenarios executed
- [ ] Screenshots saved for each test
- [ ] Issues documented in test report
- [ ] Code comments added to relevant files
- [ ] Browser compatibility verified
- [ ] Performance metrics recorded
- [ ] Security checks completed
- [ ] Test report generated

---

## Next Steps

After completing manual testing:

1. Review all screenshots
2. Compile findings into `TEST_REPORT.md`
3. Add inline comments to code files documenting issues
4. Submit test report with recommendations

---

## Contact

For questions or clarifications:
- Review `ats/template_views.py` (lines 113-1724)
- Review `ats/urls_frontend.py` (lines 72-81)
- Check `ats/models.py` for JobPosting model definition

---

**Generated:** 2026-01-16
**Version:** 1.0
**Module:** ATS Jobs Testing Guide
