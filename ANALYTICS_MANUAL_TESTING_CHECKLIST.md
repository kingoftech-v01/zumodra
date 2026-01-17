# Analytics and Reporting System - Manual Testing Checklist

**Test Date:** 2026-01-16
**Tester:** [Tester Name]
**Environment:** Development (Docker Compose)

---

## Pre-Test Setup

### Prerequisites
- [ ] Docker Compose running with all services
- [ ] Database migrations complete: `python manage.py migrate_schemas`
- [ ] Demo tenant created: `python manage.py bootstrap_demo_tenant`
- [ ] Sample data seeded: `python manage.py setup_demo_data --num-jobs 20 --num-candidates 100`
- [ ] Static files collected: `python manage.py collectstatic`

### Browser Setup
- [ ] Modern browser (Chrome, Firefox, Safari)
- [ ] JavaScript enabled
- [ ] Cookies/Session storage enabled
- [ ] Network tab ready for monitoring

### Test Account
- [ ] Admin/PDG account created
- [ ] HR Manager account created
- [ ] Recruiter account created
- [ ] Employee account created

---

## Section 1: Dashboard Quick Stats Generation

### Test 1.1: Dashboard Loads
**Purpose:** Verify dashboard page loads without errors
**Steps:**
1. Navigate to `http://localhost:8084/dashboard/`
2. Verify page loads within 3 seconds
3. Check browser console for JavaScript errors
4. Verify all widgets are visible

**Expected Result:**
- [ ] Page loads successfully
- [ ] No console errors
- [ ] Dashboard widgets display
- [ ] Quick stats section visible

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 1.2: Quick Stats Display Correct Values
**Purpose:** Verify quick stats show accurate data
**Steps:**
1. From dashboard, locate the "Quick Stats" section
2. Note displayed values:
   - Open Jobs: ___
   - Total Candidates: ___
   - Active Applications: ___
   - Pending Interviews: ___
3. Open another tab and verify from database/ATS directly
4. Compare values

**Expected Result:**
- [ ] All values match database
- [ ] No negative numbers
- [ ] All values are integers
- [ ] Values update without full page refresh (if AJAX)

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 1.3: Quick Stats Loading Performance
**Purpose:** Verify stats load quickly
**Steps:**
1. Open Network tab in DevTools
2. Navigate to dashboard
3. Monitor network requests for `/api/dashboard/` or similar
4. Note request time

**Expected Result:**
- [ ] Initial page load < 3 seconds
- [ ] API request < 1 second (from server)
- [ ] No failed requests
- [ ] Caching headers present

**Actual Result:** _______________
Request Time: ___ ms

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 1.4: Quick Stats Refresh
**Purpose:** Verify stats can be refreshed/updated
**Steps:**
1. On dashboard, look for "Refresh" button (if present)
2. Click refresh
3. Verify stats update
4. Check Network tab for new request

**Expected Result:**
- [ ] Refresh button works
- [ ] Stats update with new values
- [ ] No errors on refresh
- [ ] User sees loading indication

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Section 2: ATS Pipeline Analytics

### Test 2.1: Funnel Chart Displays
**Purpose:** Verify hiring funnel chart renders correctly
**Steps:**
1. Navigate to ATS Analytics or main dashboard
2. Locate "Hiring Funnel" section
3. Verify chart displays all stages:
   - Applied
   - Reviewed
   - Interviewed
   - Offered
   - Hired
4. Verify numbers decrease progressively

**Expected Result:**
- [ ] Chart renders without errors
- [ ] All stages visible
- [ ] Numbers decrease (or increase proportionally)
- [ ] Chart interactive (hover shows tooltips)

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 2.2: Conversion Rates Calculate Correctly
**Purpose:** Verify conversion rates between pipeline stages
**Steps:**
1. In funnel chart, note numbers at each stage
2. Calculate conversion rates:
   - Reviewed/Applied = ____%
   - Interviewed/Reviewed = ____%
   - Offered/Interviewed = ____%
   - Hired/Offered = ____%
3. Verify calculations are correct

**Expected Result:**
- [ ] All conversion rates shown
- [ ] Rates are between 0-100%
- [ ] Rates decrease progressively
- [ ] Rates match manual calculation

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 2.3: Pipeline Breakdown by Source
**Purpose:** Verify pipeline metrics break down by job source
**Steps:**
1. Navigate to "Source Analytics" or similar
2. Look for pipeline breakdown by source:
   - LinkedIn
   - Indeed
   - Internal referral
   - etc.
3. Verify numbers for each source
4. Total should equal overall pipeline numbers

**Expected Result:**
- [ ] All sources listed
- [ ] Numbers for each source displayed
- [ ] Total matches overall funnel
- [ ] Top source highlighted

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 2.4: Time-to-Hire Metrics
**Purpose:** Verify time-to-hire statistics display
**Steps:**
1. Navigate to "Time-to-Hire" analytics
2. Verify the following metrics display:
   - Average: __ days
   - Median: __ days
   - 75th Percentile: __ days
3. Verify metrics by source (if available)
4. Verify trend chart over time

**Expected Result:**
- [ ] All metrics display
- [ ] Numbers are reasonable (typically 20-90 days)
- [ ] Median <= Average
- [ ] 75th >= Median
- [ ] Trend chart shows history

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 2.5: Source Effectiveness (ROI)
**Purpose:** Verify source effectiveness metrics
**Steps:**
1. Navigate to "Source Analytics"
2. Verify metrics for each source:
   - Cost per hire
   - Time to hire
   - Quality score (if available)
   - ROI or effectiveness score
3. Identify best/worst performing sources

**Expected Result:**
- [ ] All sources ranked by effectiveness
- [ ] Cost per hire calculated
- [ ] Time to hire shown per source
- [ ] Best source highlighted

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Section 3: HR Metrics (Headcount, Turnover)

### Test 3.1: Headcount Metrics Display
**Purpose:** Verify headcount statistics display
**Steps:**
1. Navigate to HR Analytics or HR Dashboard
2. Verify headcount metrics:
   - Total employees: ___
   - By department: [list departments and counts]
   - By status: Active/Inactive/On Leave
3. Verify total matches sum of departments

**Expected Result:**
- [ ] Total headcount displayed
- [ ] Department breakdown shown
- [ ] Status breakdown shown
- [ ] Totals match

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 3.2: Turnover Rate Calculation
**Purpose:** Verify turnover rate calculations
**Steps:**
1. In HR Dashboard, locate "Turnover" section
2. Verify metrics:
   - Annual turnover rate: ___%
   - Voluntary: ___%
   - Involuntary: ___%
   - By department (if available)
3. Manual calculation: (Separations / Avg Headcount) * 100

**Expected Result:**
- [ ] Turnover rates calculated
- [ ] Rates between 0-100%
- [ ] Voluntary + Involuntary = Total
- [ ] Department breakdown accurate

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 3.3: New Hires Metric
**Purpose:** Verify new hires tracked over time
**Steps:**
1. In HR Dashboard, find "New Hires" section
2. Verify new hires shown for:
   - This month: ___
   - Last 30 days: ___
   - Last 90 days: ___
   - This year: ___
3. Verify trend chart showing hiring rate

**Expected Result:**
- [ ] New hires tracked by period
- [ ] Numbers displayed
- [ ] Trend chart shows hiring rate
- [ ] Recent hires highlighted

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 3.4: Separations Tracking
**Purpose:** Verify employee separations tracked
**Steps:**
1. In HR Dashboard, find "Separations" section
2. Verify separations shown:
   - Voluntary (resignations): ___
   - Involuntary (terminations): ___
   - Retirement: ___
3. Verify breakdown by department
4. Verify trend over months

**Expected Result:**
- [ ] All separation types tracked
- [ ] Department breakdown shown
- [ ] Trend chart displayed
- [ ] Monthly trends visible

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 3.5: Retention Rate
**Purpose:** Verify retention rate calculations
**Steps:**
1. Find "Retention" section in HR Dashboard
2. Verify retention rates:
   - Overall retention: ___%
   - 1-year retention: ___%
   - 3-year retention: ___%
3. Verify department breakdown

**Expected Result:**
- [ ] Retention rates calculated
- [ ] Rates between 0-100%
- [ ] 3-year <= 1-year <= Overall
- [ ] Department comparison available

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Section 4: Financial Reports

### Test 4.1: Cost Analysis Report
**Purpose:** Verify cost analysis data
**Steps:**
1. Navigate to Reports section
2. Generate or view "Cost Analysis" report
3. Verify metrics:
   - Total cost per hire: $___
   - Cost by source: [list sources and costs]
   - Cost by department: [list departments]
4. Verify calculations

**Expected Result:**
- [ ] Report generates without error
- [ ] All costs displayed
- [ ] Calculations accurate
- [ ] Highest cost source identified

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 4.2: Financial Report Export
**Purpose:** Verify financial reports can be exported
**Steps:**
1. In Reports section, find export option
2. Select "Financial Report"
3. Choose format: PDF
4. Click export
5. Verify file downloads

**Expected Result:**
- [ ] Export starts without error
- [ ] File downloads successfully
- [ ] File size reasonable (> 50KB for PDF)
- [ ] File can be opened in PDF viewer

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Section 5: Export Functionality

### Test 5.1: CSV Export - Recruitment Data
**Purpose:** Verify CSV export works
**Steps:**
1. Navigate to Analytics Dashboard
2. Select data or report to export
3. Choose format: CSV
4. Click Export
5. Verify file downloads
6. Open file in spreadsheet application

**Expected Result:**
- [ ] Export completes without error
- [ ] CSV file downloads
- [ ] File opens in Excel/Sheets
- [ ] Data properly formatted (commas, quotes)
- [ ] Headers present
- [ ] All data rows included

**Actual Result:** _______________
File Size: ___ KB
Rows: ___

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 5.2: Excel Export - Full Dashboard
**Purpose:** Verify Excel export includes all data
**Steps:**
1. From Dashboard, select "Export Dashboard"
2. Choose format: Excel
3. Click Export
4. Verify file downloads
5. Open in Excel
6. Verify multiple sheets

**Expected Result:**
- [ ] Excel file downloads
- [ ] File opens in Excel
- [ ] Multiple sheets present (metrics, details, etc.)
- [ ] Charts/images included (if applicable)
- [ ] Formatting preserved
- [ ] File size reasonable

**Actual Result:** _______________
Sheets: ___
File Size: ___ MB

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 5.3: PDF Export - With Charts
**Purpose:** Verify PDF export includes visualizations
**Steps:**
1. From Analytics Dashboard, select "Export as PDF"
2. Verify options for "Include Charts"
3. Check "Include Charts"
4. Click Export
5. Verify file downloads and opens

**Expected Result:**
- [ ] PDF file downloads
- [ ] File opens in PDF viewer
- [ ] Charts rendered as images
- [ ] All metrics visible
- [ ] Text readable
- [ ] Multi-page (if large report)

**Actual Result:** _______________
Pages: ___
File Size: ___ MB

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 5.4: Export with Date Range Filter
**Purpose:** Verify exports respect date filters
**Steps:**
1. Apply date filter (e.g., last 30 days)
2. Initiate export (CSV or Excel)
3. Verify export file only contains data for selected range
4. Check first and last dates in export

**Expected Result:**
- [ ] Export respects date range
- [ ] First date matches start date
- [ ] Last date matches end date
- [ ] No data outside range
- [ ] Date range shown in export header

**Actual Result:** _______________
Start Date: ___
End Date: ___

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 5.5: Export File Naming
**Purpose:** Verify exported files have proper names
**Steps:**
1. Export in CSV format
2. Note filename: _____
3. Export in Excel format
4. Note filename: _____
5. Export in PDF format
6. Note filename: _____

**Expected Result:**
- [ ] Filenames include report type
- [ ] Filenames include timestamp/date
- [ ] Filenames are descriptive
- [ ] No special characters causing issues

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Section 6: Date Range Filtering

### Test 6.1: Preset Period - Last 7 Days
**Purpose:** Verify last 7 days filter works
**Steps:**
1. On Dashboard, find date filter
2. Select "Last 7 Days" or "Week"
3. Note date range displayed: ___ to ___
4. Verify stats update
5. Verify charts show data for 7-day range

**Expected Result:**
- [ ] Filter applied successfully
- [ ] Date range shows correctly
- [ ] Data updates to last 7 days
- [ ] No data outside range
- [ ] Charts show weekly data

**Actual Result:** _______________
Range: ___ to ___

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 6.2: Preset Period - Last 30 Days
**Purpose:** Verify last 30 days filter works
**Steps:**
1. Select "Last 30 Days" or "Month"
2. Note date range: ___ to ___
3. Verify stats update
4. Compare to manual calculation

**Expected Result:**
- [ ] Filter applied
- [ ] 30-day range shown
- [ ] Data updates
- [ ] All metrics recalculated
- [ ] Charts show monthly trends

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 6.3: Preset Period - Last 90 Days (Quarter)
**Purpose:** Verify quarterly filter works
**Steps:**
1. Select "Last 90 Days" or "Quarter"
2. Note date range
3. Verify quarter-level aggregation

**Expected Result:**
- [ ] Filter applied
- [ ] 90-day range shown
- [ ] Quarterly trends visible
- [ ] Data aggregated appropriately

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 6.4: Preset Period - Last Year
**Purpose:** Verify year filter works
**Steps:**
1. Select "Last Year" or "Year"
2. Verify 365-day range
3. Check yearly trends

**Expected Result:**
- [ ] Filter applied
- [ ] 12-month range shown
- [ ] Yearly totals displayed
- [ ] Annual trends visible

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 6.5: Custom Date Range
**Purpose:** Verify custom date range selection
**Steps:**
1. Find "Custom Date Range" option
2. Select start date: ___ (pick a date)
3. Select end date: ___ (pick a later date)
4. Apply filter
5. Verify data updates

**Expected Result:**
- [ ] Date pickers work
- [ ] Custom range applied
- [ ] Data shows only selected range
- [ ] Filters can be adjusted
- [ ] Export respects custom range

**Actual Result:** _______________
Custom Range: ___ to ___

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 6.6: Date Filter Persistence
**Purpose:** Verify date filter persists during navigation
**Steps:**
1. Apply custom date filter
2. Navigate to different analytics section
3. Return to original section
4. Verify filter is still applied

**Expected Result:**
- [ ] Filter persists during navigation
- [ ] Same date range shown
- [ ] Data consistent
- [ ] Filter can be cleared if needed

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Section 7: Chart Rendering

### Test 7.1: Funnel Chart Renders Correctly
**Purpose:** Verify funnel visualization displays
**Steps:**
1. Navigate to Hiring Funnel section
2. Verify chart displays as funnel shape
3. Verify all stages labeled
4. Verify numbers shown at each stage
5. Verify colors are distinct

**Expected Result:**
- [ ] Funnel shape rendered
- [ ] All stages visible
- [ ] Numbers displayed
- [ ] Stage labels clear
- [ ] Colors distinguishable

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 7.2: Trend Line Chart Renders
**Purpose:** Verify trend charts display time series data
**Steps:**
1. Navigate to Trends section
2. Look for line chart showing:
   - Applications over time
   - Hires over time
   - Turnover over time
3. Verify X-axis shows dates
4. Verify Y-axis shows quantities
5. Verify line connected between points

**Expected Result:**
- [ ] Line chart renders
- [ ] Axes labeled correctly
- [ ] Data points connected
- [ ] Legend shown
- [ ] Grid lines visible

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 7.3: Bar Chart Renders
**Purpose:** Verify bar charts display categorical data
**Steps:**
1. Find bar chart (e.g., hires by source)
2. Verify bars for each category
3. Verify heights proportional to values
4. Verify category labels on X-axis
5. Verify values on Y-axis

**Expected Result:**
- [ ] Bar chart renders
- [ ] All categories shown
- [ ] Bar heights proportional
- [ ] Axes labeled
- [ ] Legend available

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 7.4: Pie Chart Renders (if applicable)
**Purpose:** Verify pie charts display proportions
**Steps:**
1. Find pie chart (e.g., source breakdown)
2. Verify all slices shown
3. Verify slices proportional to percentages
4. Verify legend with labels
5. Verify percentages add to 100%

**Expected Result:**
- [ ] Pie chart renders
- [ ] All slices visible
- [ ] Proportions correct
- [ ] Legend clear
- [ ] Percentages total 100%

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 7.5: Chart Interactivity
**Purpose:** Verify charts are interactive
**Steps:**
1. Hover over chart data point
2. Verify tooltip shows value
3. Click on legend items (if applicable)
4. Verify chart updates based on selection
5. Verify zoom/pan if available

**Expected Result:**
- [ ] Tooltips work on hover
- [ ] Legend clickable (toggles data)
- [ ] Zoom works (if available)
- [ ] Pan works (if available)
- [ ] No console errors on interaction

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 7.6: Chart Responsiveness
**Purpose:** Verify charts adjust to window size
**Steps:**
1. View chart at full screen
2. Resize browser window to smaller size
3. Verify chart adjusts
4. Resize to mobile width
5. Verify chart still readable

**Expected Result:**
- [ ] Chart resizes with window
- [ ] Text remains readable
- [ ] Data points still visible
- [ ] No horizontal scroll required (mobile)
- [ ] Touch-friendly on mobile

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Section 8: Performance and Stability

### Test 8.1: Dashboard Load Time
**Purpose:** Verify dashboard loads in reasonable time
**Steps:**
1. Clear browser cache
2. Navigate to dashboard
3. Measure load time (Network tab)
4. Repeat 3 times

**Expected Result:**
- [ ] Initial load < 5 seconds
- [ ] Average load time acceptable
- [ ] No timeout errors
- [ ] All resources load

**Actual Result:** _______________
Load Times: ___ , ___ , ___ms

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 8.2: Large Dataset Handling
**Purpose:** Verify system handles large data exports
**Steps:**
1. Apply wide date range (e.g., full year)
2. Attempt export to CSV/Excel
3. Monitor memory and network
4. Verify export completes

**Expected Result:**
- [ ] Export handles large data
- [ ] No timeout errors
- [ ] File downloads successfully
- [ ] No browser crashes

**Actual Result:** _______________
Data Rows: ___
Export Time: ___ seconds

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 8.3: Concurrent User Handling
**Purpose:** Verify system handles multiple concurrent users
**Steps:**
1. Open dashboard in 2+ browser windows
2. Apply filters in each window independently
3. Refresh data in each window
4. Verify no interference between windows

**Expected Result:**
- [ ] Each window shows independent data
- [ ] Filters don't affect other windows
- [ ] No data corruption
- [ ] System remains responsive

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Section 9: Security and Access Control

### Test 9.1: Authentication Required
**Purpose:** Verify anonymous users cannot access analytics
**Steps:**
1. Log out or use incognito browser
2. Try to access dashboard directly: `/dashboard/`
3. Verify redirect to login
4. Try to access API: `/api/v1/analytics/recruitment/`
5. Verify 401 Unauthorized response

**Expected Result:**
- [ ] Unauthenticated users redirected to login
- [ ] API returns 401 for unauthenticated requests
- [ ] Cannot bypass authentication

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 9.2: Role-Based Access Control
**Purpose:** Verify different roles see appropriate data
**Steps:**
1. Log in as Recruiter
2. Verify access to recruitment analytics
3. Verify limited access to HR analytics
4. Log in as HR Manager
5. Verify access to HR analytics
6. Verify limited access to recruitment analytics
7. Log in as Admin
8. Verify access to all analytics

**Expected Result:**
- [ ] Recruiter sees only recruitment data
- [ ] HR Manager sees only HR data
- [ ] Admin sees all data
- [ ] Proper 403 Forbidden on unauthorized access

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 9.3: Multi-Tenant Data Isolation
**Purpose:** Verify data is isolated between tenants
**Steps:**
1. Create two test tenants
2. Add data to each
3. Log in to Tenant A
4. Verify only Tenant A data visible
5. Log in to Tenant B
6. Verify only Tenant B data visible
7. Verify no data bleed

**Expected Result:**
- [ ] Each tenant sees only own data
- [ ] No data visible from other tenants
- [ ] Totals accurate for each tenant
- [ ] Exports contain only tenant data

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Section 10: Data Accuracy and Integrity

### Test 10.1: Metrics Match Source Data
**Purpose:** Verify analytics calculations are accurate
**Steps:**
1. From dashboard, note: "Open Jobs: X"
2. Navigate to Jobs listing
3. Count open jobs manually (or filter)
4. Verify count matches dashboard
5. Repeat for other key metrics

**Expected Result:**
- [ ] Dashboard metrics match actual data
- [ ] No calculation errors
- [ ] Data consistency across views

**Actual Result:** _______________
Dashboard: ___
Actual: ___

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

### Test 10.2: Historical Data Accuracy
**Purpose:** Verify historical data is calculated correctly
**Steps:**
1. Filter by past date range (e.g., Jan 1-31, 2024)
2. Note metrics shown
3. Manually verify some calculations
4. Check that data includes all relevant records

**Expected Result:**
- [ ] Historical data accurate
- [ ] All records included
- [ ] Calculations correct for period
- [ ] No data missing

**Actual Result:** _______________

**Status:** ☐ PASS ☐ FAIL ☐ SKIP

---

## Final Sign-Off

### Summary
- Total Tests: ___
- Passed: ___
- Failed: ___
- Skipped: ___

### Overall Status
- [ ] All Critical Tests PASSED
- [ ] All Major Tests PASSED
- [ ] Minor issues noted (acceptable)

### Tester Signature

**Tester Name:** ___________________

**Date:** ___________________

**Signature:** ___________________

### Issues Found

1. **Issue:** ___________________________________________
   **Severity:** ☐ Critical ☐ Major ☐ Minor
   **Status:** ☐ Open ☐ Fixed ☐ Accepted

2. **Issue:** ___________________________________________
   **Severity:** ☐ Critical ☐ Major ☐ Minor
   **Status:** ☐ Open ☐ Fixed ☐ Accepted

### Recommendations

- [ ] System is production ready
- [ ] Minor fixes needed before production
- [ ] Significant work required before production

**Comments:** ___________________________________________

---

**End of Manual Testing Checklist**
