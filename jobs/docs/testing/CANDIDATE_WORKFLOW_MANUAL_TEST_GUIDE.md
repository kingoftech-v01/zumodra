# Candidate Management Workflow - Manual Testing Guide

**Purpose:** Step-by-step manual testing guide for the complete candidate management workflow in Zumodra ATS

**Environment:** Docker compose with PostgreSQL, Redis, RabbitMQ
**Access:** http://localhost:8084 (via nginx)

---

## Prerequisites

### Start Docker Environment

```bash
cd /c/Users/techn/OneDrive/Documents/zumodra
docker compose up -d

# Verify all services running
docker compose ps

# Check logs if issues
docker compose logs -f web
docker compose logs -f channels
```

### Access Application

- **Main URL:** http://localhost:8084
- **MailHog (Email):** http://localhost:8026
- **API Docs:** http://localhost:8084/api/docs/
- **Admin Panel:** http://localhost:8084/admin/

### Create Test Account (if needed)

```bash
docker compose exec web python manage.py create_user \
  --username testuser \
  --email test@example.com \
  --password testpass123 \
  --tenant test-company
```

---

## Test Area 1: Adding Candidates Manually

### Test 1.1: Basic Candidate Creation

**Steps:**
1. Log in with test account
2. Navigate to ATS → Candidates (or Candidates → New Candidate)
3. Click "Add New Candidate" button
4. Fill form with:
   - First Name: `John`
   - Last Name: `Doe`
   - Email: `john.doe@test-company.local`
   - Phone: `+1-555-0100`
   - Headline: `Senior Software Engineer`
   - Current Company: `Tech Corp`
   - Current Title: `Lead Developer`
   - Years Experience: `5`
   - Source: `Direct`
5. Click Save

**Expected Results:**
- Candidate created successfully
- Redirect to candidate detail page
- All fields populated correctly
- Confirmation message shown
- Candidate appears in candidate list

**Form Validations to Test:**
- [ ] Phone validation (try invalid phone)
- [ ] Email validation (try invalid email)
- [ ] LinkedIn URL validation (try non-LinkedIn URL)
- [ ] Required fields validation
- [ ] HTML stripping in text fields

---

### Test 1.2: Candidate with Skills and Languages

**Steps:**
1. From Candidates list, click "Add New Candidate"
2. Fill form with:
   - First Name: `Jane`
   - Last Name: `Smith`
   - Email: `jane.smith@test-company.local`
   - Phone: `+1-555-0101`
   - Source: `LinkedIn`
3. Scroll down to Skills section
4. Add skills: `Python`, `Django`, `PostgreSQL`, `REST API`
5. Add languages: `English`, `Spanish`, `French`
6. Click Save

**Expected Results:**
- Candidate created with all skills and languages
- Skills displayed as tags/pills
- Languages displayed properly
- Can edit/remove individual skills

**Skills Input Methods to Test:**
- [ ] Type skill and press Enter
- [ ] Type skill and press comma
- [ ] Type skill and press Tab
- [ ] Autocomplete suggestions (if available)

---

### Test 1.3: Resume Upload with Validation

**Steps:**
1. From Candidates list, click "Add New Candidate"
2. Fill basic fields:
   - First Name: `Alice`
   - Last Name: `Williams`
   - Email: `alice.williams@test-company.local`
3. Scroll to Documents section
4. Click "Upload Resume" or file picker
5. Upload valid file: `resume.pdf`
6. Click Save

**Expected Results:**
- Resume file uploaded successfully
- File appears in Documents section
- Can download/view resume
- File size displayed
- Upload date shown

**Test Invalid Files:**
- [ ] Try uploading `.exe` file → Should reject with error
- [ ] Try uploading `.jpg` image → Should reject with error
- [ ] Try uploading file > 10MB → Should reject with size error
- [ ] Upload valid formats: PDF, DOC, DOCX, RTF, TXT

**File Upload Validations:**
- [ ] Check allowed extensions: pdf, doc, docx, rtf, txt
- [ ] Check max file size: 10MB
- [ ] Check MIME type validation
- [ ] Check error messages are user-friendly

---

### Test 1.4: Candidate with Social Profiles

**Steps:**
1. From Candidates list, click "Add New Candidate"
2. Fill basic fields
3. Scroll to Social Profiles section
4. Fill:
   - LinkedIn: `https://linkedin.com/in/bobsmith`
   - GitHub: `https://github.com/bobsmith`
   - Twitter: `https://twitter.com/bobsmith`
   - Website: `https://bobsmith.dev`
5. Click Save

**Expected Results:**
- All social profile URLs saved correctly
- URLs displayed as clickable links
- Invalid URLs rejected with validation errors

**Social URL Validation:**
- [ ] LinkedIn URL must contain 'linkedin.com'
- [ ] GitHub URL must be valid URL format
- [ ] URLs are clickable from candidate detail page
- [ ] Empty fields allowed (optional)

---

### Test 1.5: Candidate with Salary Preferences

**Steps:**
1. Create new candidate
2. Fill basic fields
3. Scroll to Preferences section
4. Fill:
   - Desired Salary Min: `80000`
   - Desired Salary Max: `120000`
   - Notice Period (days): `30`
   - Work Authorization: `US Citizen`
   - Willing to Relocate: Check if relocatable
5. Click Save

**Expected Results:**
- Salary range saved correctly
- Notice period stored
- Work authorization information displayed
- Relocation preference tracked

**Validation Tests:**
- [ ] Min salary cannot be greater than max salary
- [ ] Salaries must be positive numbers
- [ ] Notice period must be positive integer
- [ ] All fields optional

---

## Test Area 2: Importing Candidates from Applications

### Test 2.1: Link Candidate to Job Application

**Prerequisites:**
- Create a job posting first (if not existing)
- Candidate exists or will be created during application

**Steps:**
1. Navigate to a Job Posting
2. Click "Applications" tab
3. Click "New Application"
4. Fill application form:
   - First Name: `David`
   - Last Name: `Lee`
   - Email: `david.lee@test-company.local`
   - Phone: `+1-555-0102`
   - Cover Letter: `I am very interested...`
5. If "Link to existing candidate" option exists:
   - Search for candidate
   - Select from dropdown
6. Click Submit

**Expected Results:**
- Application created successfully
- Candidate linked to application
- Application appears in job's application list
- Candidate profile accessible from application

---

### Test 2.2: Create Candidate from Application (Auto-Import)

**Steps:**
1. Navigate to Applications page
2. If application has no linked candidate, click "Import to Candidates"
3. Verify the import dialog:
   - Pre-filled fields from application
   - Option to modify before saving
4. Click "Import"

**Expected Results:**
- New candidate created from application data
- Candidate linked to application
- Application stage moved appropriately
- Confirmation message shown

---

### Test 2.3: Bulk Import Candidates from CSV

**Prepare CSV File:**
```csv
first_name,last_name,email,phone,current_title,years_experience,source
John,Smith,john.smith@test.com,+1-555-0103,Developer,5,IMPORTED
Jane,Johnson,jane.johnson@test.com,+1-555-0104,Manager,8,IMPORTED
Bob,Brown,bob.brown@test.com,+1-555-0105,Designer,3,IMPORTED
```

**Steps:**
1. Navigate to Candidates → Bulk Import (or similar menu)
2. Click "Select File" and choose prepared CSV
3. Check options:
   - [ ] Skip duplicates (if applicable)
   - [ ] Send confirmation emails (optional)
4. Click "Import"

**Expected Results:**
- Import progress shown
- All 3 candidates created successfully
- Import report displayed (success/failures)
- Candidates appear in candidate list
- Email confirmations sent (if enabled)

**Test Duplicate Handling:**
- [ ] Import same CSV twice with "Skip duplicates" → Should skip second set
- [ ] Import same CSV twice without "Skip duplicates" → Should create duplicates or show error
- [ ] Check for exact email match deduplication

---

### Test 2.4: Bulk Import Validation

**Test Invalid CSV Files:**

**File:** `invalid.csv` (missing required columns)
```
name,contact
John Doe,john@test.com
```
- Upload and verify error message about missing columns
- [ ] Clear error message shown
- [ ] Import fails gracefully

**File:** `invalid_format.txt` (wrong file type)
- Upload .txt file to CSV importer
- [ ] Verify rejection or conversion attempt
- [ ] Appropriate error message

**File:** `large.csv` (many records)
- Create CSV with 100+ records
- Upload and verify bulk processing
- [ ] Check for timeouts
- [ ] Verify all records imported
- [ ] Performance acceptable

---

## Test Area 3: Updating Candidate Profiles

### Test 3.1: Edit Basic Information

**Steps:**
1. Navigate to Candidates list
2. Click on a candidate (e.g., John Doe from Test 1.1)
3. Click "Edit" or inline edit buttons
4. Modify fields:
   - Change first name to "Jonathan"
   - Update phone number
   - Change current title
5. Click "Save"

**Expected Results:**
- Changes saved successfully
- Updated fields reflected immediately
- Last modified timestamp updated
- Can see change history (if available)

---

### Test 3.2: Update Skills and Education

**Steps:**
1. Open candidate detail page
2. Find Skills section
3. Add skill: `React`
4. Click Education tab/section
5. Add education entry:
   - School: `MIT`
   - Degree: `PhD`
   - Field: `Computer Science`
   - Start Year: `2010`
   - End Year: `2015`
6. Click Save

**Expected Results:**
- New skill added to existing list
- Education entry created and displayed
- Can edit/remove education entries
- All data persisted

---

### Test 3.3: Update Work Experience

**Steps:**
1. Open candidate detail page
2. Find Work Experience section
3. Click "Add Experience"
4. Fill form:
   - Company: `Tech Innovations Inc`
   - Position: `Senior Engineer`
   - Start Date: `01/01/2020`
   - End Date: `12/31/2023`
   - Description: (optional)
5. Click Save

**Expected Results:**
- Experience entry created
- Displayed in chronological order
- Can edit/delete entries
- Years calculated correctly

---

### Test 3.4: Update Cover Letter

**Steps:**
1. Open candidate detail page
2. Find Cover Letter section
3. Click "Edit" or open rich text editor
4. Add/modify cover letter text:
   ```
   Dear Hiring Manager,

   I am very interested in this position...
   ```
5. Click Save

**Expected Results:**
- Cover letter saved successfully
- Character count shown
- Formatting preserved (if rich text)
- Updated timestamp shown

---

### Test 3.5: Update Social Profiles

**Steps:**
1. Open candidate detail page
2. Find Social Profiles section
3. Update URLs:
   - LinkedIn: `https://linkedin.com/in/newprofile`
   - GitHub: Add new URL
   - Remove Twitter if present
4. Click Save

**Expected Results:**
- URLs updated correctly
- Invalid URLs rejected
- URLs are clickable
- Empty fields allowed

---

## Test Area 4: Managing Candidate Documents/CVs

### Test 4.1: Upload Multiple Resumes (Versions)

**Steps:**
1. Open candidate detail page
2. Find Documents section
3. Upload resume v1 (resume_draft.pdf)
4. Verify uploaded
5. Replace with resume v2 (resume_final.pdf)
6. Verify both actions

**Expected Results:**
- New resume replaces old one (or versions tracked)
- Upload date/time shown
- Can download current resume
- File size displayed
- Delete option available

---

### Test 4.2: Upload Different File Formats

**Steps:**
1. Open candidate detail page
2. For each format, upload resume:
   - `resume.pdf` → Upload → Verify
   - `resume.docx` → Upload → Replace → Verify
   - `resume.txt` → Upload → Replace → Verify
   - `resume.rtf` → Upload → Replace → Verify

**Expected Results:**
- All formats accepted
- Each replaces previous
- File type indicated in UI
- Can download each format

---

### Test 4.3: Resume Text Extraction

**Steps:**
1. Upload a real PDF resume with text
2. Check if resume text auto-extracted
3. View candidate profile

**Expected Results (if implemented):**
- Resume text displayed in "Parsed Resume" section
- Full-text searchable
- Can edit parsed text

**If Not Implemented:**
- [ ] Note that resume parsing not yet implemented
- [ ] Parsed text field empty or N/A

---

### Test 4.4: Store Multiple Document Types

**Steps:**
1. Open candidate detail page
2. Attempt to upload:
   - Certificates (PDF)
   - Verification documents
   - Portfolio samples (if separate from portfolio URL)

**Expected Results:**
- Documents section shows all uploads
- Can organize/categorize documents
- Can download each
- Deletion available

---

## Test Area 5: Moving Candidates Through Pipeline Stages

### Test 5.1: Create Application (Initial Stage)

**Prerequisites:**
- Job posting exists
- Candidate exists or will be created
- Pipeline has stages: Applied, Screening, Interview, Offer, Hired

**Steps:**
1. Open job posting
2. Click "New Application"
3. Select candidate or fill new candidate info:
   - Candidate: John Doe (from earlier test)
4. Click "Create Application"

**Expected Results:**
- Application created in "Applied" stage (first stage)
- Application appears in job's application list
- Status shows current stage
- Stage transition buttons available

---

### Test 5.2: Move Candidate to Screening

**Steps:**
1. Open application (from Test 5.1)
2. Find stage selector or "Move to Next Stage" button
3. Select "Screening" stage
4. Add optional notes: "Passed initial review"
5. Click "Move" or "Update"

**Expected Results:**
- Application moved to Screening stage
- Status updated immediately
- Stage change recorded with timestamp
- Notes saved (if provided)
- Can view stage history

---

### Test 5.3: Move Through Full Pipeline

**Steps:**
1. Open application from previous tests
2. Move through each stage:
   - Applied → Screening → Interview → Offer → Hired
   - At each stage, add notes explaining decision
3. Final stage: Application should mark as "Hired"

**Expected Results:**
- Each stage move successful
- Full history visible
- Notes preserved at each stage
- Final status shows "Hired" or similar
- Date progression visible

---

### Test 5.4: Add Interview to Pipeline

**Steps:**
1. While application in "Interview" stage
2. Look for "Schedule Interview" button/link
3. Click to open interview scheduling form
4. Fill:
   - Title: `Technical Round 1`
   - Type: `Technical`
   - Date/Time: `2026-01-20 10:00 AM`
   - Duration: `1 hour`
   - Location: `Zoom` or `In-person`
   - Meeting Link: `https://zoom.us/...` (if virtual)
5. Click Save

**Expected Results:**
- Interview scheduled and linked to application
- Appears in application timeline
- Reminder notifications sent (if configured)
- Interview status tracked

---

### Test 5.5: Move Application Back to Previous Stage

**Steps:**
1. Open application in advanced stage (e.g., Interview)
2. Look for "Move Back" or stage selector allowing backward movement
3. Move back to Screening
4. Add reason/notes: "Needs further review"

**Expected Results:**
- Application moved back successfully
- Full history maintained
- Can see both forward and backward movement
- Notes record reason for movement

---

## Test Area 6: Candidate Search and Filtering

### Test 6.1: Search by Name

**Steps:**
1. Navigate to Candidates list
2. Find search box
3. Enter search: `john`
4. Press Enter or wait for auto-search

**Expected Results:**
- Results show all candidates with "john" in first or last name
- John Doe, Jonathan Smith, etc. appear
- Results count shown
- Clear results button available

---

### Test 6.2: Filter by Years of Experience

**Steps:**
1. Navigate to Candidates list
2. Find Filters section (if available)
3. Select Experience range:
   - Min Years: `5`
   - Max Years: `15`
4. Apply filter

**Expected Results:**
- Candidates with 5-15 years experience shown
- Result count updated
- Other filters still available
- Can clear/modify filter

---

### Test 6.3: Filter by Source

**Steps:**
1. Navigate to Candidates list
2. Find Source filter
3. Select: `LinkedIn`
4. Apply filter

**Expected Results:**
- Only candidates from LinkedIn source shown
- Result count updated
- Can multi-select sources (if available)
- Results match source

---

### Test 6.4: Filter by Skills

**Steps:**
1. Navigate to Candidates list
2. Find Skills filter
3. Type/Select: `Python`
4. Apply filter

**Expected Results:**
- Only candidates with Python skill shown
- Result count updated
- Can add multiple skills (if available)
- Skill matching works correctly

---

### Test 6.5: Filter by Location

**Steps:**
1. Navigate to Candidates list
2. Find Location filter
3. Enter/Select city: `San Francisco`
4. Apply filter

**Expected Results:**
- Candidates in San Francisco shown
- Can also filter by state/country (if available)
- Result count updated
- Map view available (if supported)

---

### Test 6.6: Filter by Salary Range

**Steps:**
1. Navigate to Candidates list
2. Find Salary filter
3. Set range:
   - Min: `$80,000`
   - Max: `$150,000`
4. Apply filter

**Expected Results:**
- Candidates seeking salary in range shown
- Result count updated
- Currency displayed correctly
- Can adjust range easily

---

### Test 6.7: Combined Filtering

**Steps:**
1. Navigate to Candidates list
2. Apply multiple filters:
   - Source: LinkedIn
   - Experience: 5+ years
   - Skills: Python
   - Location: San Francisco
3. Apply all filters

**Expected Results:**
- Results match ALL filter criteria
- Result count shows intersection
- Can remove individual filters
- "Clear All Filters" button available

---

### Test 6.8: Search by Tags

**Steps:**
1. Navigate to Candidates list
2. Find Tags filter (if available)
3. Select: `Available`
4. Apply filter

**Expected Results:**
- Candidates with "Available" tag shown
- Result count updated
- Can search multiple tags

---

## Test Area 7: Bulk Operations on Candidates

### Test 7.1: Select Multiple Candidates

**Steps:**
1. Navigate to Candidates list
2. Look for checkboxes at top and next to each candidate
3. Check "Select All" checkbox (if available)
4. Or manually check 5 candidates

**Expected Results:**
- All candidates selected
- Selection count shown
- Bulk action menu appears
- Can deselect individual candidates

---

### Test 7.2: Bulk Add Tag

**Steps:**
1. From Test 7.1, with 5 candidates selected
2. Look for Bulk Actions menu
3. Select: "Add Tag"
4. Enter tag: `Reviewed`
5. Click Apply

**Expected Results:**
- Tag added to all selected candidates
- Confirmation message shown
- Result count updated
- Tag appears on each candidate's detail page

---

### Test 7.3: Bulk Change Source

**Steps:**
1. Select 3 candidates with source "Direct"
2. From Bulk Actions, select: "Change Source"
3. Select new source: `LinkedIn`
4. Click Apply

**Expected Results:**
- Source changed for all selected candidates
- Confirmation message shown
- Candidates list updated
- Filter by source reflects changes

---

### Test 7.4: Bulk Assign to Job

**Steps:**
1. Select 5 candidates
2. From Bulk Actions, select: "Assign to Job"
3. Select job: "Senior Developer"
4. Click Apply

**Expected Results:**
- Applications created for all candidates for selected job
- All appear in job's application list
- Each in "Applied" stage
- Confirmation message with count

---

### Test 7.5: Bulk Delete/Archive

**Steps:**
1. Select 3 candidates marked for deletion/archival
2. From Bulk Actions, select: "Delete" or "Archive"
3. Confirm deletion in dialog
4. Verify

**Expected Results:**
- Candidates soft-deleted (not permanently removed)
- Disappear from active candidate list
- Can restore from archive (if implemented)
- Confirmation message shown
- Count updated

---

### Test 7.6: Export Candidate Data

**Steps:**
1. Navigate to Candidates list
2. Look for "Export" button
3. Select candidates (all or filtered)
4. Choose format: CSV
5. Click Export

**Expected Results:**
- CSV file downloaded
- Contains all candidate data (selected columns)
- File opens correctly in Excel/Google Sheets
- Date formats preserved
- Email addresses included

**Export Format Verification:**
- [ ] Column headers included
- [ ] All data properly escaped (quotes, commas)
- [ ] Unicode characters handled
- [ ] Large exports complete without truncation

---

## Test Area 8: Permissions and Security

### Test 8.1: Tenant Isolation

**Prerequisites:**
- Two different tenant accounts set up
- Each with test candidates

**Steps:**
1. Log in as Tenant A user
2. Navigate to Candidates
3. Verify only Tenant A candidates shown
4. Try accessing Tenant B candidate via URL manipulation
   - URL: `/candidates/<tenant-b-candidate-id>/`
5. Log out and log in as Tenant B user
6. Verify Tenant B candidates visible, not Tenant A

**Expected Results:**
- Each tenant only sees their own candidates
- No cross-tenant data leakage
- Direct URL access to other tenant's data denied
- No error messages revealing existence of other tenant

---

### Test 8.2: Permission Checks - Add Candidate

**Prerequisites:**
- User with "Add Candidate" permission
- User without "Add Candidate" permission

**Steps:**
1. Log in as restricted user
2. Navigate to Candidates
3. Look for "Add New Candidate" button
4. Should be disabled/hidden or show permission error on click

**Expected Results:**
- Button disabled or hidden for restricted user
- Clear permission error if attempted
- Admin/manager can create candidates
- Appropriate error message shown

---

### Test 8.3: Permission Checks - Edit Candidate

**Steps:**
1. Log in as user with view-only permission
2. Open candidate profile
3. Try to click Edit button
4. Should be disabled/hidden

**Expected Results:**
- Edit buttons not available for view-only user
- Clear permission message
- All candidates visible but not editable

---

### Test 8.4: Permission Checks - Delete Candidate

**Steps:**
1. Log in as user without delete permission
2. Open candidate profile
3. Look for Delete button
4. Should not appear or should be disabled

**Expected Results:**
- Delete button hidden or disabled
- No error on page
- Only users with proper permission can delete

---

### Test 8.5: GDPR Consent Fields

**Steps:**
1. Open candidate detail page
2. Look for GDPR/Privacy section
3. Verify visible:
   - [ ] Consent to store checkbox
   - [ ] Consent date
   - [ ] Data retention until date
4. When creating new candidate, check if consent requested

**Expected Results:**
- GDPR fields visible in candidate profile
- Can modify consent status
- Dates recorded correctly
- Audit trail maintained (if available)

---

### Test 8.6: Form Input Sanitization

**Steps:**
1. Create new candidate
2. In "Headline" field, try to enter:
   ```
   <script>alert('xss')</script>My Headline
   ```
3. Save
4. View candidate detail

**Expected Results:**
- HTML tags stripped from output
- Headline shows: "My Headline" (without script tags)
- No JavaScript executed
- Similar test for: first_name, summary, etc.

---

### Test 8.7: Email Validation

**Steps:**
1. Create new candidate
2. Try invalid emails:
   - `notanemail`
   - `user@`
   - `@domain.com`
   - `user @domain.com` (space)
3. For each, try to Save

**Expected Results:**
- Each invalid email rejected
- Clear validation error message
- Form not submitted
- Valid format required

---

## Test Area 9: Integration Tests

### Test 9.1: Full Workflow - Candidate to Hire

**Steps:**
1. Create new candidate: "Integration Test User"
2. Create job posting: "Integration Test Job"
3. Create application linking candidate to job
4. Move application through pipeline:
   - Applied → Screening (add notes)
   - Screening → Interview (schedule interview)
   - Interview → Offer (create offer)
   - Offer → Hired (confirm acceptance)
5. Verify final status

**Expected Results:**
- Complete workflow functions
- All data persists
- Timeline shows progression
- Notifications sent at each stage (if configured)

---

### Test 9.2: Interview Feedback

**Steps:**
1. From workflow above, at Interview stage
2. Schedule interview
3. After interview, click "Add Feedback"
4. Fill feedback form:
   - Rating: 4/5
   - Recommendation: "Hire"
   - Strengths: Technical skills, problem-solving
   - Weaknesses: Limited leadership experience
   - Notes: Good candidate, recommend move to offer
5. Save feedback

**Expected Results:**
- Feedback saved and associated with interview
- Interview status updated
- Feedback visible on application timeline
- Can edit feedback
- Feedback influences next stage decision

---

### Test 9.3: Offer Creation and Response

**Steps:**
1. Create offer from interview feedback
2. Fill offer form:
   - Job Title: "Senior Software Engineer"
   - Base Salary: "$120,000"
   - Bonus: "$15,000"
   - Start Date: "2026-03-01"
   - Benefits Summary: Comprehensive health insurance, 401(k), PTO
3. Send offer to candidate
4. Wait for candidate response or respond as admin:
   - Accept offer
   - Decline offer
   - Counter offer

**Expected Results:**
- Offer created successfully
- Email sent to candidate (check MailHog at localhost:8026)
- Candidate can respond (if self-service portal available)
- Response recorded and application status updated
- Final hire status reached on acceptance

---

## Performance Tests

### Test 10.1: Candidate List Performance (Large Dataset)

**Setup:**
```bash
docker compose exec web python manage.py shell
>>> from conftest import CandidateFactory
>>> for i in range(1000): CandidateFactory()
```

**Steps:**
1. Navigate to Candidates list
2. Measure load time
3. Apply filters
4. Measure filter time
5. Scroll/paginate through results

**Expected Results:**
- Initial load < 2 seconds
- Filter application < 1 second
- Pagination smooth
- No UI freezing
- Search/filter responsive

---

### Test 10.2: Bulk Import Performance

**Setup:**
- Create CSV with 500 candidate records

**Steps:**
1. Perform bulk import
2. Monitor progress
3. Measure total time
4. Check final count

**Expected Results:**
- Import completes in reasonable time (< 5 minutes)
- Progress feedback provided
- All records created successfully
- No timeout errors
- Database remains responsive

---

## Error Handling Tests

### Test 11.1: Handle Missing Required Fields

**Steps:**
1. Create new candidate
2. Leave "Email" field blank
3. Try to Save

**Expected Results:**
- Clear error message: "Email field is required"
- Form highlights missing field
- No submission occurs

---

### Test 11.2: Handle Duplicate Email

**Steps:**
1. Create candidate with email `test@example.com`
2. Try to create another candidate with same email
3. Try to Save

**Expected Results:**
- Error message or warning about duplicate
- Option to merge or create anyway (depending on design)
- Form doesn't submit without user acknowledgment

---

### Test 11.3: Handle File Upload Errors

**Steps:**
1. Create candidate
2. Try to upload file > 10MB
3. Try to upload `.exe` file

**Expected Results:**
- Each rejected with appropriate error
- File not uploaded
- User can retry
- Clear error messages

---

### Test 11.4: Handle Network Errors

**Steps:**
1. Start upload
2. While uploading, turn off internet/kill network
3. Wait for timeout

**Expected Results:**
- Timeout error shown
- Upload can be retried
- No partial data in database
- User informed of issue

---

## Checklist Summary

### Add Candidates
- [ ] Form validation working
- [ ] Resume upload works (all formats)
- [ ] Skills/languages stored correctly
- [ ] Social profiles saved
- [ ] Salary preferences recorded
- [ ] XSS protection active
- [ ] Duplicate detection works

### Import Candidates
- [ ] CSV bulk import works
- [ ] Application linking works
- [ ] Duplicate prevention works
- [ ] Confirmation emails sent

### Update Profiles
- [ ] All fields editable
- [ ] Skills/education/experience update
- [ ] Social profiles update
- [ ] Changes persist
- [ ] Timestamps updated

### Documents
- [ ] File upload works
- [ ] Multiple formats supported
- [ ] File replacement works
- [ ] Resume text parsing (if implemented)
- [ ] File size validation works

### Pipeline Movement
- [ ] Applications created in initial stage
- [ ] Stage transitions work
- [ ] Full pipeline movement possible
- [ ] Stage history visible
- [ ] Interview scheduling works
- [ ] Feedback collection works

### Search & Filter
- [ ] Name search works
- [ ] Experience filtering works
- [ ] Source filtering works
- [ ] Skill filtering works
- [ ] Location filtering works
- [ ] Salary range filtering works
- [ ] Combined filters work
- [ ] Tag filtering works

### Bulk Operations
- [ ] Multi-select works
- [ ] Bulk tag addition works
- [ ] Bulk source change works
- [ ] Bulk job assignment works
- [ ] Bulk delete/archive works
- [ ] Export works
- [ ] Large operations performant

### Permissions & Security
- [ ] Tenant isolation enforced
- [ ] Permission checks work
- [ ] Input sanitization active
- [ ] Email validation works
- [ ] File upload validation works
- [ ] GDPR consent tracked
- [ ] No XSS vulnerabilities
- [ ] No SQL injection possible

---

## Bug Reporting Template

**If you find an issue, document it as:**

```
### [Area]: [Specific Issue]

**Steps to Reproduce:**
1. ...
2. ...
3. ...

**Expected Result:**
...

**Actual Result:**
...

**Error Message (if any):**
...

**Environment:**
- Browser: [Chrome/Firefox/Safari]
- OS: [Windows/Mac/Linux]
- Zumodra Version: [if applicable]

**Attachment:**
- Screenshot/screencast
- Browser console error (F12)
- Server logs (docker compose logs web)
```

---

## Success Criteria

All of the following must PASS for workflow to be considered complete:

1. ✓ Can create candidates with all field types
2. ✓ Can upload and manage documents
3. ✓ Can import candidates from applications
4. ✓ Can search and filter candidates effectively
5. ✓ Can move candidates through pipeline
6. ✓ Can perform bulk operations
7. ✓ Form validation working correctly
8. ✓ Security (XSS, SQL injection, tenant isolation) enforced
9. ✓ No errors in browser console
10. ✓ No errors in server logs

---

**Last Updated:** 2026-01-16
