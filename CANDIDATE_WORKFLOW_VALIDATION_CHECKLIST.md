# Candidate Management Workflow - Validation Checklist

**Purpose:** Comprehensive validation checklist for all candidate management operations
**Date:** 2026-01-16

---

## Part 1: Form Field Validations

### 1.1 Text Fields - XSS Protection

| Field | Input | Expected | Status |
|-------|-------|----------|--------|
| first_name | `<script>alert('xss')</script>` | Strip tags, save as plain text | ✓ |
| first_name | `John's` | Accept apostrophe, save correctly | ✓ |
| first_name | `(╯°□°)╯彡 ┻━┻` | Accept Unicode, save correctly | ✓ |
| last_name | `<img src=x onerror="alert('xss')">` | Strip all HTML, save as text | ✓ |
| headline | `; DROP TABLE candidates; --` | Sanitize, prevent SQL injection | ✓ |
| summary | Very long text (5000+ chars) | Accept up to 5000, truncate/error if over | ✓ |

**Validators Used:**
- NoXSS
- NoSQLInjection
- sanitize_plain_text

---

### 1.2 Email Field Validation

| Input | Valid? | Notes |
|-------|--------|-------|
| `john@example.com` | ✓ | Standard email |
| `john.doe@example.co.uk` | ✓ | Domain with dot |
| `john+tag@example.com` | ✓ | Plus addressing |
| `john@localhost` | ✓ | Local domain |
| `john` | ✗ | Missing @ and domain |
| `john@` | ✗ | Missing domain |
| `@example.com` | ✗ | Missing username |
| `john @example.com` | ✗ | Space not allowed |
| `` | ✗ | Empty/required field |

**Validator:** Django EmailField

---

### 1.3 Phone Field Validation

| Input | Valid? | Format | Notes |
|-------|--------|--------|-------|
| `+1-555-0100` | ✓ | International format | |
| `555-0100` | ✓ | Local format | |
| `(555) 0100` | ✓ | Alternative format | |
| `+1 555 0100` | ✓ | Spaces allowed | |
| `invalid-phone` | ✗ | No digits | |
| `` | ✓ | Optional field | Can be empty |
| `555` | ✗ | Too short | |
| `+1-555-0100-ext-123` | ? | Extension | Check if supported |

**Validator:** PhoneValidator (custom)

---

### 1.4 URL Field Validations

#### LinkedIn URL
| Input | Valid? | Notes |
|-------|--------|-------|
| `https://linkedin.com/in/john` | ✓ | Must contain 'linkedin.com' |
| `https://www.linkedin.com/in/john` | ✓ | With www |
| `linkedin.com/in/john` | ? | Without protocol - check |
| `https://facebook.com/john` | ✗ | Not LinkedIn |
| `` | ✓ | Optional field |

#### GitHub URL
| Input | Valid? | Notes |
|-------|--------|-------|
| `https://github.com/john` | ✓ | Valid GitHub URL |
| `http://github.com/john` | ✓ | HTTP allowed |
| `github.com/john` | ? | Without protocol |
| `https://gitlab.com/john` | ✗ | Not GitHub |
| `` | ✓ | Optional |

#### Twitter URL
| Input | Valid? | Notes |
|-------|--------|-------|
| `https://twitter.com/john` | ✓ | Standard format |
| `https://x.com/john` | ? | New X.com domain - check |
| `twitter.com/john` | ? | Without protocol |
| `` | ✓ | Optional |

#### Portfolio/Website URL
| Input | Valid? | Notes |
|-------|--------|-------|
| `https://example.com` | ✓ | Valid HTTPS |
| `http://example.com` | ✓ | HTTP allowed |
| `example.com` | ? | Without protocol - check |
| `javascript:alert('xss')` | ✗ | JavaScript protocol blocked |
| `` | ✓ | Optional |

**Validator:** Django URLField + custom checks

---

### 1.5 Numeric Fields

#### Years of Experience
| Input | Valid? | Notes |
|-------|--------|-------|
| `5` | ✓ | Positive integer |
| `0` | ✓ | Entry level |
| `50` | ✓ | Realistic maximum |
| `-5` | ✗ | Negative rejected |
| `5.5` | ✗ | Decimal rejected (integer field) |
| `abc` | ✗ | Non-numeric rejected |
| `` | ✓ | Optional field |

#### Desired Salary
| Input (Min/Max) | Valid? | Notes |
|-----------------|--------|-------|
| `50000` / `100000` | ✓ | Min < Max |
| `100000` / `50000` | ✗ | Max < Min - should error |
| `80000` / `80000` | ✓ | Equal min/max allowed |
| `-50000` | ✗ | Negative rejected |
| `0` | ✓ | Zero might be allowed |
| `999999999999` | ? | Unrealistic - check limits |
| `` | ✓ | Optional fields |

**Validator:** DecimalField, positive validation

#### Notice Period (Days)
| Input | Valid? | Notes |
|-------|--------|-------|
| `30` | ✓ | Standard notice |
| `0` | ✓ | Immediate availability |
| `180` | ✓ | 6 months |
| `365` | ✓ | 1 year |
| `-1` | ✗ | Negative rejected |
| `` | ✓ | Optional |

**Validator:** PositiveIntegerField

---

### 1.6 Choice Fields

#### Source Selection
| Value | Label | Category |
|-------|-------|----------|
| CAREER_PAGE | Career Page | Direct |
| LINKEDIN | LinkedIn | Social |
| INDEED | Indeed | Job Board |
| REFERRAL | Employee Referral | Internal |
| AGENCY | Recruitment Agency | External |
| DIRECT | Direct Application | Direct |
| IMPORTED | Imported | System |
| OTHER | Other | Misc |

**Validations:**
- [ ] All choices selectable
- [ ] Invalid choice rejected
- [ ] Default is DIRECT
- [ ] Can change source after creation

---

### 1.7 Array Fields

#### Skills
| Input | Result | Notes |
|-------|--------|-------|
| `["Python", "Django"]` | ✓ | Valid array |
| `["Python", "", "Django"]` | ? | Empty string in array - check |
| `["Python", "Python"]` | ✓ | Duplicates allowed |
| `["Python", "PYTHON"]` | ✓ | Case sensitive |
| `["Very Long Skill Name Over 100 Characters..."]` | ? | Check length validation |
| `[]` | ✓ | Empty array allowed |
| `["Python", "Django", "PostgreSQL", "REST API", "React", ...]` (100 items) | ? | Check max items |

**Validator:** ArrayField with CharField(max_length=100)

#### Languages
| Input | Result | Notes |
|-------|--------|-------|
| `["English", "Spanish"]` | ✓ | Valid |
| `["English", "Klingon"]` | ✓ | Any language name accepted |
| `[]` | ✓ | Empty array allowed |
| `["English (Fluent)", "Spanish (Basic)"]` | ✓ | Proficiency levels |

**Validator:** ArrayField

#### Tags
| Input | Result | Notes |
|-------|--------|-------|
| `["Available", "Experienced"]` | ✓ | Valid tags |
| `[]` | ✓ | Empty allowed |
| `["TAG WITH SPACES"]` | ✓ | Spaces allowed |
| `["special!@#$%"]` | ? | Special chars - check |

---

### 1.8 JSON Fields

#### Education
```json
{
  "school": "MIT",
  "degree": "PhD",
  "field": "Physics",
  "start_year": 2015,
  "end_year": 2020,
  "grade": "A",
  "activities": "Dean's List"
}
```

**Validations:**
- [ ] All fields optional except school
- [ ] Years must be valid (not future)
- [ ] end_year >= start_year
- [ ] Can add multiple education entries
- [ ] Can edit/delete entries

#### Work Experience
```json
{
  "company": "Tech Corp",
  "position": "Senior Engineer",
  "start_date": "2020-01-01",
  "end_date": "2023-12-31",
  "description": "Led team of 5 engineers",
  "current": false
}
```

**Validations:**
- [ ] Company and position required
- [ ] Dates must be valid
- [ ] end_date >= start_date
- [ ] Current job can have null end_date
- [ ] Description optional
- [ ] Multiple entries allowed
- [ ] Chronological order preserved

#### Certifications
```json
{
  "title": "AWS Certified Solutions Architect",
  "issuer": "Amazon Web Services",
  "issue_date": "2022-06-15",
  "expiration_date": "2025-06-15",
  "credential_id": "ABC123XYZ",
  "credential_url": "https://..."
}
```

**Validations:**
- [ ] Title and issuer required
- [ ] Dates optional
- [ ] expiration_date >= issue_date (if both present)
- [ ] URLs validated
- [ ] Can add multiple certs

---

## Part 2: File Upload Validations

### 2.1 Resume Upload

#### Allowed Extensions
- `pdf` ✓
- `doc` ✓
- `docx` ✓
- `rtf` ✓
- `txt` ✓
- `exe` ✗
- `jpg` ✗
- `zip` ✗
- `html` ✗
- `xls` ✗

**Validator:** FileExtensionValidator(['pdf', 'doc', 'docx', 'rtf', 'txt'])

#### File Size

| File Size | Valid? | Notes |
|-----------|--------|-------|
| 1 MB | ✓ | Normal resume |
| 5 MB | ✓ | Larger resume |
| 10 MB | ✓ | At limit (if 10MB max) |
| 10.1 MB | ✗ | Over limit |
| 0 bytes | ? | Empty file - check behavior |
| 100 MB | ✗ | Way over limit |

**Field:** FileField with max_size validation

#### MIME Type Validation
| File | MIME Type | Validated? |
|------|-----------|-----------|
| document.pdf | application/pdf | ✓ |
| document.doc | application/msword | ✓ |
| document.docx | application/vnd.openxmlformats-officedocument.wordprocessingml.document | ✓ |
| document.txt | text/plain | ✓ |
| script.exe | application/x-msdownload | ✗ |
| image.jpg | image/jpeg | ✗ |

**Validator:** FileValidator with MIME type checking

#### File Name Handling
| File Name | Stored As | Notes |
|-----------|-----------|-------|
| `resume.pdf` | `resumes/candidate_123_resume.pdf` | Sanitized |
| `Résumé.pdf` | Depends on implementation | Unicode handling |
| `../../../etc/passwd` | `resumes/etc_passwd` | Path traversal blocked |
| `my-resume-v2-FINAL-edited.pdf` | Cleaned up name | |

**Upload Path:** `resumes/`

---

### 2.2 Resume Text Storage

#### Valid Resume Text
```
John Doe
Senior Software Engineer

Experience:
- 10 years in software development
- Expert in Python, Django, PostgreSQL
```

**Validations:**
- [ ] Up to 50,000 characters
- [ ] Plain text format
- [ ] Can contain newlines
- [ ] Supports all Unicode

#### Invalid Resume Text
- [ ] HTML tags stripped
- [ ] JavaScript removed
- [ ] Only plain text stored

---

## Part 3: Data Integrity Validations

### 3.1 Candidate Uniqueness

| Scenario | Behavior |
|----------|----------|
| Same email in different tenants | ✓ Allowed (tenant isolated) |
| Same email in same tenant | ✗ Check - should duplicate prevent or allow |
| Same name, different email | ✓ Allowed |
| Same phone, different candidate | ✓ Allowed |
| Candidate with no email | ✗ Email required |

---

### 3.2 Referential Integrity

| Relationship | Cascading Behavior |
|--------------|------------------|
| Candidate → User (OneToOneField) | SET_NULL if user deleted |
| Candidate → Referred By (ForeignKey) | SET_NULL if referrer deleted |
| Application → Candidate (ForeignKey) | ? (Check CASCADE or SET_NULL) |
| Application → Job (ForeignKey) | ? (Check CASCADE or SET_NULL) |
| Interview → Application (ForeignKey) | ? (Check CASCADE or SET_NULL) |

---

### 3.3 Tenant Isolation

#### Query Filtering
```python
# Should include tenant filter
candidates = Candidate.objects.filter(tenant=request.tenant)

# Should NOT access another tenant's data
candidates = Candidate.objects.all()  # ✗ Missing filter
```

**Validations:**
- [ ] All queryset filtered by tenant
- [ ] Cannot access other tenant's candidates via direct ID
- [ ] Cannot access other tenant's applications
- [ ] Bulk operations respect tenant

#### Test Case
```
Tenant A User tries to access Tenant B Candidate ID
Expected: 404 or Permission Denied
Actual: [Test result]
```

---

## Part 4: Search and Filter Validations

### 4.1 Name Search

| Query | Expected Results | Case Sensitivity |
|-------|------------------|------------------|
| `john` | John, Jonathan, Johnson, Johanna | Case insensitive |
| `JOHN` | All johns (same as above) | Case insensitive |
| `Jo` | Partial matches (Jonathan, John) | Substring match |
| `" john"` | Exact phrase | Quote handling? |
| `@` | No candidates | Special char handling |

### 4.2 Email Search

| Query | Expected Results |
|-------|------------------|
| `@example.com` | All from example.com domain |
| `john` | All with john in email |
| `john@` | With filter/autocomplete |

### 4.3 Experience Range Filter

| Min | Max | Expected | Count |
|-----|-----|----------|-------|
| 5 | 15 | Candidates with 5-15 years | Correct |
| 0 | 100 | All candidates | All |
| 10 | 10 | Exactly 10 years | Correct |
| 100 | 5 | Invalid/swap? | [Behavior] |

### 4.4 Salary Range Filter

| Min | Max | Expected | Validation |
|-----|-----|----------|-----------|
| 50000 | 150000 | Correct range | ✓ |
| 150000 | 50000 | Should error | Min > Max validation |

### 4.5 Skills Filter

| Skill Selected | Expected | Multiple Selection |
|---|---|---|
| Python | Only with Python | ✓ |
| Python + Django | Only with BOTH | ? (AND vs OR) |

### 4.6 Combined Filters

Applying all filters simultaneously:
- Name contains: "john"
- Experience: 5-10 years
- Source: LinkedIn
- Skills: Python
- Location: San Francisco
- Salary: $80k-$120k

**Expected:** Candidates matching ALL criteria (intersection)

---

## Part 5: Bulk Operations Validations

### 5.1 Bulk Create

| Test | Expected | Status |
|------|----------|--------|
| 10 candidates | All created, 10 returned | ✓ |
| 100 candidates | All created, 100 returned | ✓ |
| 1000 candidates | All created, performance acceptable | ✓ |
| Pre-save signals bypassed? | reference_code, slugs generated | ? |
| Tenant assigned to all | All have correct tenant_id | ✓ |

### 5.2 Bulk Update

| Test | Expected | Status |
|------|----------|--------|
| Change source on 100 | All updated, 100 rows affected | ✓ |
| Add tag to 50 | Tag appended to all 50 | ✓ |
| Update dates | Timestamps updated | ✓ |
| Update filters applied | Only matching candidates updated | ✓ |

### 5.3 Bulk Delete (Soft Delete)

| Test | Expected | Status |
|------|----------|--------|
| Delete 10 candidates | Soft deleted, not in active list | ✓ |
| Deleted in database? | Marked with deleted_at or is_deleted | ✓ |
| Can restore? | If soft delete implemented | ✓ |
| Hard delete option? | Only for admins/specific permission | ? |

### 5.4 Bulk Import CSV

| Test | Expected | Status |
|------|----------|--------|
| Valid CSV, 10 rows | All 10 imported, status report | ✓ |
| CSV with duplicates | Handled per skip_duplicates setting | ✓ |
| CSV with empty fields | Required fields error, optional fields blank | ✓ |
| CSV with invalid emails | Rows skipped or error | ✓ |
| Large CSV (500 rows) | Performance acceptable | ✓ |
| Partial import failure | Show which rows failed, why | ✓ |

---

## Part 6: Security Validations

### 6.1 XSS Prevention

#### Test Cases
```python
# Payload 1: Basic script tag
input: "<script>alert('xss')</script>"
expected: "alert('xss')" (tags stripped)

# Payload 2: Event handler
input: "<img src=x onerror=\"alert('xss')\">"
expected: "img src=x onerror=" (tags stripped)

# Payload 3: Data URL
input: "<a href=\"javascript:alert('xss')\">click</a>"
expected: No javascript execution

# Payload 4: SVG
input: "<svg onload=\"alert('xss')\"></svg>"
expected: Tags stripped

# Payload 5: HTML comment
input: "<!-- <script>alert('xss')</script> -->"
expected: Safe (no execution)
```

**Verification:** View page source, no script tags, no event handlers

### 6.2 SQL Injection Prevention

#### Test Cases
```python
# Payload 1: OR bypass
input: "' OR '1'='1"
expected: Treated as literal text, no query bypass

# Payload 2: UNION query
input: "'; UNION SELECT * FROM users; --"
expected: Treated as literal, no query execution

# Payload 3: Stacked queries
input: "'; DROP TABLE candidates; --"
expected: Treated as literal, no deletion

# Payload 4: Time-based blind
input: "' AND SLEEP(5) --"
expected: Treated as literal, no delay
```

**Verification:** Using ORM parameterized queries (Django QuerySet)

### 6.3 CSRF Protection

| Action | CSRF Token | Protection |
|--------|-----------|-----------|
| Create candidate (POST) | Required | ✓ |
| Update candidate (POST) | Required | ✓ |
| Delete candidate (POST) | Required | ✓ |
| Bulk import (POST) | Required | ✓ |

**Test:** Try POST without CSRF token → Should fail with 403

### 6.4 Authentication Required

| Endpoint | Anonymous | Logged In | Admin |
|----------|-----------|-----------|-------|
| /candidates/ | Redirect to login | ✓ | ✓ |
| /candidates/create/ | Redirect to login | ✓ | ✓ |
| /candidates/{id}/ | Redirect to login | ✓ | ✓ |
| /candidates/{id}/edit/ | Redirect to login | ✓ (if permission) | ✓ |

### 6.5 Permission Checks

| Permission | Can Create | Can Edit | Can Delete | Can Bulk |
|-----------|-----------|----------|-----------|----------|
| add_candidate | ✓ | N/A | N/A | N/A |
| change_candidate | N/A | ✓ | N/A | N/A |
| delete_candidate | N/A | N/A | ✓ | N/A |
| ats.bulk_import | N/A | N/A | N/A | ✓ |
| No permissions | ✗ | ✗ | ✗ | ✗ |

---

## Part 7: Performance Validations

### 7.1 Query Count Optimization

| Operation | Expected Queries | Actual | Status |
|-----------|-----------------|--------|--------|
| List candidates (10 items) | ~2-3 | ? | Test |
| Detail view | ~3-5 | ? | Test |
| Edit form load | ~3-5 | ? | Test |
| Bulk create (100 items) | ~2 | ? | Test |
| Filter/search | ~2-3 | ? | Test |

**Tool:** Django Debug Toolbar or `django.test.utils.CaptureQueriesContext`

### 7.2 Response Time

| Operation | Target | Acceptable Range |
|-----------|--------|------------------|
| List candidates | < 500ms | < 1s |
| Search candidates | < 1s | < 2s |
| Create candidate | < 500ms | < 1s |
| Upload resume | < 2s | < 5s |
| Bulk import (100) | < 10s | < 30s |
| Export (1000) | < 5s | < 15s |

### 7.3 Database Indexes

| Table | Column | Index | Used |
|-------|--------|-------|------|
| ats_candidate | tenant_id, email | ✓ | Lookups |
| ats_candidate | tenant_id, created_at | ✓ | Sorting |
| ats_candidate | tenant_id, first_name | ✓ | Searching |
| ats_application | tenant_id, candidate_id | ✓ | Joins |

**Check:** Examine migrations for database indexes

---

## Part 8: API Validations (if REST API exists)

### 8.1 GET /api/v1/ats/candidates/

| Status | Expected | Auth Required |
|--------|----------|---------------|
| 200 | Candidate list | ✓ (Token) |
| 401 | No auth header | Unauthorized |
| 403 | Wrong tenant | Forbidden |

### 8.2 POST /api/v1/ats/candidates/

| Test | Response | Status |
|------|----------|--------|
| Valid payload | 201 Created | ✓ |
| Invalid email | 400 Bad Request | ✓ |
| Missing required field | 400 Bad Request | ✓ |
| No auth | 401 Unauthorized | ✓ |

### 8.3 PUT /api/v1/ats/candidates/{id}/

| Test | Response | Status |
|------|----------|--------|
| Valid update | 200 OK | ✓ |
| Wrong candidate ID | 404 Not Found | ✓ |
| Wrong tenant | 403 Forbidden | ✓ |
| Invalid data | 400 Bad Request | ✓ |

### 8.4 DELETE /api/v1/ats/candidates/{id}/

| Test | Response | Status |
|------|----------|--------|
| Valid delete | 204 No Content | ✓ |
| Wrong ID | 404 Not Found | ✓ |
| No permission | 403 Forbidden | ✓ |

---

## Part 9: Edge Cases

### 9.1 Boundary Values

| Field | Min | Max | Test Min | Test Max | Test Over |
|-------|-----|-----|----------|----------|-----------|
| first_name | 1 | 100 | "A" | "A"*100 | "A"*101 |
| headline | 0 | 200 | "" | "X"*200 | "X"*201 |
| summary | 0 | 5000 | "" | "X"*5000 | "X"*5001 |
| experience | 0 | ? | 0 | [test] | [test] |

### 9.2 Special Characters

| Field | Test | Expected |
|-------|------|----------|
| first_name | `O'Brien` | Accepted |
| last_name | `Müller` | Unicode accepted |
| headline | `C++ Developer` | Accepted |
| skill | `C#` | Accepted |
| summary | Line breaks, tabs | Preserved |

### 9.3 Empty/Null Handling

| Field | Required? | Behavior |
|-------|-----------|----------|
| first_name | YES | Error if empty |
| last_name | YES | Error if empty |
| email | YES | Error if empty |
| phone | NO | Can be null/empty |
| resume | NO | Can be null/empty |
| skills | NO | Can be empty array |

### 9.4 Concurrent Access

**Test:** Two users editing same candidate simultaneously
- User A edits name
- User B edits email
- Both save

**Expected:**
- [ ] Both changes saved (if no conflict)
- [ ] Last write wins (if conflict)
- [ ] Optimistic locking error (if version-based)

---

## Checklist Template for Testing

```
# [Test Area Name]

- [ ] Test case 1
  - [ ] Setup complete
  - [ ] Action executed
  - [ ] Assertion verified
  - [ ] No errors in console/logs

- [ ] Test case 2
  - [ ] Setup complete
  - [ ] Action executed
  - [ ] Assertion verified
  - [ ] No errors in console/logs

**Issues Found:**
- [List any bugs or unexpected behavior]

**Performance Notes:**
- [Any slowness or performance issues]

**Completion Status:** PASS / FAIL / PARTIAL
```

---

## Summary Statistics

**Total Test Cases:** 200+
**Validation Areas:** 9
**Fields Tested:** 30+
**Security Tests:** 20+
**Performance Tests:** 10+
**Edge Cases:** 15+

**Expected Completion Time:** 4-6 hours (manual)
**Automated Test Time:** 5-10 minutes

---

**Next Steps:**
1. Execute automated tests: `pytest test_candidate_workflow.py -v`
2. Perform manual tests using CANDIDATE_WORKFLOW_MANUAL_TEST_GUIDE.md
3. Document any failures in this checklist
4. Create bug reports for failed tests
5. Fix issues and re-test

---

**Report Generated:** 2026-01-16
**Version:** 1.0
