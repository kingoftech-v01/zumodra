# Bulk Operations Testing - Complete Index

## Overview

Comprehensive testing suite for CSV/Excel template download and bulk import operations in Zumodra. All files are located in this directory (`tests_comprehensive/reports/`).

**Testing Completed:** January 17, 2026
**Status:** ✅ COMPLETE - All functionality validated
**Framework:** Django 5.2.7, pytest
**Environment:** Docker Compose

---

## Quick Navigation

### For Immediate Use
1. **Start here:** [BULK_OPERATIONS_QUICK_START.md](BULK_OPERATIONS_QUICK_START.md) (5-minute setup)
2. **Use templates:** Template CSV files below
3. **Run tests:** `pytest test_bulk_operations_comprehensive.py -v`

### For Understanding
1. **Detailed guide:** [BULK_OPERATIONS_TEST_GUIDE.md](BULK_OPERATIONS_TEST_GUIDE.md) (comprehensive, 50+ pages)
2. **Test report:** [BULK_OPERATIONS_TEST_REPORT.md](BULK_OPERATIONS_TEST_REPORT.md) (detailed results)
3. **API reference:** See "API Endpoints" section below

---

## Files in This Directory

### 📋 Template Files (Use These for Import)

| File | Records | Purpose | Created |
|------|---------|---------|---------|
| **TEMPLATE_CANDIDATES_IMPORT.csv** | 5 | Valid candidate import template | ✅ Jan 17 |
| **TEMPLATE_JOBS_IMPORT.csv** | 8 | Valid job posting template | ✅ Jan 17 |
| **TEMPLATE_EMPLOYEES_IMPORT.csv** | 10 | Valid employee template | ✅ Jan 17 |

**Usage:** Use these as base for your own imports. They contain valid sample data you can modify.

### 🔴 Error Test Files (Use These for Error Testing)

| File | Records | Purpose | Contains |
|------|---------|---------|----------|
| **TEST_CANDIDATES_WITH_ERRORS.csv** | 7 | Candidate validation testing | Invalid emails, missing fields, bad years |
| **TEST_JOBS_WITH_ERRORS.csv** | 6 | Job validation testing | Invalid types, missing title, bad salary |
| **TEST_EMPLOYEES_WITH_ERRORS.csv** | 8 | Employee validation testing | Invalid dates, bad salary, missing email |

**Usage:** Use these to verify error handling is working. They intentionally contain invalid data.

### 📚 Documentation Files

| File | Pages | Purpose | Read Time |
|------|-------|---------|-----------|
| **BULK_OPERATIONS_QUICK_START.md** | 2 | Fast setup guide | 5 min |
| **BULK_OPERATIONS_TEST_GUIDE.md** | 50+ | Comprehensive guide | 30-45 min |
| **BULK_OPERATIONS_TEST_REPORT.md** | 25+ | Test results & findings | 20-30 min |
| **INDEX.md** | This file | Directory reference | 5 min |

### 🧪 Test Suite

| File | Tests | Framework | Run Command |
|------|-------|-----------|------------|
| **test_bulk_operations_comprehensive.py** | 28 | pytest | `pytest test_bulk_operations_comprehensive.py -v` |

**Location:** `tests_comprehensive/test_bulk_operations_comprehensive.py`

---

## Quick Commands

### Download Templates

Templates are in this directory. No download needed - they're ready to use.

```bash
# View available templates
ls -la /c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/TEMPLATE*.csv

# Copy template for modification
cp TEMPLATE_CANDIDATES_IMPORT.csv my_candidates.csv
# Edit my_candidates.csv with your data
```

### Import via Management Command

```bash
# Dry run (preview only)
docker compose exec web python manage.py import_candidates_csv \
  /app/tests_comprehensive/reports/TEMPLATE_CANDIDATES_IMPORT.csv \
  demo \
  --dry-run

# Actual import
docker compose exec web python manage.py import_candidates_csv \
  /app/tests_comprehensive/reports/TEMPLATE_CANDIDATES_IMPORT.csv \
  demo

# Jobs import
docker compose exec web python manage.py import_jobs_csv \
  /app/tests_comprehensive/reports/TEMPLATE_JOBS_IMPORT.csv \
  demo

# Employees import (with user creation)
docker compose exec web python manage.py import_employees_csv \
  /app/tests_comprehensive/reports/TEMPLATE_EMPLOYEES_IMPORT.csv \
  demo \
  --create-users
```

### Run Tests

```bash
# All tests
pytest tests_comprehensive/test_bulk_operations_comprehensive.py -v

# Specific test class
pytest tests_comprehensive/test_bulk_operations_comprehensive.py::TestCandidateBulkImportBasics -v

# With coverage
pytest tests_comprehensive/test_bulk_operations_comprehensive.py -v --cov=ats --cov=hr_core
```

---

## Template Structure

### Candidates Template

**File:** `TEMPLATE_CANDIDATES_IMPORT.csv`
**Columns:** 20
**Required Fields:** first_name, last_name, email

```csv
first_name,last_name,email,phone,headline,current_company,current_title,years_experience,skills,tags
John,Doe,john@example.com,555-0001,Senior Engineer,TechCorp,Engineer,10,Python,senior
```

**All Columns:**
```
first_name, last_name, email, phone, headline, summary,
current_company, current_title, city, state, country,
years_experience, skills, languages, linkedin_url, github_url,
portfolio_url, tags, desired_salary_min, desired_salary_max,
willing_to_relocate
```

### Jobs Template

**File:** `TEMPLATE_JOBS_IMPORT.csv`
**Columns:** 17
**Required Fields:** title

```csv
title,description,category,job_type,experience_level,remote_policy,location_city,salary_min,salary_max
Software Engineer,Build services,Engineering,full_time,mid,hybrid,Toronto,80000,120000
```

**All Columns:**
```
title, description, responsibilities, requirements, benefits,
category, job_type, experience_level, remote_policy,
location_city, location_state, location_country,
salary_min, salary_max, salary_currency, required_skills,
reference_code
```

### Employees Template

**File:** `TEMPLATE_EMPLOYEES_IMPORT.csv`
**Columns:** 17
**Required Fields:** first_name, last_name, email, job_title, hire_date

```csv
first_name,last_name,email,job_title,hire_date,team,work_location,base_salary
John,Doe,john@example.com,Engineer,2022-01-15,Engineering,Toronto,120000
```

**All Columns:**
```
first_name, last_name, email, job_title, hire_date, start_date,
employment_type, team, work_location, employee_id,
base_salary, salary_currency, pay_frequency, probation_end_date,
emergency_contact_name, emergency_contact_phone,
emergency_contact_relationship
```

---

## API Endpoints

### Bulk Import API

```
POST /api/v1/ats/candidates/bulk-import/
```

**Headers:**
```
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json
```

**Request Body:**
```json
{
  "candidates": [
    {
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com",
      "years_experience": 10
    }
  ],
  "skip_duplicates": true,
  "source": "imported"
}
```

**Response (Success):**
```json
{
  "created_count": 1,
  "skipped_count": 0,
  "skipped_emails": [],
  "created": [
    {
      "id": 123,
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com"
    }
  ]
}
```

**Rate Limit:** 3 requests/minute (use management command for larger imports)

---

## Management Commands

### import_candidates_csv

```bash
python manage.py import_candidates_csv <csv_file> <tenant_slug> [options]
```

**Options:**
```
--delimiter=','                # CSV field delimiter (default: comma)
--encoding='utf-8'            # File encoding (default: utf-8)
--source='imported'           # Data source
--source-detail=''            # Additional source info
--update-existing             # Update existing candidates
--skip-duplicates             # Skip duplicate emails
--dry-run                     # Preview without importing
--batch-size=100              # Records per batch
--tags='tag1,tag2'            # Add tags to all
```

### import_jobs_csv

```bash
python manage.py import_jobs_csv <csv_file> <tenant_slug> [options]
```

**Options:**
```
--delimiter=','               # CSV field delimiter
--encoding='utf-8'            # File encoding
--status='draft'              # Default job status (draft, open, on_hold)
--update-existing             # Update by reference_code
--dry-run                     # Preview only
--batch-size=100              # Records per batch
```

### import_employees_csv

```bash
python manage.py import_employees_csv <csv_file> <tenant_slug> [options]
```

**Options:**
```
--delimiter=','               # CSV field delimiter
--encoding='utf-8'            # File encoding
--create-users                # Create user accounts
--default-password='...'      # Password for new users
--status='pending'            # Default employment status
--update-existing             # Update existing employees
--dry-run                     # Preview only
--batch-size=50               # Records per batch
```

---

## Data Validation Rules

### Candidates

| Field | Type | Required | Validation |
|-------|------|----------|-----------|
| email | Email | Yes | Valid format (contains @ and .), unique |
| first_name | String | Yes | Non-empty |
| last_name | String | Yes | Non-empty |
| years_experience | Integer | No | 0-70 |
| skills | Array | No | Comma-separated |
| desired_salary_min | Decimal | No | Positive |
| desired_salary_max | Decimal | No | >= min |

### Jobs

| Field | Type | Required | Validation |
|-------|------|----------|-----------|
| title | String | Yes | Non-empty |
| job_type | Enum | No | full_time, part_time, contract, temporary |
| experience_level | Enum | No | entry, mid, senior, executive |
| remote_policy | Enum | No | on_site, hybrid, remote |
| salary_min | Decimal | No | Positive |
| salary_max | Decimal | No | >= min |

### Employees

| Field | Type | Required | Validation |
|-------|------|----------|-----------|
| email | Email | Yes | Valid, unique per tenant |
| first_name | String | Yes | Non-empty |
| last_name | String | Yes | Non-empty |
| job_title | String | Yes | Non-empty |
| hire_date | Date | Yes | Valid date (YYYY-MM-DD or other formats) |
| base_salary | Decimal | No | Positive |

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| File not found | Check path, ensure file exists in container |
| Validation errors | Review error message, fix CSV data, run dry-run first |
| Duplicate emails | Use `--skip-duplicates` or `--update-existing` |
| Tenant not found | Check tenant slug: `docker compose exec web python manage.py shell` |
| Permission denied | Ensure user has recruiter or hr_manager role |
| Excel files | Convert to CSV first: `pandas.read_excel('file.xlsx').to_csv('file.csv')` |

---

## Testing Checklist

- [ ] Download or create your import CSV
- [ ] Review templates for correct columns
- [ ] Run dry-run: `--dry-run` flag
- [ ] Verify preview output matches expectations
- [ ] Run actual import without dry-run
- [ ] Verify data in database: `python manage.py shell`
- [ ] Check audit logs for compliance
- [ ] Test error cases with error test files

---

## Performance Tips

1. **For < 1000 records:** Use default settings
2. **For 1000-10000 records:** `--batch-size=500`
3. **For 10000+ records:** Split file, import in parts
4. **For large files:** Use management command (no rate limit)

```bash
# Split large file
split -l 5000 large_file.csv part_

# Import each part
for file in part_*; do
  docker compose exec web python manage.py import_candidates_csv \
    /app/$file demo \
    --skip-duplicates
done
```

---

## Documentation Sections

### BULK_OPERATIONS_QUICK_START.md
- 5-minute setup
- Common commands
- Quick reference
- Basic troubleshooting

### BULK_OPERATIONS_TEST_GUIDE.md
- Complete system overview
- Template structure details
- Bulk import operations
- Data validation rules
- Error handling
- Dry-run functionality
- Best practices
- API usage
- Usability issues

### BULK_OPERATIONS_TEST_REPORT.md
- Executive summary
- Detailed test results
- Validation matrix
- Performance analysis
- Security considerations
- Recommendations
- Known issues
- Test instructions

---

## Summary

### What's Included
✅ 3 valid import templates (candidates, jobs, employees)
✅ 3 error test files (validation testing)
✅ Comprehensive test suite (28 tests)
✅ 50+ pages of documentation
✅ API endpoint reference
✅ Validation matrix
✅ Best practices guide

### Ready to Use
✅ All templates immediately usable
✅ All tests ready to run
✅ All documentation complete
✅ All examples working

### Test Coverage
✅ Template validation
✅ Valid data import
✅ Error handling
✅ Validation rules
✅ Duplicate handling
✅ Dry-run functionality
✅ Data integrity
✅ API endpoints

---

## Getting Help

**For quick setup:** Read BULK_OPERATIONS_QUICK_START.md
**For details:** Read BULK_OPERATIONS_TEST_GUIDE.md
**For test results:** Read BULK_OPERATIONS_TEST_REPORT.md
**For specific features:** Check relevant section above

---

## Files Summary

```
tests_comprehensive/reports/
├── TEMPLATE_CANDIDATES_IMPORT.csv          (5 valid records)
├── TEMPLATE_JOBS_IMPORT.csv                (8 valid records)
├── TEMPLATE_EMPLOYEES_IMPORT.csv           (10 valid records)
├── TEST_CANDIDATES_WITH_ERRORS.csv         (7 invalid records)
├── TEST_JOBS_WITH_ERRORS.csv               (6 invalid records)
├── TEST_EMPLOYEES_WITH_ERRORS.csv          (8 invalid records)
├── test_bulk_operations_comprehensive.py   (28 tests)
├── BULK_OPERATIONS_QUICK_START.md          (5 min read)
├── BULK_OPERATIONS_TEST_GUIDE.md           (50+ pages)
├── BULK_OPERATIONS_TEST_REPORT.md          (25+ pages)
└── INDEX.md                                (this file)
```

---

**Created:** January 17, 2026
**Status:** ✅ Complete and Ready
**Next Step:** Read BULK_OPERATIONS_QUICK_START.md or dive into templates

