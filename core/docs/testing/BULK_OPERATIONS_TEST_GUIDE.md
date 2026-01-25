# Zumodra Bulk Import/Export Testing Guide

## Overview

This guide provides comprehensive instructions for testing CSV/Excel template download and bulk operations on the Zumodra platform. All testing has been performed on the development environment using Docker Compose.

**Project:** Zumodra Multi-Tenant SaaS Platform
**Testing Date:** January 17, 2026
**Platform:** Django 5.2.7, PostgreSQL 16, Django REST Framework
**Test Environment:** Docker Compose (zumodra:/root/zumodra)

---

## Table of Contents

1. [System Setup](#system-setup)
2. [Template Downloads](#template-downloads)
3. [Bulk Import Operations](#bulk-import-operations)
4. [Data Validation](#data-validation)
5. [Error Handling](#error-handling)
6. [Partial Import with Error Skip](#partial-import-with-error-skip)
7. [Import Preview (Dry-Run)](#import-preview-dry-run)
8. [Test Results Summary](#test-results-summary)
9. [Known Issues & Limitations](#known-issues--limitations)
10. [Recommendations](#recommendations)

---

## System Setup

### Docker Environment

The Zumodra application runs in Docker Compose with the following services:

| Service | Port | Purpose |
|---------|------|---------|
| web | 8002 | Django application |
| db | 5434 | PostgreSQL + PostGIS |
| redis | 6380 | Cache & sessions |
| rabbitmq | 5673 | Message broker |
| nginx | 8084 | Reverse proxy |

### Starting the Environment

```bash
cd /c/Users/techn/OneDrive/Documents/zumodra

# Start all services
docker compose up -d

# Verify services are running
docker compose ps

# Create demo tenant (if needed)
docker compose exec web python manage.py bootstrap_demo_tenant

# Run migrations
docker compose exec web python manage.py migrate_schemas --shared
docker compose exec web python manage.py migrate_schemas --tenant
```

### Environment Variables

Key configuration in `.env`:
- `DEBUG=True` (development mode)
- `CREATE_DEMO_TENANT=true` (auto-create demo tenant)
- `DB_NAME=zumodra`
- `CELERY_BROKER_URL=amqp://zumodra:password@rabbitmq:5672/zumodra`

---

## Template Downloads

### 1. Candidate Import Template

**File:** `TEMPLATE_CANDIDATES_IMPORT.csv`
**Location:** `tests_comprehensive/reports/TEMPLATE_CANDIDATES_IMPORT.csv`

#### Expected Headers

The candidate import template includes the following columns:

| Column | Type | Required | Description |
|--------|------|----------|-------------|
| first_name | String | Yes | Candidate's first name |
| last_name | String | Yes | Candidate's last name |
| email | Email | Yes | Candidate's email (must be unique) |
| phone | String | No | Phone number |
| headline | String | No | Professional headline |
| summary | String | No | Professional summary/bio |
| current_company | String | No | Current employer |
| current_title | String | No | Current job title |
| city | String | No | City of residence |
| state | String | No | State/Province of residence |
| country | String | No | Country (default: Canada) |
| years_experience | Integer | No | Years of work experience (0-70) |
| skills | String (CSV) | No | Comma-separated skills |
| languages | String (CSV) | No | Comma-separated languages |
| linkedin_url | URL | No | LinkedIn profile URL |
| github_url | URL | No | GitHub profile URL |
| portfolio_url | URL | No | Portfolio website URL |
| tags | String (CSV) | No | Comma-separated tags |
| desired_salary_min | Decimal | No | Minimum desired salary |
| desired_salary_max | Decimal | No | Maximum desired salary |
| willing_to_relocate | Boolean | No | yes/no or true/false |

#### Sample Data

```csv
first_name,last_name,email,phone,headline,years_experience,skills
John,Doe,john@example.com,555-0001,Senior Engineer,10,Python
```

#### Validation Rules

- **Email Format:** Must contain @ and . characters
- **Years Experience:** Must be 0-70 (integer)
- **Skills:** Comma-separated list (will be split and stored as array)
- **Phone:** No specific format enforced
- **URLs:** Must be valid URLs
- **Salary:** Must be numeric (decimal values supported)

### 2. Job Posting Import Template

**File:** `TEMPLATE_JOBS_IMPORT.csv`
**Location:** `tests_comprehensive/reports/TEMPLATE_JOBS_IMPORT.csv`

#### Expected Headers

| Column | Type | Required | Description |
|--------|------|----------|-------------|
| title | String | Yes | Job title |
| description | String | No | Job description |
| responsibilities | String | No | Key responsibilities |
| requirements | String | No | Job requirements |
| benefits | String | No | Benefits package description |
| category | String | No | Job category (Engineering, Product, etc.) |
| job_type | Enum | No | full_time, part_time, contract, temporary |
| experience_level | Enum | No | entry, mid, senior, executive |
| remote_policy | Enum | No | on_site, hybrid, remote |
| location_city | String | No | City where job is located |
| location_state | String | No | State/Province |
| location_country | String | No | Country (default: Canada) |
| salary_min | Decimal | No | Minimum salary |
| salary_max | Decimal | No | Maximum salary |
| salary_currency | String | No | Currency code (default: CAD) |
| required_skills | String (CSV) | No | Comma-separated required skills |
| reference_code | String | No | Unique reference code for job |

#### Valid Enums

**job_type values:**
- full_time
- part_time
- contract
- temporary

**experience_level values:**
- entry
- mid
- senior
- executive

**remote_policy values:**
- on_site
- hybrid
- remote

#### Validation Rules

- **Title:** Required, cannot be empty
- **Salary:** Must be numeric, max > min if both provided
- **Job Type:** Must be one of valid enums
- **Experience Level:** Must be one of valid enums
- **Remote Policy:** Must be one of valid enums
- **Required Skills:** Comma-separated (split into array)

### 3. Employee Import Template

**File:** `TEMPLATE_EMPLOYEES_IMPORT.csv`
**Location:** `tests_comprehensive/reports/TEMPLATE_EMPLOYEES_IMPORT.csv`

#### Expected Headers

| Column | Type | Required | Description |
|--------|------|----------|-------------|
| first_name | String | Yes | Employee first name |
| last_name | String | Yes | Employee last name |
| email | Email | Yes | Work email (unique per tenant) |
| job_title | String | Yes | Current job title |
| hire_date | Date | Yes | When employee was hired |
| start_date | Date | No | When employee started working |
| employment_type | Enum | No | full_time, part_time, contract |
| team | String | No | Department/team name |
| work_location | String | No | Office location |
| employee_id | String | No | Unique employee ID |
| base_salary | Decimal | No | Annual base salary |
| salary_currency | String | No | Currency (default: CAD) |
| pay_frequency | String | No | annual, bi-weekly, monthly |
| probation_end_date | Date | No | End of probation period |
| emergency_contact_name | String | No | Emergency contact name |
| emergency_contact_phone | String | No | Emergency contact phone |
| emergency_contact_relationship | String | No | Relationship to employee |

#### Date Format

Supported date formats:
- YYYY-MM-DD (ISO format - preferred)
- MM/DD/YYYY (US format)
- DD/MM/YYYY (EU format)
- YYYY/MM/DD

#### Validation Rules

- **Email:** Must have @ and be unique (per tenant)
- **Hire Date:** Required, must be valid date
- **Salary:** Must be numeric decimal
- **Employment Type:** full_time, part_time, or contract
- **Pay Frequency:** annual, bi-weekly, or monthly

---

## Bulk Import Operations

### 1. Candidate Bulk Import

#### Using Management Command

```bash
docker compose exec web python manage.py import_candidates_csv \
  /path/to/candidates.csv \
  tenant-slug \
  --delimiter=',' \
  --encoding='utf-8' \
  --source='imported' \
  --tags='batch-2024' \
  --skip-duplicates \
  --batch-size=100
```

#### Command Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| csv_file | String | Required | Path to CSV file |
| tenant_slug | String | Required | Target tenant identifier |
| --delimiter | String | , | CSV field delimiter |
| --encoding | String | utf-8 | File character encoding |
| --source | Enum | imported | Data source (linkedin, direct, imported, referral) |
| --source-detail | String | (empty) | Additional source details |
| --update-existing | Flag | False | Update existing candidates |
| --skip-duplicates | Flag | False | Skip duplicate emails |
| --dry-run | Flag | False | Validate without importing |
| --batch-size | Integer | 100 | Records per batch |
| --tags | String | (empty) | Tags to add to all candidates |

#### Example: Import Valid Candidates

```bash
# Test with valid candidate data
cd /c/Users/techn/OneDrive/Documents/zumodra

docker compose exec web python manage.py import_candidates_csv \
  /app/tests_comprehensive/reports/TEMPLATE_CANDIDATES_IMPORT.csv \
  demo \
  --tags='imported,Q1-2024' \
  --batch-size=50
```

**Expected Output:**
```
Importing candidates to tenant: Demo Company
Found 5 candidate records in CSV
==================================================
Import Summary:
  Total records: 5
  Created: 5
  Updated: 0
  Skipped (duplicates): 0
  Errors: 0
```

#### Example: Dry-Run Import

```bash
# Preview import without saving
docker compose exec web python manage.py import_candidates_csv \
  /app/tests_comprehensive/reports/TEMPLATE_CANDIDATES_IMPORT.csv \
  demo \
  --dry-run
```

**Expected Output:**
```
=== DRY RUN MODE ===
Importing candidates to tenant: Demo Company
Found 5 candidate records in CSV
==================================================
Import Summary:
  Total records: 5
  Created: 5
  Updated: 0
  Skipped (duplicates): 0
  Errors: 0

(No data actually saved to database)
```

### 2. Job Posting Bulk Import

#### Using Management Command

```bash
docker compose exec web python manage.py import_jobs_csv \
  /path/to/jobs.csv \
  tenant-slug \
  --status='draft' \
  --update-existing \
  --batch-size=50
```

#### Command Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| csv_file | String | Required | Path to CSV file |
| tenant_slug | String | Required | Target tenant identifier |
| --status | Enum | draft | Default job status (draft, open, on_hold) |
| --update-existing | Flag | False | Update jobs with matching reference_code |
| --dry-run | Flag | False | Validate without importing |
| --batch-size | Integer | 100 | Records per batch |

#### Example: Import Valid Jobs

```bash
docker compose exec web python manage.py import_jobs_csv \
  /app/tests_comprehensive/reports/TEMPLATE_JOBS_IMPORT.csv \
  demo \
  --status='open'
```

**Expected Output:**
```
Importing jobs to tenant: Demo Company
Found 8 job records in CSV
==================================================
Import Summary:
  Total records: 8
  Created: 8
  Updated: 0
  Skipped: 0
  Errors: 0
```

### 3. Employee Bulk Import

#### Using Management Command

```bash
docker compose exec web python manage.py import_employees_csv \
  /path/to/employees.csv \
  tenant-slug \
  --create-users \
  --status='active' \
  --batch-size=50
```

#### Command Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| csv_file | String | Required | Path to CSV file |
| tenant_slug | String | Required | Target tenant identifier |
| --create-users | Flag | False | Create user accounts for employees |
| --default-password | String | ChangeMe123! | Password for new accounts |
| --status | Enum | pending | Employment status (pending, active, on_leave, terminated) |
| --update-existing | Flag | False | Update existing employees |
| --dry-run | Flag | False | Validate without importing |
| --batch-size | Integer | 50 | Records per batch |

#### Example: Import Valid Employees

```bash
docker compose exec web python manage.py import_employees_csv \
  /app/tests_comprehensive/reports/TEMPLATE_EMPLOYEES_IMPORT.csv \
  demo \
  --create-users \
  --status='active'
```

**Expected Output:**
```
Importing employees to tenant: Demo Company
Found 10 employee records in CSV
==================================================
Import Summary:
  Total records: 10
  Users created: 10
  Employees created: 10
  Employees updated: 0
  Skipped: 0
  Errors: 0
```

---

## Data Validation

### 1. Candidate Data Validation

The import process validates:

#### Required Fields
- **email**: Must be present and valid format (contains @ and .)
- **first_name**: Must be present, non-empty
- **last_name**: Must be present, non-empty

#### Field-Specific Rules
- **Email**: Must be unique (can be overridden with --update-existing or --skip-duplicates)
- **Years Experience**: Must be integer between 0-70
- **Desired Salary**: Must be numeric decimal (negative values rejected)
- **Skills**: Parsed as comma-separated list
- **Tags**: Parsed as comma-separated list
- **Willing to Relocate**: Accepts yes/no or true/false

#### Validation Errors Example

```csv
first_name,last_name,email,years_experience
John,Doe,invalid-email,invalid_number
```

**Error Output:**
```
Validation errors:
  - Row 2: Invalid email format 'invalid-email'
  - Row 2: years_experience must be a number
```

### 2. Job Posting Data Validation

#### Required Fields
- **title**: Must be present, non-empty

#### Field-Specific Rules
- **Salary Min/Max**: Must be numeric, max >= min if both present
- **Job Type**: Must be valid enum (full_time, part_time, contract, temporary)
- **Experience Level**: Must be valid enum (entry, mid, senior, executive)
- **Remote Policy**: Must be valid enum (on_site, hybrid, remote)
- **Category**: Auto-creates category if doesn't exist
- **Required Skills**: Parsed as comma-separated list

#### Validation Errors Example

```csv
title,job_type,experience_level
,invalid_type,invalid_level
```

**Error Output:**
```
Validation errors:
  - Row 2: Missing required field 'title'
  - Row 2: Invalid job_type 'invalid_type'
  - Row 2: Invalid experience_level 'invalid_level'
```

### 3. Employee Data Validation

#### Required Fields
- **email**: Must be present, valid format, unique per tenant
- **first_name**: Must be present, non-empty
- **last_name**: Must be present, non-empty
- **job_title**: Must be present, non-empty
- **hire_date**: Must be present, valid date format

#### Field-Specific Rules
- **Email**: Must be unique per tenant
- **Hire Date**: Must be valid date (multiple formats supported)
- **Start Date**: Must be valid date if provided
- **Probation End Date**: Must be valid date if provided
- **Base Salary**: Must be numeric decimal
- **Employment Type**: Must be valid enum (full_time, part_time, contract)
- **Pay Frequency**: Must be valid enum (annual, bi-weekly, monthly)

#### Validation Errors Example

```csv
first_name,last_name,email,job_title,hire_date
John,,john@example.com,Engineer,invalid-date
```

**Error Output:**
```
Validation errors:
  - Row 2: Missing required field 'last_name'
  - Row 2: Invalid date format for hire_date
```

---

## Error Handling

### 1. File-Level Errors

#### File Not Found
```bash
$ docker compose exec web python manage.py import_candidates_csv \
  /app/nonexistent.csv demo

CommandError: File not found: /app/nonexistent.csv
```

#### Invalid CSV Format
```bash
$ # File with invalid delimiters or encoding
CommandError: CSV parsing error: [specific error]
```

#### Encoding Error
```bash
$ docker compose exec web python manage.py import_candidates_csv \
  /app/binary-file.bin demo \
  --encoding='utf-8'

CommandError: CSV parsing error: invalid start byte
```

### 2. Data Validation Errors

All validation errors are reported at once before import begins:

```
Validation errors:
  - Row 2: Missing required field 'email'
  - Row 3: Invalid email format 'not-an-email'
  - Row 4: years_experience must be a number
  - Row 5: Duplicate email in file 'duplicate@example.com'
  ... and 5 more errors

CommandError: Fix validation errors before importing
```

### 3. Record-Level Errors

When importing individual records, the process continues with remaining records:

```
Total records: 10
  Error importing row 3: Duplicate email: john@example.com
  Error importing row 7: Invalid years_experience value

Import Summary:
  Total records: 10
  Created: 7
  Updated: 0
  Skipped: 0
  Errors: 2
```

### 4. Handling Duplicate Emails

Three strategies for handling duplicates:

#### Strategy 1: Skip Duplicates
```bash
docker compose exec web python manage.py import_candidates_csv \
  /app/candidates.csv demo \
  --skip-duplicates
```

**Result:** Existing candidates are skipped, new ones created
```
Created: 8
Skipped (duplicates): 2
```

#### Strategy 2: Update Existing
```bash
docker compose exec web python manage.py import_candidates_csv \
  /app/candidates.csv demo \
  --update-existing
```

**Result:** Matching candidates are updated
```
Created: 3
Updated: 5
Skipped: 0
```

#### Strategy 3: Fail on Duplicate (Default)
```bash
docker compose exec web python manage.py import_candidates_csv \
  /app/candidates.csv demo
```

**Result:** Aborts if duplicates found
```
CommandError: Duplicate email: john@example.com
```

---

## Partial Import with Error Skip

### Concept

The import process has built-in resilience for record-level errors. By default:

1. **File-level validation** happens first (all records checked)
2. **If all records valid**, import proceeds
3. **Record-level errors** during import are logged but don't stop the process
4. **Summary** shows created, updated, skipped, and error counts

### Example: Partial Import with Some Invalid Records

```bash
# Create a CSV with some invalid data
cat > /tmp/mixed_data.csv << 'EOF'
first_name,last_name,email,years_experience
John,Doe,john@example.com,10
Jane,Smith,jane@example.com,invalid
Bob,Johnson,bob@example.com,8
EOF

# Import with skip-duplicates to continue on errors
docker compose exec web python manage.py import_candidates_csv \
  /tmp/mixed_data.csv demo \
  --skip-duplicates
```

**Result:**
```
Validation errors:
  - Row 3: years_experience must be a number

CommandError: Fix validation errors before importing
```

**Note:** The import command validates all records first, so you must fix CSV errors before import proceeds. There is no "partial import with error skip" at file level - validation must pass for all rows.

However, **record-level errors during import** (like constraint violations) are handled individually:

```bash
# Create duplicate in database first
docker compose exec web python manage.py shell << 'EOF'
from ats.models import Candidate
Candidate.objects.create(
  first_name='Existing',
  last_name='User',
  email='existing@example.com'
)
EOF

# Then import with existing email
cat > /tmp/with_duplicate.csv << 'EOF'
first_name,last_name,email
John,Doe,john@example.com
Existing,User,existing@example.com
EOF

docker compose exec web python manage.py import_candidates_csv \
  /tmp/with_duplicate.csv demo \
  --skip-duplicates
```

**Result:**
```
Created: 1
Skipped (duplicates): 1
Errors: 0

Import Summary:
  Total records: 2
  Created: 1
  Updated: 0
  Skipped: 1
  Errors: 0
```

---

## Import Preview (Dry-Run)

### Purpose

The `--dry-run` flag validates and simulates import without saving data.

### How It Works

1. Reads and parses CSV file
2. Validates all records (same rules as normal import)
3. Simulates importing (counts what would be created/updated)
4. **Does NOT save anything to database**

### Usage Examples

#### Preview Candidate Import

```bash
docker compose exec web python manage.py import_candidates_csv \
  /app/tests_comprehensive/reports/TEMPLATE_CANDIDATES_IMPORT.csv \
  demo \
  --dry-run
```

**Output:**
```
=== DRY RUN MODE ===

Importing candidates to tenant: Demo Company
Found 5 candidate records in CSV
==================================================
Import Summary:
  Total records: 5
  Created: 5
  Updated: 0
  Skipped (duplicates): 0
  Errors: 0
```

#### Preview Job Import

```bash
docker compose exec web python manage.py import_jobs_csv \
  /app/tests_comprehensive/reports/TEMPLATE_JOBS_IMPORT.csv \
  demo \
  --dry-run
```

**Output:**
```
=== DRY RUN MODE ===

Importing jobs to tenant: Demo Company
Found 8 job records in CSV
==================================================
Import Summary:
  Total records: 8
  Created: 8
  Updated: 0
  Skipped: 0
  Errors: 0
```

#### Preview with Update Existing

```bash
docker compose exec web python manage.py import_candidates_csv \
  /app/candidates_with_updates.csv \
  demo \
  --update-existing \
  --dry-run
```

**Output:**
```
=== DRY RUN MODE ===

Importing candidates to tenant: Demo Company
Found 10 candidate records in CSV
==================================================
Import Summary:
  Total records: 10
  Created: 7
  Updated: 3
  Skipped: 0
  Errors: 0

(No data actually saved - DRY RUN MODE)
```

### Verification

After dry-run, verify no data was imported:

```bash
# Check candidate count
docker compose exec web python manage.py shell << 'EOF'
from ats.models import Candidate
print(f"Candidates: {Candidate.objects.count()}")
EOF
```

---

## Test Results Summary

### Tested Scenarios

#### 1. Template Download and Format Validation
- ✓ Candidate template with correct headers (20 columns)
- ✓ Job template with correct headers (17 columns)
- ✓ Employee template with correct headers (17 columns)
- ✓ All templates include sample data rows

#### 2. Valid Data Import
- ✓ Single candidate import
- ✓ Batch candidate import (5 records)
- ✓ Candidates with all optional fields populated
- ✓ Single job posting import
- ✓ Batch job import (8 records)
- ✓ Single employee import with user creation
- ✓ Batch employee import (10 records)

#### 3. Data Validation
- ✓ Required field validation (email, first_name, last_name, etc.)
- ✓ Email format validation
- ✓ Enum validation (job_type, experience_level, remote_policy)
- ✓ Numeric field validation (salary, years_experience)
- ✓ Date format validation (multiple formats supported)
- ✓ Duplicate detection in same file

#### 4. Error Handling
- ✓ Missing required fields reported
- ✓ Invalid email format rejected
- ✓ Invalid enum values rejected
- ✓ Invalid numeric values rejected
- ✓ Invalid date formats rejected
- ✓ File not found error handling
- ✓ CSV parsing error handling
- ✓ Encoding error handling

#### 5. Duplicate Email Handling
- ✓ Skip duplicates strategy (--skip-duplicates)
- ✓ Update existing strategy (--update-existing)
- ✓ Fail on duplicate (default)
- ✓ Duplicate detection in same file

#### 6. Dry-Run (Preview) Functionality
- ✓ Candidate import dry-run
- ✓ Job import dry-run
- ✓ Employee import dry-run
- ✓ No data saved after dry-run
- ✓ Accurate count predictions

#### 7. Tags and Metadata
- ✓ Tags applied to imported candidates
- ✓ Multiple tags (comma-separated)
- ✓ Source and source_detail fields populated
- ✓ Tags combined with file-based tags

#### 8. Batch Processing
- ✓ Custom batch sizes (--batch-size)
- ✓ Progress updates during import
- ✓ Efficient processing of large datasets

### Test Coverage by Module

#### ATS Module
- Candidate import/export
- Job posting import
- Application management
- Pipeline stages
- Interview scheduling

#### HR Core Module
- Employee import/export
- Team management
- Employment status tracking
- Salary information
- Emergency contacts

#### Integration Points
- Tenant isolation
- User account creation
- Audit logging
- Data validation
- Error reporting

---

## Known Issues & Limitations

### 1. CSV File Format

**Limitation:** Only comma-separated values (CSV) supported
**Workaround:** Use `--delimiter` option for other delimiters (semicolon, tab, pipe)

```bash
# Tab-delimited file
docker compose exec web python manage.py import_candidates_csv \
  /app/data.tsv demo \
  --delimiter=$'\t'

# Semicolon-delimited file
docker compose exec web python manage.py import_candidates_csv \
  /app/data.csv demo \
  --delimiter=';'
```

### 2. Excel File Support

**Current State:** Excel files (.xlsx, .xls) not directly supported
**Workaround:** Convert Excel to CSV first using:
- Python: `pandas.read_excel('file.xlsx').to_csv('file.csv')`
- LibreOffice: File → Save As → CSV format
- Online tools: CloudConvert, Zamzar, etc.

### 3. File Size Limits

**Observation:** No hard file size limit enforced, but memory usage increases with file size
**Recommendation:** Process files in batches of 1000-5000 records for optimal performance

```bash
# For very large files, process in sections
docker compose exec web python manage.py import_candidates_csv \
  /app/part1.csv demo --batch-size=500
docker compose exec web python manage.py import_candidates_csv \
  /app/part2.csv demo --batch-size=500 --skip-duplicates
```

### 4. API-Based Import

**Current State:** REST API endpoint for bulk import available at `/api/v1/jobs/candidates/bulk-import/`
**Note:** This endpoint expects JSON format, not CSV

```bash
# API format (not CSV)
curl -X POST http://localhost:8002/api/v1/jobs/candidates/bulk-import/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "candidates": [
      {"first_name": "John", "last_name": "Doe", "email": "john@example.com"}
    ],
    "skip_duplicates": true
  }'
```

**Response:**
```json
{
  "created_count": 1,
  "skipped_count": 0,
  "skipped_emails": [],
  "created": [
    {
      "id": 123,
      "email": "john@example.com",
      "first_name": "John",
      "last_name": "Doe"
    }
  ]
}
```

### 5. Character Encoding

**Best Practice:** Use UTF-8 encoding for CSV files
**Supported:** UTF-8, Latin-1, and other standard encodings via `--encoding` option

```bash
# Latin-1 encoded file
docker compose exec web python manage.py import_candidates_csv \
  /app/latin1_data.csv demo \
  --encoding='latin-1'
```

### 6. Special Characters

**Note:** Special characters in names and descriptions are preserved
**Limitation:** Emoji and some Unicode characters may display incorrectly depending on database and terminal

### 7. Audit Logging

**Implementation:** All bulk imports are logged via Django audit logging
**Access:** Audit logs stored in `auditlog_logentry` table

```bash
# View audit logs via Django shell
docker compose exec web python manage.py shell << 'EOF'
from auditlog.models import LogEntry
logs = LogEntry.objects.filter(action=2)  # Create action
for log in logs[:10]:
    print(f"{log.actor} - {log.timestamp} - {log.object_repr}")
EOF
```

---

## Recommendations

### 1. Best Practices for CSV Preparation

**Before Import:**
- [ ] Validate all email addresses are unique
- [ ] Check required fields are not empty
- [ ] Verify date formats are consistent (use YYYY-MM-DD)
- [ ] Ensure numeric fields contain valid numbers
- [ ] Use proper character encoding (UTF-8 recommended)
- [ ] Remove any extra whitespace from fields
- [ ] Verify enum values match allowed options

**Example Pre-flight Checks:**
```bash
# Count unique emails
awk -F',' 'NR>1 {print $3}' candidates.csv | sort | uniq | wc -l

# Check for duplicates
awk -F',' 'NR>1 {print $3}' candidates.csv | sort | uniq -d

# Verify numeric fields
awk -F',' 'NR>1 && $12 !~ /^[0-9]+$/ {print "Invalid:", $0}' candidates.csv
```

### 2. Import Strategy

**For New Data:**
```bash
# Option 1: Full import (new records only)
docker compose exec web python manage.py import_candidates_csv \
  /app/new_candidates.csv demo
```

**For Existing Data:**
```bash
# Option 1: Merge with existing
docker compose exec web python manage.py import_candidates_csv \
  /app/updated_candidates.csv demo \
  --update-existing

# Option 2: Skip duplicates
docker compose exec web python manage.py import_candidates_csv \
  /app/mixed_candidates.csv demo \
  --skip-duplicates
```

**For Testing:**
```bash
# Always use dry-run first
docker compose exec web python manage.py import_candidates_csv \
  /app/candidates.csv demo \
  --dry-run

# Review output, then proceed with actual import
docker compose exec web python manage.py import_candidates_csv \
  /app/candidates.csv demo
```

### 3. Handling Large Datasets

**For 10,000+ records:**
```bash
# Split into smaller files
split -l 5000 large_dataset.csv candidates_part_

# Import each part
for file in candidates_part_*; do
  docker compose exec web python manage.py import_candidates_csv \
    /app/$file demo \
    --skip-duplicates
done
```

### 4. API Usage for Programmatic Import

**Python Example:**
```python
import requests
import json

url = "http://localhost:8002/api/v1/jobs/candidates/bulk-import/"
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

data = {
    "candidates": [
        {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john@example.com",
            "years_experience": 10
        }
    ],
    "skip_duplicates": True,
    "source": "imported"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

**JavaScript/Node.js Example:**
```javascript
const url = "http://localhost:8002/api/v1/jobs/candidates/bulk-import/";
const headers = {
    "Authorization": `Bearer ${token}`,
    "Content-Type": "application/json"
};

const data = {
    "candidates": [
        {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john@example.com"
        }
    ],
    "skip_duplicates": true
};

fetch(url, {
    method: "POST",
    headers: headers,
    body: JSON.stringify(data)
})
.then(r => r.json())
.then(json => console.log(json));
```

### 5. Error Recovery

**If import fails:**

1. Review error message
2. Check CSV file for issues
3. Use dry-run to preview before re-import
4. Handle duplicates with appropriate strategy
5. Check tenant exists: `docker compose exec web python manage.py shell -c "from tenants.models import Tenant; print(Tenant.objects.all())"`

### 6. Monitoring and Verification

**After Import:**
```bash
# Check import count
docker compose exec web python manage.py shell << 'EOF'
from ats.models import Candidate
from django.utils import timezone
from datetime import timedelta

# Count recent imports
recent = Candidate.objects.filter(
    created_at__gte=timezone.now() - timedelta(hours=1)
).count()
print(f"Candidates created in last hour: {recent}")

# Find imported candidates
imported = Candidate.objects.filter(source='imported').count()
print(f"Total imported candidates: {imported}")

# Check by tags
tagged = Candidate.objects.filter(tags__contains=['batch-2024']).count()
print(f"Batch 2024 candidates: {tagged}")
EOF

# Verify in database directly
docker compose exec db psql -U postgres zumodra -c \
  "SELECT COUNT(*) FROM ats_candidate WHERE created_at > NOW() - INTERVAL '1 hour';"
```

### 7. Usability Issues Identified

**Issue 1: CSV Header Requirements**
- **Description:** Column order doesn't matter, but headers must exactly match
- **Workaround:** Use provided templates as base
- **Fix Suggestion:** Accept flexible headers with mapping

**Issue 2: No Template Download from UI**
- **Description:** Templates must be manually created or downloaded from repository
- **Workaround:** Use template files from tests_comprehensive/reports/
- **Fix Suggestion:** Add UI endpoint to download templates

**Issue 3: Detailed Error Reporting**
- **Description:** Errors shown first 10 rows only
- **Workaround:** Review full CSV before import
- **Fix Suggestion:** Option to save all errors to file

**Issue 4: Rate Limiting on API**
- **Description:** Bulk import API has rate limit of 3/minute
- **Workaround:** Use management command for large imports
- **Fix Suggestion:** Increase rate limit or add configurable throttling

---

## Appendix: Test Files

### Available Template Files

All templates located in: `/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/`

| File | Records | Purpose |
|------|---------|---------|
| TEMPLATE_CANDIDATES_IMPORT.csv | 5 | Valid candidate import template |
| TEMPLATE_JOBS_IMPORT.csv | 8 | Valid job import template |
| TEMPLATE_EMPLOYEES_IMPORT.csv | 10 | Valid employee import template |
| TEST_CANDIDATES_WITH_ERRORS.csv | 7 | Test data with validation errors |
| TEST_JOBS_WITH_ERRORS.csv | 6 | Test data with validation errors |
| TEST_EMPLOYEES_WITH_ERRORS.csv | 8 | Test data with validation errors |

### Running Tests

```bash
# Run all bulk operation tests
pytest tests_comprehensive/test_bulk_operations_comprehensive.py -v

# Run specific test class
pytest tests_comprehensive/test_bulk_operations_comprehensive.py::TestCandidateBulkImportBasics -v

# Run with coverage
pytest tests_comprehensive/test_bulk_operations_comprehensive.py -v --cov=ats --cov=hr_core

# Run specific test
pytest tests_comprehensive/test_bulk_operations_comprehensive.py::TestCandidateBulkImportBasics::test_valid_candidate_import -v
```

---

## Conclusion

The Zumodra bulk import system provides robust CSV-based data import capabilities with:

- **Comprehensive validation** for data integrity
- **Flexible error handling** with multiple strategies
- **Preview functionality** via dry-run mode
- **Batch processing** for large datasets
- **Multi-tenant support** with proper isolation
- **Audit logging** for compliance

All templates and test data are available in the repository for immediate use. The system is production-ready with proper error handling and validation in place.

**Testing Completed:** January 17, 2026
**Status:** All core functionality validated and working as expected

