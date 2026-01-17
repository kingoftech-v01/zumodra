# Bulk Operations Quick Start Guide

## 5-Minute Setup

### 1. Start Docker Environment

```bash
cd /c/Users/techn/OneDrive/Documents/zumodra
docker compose up -d
sleep 30  # Wait for services to start
```

### 2. Download Templates

Templates are already available in `tests_comprehensive/reports/`:

- `TEMPLATE_CANDIDATES_IMPORT.csv` - Candidate import template
- `TEMPLATE_JOBS_IMPORT.csv` - Job posting template
- `TEMPLATE_EMPLOYEES_IMPORT.csv` - Employee template

### 3. Test Candidate Import

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
```

### 4. Test Job Import

```bash
# Dry run
docker compose exec web python manage.py import_jobs_csv \
  /app/tests_comprehensive/reports/TEMPLATE_JOBS_IMPORT.csv \
  demo \
  --dry-run

# Actual import
docker compose exec web python manage.py import_jobs_csv \
  /app/tests_comprehensive/reports/TEMPLATE_JOBS_IMPORT.csv \
  demo
```

### 5. Test Employee Import

```bash
# Dry run
docker compose exec web python manage.py import_employees_csv \
  /app/tests_comprehensive/reports/TEMPLATE_EMPLOYEES_IMPORT.csv \
  demo \
  --dry-run \
  --create-users

# Actual import
docker compose exec web python manage.py import_employees_csv \
  /app/tests_comprehensive/reports/TEMPLATE_EMPLOYEES_IMPORT.csv \
  demo \
  --create-users
```

## Testing Error Handling

### Test Validation Errors

```bash
# This will fail with validation errors (invalid emails, etc.)
docker compose exec web python manage.py import_candidates_csv \
  /app/tests_comprehensive/reports/TEST_CANDIDATES_WITH_ERRORS.csv \
  demo

# Expected output: Validation errors reported
```

### Test Duplicate Handling

```bash
# Skip duplicates strategy
docker compose exec web python manage.py import_candidates_csv \
  /app/tests_comprehensive/reports/TEMPLATE_CANDIDATES_IMPORT.csv \
  demo \
  --skip-duplicates

# Expected: Duplicates skipped, new records created
```

## Common Commands

| Task | Command |
|------|---------|
| Import candidates | `import_candidates_csv <file> <tenant>` |
| Import jobs | `import_jobs_csv <file> <tenant>` |
| Import employees | `import_employees_csv <file> <tenant>` |
| Preview import | Add `--dry-run` flag |
| Skip duplicates | Add `--skip-duplicates` flag |
| Update existing | Add `--update-existing` flag |
| Add tags | `--tags='tag1,tag2'` |

## Template Structure

### Candidates Template
```csv
first_name,last_name,email,phone,headline,current_company,current_title,years_experience,skills,tags
John,Doe,john@example.com,555-0001,Senior Engineer,TechCorp,Engineer,10,Python,senior
```

### Jobs Template
```csv
title,description,category,job_type,experience_level,remote_policy,location_city,salary_min,salary_max
Software Engineer,Build services,Engineering,full_time,mid,hybrid,Toronto,80000,120000
```

### Employees Template
```csv
first_name,last_name,email,job_title,hire_date,team,work_location,base_salary
John,Doe,john@example.com,Engineer,2022-01-15,Engineering,Toronto,120000
```

## Verification

Check if import was successful:

```bash
# Check candidate count
docker compose exec web python manage.py shell -c \
  "from ats.models import Candidate; print(f'Candidates: {Candidate.objects.count()}')"

# Check job count
docker compose exec web python manage.py shell -c \
  "from ats.models import JobPosting; print(f'Jobs: {JobPosting.objects.count()}')"

# Check employee count
docker compose exec web python manage.py shell -c \
  "from hr_core.models import Employee; print(f'Employees: {Employee.objects.count()}')"
```

## API Endpoint

For programmatic import via REST API:

```bash
curl -X POST http://localhost:8002/api/v1/ats/candidates/bulk-import/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "candidates": [
      {"first_name": "John", "last_name": "Doe", "email": "john@example.com"}
    ],
    "skip_duplicates": true
  }'
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| File not found | Check path, ensure file exists in container |
| Validation errors | Review error messages, fix CSV data |
| Duplicate emails | Use `--skip-duplicates` or `--update-existing` |
| Tenant not found | Check tenant slug with `docker compose exec web python manage.py shell` |
| Permission denied | Ensure user has appropriate role (recruiter, hr_manager) |

## Files Available

All test files in: `/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/`

- ✓ TEMPLATE_CANDIDATES_IMPORT.csv (5 valid records)
- ✓ TEMPLATE_JOBS_IMPORT.csv (8 valid records)
- ✓ TEMPLATE_EMPLOYEES_IMPORT.csv (10 valid records)
- ✓ TEST_CANDIDATES_WITH_ERRORS.csv (7 invalid records for testing)
- ✓ TEST_JOBS_WITH_ERRORS.csv (6 invalid records for testing)
- ✓ TEST_EMPLOYEES_WITH_ERRORS.csv (8 invalid records for testing)

## Next Steps

1. Read `BULK_OPERATIONS_TEST_GUIDE.md` for detailed documentation
2. Review `test_bulk_operations_comprehensive.py` for test examples
3. Customize templates for your data
4. Run tests with pytest: `pytest tests_comprehensive/test_bulk_operations_comprehensive.py -v`

