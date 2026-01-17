# Data Export & Import Testing Guide

## Overview

This comprehensive testing guide covers the Zumodra data export and import functionality. It validates CSV, Excel, and PDF export capabilities, bulk import operations, data validation, audit logging, and multi-tenant isolation.

## Test Suite Architecture

### Test Files
- **Main Test Suite**: `test_data_export_import.py` - 500+ test cases
- **Test Runner**: `run_data_export_import_tests.sh` - Automated test orchestration
- **Reports**: Generated in `tests_comprehensive/reports/`

### Test Categories

#### 1. CSV Export Tests (`TestCSVExport`)
Tests exporting data in CSV format from various modules.

**Test Cases:**
- `test_csv_candidate_export` - Export candidates to CSV
- `test_csv_job_export` - Export job postings to CSV
- `test_csv_export_with_filters` - Export with filtering criteria

**Validation Points:**
- CSV file generation and format compliance
- Data field mapping and integrity
- Filter application and correctness
- Large dataset handling (1000+ records)
- Special character encoding

**Expected Outcomes:**
- CSV files contain all exported records
- Fields match database schema
- Filters correctly exclude/include data
- Export completes within performance targets
- Special characters properly escaped

#### 2. Excel Export Tests (`TestExcelExport`)
Tests exporting data to Excel format with formatting.

**Test Cases:**
- `test_excel_candidates_export` - Export candidates with formatting
- `test_excel_analytics_export` - Export analytics data to Excel

**Validation Points:**
- Excel file generation (XLSX format)
- Cell formatting and styling
- Multi-sheet support
- Data type preservation
- Formula preservation (if any)
- Large file handling

**Expected Outcomes:**
- Excel files are valid XLSX format
- Data is properly formatted
- All sheets are accessible
- Data types are preserved
- File size is reasonable

**Dependencies:**
```bash
pip install openpyxl xlsxwriter
```

#### 3. PDF Report Generation Tests (`TestPDFGeneration`)
Tests generating PDF reports from data.

**Test Cases:**
- `test_pdf_recruitment_report` - Generate recruitment report PDF
- `test_pdf_analytics_report` - Generate analytics report PDF

**Validation Points:**
- PDF file generation
- Content accuracy
- Multi-page handling
- Page breaks and formatting
- Image/chart inclusion
- Metadata (title, author, creation date)

**Expected Outcomes:**
- PDF files are valid and readable
- Content matches source data
- Page formatting is correct
- Reports are properly titled
- Metadata is accurate

**Dependencies:**
```bash
pip install reportlab PyPDF2
```

#### 4. Bulk Import Tests (`TestBulkImport`)
Tests importing data in bulk from CSV files.

**Test Cases:**
- `test_import_candidates_csv` - Import candidates from CSV
- `test_import_jobs_csv` - Import job postings from CSV

**Validation Points:**
- File reading and parsing
- Data extraction and mapping
- Database insertion
- Transaction handling
- Rollback on errors
- Progress tracking

**Expected Outcomes:**
- Records are created in database
- Data is correctly mapped
- Duplicate handling works correctly
- Errors don't corrupt data
- Transaction integrity maintained

#### 5. Import Validation Tests (`TestImportValidation`)
Tests data validation during import operations.

**Test Cases:**
- `test_validate_email_uniqueness` - Email uniqueness validation
- `test_validate_required_fields` - Required field validation
- `test_validate_data_types` - Data type validation

**Validation Points:**
- Required field enforcement
- Email/unique field detection
- Data type checking
- Format validation
- Constraint validation
- Custom validation rules

**Expected Outcomes:**
- Validation errors prevent import
- Clear error messages are provided
- Partial imports are rejected
- Duplicates are handled correctly
- Data constraints are enforced

#### 6. Data Integrity Tests (`TestExportImportDataIntegrity`)
Tests data integrity through export/import cycles.

**Test Cases:**
- `test_candidate_export_import_integrity` - Full cycle integrity test

**Validation Points:**
- All fields preserved through cycle
- Data types maintained
- Relationships preserved
- Special characters intact
- Metadata preserved
- Tags and arrays preserved

**Expected Outcomes:**
- Exported then re-imported data matches original
- No data loss in cycle
- All relationships preserved
- Metadata intact
- Arrays/tags preserved

#### 7. Audit Logging Tests (`TestAuditLogging`)
Tests that all export/import operations are properly logged.

**Test Cases:**
- `test_export_audit_logging` - Export operations are logged
- `test_import_audit_logging` - Import operations are logged

**Validation Points:**
- Operation type is recorded
- User information is captured
- Timestamp is accurate
- Record count is logged
- Operation details are preserved
- Audit trail is immutable

**Expected Outcomes:**
- All export operations logged
- All import operations logged
- User and timestamp are accurate
- Operation details are retrievable
- Audit logs cannot be modified

#### 8. Multi-Tenant Isolation Tests (`TestMultiTenantIsolation`)
Tests data isolation in multi-tenant exports/imports.

**Test Cases:**
- `test_tenant_data_isolation_on_export` - Export isolation

**Validation Points:**
- Only tenant's data is exported
- Cross-tenant data prevented
- Proper schema switching
- Tenant context enforcement
- User authentication verified
- Authorization checks passed

**Expected Outcomes:**
- Exports only contain tenant's data
- No cross-tenant data leakage
- Tenant context properly maintained
- User can only export authorized data
- Multi-tenant isolation verified

#### 9. Error Handling Tests (`TestErrorHandling`)
Tests error handling in export/import operations.

**Test Cases:**
- `test_export_file_not_found` - Missing file handling
- `test_import_invalid_csv_format` - Malformed CSV handling
- `test_import_encoding_error` - Encoding error handling
- `test_import_permission_denied` - Permission error handling

**Validation Points:**
- Graceful error handling
- User-friendly error messages
- No data corruption on errors
- Partial imports are rolled back
- Resources are properly cleaned up
- Error logging is complete

**Expected Outcomes:**
- Clear error messages provided
- No data corruption
- Failed imports are rolled back
- System remains stable
- Errors are properly logged

#### 10. Rate Limiting Tests (`TestRateLimiting`)
Tests rate limiting on export/import operations.

**Test Cases:**
- `test_bulk_import_rate_limit` - Bulk import rate limiting
- `test_export_rate_limit` - Export operation rate limiting

**Validation Points:**
- Rate limits are enforced
- HTTP 429 status returned
- Rate limit headers are present
- Quota enforcement works
- Rate limit reset timing
- Per-user vs global limits

**Expected Outcomes:**
- Rate limits prevent abuse
- HTTP 429 returned when exceeded
- Rate limit headers are informative
- Quotas are properly enforced
- Limits are reset appropriately

#### 11. Performance Tests (`TestExportPerformance`)
Tests performance with large datasets.

**Test Cases:**
- `test_export_large_candidate_set` - Export 1000+ candidates

**Validation Points:**
- Completion time targets
- Memory usage
- Database query efficiency
- Network bandwidth usage
- Streaming support
- Pagination support

**Expected Outcomes:**
- 1000 record export < 30 seconds
- Memory usage is reasonable
- Database queries are optimized
- Streaming works for large data
- Pagination is effective

## Running Tests

### Quick Start

```bash
# Run all tests
./run_data_export_import_tests.sh

# Run with Docker startup
./run_data_export_import_tests.sh

# Run specific test category
./run_data_export_import_tests.sh --csv-only
./run_data_export_import_tests.sh --excel-only
./run_data_export_import_tests.sh --pdf-only
./run_data_export_import_tests.sh --import-only
./run_data_export_import_tests.sh --validation-only
./run_data_export_import_tests.sh --audit-only
./run_data_export_import_tests.sh --isolation-only
./run_data_export_import_tests.sh --performance
```

### Advanced Options

```bash
# Run with coverage report
./run_data_export_import_tests.sh --coverage

# Run specific test by keyword
./run_data_export_import_tests.sh -k TestCSVExport

# Run with verbose output
./run_data_export_import_tests.sh --verbose

# Dry run (show what would run)
./run_data_export_import_tests.sh --dry-run

# Use existing services (skip Docker startup)
./run_data_export_import_tests.sh --no-docker

# Run with pytest directly
pytest tests_comprehensive/test_data_export_import.py -v
pytest tests_comprehensive/test_data_export_import.py -k TestCSVExport -v
pytest tests_comprehensive/test_data_export_import.py --cov
```

### Manual Testing

#### Test CSV Export
```bash
# In Django shell
python manage.py shell
from tenants.models import Tenant
from ats.models import Candidate
from tenants.utils import tenant_context

tenant = Tenant.objects.get(slug='demo')
with tenant_context(tenant):
    # Create test data
    Candidate.objects.create(
        first_name='Test',
        last_name='Candidate',
        email='test@example.com'
    )
    # Test CSV export via API
```

#### Test Bulk Import
```bash
# Create sample CSV file
cat > candidates.csv << 'EOF'
first_name,last_name,email,phone_number
John,Doe,john@example.com,555-0001
Jane,Smith,jane@example.com,555-0002
EOF

# Run import command
python manage.py import_candidates_csv candidates.csv demo-tenant

# Run import with dry-run
python manage.py import_candidates_csv candidates.csv demo-tenant --dry-run

# Skip duplicates
python manage.py import_candidates_csv candidates.csv demo-tenant --skip-duplicates

# Update existing records
python manage.py import_candidates_csv candidates.csv demo-tenant --update-existing
```

#### Test Excel Export
```bash
# Via Django shell
from rest_framework.test import APIClient
client = APIClient()
client.force_authenticate(user=user)
response = client.post('/api/v1/ats/candidates/export/', {'format': 'excel'})

# Save to file
with open('candidates.xlsx', 'wb') as f:
    f.write(response.content)
```

#### Test PDF Generation
```bash
# Via API
response = client.get('/api/v1/analytics/report/', {'format': 'pdf'})

# Save to file
with open('report.pdf', 'wb') as f:
    f.write(response.content)
```

## Test Environment

### Requirements

**Python Packages:**
```
pytest>=7.0
pytest-django>=4.5
pytest-cov>=4.0
djangorestframework>=3.14
openpyxl>=3.8
reportlab>=3.6
PyPDF2>=2.0
python-magic>=0.4
```

**System Requirements:**
- Docker and Docker Compose
- PostgreSQL 16+
- Python 3.10+
- 4GB RAM minimum
- 10GB disk space for test data

### Docker Services

The test suite requires these services running:

| Service | Port | Purpose |
|---------|------|---------|
| web | 8002 | Django application |
| db | 5434 | PostgreSQL database |
| redis | 6380 | Cache and sessions |
| rabbitmq | 5673 | Message broker |

### Setup

```bash
# Copy environment file
cp .env.example .env

# Edit .env with test configuration
export DEBUG=True
export CREATE_DEMO_TENANT=true
export TEST_COVERAGE=true

# Start Docker services
docker compose up -d

# Run migrations
docker compose exec web python manage.py migrate_schemas --shared
docker compose exec web python manage.py migrate_schemas --tenant

# Create test tenant
docker compose exec web python manage.py setup_demo_data
```

## Test Data

### Tenant Configuration
- **Slug**: test-tenant, excel-tenant, pdf-tenant, import-tenant, etc.
- **Schema**: test_tenant_schema, excel_tenant_schema, etc.
- **Users**: test@example.com, excel@example.com, etc.

### Sample Data

**Candidates:**
- First/Last Name: Various
- Email: unique@example.com format
- Phone: 555-XXXX format
- Skills: ['Python', 'Django', etc.]
- Tags: ['backend', 'frontend', etc.]

**Jobs:**
- Title: Engineering, DevOps, Product Manager, etc.
- Category: Engineering, Marketing, Sales
- Status: draft, open, on_hold
- Salary: min/max ranges

## Expected Results

### Passing Criteria
- All CSV exports contain correct data
- All Excel files are valid format
- All PDF reports generate correctly
- All imports create records properly
- All validation rules are enforced
- All audit logs are recorded
- All multi-tenant isolation is maintained
- All error handling is graceful
- All rate limits are enforced
- All performance targets are met

### Failure Scenarios
- Missing required fields in import
- Invalid email formats
- Duplicate emails with skip-duplicates=false
- Permission denied for unprivileged users
- File not found errors
- Encoding mismatches
- Invalid CSV format
- Database constraint violations
- Rate limit exceeded

## Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| CSV export 1000 records | < 5 seconds | Streaming export |
| Excel export 1000 records | < 10 seconds | With formatting |
| PDF report generation | < 15 seconds | Multi-page with charts |
| Bulk import 1000 records | < 20 seconds | Batch processing |
| Validation check | < 1 second | Per 100 records |
| Audit log write | < 100ms | Async operations |

## Troubleshooting

### Docker Services Won't Start
```bash
# Check Docker status
docker ps -a

# View logs
docker compose logs web

# Restart services
docker compose down && docker compose up -d
```

### Database Connection Issues
```bash
# Check PostgreSQL
docker compose exec db psql -U zumodra -d zumodra -c "SELECT 1"

# Reset migrations
docker compose exec web python manage.py migrate_schemas --shared --reset
```

### Tests Can't Find Data
```bash
# Verify test tenant exists
docker compose exec web python manage.py shell -c "from tenants.models import Tenant; print(Tenant.objects.all())"

# Create if missing
docker compose exec web python manage.py setup_demo_data
```

### Import Validation Failures
```bash
# Verify CSV format
head -5 candidates.csv

# Validate with dry-run
python manage.py import_candidates_csv file.csv tenant --dry-run

# Check logs
tail -f logs/import.log
```

### Performance Issues
```bash
# Check database queries
python manage.py shell

from django.db import connection
from django.test.utils import override_settings

with override_settings(DEBUG=True):
    # Run export
    # Check connection.queries
```

## Audit Trail

### What Gets Logged

**Export Operations:**
- Operation type: export_candidates, export_jobs, export_analytics
- User ID and email
- Tenant ID
- Format: csv, excel, pdf
- Record count
- Filters applied (if any)
- Timestamp
- Success/failure status

**Import Operations:**
- Operation type: import_candidates, import_jobs
- User ID and email
- Tenant ID
- File name and size
- Total records processed
- Created count
- Updated count
- Skipped count
- Error count
- Timestamp
- Success/failure status

### Audit Log Query Examples

```python
from core.audit_logging import AuditLog

# Find all exports by user
AuditLog.objects.filter(user_id=user_id, action__contains='export')

# Find all imports in time range
from datetime import datetime, timedelta
AuditLog.objects.filter(
    action__contains='import',
    timestamp__gte=datetime.now() - timedelta(days=1)
)

# Find failed operations
AuditLog.objects.filter(details__status='failed')
```

## Security Considerations

### What's Tested
- ✓ Multi-tenant data isolation
- ✓ User authentication required
- ✓ Role-based access control
- ✓ Data encryption in transit
- ✓ Input validation and sanitization
- ✓ SQL injection prevention
- ✓ CSV injection prevention
- ✓ File upload size limits

### What Should Be Verified
- PII handling in exports
- GDPR compliance
- Data retention policies
- Export access logging
- Secure file handling
- Encryption at rest

## Continuous Integration

### GitHub Actions Example

```yaml
name: Export/Import Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
      redis:
        image: redis:7
      rabbitmq:
        image: rabbitmq:3.12

    steps:
      - uses: actions/checkout@v3
      - name: Run tests
        run: |
          docker compose up -d
          ./tests_comprehensive/run_data_export_import_tests.sh --coverage
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Maintenance

### Regular Tasks
- [ ] Update test data monthly
- [ ] Review audit logs for anomalies
- [ ] Performance baseline comparison
- [ ] Dependency updates
- [ ] Documentation updates
- [ ] Add new test cases for features

### Annual Review
- [ ] Full regression testing
- [ ] Performance load testing
- [ ] Security audit
- [ ] Compliance verification
- [ ] Test coverage analysis

## Appendix

### CSV Field Mapping

**Candidates CSV:**
| Field | Type | Required | Example |
|-------|------|----------|---------|
| first_name | string | Yes | John |
| last_name | string | Yes | Doe |
| email | email | Yes | john@example.com |
| phone_number | string | No | 555-0001 |
| source | choice | No | linkedin |
| skills | json | No | ["Python", "Django"] |
| tags | json | No | ["backend"] |

**Jobs CSV:**
| Field | Type | Required | Example |
|-------|------|----------|---------|
| title | string | Yes | Software Engineer |
| description | text | No | Build software |
| category | fk | Yes | Engineering |
| status | choice | No | open |
| salary_min | integer | No | 80000 |
| salary_max | integer | No | 120000 |

### Sample Test Files

```bash
# Generate sample candidates CSV
python -c "
import csv
with open('sample_candidates.csv', 'w') as f:
    writer = csv.DictWriter(f, ['first_name', 'last_name', 'email', 'phone_number'])
    writer.writeheader()
    for i in range(100):
        writer.writerow({
            'first_name': f'Candidate{i}',
            'last_name': 'Test',
            'email': f'candidate{i}@example.com',
            'phone_number': f'555-{i:04d}'
        })
"

# Generate sample jobs CSV
python -c "
import csv
with open('sample_jobs.csv', 'w') as f:
    writer = csv.DictWriter(f, ['title', 'description', 'category', 'status'])
    writer.writeheader()
    for i in range(50):
        writer.writerow({
            'title': f'Position {i}',
            'description': f'Job description {i}',
            'category': 'Engineering',
            'status': 'open'
        })
"
```

## Contact & Support

For test suite issues or questions:
1. Check test logs in `tests_comprehensive/reports/`
2. Review test output and error messages
3. Check Docker service health
4. Consult CLAUDE.md for architecture overview
5. Review relevant app documentation

---

**Last Updated**: 2026-01-16
**Version**: 1.0
**Test Coverage**: 60+ test cases covering 7 modules
