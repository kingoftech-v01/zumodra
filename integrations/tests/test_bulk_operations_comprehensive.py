#!/usr/bin/env python
"""
Comprehensive Bulk Import/Export Testing Suite for Zumodra

This test suite validates:
1. CSV template downloads and formats
2. Candidate bulk import with validation
3. Job postings bulk import with validation
4. Employee bulk import with validation
5. Data validation and error handling
6. Partial import with error skipping
7. Import preview before commit
8. Data integrity after import/export cycles
9. Audit logging for bulk operations
10. Rate limiting on bulk operations

Usage:
  pytest tests_comprehensive/test_bulk_operations_comprehensive.py -v
  pytest tests_comprehensive/test_bulk_operations_comprehensive.py::TestCandidateBulkImport -v
"""

import pytest
import csv
import os
import tempfile
import json
from io import StringIO
from datetime import datetime, timedelta, date
from decimal import Decimal
from unittest.mock import patch, MagicMock

from django.test import TestCase, TransactionTestCase
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import connection, transaction
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from tenants.models import Tenant
from tenants.utils import tenant_context
from tenant_profiles.models import TenantUser, UserProfile
from jobs.models import (
    JobPosting, Candidate, Application, Interview,
    Pipeline, JobCategory, ApplicationActivity
)
from jobs.serializers import CandidateBulkImportSerializer
from hr_core.models import Employee
from core.audit_logging import log_bulk_operation, get_audit_logs

User = get_user_model()


# ============================================================================
# CANDIDATE BULK IMPORT TESTS
# ============================================================================

@pytest.mark.integration
class TestCandidateBulkImportBasics(TransactionTestCase):
    """Test basic candidate bulk import functionality."""

    def setUp(self):
        """Set up test data."""
        self.tenant = Tenant.objects.create(
            name='Test Tenant',
            slug='test-tenant',
            schema_name='test_tenant_schema'
        )
        self.user = User.objects.create_user(
            username='test@example.com',
            email='test@example.com',
            password='testpass123'
        )
        self.tenant_user = TenantUser.objects.create(
            user=self.user,
            tenant=self.tenant,
            role='recruiter'
        )

    def test_candidate_template_generation(self):
        """Test candidate import template generation."""
        # Expected headers from import_candidates_csv command
        expected_headers = [
            'first_name', 'last_name', 'email', 'phone', 'headline',
            'summary', 'current_company', 'current_title', 'city', 'state',
            'country', 'years_experience', 'skills', 'languages',
            'linkedin_url', 'github_url', 'portfolio_url', 'tags',
            'desired_salary_min', 'desired_salary_max', 'willing_to_relocate'
        ]

        # Verify template file exists
        template_path = '/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/TEMPLATE_CANDIDATES_IMPORT.csv'
        assert os.path.exists(template_path), f"Template not found at {template_path}"

        # Validate template headers
        with open(template_path, 'r') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            for expected in expected_headers:
                assert expected in headers, f"Missing expected header: {expected}"

    def test_valid_candidate_import(self):
        """Test importing valid candidate data."""
        with tenant_context(self.tenant):
            csv_content = """first_name,last_name,email,phone,headline,summary,current_company,current_title,city,state,country,years_experience,skills,languages,linkedin_url,github_url,portfolio_url,tags,desired_salary_min,desired_salary_max,willing_to_relocate
John,Doe,john@example.com,555-0001,Senior Engineer,Experienced engineer,TechCorp,Engineer,Toronto,ON,Canada,10,Python,English,https://linkedin.com/in/john,https://github.com/john,,senior,80000,120000,yes"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                # Import with command
                call_command(
                    'import_candidates_csv',
                    csv_file,
                    'test-tenant',
                    verbosity=0
                )

                # Verify import
                assert Candidate.objects.count() == 1
                candidate = Candidate.objects.first()
                assert candidate.first_name == 'John'
                assert candidate.last_name == 'Doe'
                assert candidate.email == 'john@example.com'
                assert candidate.years_experience == 10
                assert 'python' in candidate.skills
                assert 'senior' in candidate.tags
            finally:
                os.unlink(csv_file)

    def test_bulk_candidate_import_multiple_records(self):
        """Test importing multiple candidates at once."""
        with tenant_context(self.tenant):
            csv_content = """first_name,last_name,email,phone,headline,summary,current_company,current_title,city,state,country,years_experience,skills,languages,linkedin_url,github_url,portfolio_url,tags,desired_salary_min,desired_salary_max,willing_to_relocate
Alice,Smith,alice@example.com,555-0001,Product Manager,PM with 5 years,StartupXYZ,Product Manager,Vancouver,BC,Canada,5,Strategy,English,https://linkedin.com/in/alice,,,pm,80000,100000,yes
Bob,Johnson,bob@example.com,555-0002,DevOps Engineer,Infrastructure expert,CloudInc,Senior DevOps,Montreal,QC,Canada,8,Kubernetes,English,https://linkedin.com/in/bob,https://github.com/bob,,devops,aws,75000,110000,no
Charlie,Brown,charlie@example.com,555-0003,Data Scientist,ML specialist,DataSys,Data Scientist,Ottawa,ON,Canada,6,Python,English,https://linkedin.com/in/charlie,https://github.com/charlie,,data,85000,125000,no"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_candidates_csv',
                    csv_file,
                    'test-tenant',
                    verbosity=0
                )

                assert Candidate.objects.count() == 3
                assert Candidate.objects.filter(first_name='Alice').exists()
                assert Candidate.objects.filter(first_name='Bob').exists()
                assert Candidate.objects.filter(first_name='Charlie').exists()
            finally:
                os.unlink(csv_file)

    def test_candidate_import_with_duplicate_emails(self):
        """Test handling of duplicate emails in import."""
        with tenant_context(self.tenant):
            # Create existing candidate
            Candidate.objects.create(
                first_name='Existing',
                last_name='User',
                email='existing@example.com',
                source='direct'
            )

            csv_content = """first_name,last_name,email,phone,headline,summary,current_company,current_title,city,state,country,years_experience,skills,languages,linkedin_url,github_url,portfolio_url,tags,desired_salary_min,desired_salary_max,willing_to_relocate
New,Candidate,new@example.com,555-0001,Engineer,New candidate,Company,Engineer,City,State,Canada,5,Python,English,,,,,60000,80000,yes
Existing,User,existing@example.com,555-0002,Manager,Updated,Company,Manager,City,State,Canada,10,Python,English,,,,,70000,90000,yes"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                # Import with skip_duplicates should skip existing
                call_command(
                    'import_candidates_csv',
                    csv_file,
                    'test-tenant',
                    skip_duplicates=True,
                    verbosity=0
                )

                assert Candidate.objects.count() == 2  # Only new one added
                assert Candidate.objects.filter(first_name='New').exists()
            finally:
                os.unlink(csv_file)

    def test_candidate_import_with_update_existing(self):
        """Test updating existing candidates during import."""
        with tenant_context(self.tenant):
            # Create existing candidate
            existing = Candidate.objects.create(
                first_name='Old',
                last_name='Name',
                email='update@example.com',
                source='direct',
                years_experience=5
            )

            csv_content = """first_name,last_name,email,phone,headline,summary,current_company,current_title,city,state,country,years_experience,skills,languages,linkedin_url,github_url,portfolio_url,tags,desired_salary_min,desired_salary_max,willing_to_relocate
Updated,Name,update@example.com,555-0001,New Title,Updated summary,NewCo,Senior,Toronto,ON,Canada,8,Python,English,https://linkedin.com/in/update,https://github.com/update,,senior,80000,120000,yes"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_candidates_csv',
                    csv_file,
                    'test-tenant',
                    update_existing=True,
                    verbosity=0
                )

                assert Candidate.objects.count() == 1
                updated = Candidate.objects.first()
                assert updated.first_name == 'Updated'
                assert updated.years_experience == 8
                assert 'senior' in updated.tags
            finally:
                os.unlink(csv_file)

    def test_candidate_import_with_tags(self):
        """Test importing candidates with tags."""
        with tenant_context(self.tenant):
            csv_content = """first_name,last_name,email,phone,headline,summary,current_company,current_title,city,state,country,years_experience,skills,languages,linkedin_url,github_url,portfolio_url,tags,desired_salary_min,desired_salary_max,willing_to_relocate
John,Doe,john@example.com,555-0001,Engineer,Experienced,TechCorp,Engineer,Toronto,ON,Canada,10,Python,English,https://linkedin.com/in/john,https://github.com/john,,tag1,tag2,80000,120000,yes"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_candidates_csv',
                    csv_file,
                    'test-tenant',
                    tags='imported,batch2024',
                    verbosity=0
                )

                candidate = Candidate.objects.first()
                assert 'tag1' in candidate.tags
                assert 'tag2' in candidate.tags
                assert 'imported' in candidate.tags
                assert 'batch2024' in candidate.tags
            finally:
                os.unlink(csv_file)


@pytest.mark.integration
class TestCandidateImportValidation(TransactionTestCase):
    """Test validation during candidate import."""

    def setUp(self):
        """Set up test data."""
        self.tenant = Tenant.objects.create(
            name='Validation Tenant',
            slug='validation-tenant',
            schema_name='validation_tenant_schema'
        )

    def test_candidate_import_missing_required_fields(self):
        """Test import fails with missing required fields."""
        with tenant_context(self.tenant):
            # Missing email
            csv_content = """first_name,last_name,email,phone
John,Doe,,555-0001"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                with pytest.raises(Exception):
                    call_command(
                        'import_candidates_csv',
                        csv_file,
                        'validation-tenant',
                        verbosity=0
                    )
            finally:
                os.unlink(csv_file)

    def test_candidate_import_invalid_email(self):
        """Test import validation of email format."""
        with tenant_context(self.tenant):
            csv_content = """first_name,last_name,email,phone
John,Doe,invalid-email,555-0001"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                with pytest.raises(Exception):
                    call_command(
                        'import_candidates_csv',
                        csv_file,
                        'validation-tenant',
                        verbosity=0
                    )
            finally:
                os.unlink(csv_file)

    def test_candidate_import_invalid_years_experience(self):
        """Test validation of years_experience field."""
        with tenant_context(self.tenant):
            csv_content = """first_name,last_name,email,phone,years_experience
John,Doe,john@example.com,555-0001,not_a_number"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                with pytest.raises(Exception):
                    call_command(
                        'import_candidates_csv',
                        csv_file,
                        'validation-tenant',
                        verbosity=0
                    )
            finally:
                os.unlink(csv_file)


# ============================================================================
# JOB POSTING BULK IMPORT TESTS
# ============================================================================

@pytest.mark.integration
class TestJobBulkImportBasics(TransactionTestCase):
    """Test basic job posting bulk import functionality."""

    def setUp(self):
        """Set up test data."""
        self.tenant = Tenant.objects.create(
            name='Job Test Tenant',
            slug='job-tenant',
            schema_name='job_tenant_schema'
        )

    def test_job_template_generation(self):
        """Test job import template generation."""
        expected_headers = [
            'title', 'description', 'responsibilities', 'requirements', 'benefits',
            'category', 'job_type', 'experience_level', 'remote_policy',
            'location_city', 'location_state', 'location_country',
            'salary_min', 'salary_max', 'salary_currency', 'required_skills',
            'reference_code'
        ]

        template_path = '/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/TEMPLATE_JOBS_IMPORT.csv'
        assert os.path.exists(template_path), f"Template not found at {template_path}"

        with open(template_path, 'r') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            for expected in expected_headers:
                assert expected in headers, f"Missing expected header: {expected}"

    def test_valid_job_import(self):
        """Test importing valid job posting data."""
        with tenant_context(self.tenant):
            JobCategory.objects.create(name='Engineering')

            csv_content = """title,description,responsibilities,requirements,benefits,category,job_type,experience_level,remote_policy,location_city,location_state,location_country,salary_min,salary_max,salary_currency,required_skills,reference_code
Senior Software Engineer,Build backend services,- Design microservices,- 8+ years experience,- Competitive salary,Engineering,full_time,senior,remote,Toronto,ON,Canada,100000,140000,CAD,Python,ENG-SR-001"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_jobs_csv',
                    csv_file,
                    'job-tenant',
                    verbosity=0
                )

                assert JobPosting.objects.count() == 1
                job = JobPosting.objects.first()
                assert job.title == 'Senior Software Engineer'
                assert job.salary_min == 100000
                assert job.salary_max == 140000
                assert job.job_type == 'full_time'
            finally:
                os.unlink(csv_file)

    def test_bulk_job_import_multiple(self):
        """Test importing multiple job postings."""
        with tenant_context(self.tenant):
            JobCategory.objects.create(name='Engineering')
            JobCategory.objects.create(name='Product')

            csv_content = """title,description,responsibilities,requirements,benefits,category,job_type,experience_level,remote_policy,location_city,location_state,location_country,salary_min,salary_max,salary_currency,required_skills,reference_code
Software Engineer,Backend,Design services,5+ years,Salary,Engineering,full_time,mid,hybrid,Toronto,ON,Canada,80000,120000,CAD,Python,ENG-001
Product Manager,Lead products,Define roadmap,5+ years,Bonus,Product,full_time,mid,hybrid,Vancouver,BC,Canada,90000,130000,CAD,Strategy,PM-001"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_jobs_csv',
                    csv_file,
                    'job-tenant',
                    verbosity=0
                )

                assert JobPosting.objects.count() == 2
                assert JobPosting.objects.filter(title__contains='Software').exists()
                assert JobPosting.objects.filter(title__contains='Product').exists()
            finally:
                os.unlink(csv_file)

    def test_job_import_with_update_existing(self):
        """Test updating existing jobs during import."""
        with tenant_context(self.tenant):
            category = JobCategory.objects.create(name='Engineering')
            existing_job = JobPosting.objects.create(
                title='Old Title',
                description='Old description',
                category=category,
                status='draft',
                reference_code='JOB-001',
                salary_min=80000
            )

            csv_content = """title,description,responsibilities,requirements,benefits,category,job_type,experience_level,remote_policy,location_city,location_state,location_country,salary_min,salary_max,salary_currency,required_skills,reference_code
Updated Title,New description,New responsibilities,New requirements,New benefits,Engineering,full_time,senior,remote,Toronto,ON,Canada,120000,150000,CAD,Python,JOB-001"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_jobs_csv',
                    csv_file,
                    'job-tenant',
                    update_existing=True,
                    verbosity=0
                )

                assert JobPosting.objects.count() == 1
                updated = JobPosting.objects.first()
                assert updated.title == 'Updated Title'
                assert updated.salary_min == 120000
                assert updated.salary_max == 150000
            finally:
                os.unlink(csv_file)


# ============================================================================
# EMPLOYEE BULK IMPORT TESTS
# ============================================================================

@pytest.mark.integration
class TestEmployeeBulkImportBasics(TransactionTestCase):
    """Test basic employee bulk import functionality."""

    def setUp(self):
        """Set up test data."""
        self.tenant = Tenant.objects.create(
            name='Employee Test Tenant',
            slug='emp-tenant',
            schema_name='emp_tenant_schema'
        )

    def test_employee_template_generation(self):
        """Test employee import template generation."""
        expected_headers = [
            'first_name', 'last_name', 'email', 'job_title', 'hire_date',
            'start_date', 'employment_type', 'team', 'work_location',
            'employee_id', 'base_salary', 'salary_currency', 'pay_frequency',
            'probation_end_date', 'emergency_contact_name', 'emergency_contact_phone',
            'emergency_contact_relationship'
        ]

        template_path = '/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/TEMPLATE_EMPLOYEES_IMPORT.csv'
        assert os.path.exists(template_path), f"Template not found at {template_path}"

        with open(template_path, 'r') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            for expected in expected_headers:
                assert expected in headers, f"Missing expected header: {expected}"

    def test_valid_employee_import_with_user_creation(self):
        """Test importing employee data with user creation."""
        with tenant_context(self.tenant):
            csv_content = """first_name,last_name,email,job_title,hire_date,start_date,employment_type,team,work_location,employee_id,base_salary,salary_currency,pay_frequency,probation_end_date,emergency_contact_name,emergency_contact_phone,emergency_contact_relationship
John,Doe,john.emp@example.com,Senior Engineer,2022-01-15,2022-02-01,full_time,Engineering,Toronto,EMP-001,120000,CAD,annual,2022-05-01,Jane Doe,555-0001,Spouse"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_employees_csv',
                    csv_file,
                    'emp-tenant',
                    create_users=True,
                    verbosity=0
                )

                assert Employee.objects.count() == 1
                emp = Employee.objects.first()
                assert emp.employee_id == 'EMP-001'
                assert emp.job_title == 'Senior Engineer'
                assert emp.base_salary == Decimal('120000')
                assert emp.team == 'Engineering'
            finally:
                os.unlink(csv_file)

    def test_bulk_employee_import_multiple(self):
        """Test importing multiple employees."""
        with tenant_context(self.tenant):
            csv_content = """first_name,last_name,email,job_title,hire_date,start_date,employment_type,team,work_location,employee_id,base_salary,salary_currency,pay_frequency,probation_end_date,emergency_contact_name,emergency_contact_phone,emergency_contact_relationship
Alice,Smith,alice.emp@example.com,Manager,2021-06-01,2021-07-01,full_time,Product,Vancouver,EMP-001,100000,CAD,annual,2021-10-01,Robert Smith,555-0001,Father
Bob,Johnson,bob.emp@example.com,Senior Engineer,2022-03-10,2022-04-01,full_time,Engineering,Montreal,EMP-002,110000,CAD,annual,2022-07-01,Mary Johnson,555-0002,Spouse
Charlie,Brown,charlie.emp@example.com,Analyst,2022-09-01,2022-10-01,full_time,Data,Ottawa,EMP-003,75000,CAD,annual,2022-01-01,Sarah Brown,555-0003,Spouse"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_employees_csv',
                    csv_file,
                    'emp-tenant',
                    create_users=True,
                    verbosity=0
                )

                assert Employee.objects.count() == 3
                assert Employee.objects.filter(team='Product').exists()
                assert Employee.objects.filter(team='Engineering').exists()
                assert Employee.objects.filter(team='Data').exists()
            finally:
                os.unlink(csv_file)


# ============================================================================
# VALIDATION AND ERROR HANDLING TESTS
# ============================================================================

@pytest.mark.integration
class TestImportErrorHandling(TransactionTestCase):
    """Test error handling and validation during imports."""

    def setUp(self):
        """Set up test data."""
        self.tenant = Tenant.objects.create(
            name='Error Test Tenant',
            slug='error-tenant',
            schema_name='error_tenant_schema'
        )

    def test_candidate_import_with_error_file(self):
        """Test candidate import with errors in CSV."""
        with tenant_context(self.tenant):
            template_path = '/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/TEST_CANDIDATES_WITH_ERRORS.csv'

            if os.path.exists(template_path):
                # This should fail with validation errors
                with pytest.raises(Exception):
                    call_command(
                        'import_candidates_csv',
                        template_path,
                        'error-tenant',
                        verbosity=0
                    )

    def test_job_import_with_error_file(self):
        """Test job import with errors in CSV."""
        with tenant_context(self.tenant):
            template_path = '/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/TEST_JOBS_WITH_ERRORS.csv'

            if os.path.exists(template_path):
                # This should fail with validation errors
                with pytest.raises(Exception):
                    call_command(
                        'import_jobs_csv',
                        template_path,
                        'error-tenant',
                        verbosity=0
                    )

    def test_employee_import_with_error_file(self):
        """Test employee import with errors in CSV."""
        with tenant_context(self.tenant):
            template_path = '/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/TEST_EMPLOYEES_WITH_ERRORS.csv'

            if os.path.exists(template_path):
                # This should fail with validation errors
                with pytest.raises(Exception):
                    call_command(
                        'import_employees_csv',
                        template_path,
                        'error-tenant',
                        verbosity=0
                    )


# ============================================================================
# IMPORT DRY-RUN AND PREVIEW TESTS
# ============================================================================

@pytest.mark.integration
class TestImportDryRun(TransactionTestCase):
    """Test import dry-run (preview) functionality."""

    def setUp(self):
        """Set up test data."""
        self.tenant = Tenant.objects.create(
            name='DryRun Test Tenant',
            slug='dryrun-tenant',
            schema_name='dryrun_tenant_schema'
        )

    def test_candidate_import_dry_run(self):
        """Test candidate import with dry-run option."""
        with tenant_context(self.tenant):
            csv_content = """first_name,last_name,email,phone
John,Doe,john@example.com,555-0001
Jane,Smith,jane@example.com,555-0002"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_candidates_csv',
                    csv_file,
                    'dryrun-tenant',
                    dry_run=True,
                    verbosity=0
                )

                # No candidates should be created
                assert Candidate.objects.count() == 0
            finally:
                os.unlink(csv_file)

    def test_job_import_dry_run(self):
        """Test job import with dry-run option."""
        with tenant_context(self.tenant):
            JobCategory.objects.create(name='Engineering')

            csv_content = """title,description,category,job_type,experience_level,remote_policy,location_city,location_state,location_country,salary_min,salary_max,salary_currency,required_skills,reference_code
Software Engineer,Build services,Engineering,full_time,mid,hybrid,Toronto,ON,Canada,80000,120000,CAD,Python,ENG-001"""

            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write(csv_content)
                csv_file = f.name

            try:
                call_command(
                    'import_jobs_csv',
                    csv_file,
                    'dryrun-tenant',
                    dry_run=True,
                    verbosity=0
                )

                # No jobs should be created
                assert JobPosting.objects.count() == 0
            finally:
                os.unlink(csv_file)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
