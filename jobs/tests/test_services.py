"""
ATS Service Layer Tests - Comprehensive tests for business logic services

This module provides comprehensive tests for:
- ApplicationService: Application lifecycle management
- CandidateService: Candidate management and deduplication
- JobPostingService: Job posting lifecycle management
- PipelineService: Pipeline and stage operations

Tests are marked with @pytest.mark.services for easy categorization.
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from io import StringIO
from unittest.mock import patch, MagicMock

from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db import transaction

from jobs.models import (
    Application,
    ApplicationActivity,
    Candidate,
    JobPosting,
    Pipeline,
    PipelineStage,
)
from jobs.services import (
    ApplicationService,
    CandidateService,
    JobPostingService,
    PipelineService,
    ServiceResult,
    PipelineMetrics,
    CandidateMatchResult,
)


# ============================================================================
# APPLICATION SERVICE TESTS
# ============================================================================

@pytest.mark.services
@pytest.mark.django_db
class TestApplicationService:
    """Tests for ApplicationService."""

    def test_apply_creates_application(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory,
        pipeline_factory,
        pipeline_stage_factory,
        user_factory
    ):
        """Test successful application creation."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)
        first_stage = pipeline_stage_factory(
            pipeline=pipeline,
            name='New',
            order=0,
            stage_type='new',
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline,
            required_skills=['Python', 'Django']
        )
        candidate = candidate_factory(
            tenant=tenant,
            skills=['Python', 'Django', 'PostgreSQL']
        )
        user = user_factory()

        # Execute
        result = ApplicationService.apply(
            tenant=tenant,
            candidate=candidate,
            job=job,
            cover_letter='I am interested in this position.',
            source='career_page',
            user=user
        )

        # Verify
        assert result.success is True
        assert result.data is not None
        assert isinstance(result.data, Application)
        assert result.data.candidate == candidate
        assert result.data.job == job
        assert result.data.cover_letter == 'I am interested in this position.'
        assert result.data.status == Application.ApplicationStatus.NEW

    def test_apply_rejects_duplicate(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory,
        application_factory
    ):
        """Test duplicate application detection."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(tenant=tenant, status='open')
        candidate = candidate_factory(tenant=tenant)

        # Create existing application
        application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job
        )

        # Execute - try to apply again
        result = ApplicationService.apply(
            tenant=tenant,
            candidate=candidate,
            job=job
        )

        # Verify
        assert result.success is False
        assert 'already applied' in result.message.lower() or 'duplicate' in str(result.errors).lower()
        assert result.data is not None  # Returns existing application

    def test_apply_closed_job_fails(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory
    ):
        """Test cannot apply to closed job."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(tenant=tenant, status='closed')
        candidate = candidate_factory(tenant=tenant)

        # Execute
        result = ApplicationService.apply(
            tenant=tenant,
            candidate=candidate,
            job=job
        )

        # Verify
        assert result.success is False
        assert 'job' in result.errors or 'not accepting' in result.message.lower()

    def test_apply_sets_initial_stage(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory,
        pipeline_factory,
        pipeline_stage_factory
    ):
        """Test application assigned to first pipeline stage."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)

        # Create stages in specific order
        first_stage = pipeline_stage_factory(
            pipeline=pipeline,
            name='Applied',
            order=0,
            stage_type='new',
            is_active=True
        )
        second_stage = pipeline_stage_factory(
            pipeline=pipeline,
            name='Screening',
            order=1,
            stage_type='screening',
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline
        )
        candidate = candidate_factory(tenant=tenant)

        # Execute
        result = ApplicationService.apply(
            tenant=tenant,
            candidate=candidate,
            job=job
        )

        # Verify
        assert result.success is True
        assert result.data.current_stage == first_stage
        assert result.data.current_stage.name == 'Applied'

    def test_advance_success(
        self,
        tenant_factory,
        application_factory,
        pipeline_factory,
        pipeline_stage_factory,
        job_posting_factory,
        candidate_factory,
        user_factory
    ):
        """Test successful stage advancement."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)

        stage1 = pipeline_stage_factory(
            pipeline=pipeline,
            name='New',
            order=0,
            stage_type='new',
            is_active=True
        )
        stage2 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Screening',
            order=1,
            stage_type='screening',
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline
        )
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            status='new',
            current_stage=stage1
        )
        user = user_factory()

        # Execute
        result = ApplicationService.advance(
            application=application,
            user=user,
            notes='Candidate looks promising'
        )

        # Verify
        assert result.success is True
        application.refresh_from_db()
        assert application.current_stage == stage2
        assert application.current_stage.name == 'Screening'

    def test_advance_terminal_fails(
        self,
        tenant_factory,
        application_factory,
        pipeline_factory,
        pipeline_stage_factory,
        job_posting_factory,
        candidate_factory
    ):
        """Test cannot advance terminal application."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)

        stage = pipeline_stage_factory(
            pipeline=pipeline,
            name='Hired',
            order=0,
            stage_type='hired',
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline
        )
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            status='hired',
            current_stage=stage
        )

        # Execute
        result = ApplicationService.advance(application=application)

        # Verify
        assert result.success is False
        assert 'terminal' in result.message.lower() or 'cannot' in result.message.lower()

    def test_reject_updates_status(
        self,
        tenant_factory,
        application_factory,
        job_posting_factory,
        candidate_factory,
        user_factory
    ):
        """Test rejection updates status correctly."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(tenant=tenant, status='open')
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            status='in_review'
        )
        user = user_factory()

        # Execute
        result = ApplicationService.reject(
            application=application,
            reason='Insufficient experience',
            feedback='Thank you for your interest.',
            user=user,
            send_email=True
        )

        # Verify
        assert result.success is True
        application.refresh_from_db()
        assert application.status == Application.ApplicationStatus.REJECTED
        assert application.rejection_reason == 'Insufficient experience'
        assert application.rejected_at is not None

    def test_bulk_reject_multiple(
        self,
        tenant_factory,
        application_factory,
        job_posting_factory,
        candidate_factory,
        user_factory
    ):
        """Test bulk rejection of multiple applications."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(tenant=tenant, status='open')
        user = user_factory()

        applications = []
        for i in range(3):
            candidate = candidate_factory(
                tenant=tenant,
                email=f'candidate{i}@test.com'
            )
            app = application_factory(
                tenant=tenant,
                candidate=candidate,
                job=job,
                status='in_review'
            )
            applications.append(app)

        apps_queryset = Application.objects.filter(
            pk__in=[a.pk for a in applications]
        )

        # Execute
        result = ApplicationService.bulk_reject(
            applications=apps_queryset,
            reason='Position filled',
            feedback='We have moved forward with another candidate.',
            user=user,
            send_email=True
        )

        # Verify
        assert result.success is True
        assert result.data['rejected_count'] == 3
        assert result.data['failed_count'] == 0

        # Check all applications are rejected
        for app in applications:
            app.refresh_from_db()
            assert app.status == Application.ApplicationStatus.REJECTED

    def test_hire_fills_position(
        self,
        tenant_factory,
        application_factory,
        job_posting_factory,
        candidate_factory,
        user_factory
    ):
        """Test hiring decrements available positions."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(
            tenant=tenant,
            status='open',
            positions_count=2
        )
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            status='offer_extended'
        )
        user = user_factory()

        # Verify initial state
        assert job.positions_remaining == 2

        # Execute
        result = ApplicationService.hire(
            application=application,
            user=user
        )

        # Verify
        assert result.success is True
        application.refresh_from_db()
        job.refresh_from_db()
        assert application.status == Application.ApplicationStatus.HIRED
        assert application.hired_at is not None
        assert job.positions_remaining == 1

    def test_hire_closes_job_when_all_positions_filled(
        self,
        tenant_factory,
        application_factory,
        job_posting_factory,
        candidate_factory,
        user_factory
    ):
        """Test job is closed when all positions are filled."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(
            tenant=tenant,
            status='open',
            positions_count=1
        )
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            status='offer_extended'
        )
        user = user_factory()

        # Execute
        result = ApplicationService.hire(
            application=application,
            user=user
        )

        # Verify
        assert result.success is True
        job.refresh_from_db()
        assert job.status == JobPosting.JobStatus.FILLED

    def test_withdraw_success(
        self,
        tenant_factory,
        application_factory,
        job_posting_factory,
        candidate_factory,
        user_factory
    ):
        """Test successful application withdrawal."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(tenant=tenant, status='open')
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            status='in_review'
        )
        user = user_factory()

        # Execute
        result = ApplicationService.withdraw(
            application=application,
            reason='Accepted another offer',
            user=user
        )

        # Verify
        assert result.success is True
        application.refresh_from_db()
        assert application.status == Application.ApplicationStatus.WITHDRAWN

    def test_move_to_stage_success(
        self,
        tenant_factory,
        application_factory,
        pipeline_factory,
        pipeline_stage_factory,
        job_posting_factory,
        candidate_factory,
        user_factory
    ):
        """Test moving application to specific stage."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)

        stage1 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Applied',
            order=0,
            is_active=True
        )
        stage3 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Interview',
            order=2,
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline
        )
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            current_stage=stage1
        )
        user = user_factory()

        # Execute
        result = ApplicationService.move_to_stage(
            application=application,
            stage=stage3,
            user=user,
            notes='Skipping to interview'
        )

        # Verify
        assert result.success is True
        application.refresh_from_db()
        assert application.current_stage == stage3

    def test_calculate_match_score(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory
    ):
        """Test match score calculation between candidate and job."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(
            tenant=tenant,
            required_skills=['Python', 'Django', 'PostgreSQL', 'Redis']
        )
        candidate = candidate_factory(
            tenant=tenant,
            skills=['Python', 'Django', 'MySQL']  # 2 out of 4 match
        )

        # Execute
        score = ApplicationService.calculate_match_score(candidate, job)

        # Verify
        assert score == 50.0  # 2/4 = 50%


# ============================================================================
# CANDIDATE SERVICE TESTS
# ============================================================================

@pytest.mark.services
@pytest.mark.django_db
class TestCandidateService:
    """Tests for CandidateService."""

    def test_merge_transfers_applications(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory,
        application_factory
    ):
        """Test merging candidates transfers applications."""
        # Setup
        tenant = tenant_factory()
        job1 = job_posting_factory(tenant=tenant, status='open')
        job2 = job_posting_factory(tenant=tenant, status='open')

        primary = candidate_factory(
            tenant=tenant,
            email='primary@test.com',
            first_name='John',
            last_name='Doe',
            skills=['Python']
        )
        secondary = candidate_factory(
            tenant=tenant,
            email='secondary@test.com',
            first_name='John',
            last_name='Smith',
            skills=['Django', 'React']
        )

        # Create applications for secondary candidate
        app1 = application_factory(
            tenant=tenant,
            candidate=secondary,
            job=job1
        )
        app2 = application_factory(
            tenant=tenant,
            candidate=secondary,
            job=job2
        )

        # Execute
        result = CandidateService.merge(
            primary=primary,
            secondary=secondary,
            delete_secondary=True
        )

        # Verify
        assert result.success is True
        assert result.data['applications_transferred'] == 2

        # Check applications transferred
        primary.refresh_from_db()
        assert primary.applications.count() == 2

        # Check skills merged
        assert 'python' in [s.lower() for s in primary.skills]
        assert 'django' in [s.lower() for s in primary.skills]
        assert 'react' in [s.lower() for s in primary.skills]

    def test_merge_same_tenant_required(
        self,
        tenant_factory,
        candidate_factory
    ):
        """Test merge requires same tenant."""
        # Setup
        tenant1 = tenant_factory()
        tenant2 = tenant_factory()

        primary = candidate_factory(tenant=tenant1)
        secondary = candidate_factory(tenant=tenant2)

        # Execute
        result = CandidateService.merge(
            primary=primary,
            secondary=secondary
        )

        # Verify
        assert result.success is False
        assert 'tenant' in result.message.lower()

    def test_merge_cannot_merge_self(
        self,
        tenant_factory,
        candidate_factory
    ):
        """Test cannot merge a candidate with itself."""
        # Setup
        tenant = tenant_factory()
        candidate = candidate_factory(tenant=tenant)

        # Execute
        result = CandidateService.merge(
            primary=candidate,
            secondary=candidate
        )

        # Verify
        assert result.success is False
        assert 'same' in result.message.lower() or 'itself' in result.message.lower()

    def test_find_duplicates_by_email(
        self,
        tenant_factory,
        candidate_factory
    ):
        """Test duplicate detection by email."""
        # Setup
        tenant = tenant_factory()

        candidate1 = candidate_factory(
            tenant=tenant,
            email='john.doe@example.com'
        )
        candidate2 = candidate_factory(
            tenant=tenant,
            email='JOHN.DOE@EXAMPLE.COM'  # Same email, different case
        )

        # Execute
        duplicates = CandidateService.find_duplicates(
            tenant=tenant,
            email='john.doe@example.com'
        )

        # Verify - should find at least one match
        assert len(duplicates) >= 1
        emails = [d[0].email.lower() for d in duplicates]
        assert 'john.doe@example.com' in emails

    def test_find_duplicates_by_name(
        self,
        tenant_factory,
        candidate_factory
    ):
        """Test duplicate detection by name."""
        # Setup
        tenant = tenant_factory()

        candidate1 = candidate_factory(
            tenant=tenant,
            first_name='John',
            last_name='Doe',
            email='john1@example.com'
        )
        candidate2 = candidate_factory(
            tenant=tenant,
            first_name='John',
            last_name='Doe',
            email='john2@example.com'
        )

        # Execute
        duplicates = CandidateService.find_duplicates(
            tenant=tenant,
            candidate=candidate1,
            threshold=0.8
        )

        # Verify - should find candidate2 as duplicate
        assert len(duplicates) >= 1
        duplicate_ids = [d[0].pk for d in duplicates]
        assert candidate2.pk in duplicate_ids

    def test_bulk_import_creates_candidates(
        self,
        tenant_factory,
        user_factory
    ):
        """Test CSV import creates candidates."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()

        csv_data = """first_name,last_name,email,phone,skills,city,country
Alice,Johnson,alice@example.com,555-0101,"Python,Django",Toronto,Canada
Bob,Smith,bob@example.com,555-0102,"JavaScript,React",Vancouver,Canada
Carol,Williams,carol@example.com,555-0103,"Java,Spring",Montreal,Canada"""

        # Execute
        result = CandidateService.bulk_import(
            tenant=tenant,
            csv_data=csv_data,
            source='imported',
            user=user,
            update_existing=False
        )

        # Verify
        assert result.success is True
        assert result.data['created_count'] == 3
        assert result.data['failed_count'] == 0

        # Verify candidates created
        assert Candidate.objects.filter(
            tenant=tenant,
            email='alice@example.com'
        ).exists()

        alice = Candidate.objects.get(
            tenant=tenant,
            email='alice@example.com'
        )
        assert alice.first_name == 'Alice'
        assert alice.last_name == 'Johnson'
        assert 'Python' in alice.skills
        assert 'Django' in alice.skills

    def test_bulk_import_skips_duplicates(
        self,
        tenant_factory,
        candidate_factory,
        user_factory
    ):
        """Test CSV import skips existing candidates when update_existing=False."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()

        # Create existing candidate
        existing = candidate_factory(
            tenant=tenant,
            email='existing@example.com',
            first_name='Existing',
            last_name='User'
        )

        csv_data = """first_name,last_name,email
New,Candidate,new@example.com
Updated,Name,existing@example.com"""

        # Execute
        result = CandidateService.bulk_import(
            tenant=tenant,
            csv_data=csv_data,
            user=user,
            update_existing=False
        )

        # Verify
        assert result.data['created_count'] == 1
        assert result.data['failed_count'] == 1  # Skipped duplicate

        # Original candidate unchanged
        existing.refresh_from_db()
        assert existing.first_name == 'Existing'

    def test_bulk_import_updates_existing(
        self,
        tenant_factory,
        candidate_factory,
        user_factory
    ):
        """Test CSV import updates existing candidates when update_existing=True."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()

        # Create existing candidate
        existing = candidate_factory(
            tenant=tenant,
            email='existing@example.com',
            first_name='Old',
            last_name='Name',
            skills=['Python']
        )

        csv_data = """first_name,last_name,email,skills
Updated,Name,existing@example.com,"Django,React" """

        # Execute
        result = CandidateService.bulk_import(
            tenant=tenant,
            csv_data=csv_data,
            user=user,
            update_existing=True
        )

        # Verify
        assert result.data['updated_count'] == 1

        existing.refresh_from_db()
        assert existing.first_name == 'Updated'
        assert existing.last_name == 'Name'
        # Skills should be merged
        assert 'Python' in existing.skills
        assert 'Django' in existing.skills

    def test_bulk_import_handles_missing_required_fields(
        self,
        tenant_factory,
        user_factory
    ):
        """Test CSV import handles missing required fields."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()

        csv_data = """first_name,last_name,email
,Missing,noname@example.com
John,,nolastname@example.com
Complete,User,"""

        # Execute
        result = CandidateService.bulk_import(
            tenant=tenant,
            csv_data=csv_data,
            user=user
        )

        # Verify - all should fail due to missing required fields
        assert result.data['created_count'] == 0
        assert result.data['failed_count'] == 3

    def test_get_best_matches(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory
    ):
        """Test job-candidate matching."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(
            tenant=tenant,
            status='open',
            required_skills=['Python', 'Django', 'PostgreSQL']
        )

        # Create candidates with varying skill matches
        perfect_match = candidate_factory(
            tenant=tenant,
            email='perfect@example.com',
            skills=['Python', 'Django', 'PostgreSQL', 'Redis']
        )
        partial_match = candidate_factory(
            tenant=tenant,
            email='partial@example.com',
            skills=['Python', 'Django']  # 2/3 = 66%
        )
        no_match = candidate_factory(
            tenant=tenant,
            email='nomatch@example.com',
            skills=['Java', 'Spring']
        )

        # Execute
        matches = CandidateService.get_best_matches(
            tenant=tenant,
            job=job,
            limit=10,
            min_score=50.0
        )

        # Verify
        assert len(matches) >= 2  # Should include perfect and partial

        # Check results are CandidateMatchResult objects
        assert all(isinstance(m, CandidateMatchResult) for m in matches)

        # Results should be sorted by score (highest first)
        if len(matches) >= 2:
            assert matches[0].match_score >= matches[1].match_score

    def test_get_best_matches_excludes_already_applied(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory,
        application_factory
    ):
        """Test matching excludes candidates who already applied."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(
            tenant=tenant,
            status='open',
            required_skills=['Python']
        )

        already_applied = candidate_factory(
            tenant=tenant,
            email='applied@example.com',
            skills=['Python']
        )
        not_applied = candidate_factory(
            tenant=tenant,
            email='notapplied@example.com',
            skills=['Python']
        )

        # Create application for one candidate
        application_factory(
            tenant=tenant,
            candidate=already_applied,
            job=job
        )

        # Execute
        matches = CandidateService.get_best_matches(
            tenant=tenant,
            job=job,
            min_score=0.0
        )

        # Verify
        match_ids = [m.candidate_id for m in matches]
        assert str(already_applied.id) not in match_ids
        assert str(not_applied.id) in match_ids

    def test_deduplicate_batch_dry_run(
        self,
        tenant_factory,
        candidate_factory
    ):
        """Test batch deduplication in dry run mode."""
        # Setup
        tenant = tenant_factory()

        # Create duplicates with same email
        candidate_factory(
            tenant=tenant,
            email='duplicate@example.com',
            first_name='John'
        )
        candidate_factory(
            tenant=tenant,
            email='unique@example.com',
            first_name='Jane'
        )

        # Execute
        result = CandidateService.deduplicate_batch(
            tenant=tenant,
            dry_run=True
        )

        # Verify
        assert result.success is True
        # Should report duplicate groups without merging
        assert 'duplicate_groups_count' in result.data
        assert result.data['merge_results'] == []  # No merges in dry run


# ============================================================================
# JOB POSTING SERVICE TESTS
# ============================================================================

@pytest.mark.services
@pytest.mark.django_db
class TestJobPostingService:
    """Tests for JobPostingService."""

    def test_publish_success(
        self,
        tenant_factory,
        job_posting_factory,
        pipeline_factory,
        user_factory
    ):
        """Test successful job publication."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)
        user = user_factory()

        job = job_posting_factory(
            tenant=tenant,
            status='draft',
            title='Software Engineer',
            description='Great opportunity!',
            pipeline=pipeline,
            published_at=None
        )

        # Execute
        result = JobPostingService.publish(job=job, user=user)

        # Verify
        assert result.success is True
        job.refresh_from_db()
        assert job.status == JobPosting.JobStatus.OPEN
        assert job.published_at is not None

    def test_publish_incomplete_fails(
        self,
        tenant_factory,
        job_posting_factory
    ):
        """Test cannot publish incomplete job."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(
            tenant=tenant,
            status='draft',
            title='',  # Missing title
            description='',  # Missing description
            pipeline=None  # Missing pipeline
        )

        # Execute
        result = JobPostingService.publish(job=job)

        # Verify
        assert result.success is False
        assert len(result.errors) > 0

    def test_publish_requires_pipeline(
        self,
        tenant_factory,
        job_posting_factory
    ):
        """Test publishing requires a pipeline."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(
            tenant=tenant,
            status='draft',
            title='Test Job',
            description='Test description',
            pipeline=None
        )

        # Execute
        result = JobPostingService.publish(job=job)

        # Verify
        assert result.success is False
        assert 'pipeline' in result.errors

    def test_clone_creates_draft(
        self,
        tenant_factory,
        job_posting_factory,
        pipeline_factory,
        user_factory
    ):
        """Test cloning creates draft copy."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)
        user = user_factory()

        original = job_posting_factory(
            tenant=tenant,
            status='open',
            title='Original Job',
            description='Original description',
            pipeline=pipeline,
            salary_min=Decimal('60000'),
            salary_max=Decimal('90000'),
            required_skills=['Python', 'Django']
        )

        # Execute
        result = JobPostingService.clone(
            job=original,
            new_title='Cloned Job',
            new_reference_code='JOB-CLONE-001',
            user=user
        )

        # Verify
        assert result.success is True
        cloned = result.data

        assert cloned.pk != original.pk
        assert cloned.title == 'Cloned Job'
        assert cloned.reference_code == 'JOB-CLONE-001'
        assert cloned.status == JobPosting.JobStatus.DRAFT  # Draft status
        assert cloned.description == original.description
        assert cloned.salary_min == original.salary_min
        assert cloned.required_skills == original.required_skills
        assert cloned.published_at is None  # Not published yet

    def test_close_with_reason(
        self,
        tenant_factory,
        job_posting_factory,
        user_factory
    ):
        """Test closing job with reason."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()
        job = job_posting_factory(
            tenant=tenant,
            status='open'
        )

        # Test closing as filled
        result = JobPostingService.close(
            job=job,
            reason='filled',
            user=user
        )

        assert result.success is True
        job.refresh_from_db()
        assert job.status == JobPosting.JobStatus.FILLED
        assert job.closed_at is not None

    def test_close_cancelled(
        self,
        tenant_factory,
        job_posting_factory,
        user_factory
    ):
        """Test closing job as cancelled."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()
        job = job_posting_factory(
            tenant=tenant,
            status='open'
        )

        # Execute
        result = JobPostingService.close(
            job=job,
            reason='cancelled',
            user=user
        )

        # Verify
        assert result.success is True
        job.refresh_from_db()
        assert job.status == JobPosting.JobStatus.CANCELLED

    def test_close_already_closed_fails(
        self,
        tenant_factory,
        job_posting_factory
    ):
        """Test cannot close already closed job."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(
            tenant=tenant,
            status='closed'
        )

        # Execute
        result = JobPostingService.close(job=job, reason='filled')

        # Verify
        assert result.success is False
        assert 'already' in result.message.lower()

    def test_get_job_metrics(
        self,
        tenant_factory,
        job_posting_factory,
        candidate_factory,
        application_factory,
        pipeline_factory,
        pipeline_stage_factory
    ):
        """Test job metrics calculation."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)
        stage = pipeline_stage_factory(pipeline=pipeline)

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline,
            positions_count=3
        )

        # Create applications with different statuses
        for i in range(5):
            candidate = candidate_factory(
                tenant=tenant,
                email=f'candidate{i}@test.com'
            )
            status = 'new' if i < 3 else ('rejected' if i == 3 else 'hired')
            app = application_factory(
                tenant=tenant,
                candidate=candidate,
                job=job,
                status=status,
                current_stage=stage
            )
            if status == 'hired':
                app.hired_at = timezone.now()
                app.save()

        # Execute
        metrics = JobPostingService.get_job_metrics(job)

        # Verify
        assert metrics['total_applications'] == 5
        assert metrics['rejected_count'] == 1
        assert metrics['hired_count'] == 1
        assert metrics['positions_remaining'] == 2  # 3 - 1 hired


# ============================================================================
# PIPELINE SERVICE TESTS
# ============================================================================

@pytest.mark.services
@pytest.mark.django_db
class TestPipelineService:
    """Tests for PipelineService."""

    def test_get_metrics(
        self,
        tenant_factory,
        pipeline_factory,
        pipeline_stage_factory,
        job_posting_factory,
        candidate_factory,
        application_factory
    ):
        """Test pipeline metrics calculation."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)

        stage1 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Applied',
            order=0,
            is_active=True
        )
        stage2 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Interview',
            order=1,
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline
        )

        # Create applications in different stages
        for i in range(3):
            candidate = candidate_factory(
                tenant=tenant,
                email=f'stage1_{i}@test.com'
            )
            application_factory(
                tenant=tenant,
                candidate=candidate,
                job=job,
                current_stage=stage1
            )

        for i in range(2):
            candidate = candidate_factory(
                tenant=tenant,
                email=f'stage2_{i}@test.com'
            )
            application_factory(
                tenant=tenant,
                candidate=candidate,
                job=job,
                current_stage=stage2
            )

        # Execute
        metrics = PipelineService.get_metrics(pipeline)

        # Verify
        assert isinstance(metrics, PipelineMetrics)
        assert metrics.total_applications == 5
        assert metrics.applications_by_stage['Applied'] == 3
        assert metrics.applications_by_stage['Interview'] == 2

    def test_get_bottlenecks(
        self,
        tenant_factory,
        pipeline_factory,
        pipeline_stage_factory
    ):
        """Test bottleneck detection."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)

        # Create stages
        pipeline_stage_factory(
            pipeline=pipeline,
            name='Applied',
            order=0,
            is_active=True,
            stage_type='new'
        )
        pipeline_stage_factory(
            pipeline=pipeline,
            name='Interview',
            order=1,
            is_active=True,
            stage_type='interview'
        )

        # Execute
        bottlenecks = PipelineService.get_bottlenecks(pipeline)

        # Verify
        assert isinstance(bottlenecks, list)
        # With no applications, no bottlenecks should be detected
        # (bottlenecks require > 10 applications in stage)

    def test_reorder_stages(
        self,
        tenant_factory,
        pipeline_factory,
        pipeline_stage_factory
    ):
        """Test stage reordering."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)

        stage1 = pipeline_stage_factory(
            pipeline=pipeline,
            name='First',
            order=0
        )
        stage2 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Second',
            order=1
        )
        stage3 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Third',
            order=2
        )

        # New order: Third, First, Second
        new_order = [str(stage3.id), str(stage1.id), str(stage2.id)]

        # Execute
        result = PipelineService.reorder_stages(
            pipeline=pipeline,
            stage_order=new_order
        )

        # Verify
        assert result.success is True

        stage1.refresh_from_db()
        stage2.refresh_from_db()
        stage3.refresh_from_db()

        assert stage3.order == 0
        assert stage1.order == 1
        assert stage2.order == 2

    def test_clone_pipeline(
        self,
        tenant_factory,
        pipeline_factory,
        pipeline_stage_factory,
        user_factory
    ):
        """Test pipeline cloning."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()

        original = pipeline_factory(
            tenant=tenant,
            name='Original Pipeline',
            description='Original description'
        )

        # Add stages
        pipeline_stage_factory(
            pipeline=original,
            name='Applied',
            order=0,
            stage_type='new'
        )
        pipeline_stage_factory(
            pipeline=original,
            name='Interview',
            order=1,
            stage_type='interview'
        )
        pipeline_stage_factory(
            pipeline=original,
            name='Offer',
            order=2,
            stage_type='offer'
        )

        # Execute
        result = PipelineService.clone_pipeline(
            pipeline=original,
            new_name='Cloned Pipeline',
            user=user
        )

        # Verify
        assert result.success is True
        cloned = result.data

        assert cloned.pk != original.pk
        assert cloned.name == 'Cloned Pipeline'
        assert cloned.description == original.description
        assert cloned.is_default is False  # Clone should not be default

        # Verify stages were cloned
        assert cloned.stages.count() == 3
        cloned_stage_names = list(cloned.stages.values_list('name', flat=True))
        assert 'Applied' in cloned_stage_names
        assert 'Interview' in cloned_stage_names
        assert 'Offer' in cloned_stage_names

    def test_move_stage(
        self,
        tenant_factory,
        pipeline_factory,
        pipeline_stage_factory,
        job_posting_factory,
        candidate_factory,
        application_factory,
        user_factory
    ):
        """Test moving application via pipeline service."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()
        pipeline = pipeline_factory(tenant=tenant)

        stage1 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Applied',
            order=0
        )
        stage2 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Interview',
            order=1
        )

        job = job_posting_factory(
            tenant=tenant,
            pipeline=pipeline,
            status='open'
        )
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            current_stage=stage1
        )

        # Execute
        result = PipelineService.move_stage(
            application=application,
            target_stage=stage2,
            user=user,
            notes='Moving to interview'
        )

        # Verify
        assert result.success is True
        application.refresh_from_db()
        assert application.current_stage == stage2

    def test_get_funnel_metrics(
        self,
        tenant_factory,
        pipeline_factory,
        pipeline_stage_factory,
        job_posting_factory,
        candidate_factory,
        application_factory
    ):
        """Test funnel metrics calculation."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)

        stage1 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Applied',
            order=0,
            stage_type='new',
            is_active=True
        )
        stage2 = pipeline_stage_factory(
            pipeline=pipeline,
            name='Interview',
            order=1,
            stage_type='interview',
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline
        )

        # Create applications
        for i in range(5):
            candidate = candidate_factory(
                tenant=tenant,
                email=f'funnel{i}@test.com'
            )
            application_factory(
                tenant=tenant,
                candidate=candidate,
                job=job,
                current_stage=stage1 if i < 3 else stage2
            )

        # Execute
        funnel_metrics = PipelineService.get_funnel_metrics(
            pipeline=pipeline,
            job=job
        )

        # Verify
        assert 'total_applications' in funnel_metrics
        assert funnel_metrics['total_applications'] == 5
        assert 'funnel' in funnel_metrics
        assert isinstance(funnel_metrics['funnel'], list)


# ============================================================================
# SERVICE RESULT TESTS
# ============================================================================

@pytest.mark.services
class TestServiceResult:
    """Tests for ServiceResult dataclass."""

    def test_success_result(self):
        """Test successful result creation."""
        result = ServiceResult(
            success=True,
            message='Operation completed',
            data={'id': 123}
        )

        assert result.success is True
        assert result.message == 'Operation completed'
        assert result.data == {'id': 123}
        assert result.errors == {}

    def test_failure_result(self):
        """Test failure result creation."""
        result = ServiceResult(
            success=False,
            message='Operation failed',
            errors={'field': 'Error message'}
        )

        assert result.success is False
        assert result.message == 'Operation failed'
        assert result.errors == {'field': 'Error message'}

    def test_errors_default_to_empty_dict(self):
        """Test errors default to empty dict."""
        result = ServiceResult(success=True, message='OK')

        assert result.errors == {}


# ============================================================================
# EDGE CASES AND ERROR HANDLING TESTS
# ============================================================================

@pytest.mark.services
@pytest.mark.django_db
class TestServiceEdgeCases:
    """Tests for edge cases and error handling in services."""

    def test_apply_with_utm_params(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory,
        pipeline_factory,
        pipeline_stage_factory
    ):
        """Test application with UTM tracking parameters."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)
        pipeline_stage_factory(
            pipeline=pipeline,
            order=0,
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline
        )
        candidate = candidate_factory(tenant=tenant)

        utm_params = {
            'source': 'linkedin',
            'medium': 'social',
            'campaign': 'developer_hiring_2024'
        }

        # Execute
        result = ApplicationService.apply(
            tenant=tenant,
            candidate=candidate,
            job=job,
            utm_params=utm_params
        )

        # Verify
        assert result.success is True
        app = result.data
        assert app.utm_source == 'linkedin'
        assert app.utm_medium == 'social'
        assert app.utm_campaign == 'developer_hiring_2024'

    def test_apply_calculates_ai_match_score(
        self,
        tenant_factory,
        candidate_factory,
        job_posting_factory,
        pipeline_factory,
        pipeline_stage_factory
    ):
        """Test application calculates AI match score."""
        # Setup
        tenant = tenant_factory()
        pipeline = pipeline_factory(tenant=tenant)
        pipeline_stage_factory(
            pipeline=pipeline,
            order=0,
            is_active=True
        )

        job = job_posting_factory(
            tenant=tenant,
            status='open',
            pipeline=pipeline,
            required_skills=['Python', 'Django', 'PostgreSQL', 'Redis']
        )
        candidate = candidate_factory(
            tenant=tenant,
            skills=['Python', 'Django']  # 50% match
        )

        # Execute
        result = ApplicationService.apply(
            tenant=tenant,
            candidate=candidate,
            job=job
        )

        # Verify
        assert result.success is True
        app = result.data
        assert app.ai_match_score is not None
        assert float(app.ai_match_score) == 50.0

    def test_reject_already_rejected_fails(
        self,
        tenant_factory,
        application_factory,
        job_posting_factory,
        candidate_factory
    ):
        """Test cannot reject already rejected application."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(tenant=tenant, status='open')
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            status='rejected'
        )

        # Execute
        result = ApplicationService.reject(application=application)

        # Verify
        assert result.success is False
        assert 'cannot' in result.message.lower() or 'terminal' in str(result.errors).lower()

    def test_withdraw_already_hired_fails(
        self,
        tenant_factory,
        application_factory,
        job_posting_factory,
        candidate_factory
    ):
        """Test cannot withdraw already hired application."""
        # Setup
        tenant = tenant_factory()
        job = job_posting_factory(tenant=tenant, status='open')
        candidate = candidate_factory(tenant=tenant)
        application = application_factory(
            tenant=tenant,
            candidate=candidate,
            job=job,
            status='hired'
        )

        # Execute
        result = ApplicationService.withdraw(application=application)

        # Verify
        assert result.success is False

    def test_bulk_import_empty_csv(
        self,
        tenant_factory,
        user_factory
    ):
        """Test bulk import with empty CSV."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()

        csv_data = "first_name,last_name,email"  # Headers only, no data

        # Execute
        result = CandidateService.bulk_import(
            tenant=tenant,
            csv_data=csv_data,
            user=user
        )

        # Verify
        assert result.success is True  # No failures, just no imports
        assert result.data['created_count'] == 0

    def test_bulk_import_malformed_csv(
        self,
        tenant_factory,
        user_factory
    ):
        """Test bulk import handles malformed CSV gracefully."""
        # Setup
        tenant = tenant_factory()
        user = user_factory()

        # Missing email column
        csv_data = """first_name,last_name
John,Doe"""

        # Execute
        result = CandidateService.bulk_import(
            tenant=tenant,
            csv_data=csv_data,
            user=user
        )

        # Verify - should handle gracefully
        assert result.data['created_count'] == 0
        assert result.data['failed_count'] >= 1
