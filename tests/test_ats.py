"""
Comprehensive ATS (Applicant Tracking System) Tests for Zumodra

This module provides extensive testing coverage for the ATS application:
- JobPosting CRUD and lifecycle management
- Pipeline and stage management
- Candidate creation and deduplication
- Application workflow and stage transitions
- Interview scheduling and feedback
- Offer creation, approval, and acceptance
- Saved searches
- Ranking/matching logic
- Permission checks (recruiter vs hiring manager)
- Bulk operations
- Export functionality

Uses factories from conftest.py and base test classes from tests/base.py.
"""

import pytest
from datetime import timedelta, date
from decimal import Decimal
from unittest.mock import MagicMock, patch
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from tests.base import TenantTestCase, APITenantTestCase

from conftest import (
    UserFactory, TenantFactory, PlanFactory, TenantUserFactory,
    JobCategoryFactory, PipelineFactory, PipelineStageFactory, DefaultPipelineFactory,
    JobPostingFactory, DraftJobPostingFactory,
    CandidateFactory, ApplicationFactory,
    ApplicationActivityFactory, ApplicationNoteFactory,
    InterviewFactory, InterviewFeedbackFactory,
    OfferFactory, SentOfferFactory,
    SavedSearchFactory,
    RecruiterTenantUserFactory, HiringManagerTenantUserFactory,
    AdminTenantUserFactory, ViewerTenantUserFactory
)


# =============================================================================
# JOB CATEGORY TESTS
# =============================================================================

@pytest.mark.django_db
class TestJobCategory:
    """Test JobCategory model functionality."""

    def test_create_job_category(self, job_category_factory):
        """Test creating a job category."""
        category = job_category_factory(name='Engineering', slug='engineering')

        assert category.pk is not None
        assert category.name == 'Engineering'
        assert category.slug == 'engineering'
        assert category.is_active is True

    def test_category_hierarchy(self, job_category_factory):
        """Test parent-child category hierarchy."""
        parent = job_category_factory(name='Engineering', slug='engineering')
        child = job_category_factory(
            name='Backend',
            slug='backend',
            parent=parent
        )

        assert child.parent == parent
        assert str(child) == 'Engineering > Backend'
        assert child.depth == 1
        assert parent.depth == 0

    def test_category_full_path(self, job_category_factory):
        """Test full path computation for nested categories."""
        level1 = job_category_factory(name='Tech', slug='tech')
        level2 = job_category_factory(name='Engineering', slug='engineering', parent=level1)
        level3 = job_category_factory(name='Backend', slug='backend', parent=level2)

        assert level3.full_path == 'Tech > Engineering > Backend'
        assert level2.full_path == 'Tech > Engineering'
        assert level1.full_path == 'Tech'

    def test_category_get_descendants(self, job_category_factory):
        """Test getting all descendants of a category."""
        parent = job_category_factory(name='Engineering', slug='engineering')
        child1 = job_category_factory(name='Backend', slug='backend', parent=parent)
        child2 = job_category_factory(name='Frontend', slug='frontend', parent=parent)
        grandchild = job_category_factory(name='Python', slug='python', parent=child1)

        descendants = parent.get_descendants()

        assert child1 in descendants
        assert child2 in descendants
        assert grandchild in descendants
        assert len(descendants) == 3

    def test_category_circular_reference_prevention(self, job_category_factory):
        """Test that circular parent references are prevented."""
        category = job_category_factory(name='Test', slug='test')
        category.parent = category

        with pytest.raises(ValidationError):
            category.clean()

    def test_category_unique_slug_per_tenant(self, job_category_factory, tenant_factory):
        """Test that category slug is unique per tenant."""
        cat1 = job_category_factory(slug='engineering')

        # Same slug should fail within same tenant
        with pytest.raises(IntegrityError):
            job_category_factory(slug='engineering', tenant=cat1.tenant)


# =============================================================================
# PIPELINE TESTS
# =============================================================================

@pytest.mark.django_db
class TestPipeline:
    """Test Pipeline model functionality."""

    def test_create_pipeline(self, pipeline_factory):
        """Test creating a pipeline."""
        pipeline = pipeline_factory(name='Standard Hiring', is_default=True)

        assert pipeline.pk is not None
        assert pipeline.name == 'Standard Hiring'
        assert pipeline.is_default is True

    def test_only_one_default_pipeline_per_tenant(self, pipeline_factory, tenant_factory, plan_factory):
        """Test that only one default pipeline can exist per tenant."""
        plan = plan_factory()
        tenant = tenant_factory(plan=plan)

        # Create first default pipeline
        pipeline1 = pipeline_factory(is_default=True)

        # Creating another default should raise validation error on clean
        pipeline2 = PipelineFactory.build(
            tenant=pipeline1.tenant,
            is_default=True
        )

        with pytest.raises(ValidationError):
            pipeline2.clean()

    def test_pipeline_clone(self, pipeline_factory, pipeline_stage_factory, user_factory):
        """Test cloning a pipeline with all stages."""
        pipeline = pipeline_factory(name='Original Pipeline')
        pipeline_stage_factory(pipeline=pipeline, name='New', order=0)
        pipeline_stage_factory(pipeline=pipeline, name='Screening', order=1)
        pipeline_stage_factory(pipeline=pipeline, name='Interview', order=2)

        user = user_factory()
        cloned = pipeline.clone(new_name='Cloned Pipeline', created_by=user)

        assert cloned.pk != pipeline.pk
        assert cloned.name == 'Cloned Pipeline'
        assert cloned.is_default is False
        assert cloned.stages.count() == pipeline.stages.count()

    def test_pipeline_set_as_default(self, pipeline_factory):
        """Test setting a pipeline as default."""
        pipeline1 = pipeline_factory(is_default=True)
        pipeline2 = pipeline_factory(is_default=False, tenant=pipeline1.tenant)

        pipeline2.set_as_default()
        pipeline1.refresh_from_db()
        pipeline2.refresh_from_db()

        assert pipeline2.is_default is True
        assert pipeline1.is_default is False

    def test_get_stages_ordered(self, pipeline_factory, pipeline_stage_factory):
        """Test getting stages in correct order."""
        pipeline = pipeline_factory()
        stage3 = pipeline_stage_factory(pipeline=pipeline, name='C', order=2)
        stage1 = pipeline_stage_factory(pipeline=pipeline, name='A', order=0)
        stage2 = pipeline_stage_factory(pipeline=pipeline, name='B', order=1)

        ordered_stages = list(pipeline.get_stages_ordered())

        assert ordered_stages[0] == stage1
        assert ordered_stages[1] == stage2
        assert ordered_stages[2] == stage3


# =============================================================================
# PIPELINE STAGE TESTS
# =============================================================================

@pytest.mark.django_db
class TestPipelineStage:
    """Test PipelineStage model functionality."""

    def test_create_pipeline_stage(self, pipeline_stage_factory, pipeline_factory):
        """Test creating a pipeline stage."""
        pipeline = pipeline_factory()
        stage = pipeline_stage_factory(
            pipeline=pipeline,
            name='Screening',
            stage_type='screening',
            order=1
        )

        assert stage.pk is not None
        assert stage.name == 'Screening'
        assert stage.stage_type == 'screening'

    def test_stage_is_terminal(self, pipeline_stage_factory, pipeline_factory):
        """Test terminal stage detection."""
        pipeline = pipeline_factory()

        hired_stage = pipeline_stage_factory(pipeline=pipeline, stage_type='hired')
        rejected_stage = pipeline_stage_factory(pipeline=pipeline, stage_type='rejected')
        interview_stage = pipeline_stage_factory(pipeline=pipeline, stage_type='interview')

        assert hired_stage.is_terminal is True
        assert rejected_stage.is_terminal is True
        assert interview_stage.is_terminal is False

    def test_get_next_stage(self, pipeline_factory, pipeline_stage_factory):
        """Test getting the next stage in pipeline."""
        pipeline = pipeline_factory()
        stage1 = pipeline_stage_factory(pipeline=pipeline, order=0)
        stage2 = pipeline_stage_factory(pipeline=pipeline, order=1)
        stage3 = pipeline_stage_factory(pipeline=pipeline, order=2)

        assert stage1.get_next_stage() == stage2
        assert stage2.get_next_stage() == stage3
        assert stage3.get_next_stage() is None

    def test_get_previous_stage(self, pipeline_factory, pipeline_stage_factory):
        """Test getting the previous stage in pipeline."""
        pipeline = pipeline_factory()
        stage1 = pipeline_stage_factory(pipeline=pipeline, order=0)
        stage2 = pipeline_stage_factory(pipeline=pipeline, order=1)
        stage3 = pipeline_stage_factory(pipeline=pipeline, order=2)

        assert stage3.get_previous_stage() == stage2
        assert stage2.get_previous_stage() == stage1
        assert stage1.get_previous_stage() is None


# =============================================================================
# JOB POSTING TESTS - CRUD AND LIFECYCLE
# =============================================================================

@pytest.mark.django_db
class TestJobPostingCRUD:
    """Test JobPosting CRUD operations."""

    def test_create_job_posting(self, job_posting_factory):
        """Test creating a job posting."""
        job = job_posting_factory(
            title='Senior Python Developer',
            status='draft'
        )

        assert job.pk is not None
        assert job.title == 'Senior Python Developer'
        assert job.uuid is not None
        assert job.reference_code is not None

    def test_create_draft_job_posting(self):
        """Test creating a draft job posting using factory."""
        job = DraftJobPostingFactory()

        assert job.status == 'draft'
        assert job.published_at is None

    def test_job_posting_required_fields(self, job_posting_factory):
        """Test job posting with all required fields."""
        job = job_posting_factory(
            title='Test Job',
            description='Test Description',
            job_type='full_time',
            experience_level='mid',
            remote_policy='hybrid'
        )

        assert job.title == 'Test Job'
        assert job.job_type == 'full_time'
        assert job.experience_level == 'mid'
        assert job.remote_policy == 'hybrid'

    def test_job_posting_salary_range_display(self, job_posting_factory):
        """Test salary range display formatting."""
        job = job_posting_factory(
            salary_min=Decimal('60000.00'),
            salary_max=Decimal('90000.00'),
            salary_currency='CAD'
        )

        assert 'CAD' in job.salary_range_display
        assert '60,000' in job.salary_range_display
        assert '90,000' in job.salary_range_display

    def test_job_posting_location_display(self, job_posting_factory):
        """Test location display formatting."""
        job = job_posting_factory(
            location_city='Toronto',
            location_state='Ontario',
            location_country='Canada'
        )

        assert job.location_display == 'Toronto, Ontario, Canada'

    def test_job_posting_unique_reference_code(self, job_posting_factory):
        """Test that reference codes are unique."""
        job1 = job_posting_factory(reference_code='JOB-001')

        with pytest.raises(IntegrityError):
            job_posting_factory(reference_code='JOB-001')


@pytest.mark.django_db
class TestJobPostingLifecycle:
    """Test JobPosting lifecycle (draft -> open -> closed -> archived)."""

    def test_job_lifecycle_draft_to_open(self, job_posting_factory, pipeline_factory):
        """Test publishing a draft job posting."""
        pipeline = pipeline_factory()
        job = job_posting_factory(
            status='draft',
            pipeline=pipeline,
            published_at=None
        )

        job.publish()

        assert job.status == 'open'
        assert job.published_at is not None
        assert job.is_open is True

    def test_job_lifecycle_open_to_closed(self, job_posting_factory):
        """Test closing an open job posting."""
        job = job_posting_factory(status='open')

        job.close(reason='closed')

        assert job.status == 'closed'
        assert job.closed_at is not None
        assert job.is_closed is True

    def test_job_lifecycle_close_as_filled(self, job_posting_factory):
        """Test closing a job as filled."""
        job = job_posting_factory(status='open')

        job.close(reason='filled')

        assert job.status == 'filled'

    def test_job_lifecycle_close_as_cancelled(self, job_posting_factory):
        """Test cancelling a job posting."""
        job = job_posting_factory(status='open')

        job.close(reason='cancelled')

        assert job.status == 'cancelled'

    def test_job_lifecycle_put_on_hold(self, job_posting_factory):
        """Test putting a job on hold."""
        job = job_posting_factory(status='open')

        job.put_on_hold()

        assert job.status == 'on_hold'

    def test_job_lifecycle_reopen(self, job_posting_factory):
        """Test reopening a closed job."""
        job = job_posting_factory(status='closed')

        job.reopen()

        assert job.status == 'open'
        assert job.closed_at is None

    def test_job_cannot_publish_without_pipeline(self, job_posting_factory):
        """Test that job cannot be published without a pipeline."""
        job = job_posting_factory(status='draft', pipeline=None)

        assert job.is_publishable is False

    def test_job_can_accept_applications(self, job_posting_factory):
        """Test checking if job can accept applications."""
        open_job = job_posting_factory(status='open')
        closed_job = job_posting_factory(status='closed')

        assert open_job.can_accept_applications is True
        assert closed_job.can_accept_applications is False

    def test_job_clone(self, job_posting_factory, user_factory):
        """Test cloning a job posting."""
        original = job_posting_factory(
            title='Original Job',
            description='Original Description',
            salary_min=Decimal('50000'),
            salary_max=Decimal('70000')
        )
        user = user_factory()

        cloned = original.clone(
            new_title='Cloned Job',
            new_reference_code='JOB-CLONE-001',
            created_by=user
        )

        assert cloned.pk != original.pk
        assert cloned.title == 'Cloned Job'
        assert cloned.status == 'draft'
        assert cloned.description == original.description
        assert cloned.salary_min == original.salary_min


# =============================================================================
# CANDIDATE TESTS
# =============================================================================

@pytest.mark.django_db
class TestCandidate:
    """Test Candidate model functionality."""

    def test_create_candidate(self, candidate_factory):
        """Test creating a candidate."""
        candidate = candidate_factory(
            first_name='John',
            last_name='Doe',
            email='john.doe@example.com'
        )

        assert candidate.pk is not None
        assert candidate.full_name == 'John Doe'
        assert candidate.email == 'john.doe@example.com'

    def test_candidate_initials(self, candidate_factory):
        """Test candidate initials."""
        candidate = candidate_factory(first_name='John', last_name='Doe')

        assert candidate.initials == 'JD'

    def test_candidate_location_display(self, candidate_factory):
        """Test candidate location display."""
        candidate = candidate_factory(
            city='Toronto',
            state='ON',
            country='Canada'
        )

        assert candidate.location_display == 'Toronto, ON, Canada'

    def test_candidate_skill_match_score(self, candidate_factory, job_posting_factory):
        """Test skill match score calculation."""
        candidate = candidate_factory(skills=['Python', 'Django', 'PostgreSQL'])
        job = job_posting_factory(required_skills=['Python', 'Django', 'React', 'AWS'])

        score = candidate.get_skill_match_score(job)

        # 2 out of 4 required skills match = 50%
        assert score == 50.0

    def test_candidate_add_tag(self, candidate_factory):
        """Test adding tags to a candidate."""
        candidate = candidate_factory(tags=[])

        candidate.add_tag('senior')
        candidate.add_tag('python')

        assert 'senior' in candidate.tags
        assert 'python' in candidate.tags

    def test_candidate_remove_tag(self, candidate_factory):
        """Test removing tags from a candidate."""
        candidate = candidate_factory(tags=['senior', 'python'])

        candidate.remove_tag('python')

        assert 'python' not in candidate.tags
        assert 'senior' in candidate.tags

    def test_candidate_unique_email_per_tenant(self, candidate_factory):
        """Test that candidate email is unique per tenant."""
        candidate1 = candidate_factory(email='test@example.com')

        with pytest.raises(IntegrityError):
            candidate_factory(email='test@example.com', tenant=candidate1.tenant)

    def test_candidate_deduplication_merge(self, candidate_factory):
        """Test merging duplicate candidates."""
        primary = candidate_factory(
            first_name='John',
            email='john@example.com',
            skills=['Python'],
            phone=''
        )
        duplicate = candidate_factory(
            first_name='John',
            email='john.duplicate@example.com',
            skills=['Django'],
            phone='+1234567890'
        )

        primary.merge_from(duplicate, delete_other=False)

        assert 'Python' in primary.skills
        assert 'Django' in primary.skills
        assert primary.phone == '+1234567890'

    def test_candidate_consent_tracking(self, candidate_factory):
        """Test GDPR consent tracking."""
        candidate = candidate_factory(
            consent_to_store=True,
            consent_date=timezone.now(),
            data_retention_until=date.today() + timedelta(days=365)
        )

        assert candidate.has_valid_consent is True

        # Test expired consent
        candidate.data_retention_until = date.today() - timedelta(days=1)
        candidate.save()

        assert candidate.has_valid_consent is False


# =============================================================================
# APPLICATION TESTS
# =============================================================================

@pytest.mark.django_db
class TestApplication:
    """Test Application model functionality."""

    def test_create_application(self, application_factory):
        """Test creating an application."""
        app = application_factory()

        assert app.pk is not None
        assert app.status == 'new'
        assert app.applied_at is not None

    def test_application_unique_per_job_candidate(self, application_factory):
        """Test that a candidate can only apply once per job."""
        app1 = application_factory()

        from ats.models import Application

        with pytest.raises(IntegrityError):
            Application.objects.create(
                tenant=app1.tenant,
                job=app1.job,
                candidate=app1.candidate,
                current_stage=app1.current_stage,
                status='new'
            )

    def test_application_is_active(self, application_factory):
        """Test checking if application is active."""
        new_app = application_factory(status='new')
        hired_app = application_factory(status='hired')
        rejected_app = application_factory(status='rejected')

        assert new_app.is_active is True
        assert hired_app.is_active is False
        assert rejected_app.is_active is False

    def test_application_is_terminal(self, application_factory):
        """Test checking if application is terminal."""
        new_app = application_factory(status='new')
        hired_app = application_factory(status='hired')
        withdrawn_app = application_factory(status='withdrawn')

        assert new_app.is_terminal is False
        assert hired_app.is_terminal is True
        assert withdrawn_app.is_terminal is True


@pytest.mark.django_db
class TestApplicationWorkflow:
    """Test Application workflow and stage transitions."""

    def test_move_to_stage(self, application_factory, pipeline_stage_factory, user_factory):
        """Test moving application to a specific stage."""
        app = application_factory(status='new')
        user = user_factory()
        next_stage = pipeline_stage_factory(
            pipeline=app.job.pipeline,
            name='Screening',
            stage_type='screening',
            order=1
        )

        app.move_to_stage(next_stage, user=user, notes='Passed initial review')

        assert app.current_stage == next_stage
        assert app.last_stage_change_at is not None

    def test_advance_to_next_stage(self, application_factory, pipeline_stage_factory, user_factory):
        """Test advancing application to next stage."""
        app = application_factory(status='new')
        user = user_factory()

        # Create stages in order
        stage1 = pipeline_stage_factory(pipeline=app.job.pipeline, order=0, stage_type='new')
        stage2 = pipeline_stage_factory(pipeline=app.job.pipeline, order=1, stage_type='screening')

        app.current_stage = stage1
        app.save()

        app.advance_to_next_stage(user=user)

        assert app.current_stage == stage2

    def test_reject_application(self, application_factory, user_factory):
        """Test rejecting an application."""
        app = application_factory(status='in_review')
        user = user_factory()

        app.reject(
            reason='Not enough experience',
            feedback='We need someone with more backend experience.',
            user=user
        )

        assert app.status == 'rejected'
        assert app.rejection_reason == 'Not enough experience'
        assert app.rejected_at is not None

    def test_cannot_reject_already_hired(self, application_factory, user_factory):
        """Test that hired applications cannot be rejected."""
        app = application_factory(status='hired')
        user = user_factory()

        with pytest.raises(ValidationError):
            app.reject(reason='Test', user=user)

    def test_withdraw_application(self, application_factory, user_factory):
        """Test withdrawing an application."""
        app = application_factory(status='in_review')
        user = user_factory()

        app.withdraw(reason='Accepted another offer', user=user)

        assert app.status == 'withdrawn'

    def test_hire_application(self, application_factory, user_factory):
        """Test hiring an application."""
        app = application_factory(status='offer_extended')
        user = user_factory()

        app.hire(user=user)

        assert app.status == 'hired'
        assert app.hired_at is not None

    def test_put_application_on_hold(self, application_factory, user_factory):
        """Test putting application on hold."""
        app = application_factory(status='in_review')
        user = user_factory()

        app.put_on_hold(reason='Waiting for budget approval', user=user)

        assert app.status == 'on_hold'

    def test_update_application_rating(self, application_factory, user_factory):
        """Test updating application rating."""
        app = application_factory()
        user = user_factory()

        app.update_rating(4.5, user=user)

        assert app.overall_rating == Decimal('4.5')

    def test_invalid_rating_raises_error(self, application_factory, user_factory):
        """Test that invalid rating raises validation error."""
        app = application_factory()
        user = user_factory()

        with pytest.raises(ValidationError):
            app.update_rating(6.0, user=user)

    def test_assign_application(self, application_factory, user_factory):
        """Test assigning application to reviewer."""
        app = application_factory()
        reviewer = user_factory()
        assigner = user_factory()

        app.assign_to(reviewer, user=assigner)

        assert app.assigned_to == reviewer


@pytest.mark.django_db
class TestApplicationActivity:
    """Test Application activity tracking."""

    def test_activity_created_on_stage_change(self, application_factory, pipeline_stage_factory, user_factory):
        """Test that activity is logged when stage changes."""
        app = application_factory()
        user = user_factory()
        new_stage = pipeline_stage_factory(
            pipeline=app.job.pipeline,
            name='Screening',
            order=1
        )

        initial_activities = app.activities.count()
        app.move_to_stage(new_stage, user=user)

        assert app.activities.count() > initial_activities

        activity = app.activities.filter(activity_type='stage_change').first()
        assert activity is not None
        assert activity.new_value == 'Screening'


@pytest.mark.django_db
class TestApplicationNote:
    """Test Application notes functionality."""

    def test_create_application_note(self, application_factory, user_factory):
        """Test creating an application note."""
        from ats.models import ApplicationNote

        app = application_factory()
        author = user_factory()

        note = ApplicationNote.objects.create(
            application=app,
            author=author,
            content='Great candidate, strong technical skills.',
            is_private=False
        )

        assert note.pk is not None
        assert note.content == 'Great candidate, strong technical skills.'
        assert note.is_private is False

    def test_private_note(self, application_factory, user_factory):
        """Test creating a private note."""
        from ats.models import ApplicationNote

        app = application_factory()
        author = user_factory()

        note = ApplicationNote.objects.create(
            application=app,
            author=author,
            content='Salary expectations too high.',
            is_private=True
        )

        assert note.is_private is True


# =============================================================================
# INTERVIEW TESTS
# =============================================================================

@pytest.mark.django_db
class TestInterview:
    """Test Interview model functionality."""

    def test_create_interview(self, interview_factory):
        """Test creating an interview."""
        interview = interview_factory()

        assert interview.pk is not None
        assert interview.status == 'scheduled'
        assert interview.uuid is not None

    def test_interview_duration(self, interview_factory):
        """Test interview duration calculation."""
        start = timezone.now() + timedelta(days=1)
        end = start + timedelta(hours=1, minutes=30)

        interview = interview_factory(
            scheduled_start=start,
            scheduled_end=end
        )

        assert interview.duration_minutes == 90

    def test_interview_is_upcoming(self, interview_factory):
        """Test checking if interview is upcoming."""
        future_interview = interview_factory(
            scheduled_start=timezone.now() + timedelta(days=1),
            status='scheduled'
        )

        assert future_interview.is_upcoming is True

    def test_interview_confirm(self, interview_factory):
        """Test confirming an interview."""
        interview = interview_factory(status='scheduled')

        interview.confirm()

        assert interview.status == 'confirmed'
        assert interview.confirmed_at is not None

    def test_interview_start(self, interview_factory):
        """Test starting an interview."""
        interview = interview_factory(status='confirmed')

        interview.start()

        assert interview.status == 'in_progress'
        assert interview.actual_start is not None

    def test_interview_complete(self, interview_factory):
        """Test completing an interview."""
        interview = interview_factory(status='in_progress')

        interview.complete()

        assert interview.status == 'completed'
        assert interview.actual_end is not None

    def test_interview_cancel(self, interview_factory):
        """Test cancelling an interview."""
        interview = interview_factory(status='scheduled')

        interview.cancel(reason='Candidate requested reschedule')

        assert interview.status == 'cancelled'
        assert interview.cancellation_reason == 'Candidate requested reschedule'
        assert interview.cancelled_at is not None

    def test_interview_reschedule(self, interview_factory):
        """Test rescheduling an interview."""
        interview = interview_factory(status='scheduled', reschedule_count=0)
        new_start = timezone.now() + timedelta(days=3)
        new_end = new_start + timedelta(hours=1)

        interview.reschedule(new_start, new_end)

        assert interview.status == 'rescheduled'
        assert interview.scheduled_start == new_start
        assert interview.scheduled_end == new_end
        assert interview.reschedule_count == 1

    def test_interview_mark_no_show(self, interview_factory):
        """Test marking interview as no-show."""
        interview = interview_factory(status='scheduled')

        interview.mark_no_show()

        assert interview.status == 'no_show'


@pytest.mark.django_db
class TestInterviewScheduling:
    """Test Interview scheduling functionality."""

    def test_schedule_interview_with_interviewer(self, application_factory, user_factory):
        """Test scheduling an interview with specific interviewer."""
        from ats.models import Interview

        app = application_factory()
        interviewer = user_factory()
        organizer = user_factory()

        interview = Interview.objects.create(
            application=app,
            interview_type='video',
            title='Technical Interview',
            scheduled_start=timezone.now() + timedelta(days=2),
            scheduled_end=timezone.now() + timedelta(days=2, hours=1),
            organizer=organizer,
            meeting_url='https://meet.example.com/abc'
        )
        interview.interviewers.add(interviewer)

        assert interviewer in interview.interviewers.all()

    def test_interview_reminder_tracking(self, interview_factory):
        """Test interview reminder status tracking."""
        interview = interview_factory()

        interview.mark_reminder_sent('1day')

        assert interview.reminder_sent_1day is True
        assert interview.reminder_sent_1hour is False


@pytest.mark.django_db
class TestInterviewFeedback:
    """Test Interview feedback functionality."""

    def test_create_feedback(self, interview_factory, user_factory):
        """Test creating interview feedback."""
        from ats.models import InterviewFeedback

        interview = interview_factory(status='completed')
        interviewer = user_factory()

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interviewer,
            overall_rating=4,
            technical_skills=5,
            communication=4,
            cultural_fit=4,
            problem_solving=5,
            recommendation='yes',
            strengths='Excellent problem solving skills',
            weaknesses='Could improve communication'
        )

        assert feedback.pk is not None
        assert feedback.overall_rating == 4
        assert feedback.recommendation == 'yes'

    def test_feedback_unique_per_interviewer(self, interview_factory, user_factory):
        """Test that each interviewer can only submit one feedback per interview."""
        from ats.models import InterviewFeedback

        interview = interview_factory(status='completed')
        interviewer = user_factory()

        InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interviewer,
            overall_rating=4,
            recommendation='yes'
        )

        with pytest.raises(IntegrityError):
            InterviewFeedback.objects.create(
                interview=interview,
                interviewer=interviewer,
                overall_rating=5,
                recommendation='strong_yes'
            )

    def test_all_feedback_submitted_check(self, interview_factory, user_factory):
        """Test checking if all feedback is submitted."""
        from ats.models import InterviewFeedback

        interview = interview_factory(status='completed')
        interviewer1 = user_factory()
        interviewer2 = user_factory()
        interview.interviewers.add(interviewer1, interviewer2)

        # Initially, not all feedback submitted
        assert interview.all_feedback_submitted is False

        # Add first feedback
        InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interviewer1,
            overall_rating=4,
            recommendation='yes'
        )

        # Still missing one
        assert interview.all_feedback_submitted is False

        # Add second feedback
        InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interviewer2,
            overall_rating=5,
            recommendation='strong_yes'
        )

        # Now all submitted
        assert interview.all_feedback_submitted is True


# =============================================================================
# OFFER TESTS
# =============================================================================

@pytest.mark.django_db
class TestOffer:
    """Test Offer model functionality."""

    def test_create_offer(self, offer_factory):
        """Test creating an offer."""
        offer = offer_factory()

        assert offer.pk is not None
        assert offer.status == 'draft'
        assert offer.uuid is not None

    def test_sent_offer_factory(self):
        """Test creating a sent offer."""
        offer = SentOfferFactory()

        assert offer.status == 'sent'
        assert offer.sent_at is not None

    def test_offer_total_compensation(self, offer_factory):
        """Test total compensation calculation."""
        offer = offer_factory(
            base_salary=Decimal('80000.00'),
            signing_bonus=Decimal('5000.00')
        )

        assert offer.total_compensation == Decimal('85000.00')


@pytest.mark.django_db
class TestOfferWorkflow:
    """Test Offer workflow and status transitions."""

    def test_send_offer_to_candidate(self, offer_factory):
        """Test sending offer to candidate."""
        offer = offer_factory(
            status='draft',
            approval_status='not_required'
        )

        offer.send_to_candidate()

        assert offer.status == 'sent'
        assert offer.sent_at is not None

    def test_cannot_send_unapproved_offer(self, offer_factory):
        """Test that unapproved offers cannot be sent."""
        offer = offer_factory(
            status='pending_approval',
            approval_status='pending_approval'
        )

        with pytest.raises(ValidationError):
            offer.send_to_candidate()

    def test_accept_offer(self, offer_factory):
        """Test accepting an offer."""
        offer = offer_factory(status='sent')

        offer.accept()

        assert offer.status == 'accepted'
        assert offer.responded_at is not None
        assert offer.application.status == 'hired'

    def test_decline_offer(self, offer_factory):
        """Test declining an offer."""
        offer = offer_factory(status='sent')

        offer.decline(reason='Accepted another offer')

        assert offer.status == 'declined'
        assert offer.decline_reason == 'Accepted another offer'

    def test_withdraw_offer(self, offer_factory):
        """Test withdrawing an offer."""
        offer = offer_factory(status='sent')

        offer.withdraw(reason='Position filled internally')

        assert offer.status == 'withdrawn'

    def test_cannot_withdraw_accepted_offer(self, offer_factory):
        """Test that accepted offers cannot be withdrawn."""
        offer = offer_factory(status='accepted')

        with pytest.raises(ValidationError):
            offer.withdraw()

    def test_offer_expiration_check(self, offer_factory):
        """Test offer expiration check."""
        expired_offer = offer_factory(
            status='sent',
            expiration_date=date.today() - timedelta(days=1)
        )
        valid_offer = offer_factory(
            status='sent',
            expiration_date=date.today() + timedelta(days=7)
        )

        assert expired_offer.is_expired is True
        assert valid_offer.is_expired is False

    def test_days_until_expiration(self, offer_factory):
        """Test days until expiration calculation."""
        offer = offer_factory(
            expiration_date=date.today() + timedelta(days=5)
        )

        assert offer.days_until_expiration == 5


@pytest.mark.django_db
class TestOfferCounterOffer:
    """Test Offer counter-offer functionality."""

    def test_create_counter_offer(self, offer_factory, user_factory):
        """Test creating a counter-offer."""
        original = offer_factory(
            status='sent',
            base_salary=Decimal('75000.00')
        )
        user = user_factory()

        counter = original.create_counter_offer(
            base_salary=Decimal('82000.00'),
            created_by=user,
            notes='Increased base salary as requested'
        )

        assert counter.pk != original.pk
        assert counter.is_counter_offer is True
        assert counter.counter_offer_count == 1
        assert counter.previous_offer == original
        assert counter.base_salary == Decimal('82000.00')
        assert original.status == 'countered'

    def test_offer_chain(self, offer_factory, user_factory):
        """Test offer chain tracking."""
        user = user_factory()
        offer1 = offer_factory(status='sent', base_salary=Decimal('70000'))
        offer2 = offer1.create_counter_offer(Decimal('75000'), user)
        offer3 = offer2.create_counter_offer(Decimal('80000'), user)

        chain = offer3.offer_chain

        assert len(chain) == 3
        assert chain[0] == offer1
        assert chain[1] == offer2
        assert chain[2] == offer3

    def test_salary_difference_from_previous(self, offer_factory, user_factory):
        """Test salary difference calculation."""
        user = user_factory()
        original = offer_factory(status='sent', base_salary=Decimal('70000'))
        counter = original.create_counter_offer(Decimal('77000'), user)

        diff = counter.get_salary_difference_from_previous()

        assert diff['amount'] == Decimal('7000')
        assert diff['percentage'] == 10.0
        assert diff['direction'] == 'increase'


# =============================================================================
# SAVED SEARCH TESTS
# =============================================================================

@pytest.mark.django_db
class TestSavedSearch:
    """Test SavedSearch functionality."""

    def test_create_saved_search(self, user_factory):
        """Test creating a saved search."""
        from ats.models import SavedSearch

        user = user_factory()

        search = SavedSearch.objects.create(
            user=user,
            name='Senior Python Developers',
            filters={
                'skills': ['Python', 'Django'],
                'experience_min': 5,
                'location': 'Toronto'
            },
            is_alert_enabled=True,
            alert_frequency='daily'
        )

        assert search.pk is not None
        assert search.name == 'Senior Python Developers'
        assert search.filters['skills'] == ['Python', 'Django']

    def test_saved_search_using_factory(self):
        """Test SavedSearchFactory."""
        search = SavedSearchFactory(
            name='Backend Engineers',
            is_alert_enabled=True
        )

        assert search.name == 'Backend Engineers'
        assert search.is_alert_enabled is True

    def test_saved_search_alert_frequencies(self, user_factory):
        """Test different alert frequencies."""
        from ats.models import SavedSearch

        user = user_factory()

        for frequency in ['instant', 'daily', 'weekly']:
            search = SavedSearch.objects.create(
                user=user,
                name=f'{frequency} Alert',
                filters={},
                is_alert_enabled=True,
                alert_frequency=frequency
            )
            assert search.alert_frequency == frequency


# =============================================================================
# RANKING/MATCHING LOGIC TESTS
# =============================================================================

@pytest.mark.django_db
class TestRankingMatching:
    """Test candidate ranking and matching logic."""

    def test_candidate_skill_match_full(self, candidate_factory, job_posting_factory):
        """Test 100% skill match."""
        candidate = candidate_factory(skills=['Python', 'Django', 'PostgreSQL'])
        job = job_posting_factory(required_skills=['Python', 'Django', 'PostgreSQL'])

        score = candidate.get_skill_match_score(job)

        assert score == 100.0

    def test_candidate_skill_match_partial(self, candidate_factory, job_posting_factory):
        """Test partial skill match."""
        candidate = candidate_factory(skills=['Python', 'Django'])
        job = job_posting_factory(required_skills=['Python', 'Django', 'React', 'AWS'])

        score = candidate.get_skill_match_score(job)

        assert score == 50.0  # 2 out of 4

    def test_candidate_skill_match_none(self, candidate_factory, job_posting_factory):
        """Test zero skill match."""
        candidate = candidate_factory(skills=['Java', 'Spring'])
        job = job_posting_factory(required_skills=['Python', 'Django'])

        score = candidate.get_skill_match_score(job)

        assert score == 0.0

    def test_candidate_skill_match_no_requirements(self, candidate_factory, job_posting_factory):
        """Test match when job has no required skills."""
        candidate = candidate_factory(skills=['Python', 'Django'])
        job = job_posting_factory(required_skills=[])

        score = candidate.get_skill_match_score(job)

        assert score == 100.0  # No requirements = 100% match

    def test_application_ai_match_score(self, application_factory):
        """Test AI match score on application."""
        app = application_factory(ai_match_score=Decimal('85.50'))

        assert app.ai_match_score == Decimal('85.50')

    def test_application_overall_rating(self, application_factory):
        """Test overall rating on application."""
        app = application_factory(overall_rating=Decimal('4.25'))

        assert app.overall_rating == Decimal('4.25')


# =============================================================================
# PERMISSION TESTS
# =============================================================================

@pytest.mark.django_db
class TestPermissions:
    """Test role-based permissions for ATS operations."""

    def test_recruiter_can_create_job(self, plan_factory, tenant_factory, user_factory):
        """Test that recruiters have job creation capabilities."""
        plan = plan_factory()
        tenant = tenant_factory(plan=plan)
        recruiter = user_factory()
        RecruiterTenantUserFactory(user=recruiter, tenant=tenant)

        # Recruiter should have job creation permissions
        # This would be enforced in views, here we verify the setup
        from accounts.models import TenantUser

        tenant_user = TenantUser.objects.get(user=recruiter, tenant=tenant)

        assert tenant_user.role == 'recruiter'
        assert tenant_user.is_active is True

    def test_hiring_manager_access_to_own_jobs(self, job_posting_factory, user_factory, tenant_factory, plan_factory):
        """Test hiring manager access to their own jobs."""
        plan = plan_factory()
        tenant = tenant_factory(plan=plan)
        hiring_manager = user_factory()
        HiringManagerTenantUserFactory(user=hiring_manager, tenant=tenant)

        job = job_posting_factory(hiring_manager=hiring_manager)

        assert job.hiring_manager == hiring_manager

    def test_viewer_role_readonly(self, plan_factory, tenant_factory, user_factory):
        """Test viewer role has read-only access."""
        plan = plan_factory()
        tenant = tenant_factory(plan=plan)
        viewer = user_factory()
        ViewerTenantUserFactory(user=viewer, tenant=tenant)

        from accounts.models import TenantUser

        tenant_user = TenantUser.objects.get(user=viewer, tenant=tenant)

        assert tenant_user.role == 'viewer'

    def test_admin_has_full_access(self, plan_factory, tenant_factory, user_factory):
        """Test admin role has full access."""
        plan = plan_factory()
        tenant = tenant_factory(plan=plan)
        admin = user_factory()
        AdminTenantUserFactory(user=admin, tenant=tenant)

        from accounts.models import TenantUser

        tenant_user = TenantUser.objects.get(user=admin, tenant=tenant)

        assert tenant_user.role == 'admin'


# =============================================================================
# BULK OPERATIONS TESTS
# =============================================================================

@pytest.mark.django_db
class TestBulkOperations:
    """Test bulk operations on ATS entities."""

    def test_bulk_reject_applications(self, application_factory, pipeline_stage_factory, user_factory):
        """Test bulk rejecting multiple applications."""
        from ats.models import Application

        apps = [application_factory(status='new') for _ in range(5)]
        user = user_factory()

        # Bulk update status
        app_ids = [app.pk for app in apps]
        Application.objects.filter(pk__in=app_ids).update(
            status='rejected',
            rejected_at=timezone.now()
        )

        # Verify all rejected
        for app in apps:
            app.refresh_from_db()
            assert app.status == 'rejected'

    def test_bulk_move_applications_to_stage(self, application_factory, pipeline_stage_factory, user_factory):
        """Test bulk moving applications to a stage."""
        from ats.models import Application

        apps = [application_factory(status='new') for _ in range(5)]

        # Create new stage
        new_stage = pipeline_stage_factory(
            pipeline=apps[0].job.pipeline,
            name='Screening',
            order=1
        )

        # Bulk update stage
        app_ids = [app.pk for app in apps]
        Application.objects.filter(pk__in=app_ids).update(
            current_stage=new_stage,
            last_stage_change_at=timezone.now()
        )

        # Verify all moved
        for app in apps:
            app.refresh_from_db()
            assert app.current_stage == new_stage

    def test_bulk_archive_jobs(self, job_posting_factory):
        """Test bulk archiving job postings."""
        from ats.models import JobPosting

        jobs = [job_posting_factory(status='closed') for _ in range(5)]

        job_ids = [job.pk for job in jobs]

        # Soft delete all
        for job in jobs:
            job.delete()

        # Verify all deleted
        assert JobPosting.objects.filter(pk__in=job_ids).count() == 0
        assert JobPosting.all_objects.filter(pk__in=job_ids).count() == 5

    def test_bulk_assign_applications(self, application_factory, user_factory):
        """Test bulk assigning applications to a reviewer."""
        from ats.models import Application

        apps = [application_factory(status='new') for _ in range(5)]
        reviewer = user_factory()

        app_ids = [app.pk for app in apps]
        Application.objects.filter(pk__in=app_ids).update(assigned_to=reviewer)

        for app in apps:
            app.refresh_from_db()
            assert app.assigned_to == reviewer


# =============================================================================
# EXPORT FUNCTIONALITY TESTS
# =============================================================================

@pytest.mark.django_db
class TestExportFunctionality:
    """Test data export functionality."""

    def test_job_posting_to_dict(self, job_posting_factory):
        """Test converting job posting to dictionary for export."""
        job = job_posting_factory(
            title='Senior Developer',
            status='open',
            salary_min=Decimal('80000'),
            salary_max=Decimal('120000')
        )

        # Simulate export data
        export_data = {
            'id': job.pk,
            'title': job.title,
            'reference_code': job.reference_code,
            'status': job.status,
            'salary_min': str(job.salary_min),
            'salary_max': str(job.salary_max),
            'created_at': job.created_at.isoformat()
        }

        assert export_data['title'] == 'Senior Developer'
        assert export_data['status'] == 'open'

    def test_candidate_export_data(self, candidate_factory):
        """Test candidate data export."""
        candidate = candidate_factory(
            first_name='John',
            last_name='Doe',
            email='john@example.com',
            skills=['Python', 'Django']
        )

        export_data = {
            'id': candidate.pk,
            'name': candidate.full_name,
            'email': candidate.email,
            'skills': candidate.skills,
            'created_at': candidate.created_at.isoformat()
        }

        assert export_data['name'] == 'John Doe'
        assert 'Python' in export_data['skills']

    def test_application_export_with_relations(self, application_factory):
        """Test application export with related data."""
        app = application_factory()

        export_data = {
            'application_id': app.pk,
            'candidate': app.candidate.full_name,
            'job': app.job.title,
            'status': app.status,
            'stage': app.current_stage.name if app.current_stage else None,
            'applied_at': app.applied_at.isoformat()
        }

        assert export_data['candidate'] is not None
        assert export_data['job'] is not None


# =============================================================================
# TENANT ISOLATION TESTS
# =============================================================================

@pytest.mark.django_db
class TestTenantIsolation:
    """Test tenant data isolation for ATS models."""

    def test_job_postings_isolated_by_tenant(self, job_posting_factory, tenant_factory, plan_factory):
        """Test that job postings are isolated by tenant."""
        plan = plan_factory()
        tenant1 = tenant_factory(plan=plan, slug='tenant-1')
        tenant2 = tenant_factory(plan=plan, slug='tenant-2')

        job1 = job_posting_factory(tenant=tenant1)
        job2 = job_posting_factory(tenant=tenant2)

        from ats.models import JobPosting

        tenant1_jobs = JobPosting.objects.filter(tenant=tenant1)
        tenant2_jobs = JobPosting.objects.filter(tenant=tenant2)

        assert job1 in tenant1_jobs
        assert job1 not in tenant2_jobs
        assert job2 in tenant2_jobs
        assert job2 not in tenant1_jobs

    def test_candidates_isolated_by_tenant(self, candidate_factory, tenant_factory, plan_factory):
        """Test that candidates are isolated by tenant."""
        plan = plan_factory()
        tenant1 = tenant_factory(plan=plan, slug='tenant-1')
        tenant2 = tenant_factory(plan=plan, slug='tenant-2')

        candidate1 = candidate_factory(tenant=tenant1, email='test@t1.com')
        candidate2 = candidate_factory(tenant=tenant2, email='test@t2.com')

        from ats.models import Candidate

        assert Candidate.objects.filter(tenant=tenant1).count() >= 1
        assert candidate1 not in Candidate.objects.filter(tenant=tenant2)

    def test_applications_isolated_by_tenant(self, application_factory, tenant_factory, plan_factory):
        """Test that applications are isolated by tenant."""
        plan = plan_factory()
        tenant1 = tenant_factory(plan=plan, slug='tenant-1')

        app = application_factory(tenant=tenant1)

        from ats.models import Application

        assert app in Application.objects.filter(tenant=tenant1)


# =============================================================================
# CONCURRENCY AND OPTIMISTIC LOCKING TESTS
# =============================================================================

@pytest.mark.django_db
class TestConcurrencyControl:
    """Test optimistic locking and concurrency control."""

    def test_job_posting_version_increment(self, job_posting_factory):
        """Test that job posting version increments on save."""
        job = job_posting_factory()
        initial_version = job.version

        job.title = 'Updated Title'
        job.save()

        job.refresh_from_db()
        assert job.version == initial_version + 1

    def test_candidate_version_increment(self, candidate_factory):
        """Test that candidate version increments on save."""
        candidate = candidate_factory()
        initial_version = candidate.version

        candidate.phone = '+1234567890'
        candidate.save()

        candidate.refresh_from_db()
        assert candidate.version == initial_version + 1

    def test_application_version_increment(self, application_factory):
        """Test that application version increments on save."""
        app = application_factory()
        initial_version = app.version

        app.status = 'in_review'
        app.save()

        app.refresh_from_db()
        assert app.version == initial_version + 1


# =============================================================================
# SOFT DELETE TESTS
# =============================================================================

@pytest.mark.django_db
class TestSoftDelete:
    """Test soft delete functionality."""

    def test_job_posting_soft_delete(self, job_posting_factory):
        """Test job posting soft delete."""
        from ats.models import JobPosting

        job = job_posting_factory()
        job_id = job.pk

        job.delete()

        # Should not be in default queryset
        assert JobPosting.objects.filter(pk=job_id).count() == 0

        # Should be in all_objects queryset
        assert JobPosting.all_objects.filter(pk=job_id).count() == 1

        # Check soft delete fields
        deleted_job = JobPosting.all_objects.get(pk=job_id)
        assert deleted_job.is_deleted is True
        assert deleted_job.deleted_at is not None

    def test_candidate_soft_delete(self, candidate_factory):
        """Test candidate soft delete."""
        from ats.models import Candidate

        candidate = candidate_factory()
        candidate_id = candidate.pk

        candidate.delete()

        assert Candidate.objects.filter(pk=candidate_id).count() == 0
        assert Candidate.all_objects.filter(pk=candidate_id).count() == 1

    def test_job_delete_cascades_to_applications(self, job_posting_factory, application_factory):
        """Test that soft deleting a job cascades to its applications."""
        from ats.models import JobPosting, Application

        job = job_posting_factory()
        app1 = application_factory(job=job)
        app2 = application_factory(job=job)

        job.delete(cascade_to_applications=True)

        # Applications should also be soft deleted
        app1.refresh_from_db()
        app2.refresh_from_db()

        assert app1.is_deleted is True
        assert app2.is_deleted is True


# =============================================================================
# VALIDATION TESTS
# =============================================================================

@pytest.mark.django_db
class TestValidation:
    """Test model validation rules."""

    def test_job_salary_validation(self, job_posting_factory):
        """Test that salary_min cannot exceed salary_max."""
        job = job_posting_factory(
            salary_min=Decimal('100000'),
            salary_max=Decimal('50000')
        )

        with pytest.raises(ValidationError):
            job.clean()

    def test_application_rating_validation(self, application_factory):
        """Test application rating validation."""
        app = application_factory()
        app.overall_rating = Decimal('6.0')  # Invalid - max is 5

        with pytest.raises(ValidationError):
            app.clean()

    def test_interview_end_after_start_validation(self, interview_factory):
        """Test interview end time must be after start time."""
        now = timezone.now()

        interview = interview_factory(
            scheduled_start=now + timedelta(hours=2),
            scheduled_end=now + timedelta(hours=1)  # End before start
        )

        with pytest.raises(ValidationError):
            interview.clean()

    def test_candidate_email_validation(self, candidate_factory):
        """Test candidate email validation."""
        candidate = candidate_factory()
        candidate.email = 'invalid-email'

        with pytest.raises(ValidationError):
            candidate.clean()


# =============================================================================
# STATISTICS AND METRICS TESTS
# =============================================================================

@pytest.mark.django_db
class TestStatisticsMetrics:
    """Test statistics and metrics calculations."""

    def test_job_applications_count(self, job_posting_factory, application_factory):
        """Test job posting applications count."""
        job = job_posting_factory()
        application_factory(job=job)
        application_factory(job=job)
        application_factory(job=job)

        assert job.applications_count == 3

    def test_job_active_applications_count(self, job_posting_factory, application_factory):
        """Test active applications count excludes rejected/withdrawn."""
        job = job_posting_factory()
        application_factory(job=job, status='new')
        application_factory(job=job, status='in_review')
        application_factory(job=job, status='rejected')
        application_factory(job=job, status='withdrawn')

        assert job.active_applications_count == 2

    def test_job_days_open(self, job_posting_factory):
        """Test days open calculation."""
        job = job_posting_factory(
            status='open',
            published_at=timezone.now() - timedelta(days=10)
        )

        assert job.days_open == 10

    def test_job_positions_remaining(self, job_posting_factory, application_factory):
        """Test positions remaining calculation."""
        job = job_posting_factory(positions_count=3)
        application_factory(job=job, status='hired')
        application_factory(job=job, status='new')

        assert job.positions_remaining == 2

    def test_candidate_applications_count(self, candidate_factory, application_factory, job_posting_factory):
        """Test candidate applications count."""
        candidate = candidate_factory()
        job1 = job_posting_factory()
        job2 = job_posting_factory()

        application_factory(candidate=candidate, job=job1)
        application_factory(candidate=candidate, job=job2)

        assert candidate.applications_count == 2

    def test_application_days_in_pipeline(self, application_factory):
        """Test days in pipeline calculation."""
        app = application_factory()

        # Since applied_at is auto_now_add, days should be 0 or very small
        assert app.days_in_pipeline >= 0

    def test_application_average_interview_rating(self, application_factory, interview_factory, user_factory):
        """Test average interview rating calculation."""
        from ats.models import InterviewFeedback

        app = application_factory()
        interview = interview_factory(application=app, status='completed')

        user1 = user_factory()
        user2 = user_factory()

        InterviewFeedback.objects.create(
            interview=interview,
            interviewer=user1,
            overall_rating=4,
            recommendation='yes'
        )
        InterviewFeedback.objects.create(
            interview=interview,
            interviewer=user2,
            overall_rating=5,
            recommendation='strong_yes'
        )

        avg_rating = app.average_interview_rating

        assert avg_rating == 4.5

    def test_pipeline_conversion_rate(self, pipeline_factory, job_posting_factory, application_factory):
        """Test pipeline conversion rate calculation."""
        pipeline = pipeline_factory()
        job = job_posting_factory(pipeline=pipeline)

        # Create 10 applications, 2 hired
        for i in range(8):
            application_factory(job=job, status='rejected')

        for i in range(2):
            application_factory(job=job, status='hired')

        rate = pipeline.conversion_rate

        assert rate == 20.0  # 2 out of 10 = 20%
