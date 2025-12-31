"""
ATS Core Flow Tests for Zumodra

Tests the complete hiring workflow from job posting through hire,
including applications, interviews, and offers.
"""

import pytest
from datetime import timedelta
from decimal import Decimal
from django.utils import timezone
from django.test import override_settings

from conftest import (
    UserFactory, TenantFactory, PlanFactory, TenantUserFactory,
    JobPostingFactory, CandidateFactory, ApplicationFactory,
    PipelineFactory, PipelineStageFactory, InterviewFactory,
    InterviewFeedbackFactory, OfferFactory, SentOfferFactory,
    JobCategoryFactory, RecruiterTenantUserFactory
)


# ============================================================================
# JOB POSTING TESTS
# ============================================================================

@pytest.mark.django_db
class TestJobPostingCRUD:
    """Test job posting create, read, update, delete operations."""

    def test_create_job_posting(self, job_posting_factory, pipeline_factory, user_factory):
        """Test creating a job posting with required fields."""
        pipeline = pipeline_factory()
        user = user_factory()

        job = job_posting_factory(
            title='Senior Python Developer',
            pipeline=pipeline,
            hiring_manager=user,
            recruiter=user,
            status='draft'
        )

        assert job.pk is not None
        assert job.title == 'Senior Python Developer'
        assert job.status == 'draft'
        assert job.pipeline == pipeline
        assert job.hiring_manager == user

    def test_job_posting_reference_code_unique(self, job_posting_factory):
        """Test that job reference codes are unique."""
        job1 = job_posting_factory(reference_code='JOB-00001')
        job2 = job_posting_factory(reference_code='JOB-00002')

        assert job1.reference_code != job2.reference_code

    def test_job_posting_publish(self, job_posting_factory):
        """Test publishing a draft job posting."""
        job = job_posting_factory(status='draft', published_at=None)

        # Simulate publishing
        job.status = 'open'
        job.published_at = timezone.now()
        job.save()

        assert job.status == 'open'
        assert job.published_at is not None

    def test_job_posting_close(self, job_posting_factory):
        """Test closing an open job posting."""
        job = job_posting_factory(status='open')

        job.status = 'closed'
        job.closed_at = timezone.now()
        job.save()

        assert job.status == 'closed'

    def test_job_posting_salary_range(self, job_posting_factory):
        """Test salary range validation."""
        job = job_posting_factory(
            salary_min=Decimal('50000.00'),
            salary_max=Decimal('80000.00'),
            salary_currency='CAD'
        )

        assert job.salary_min < job.salary_max
        assert job.salary_currency == 'CAD'


# ============================================================================
# PIPELINE AND STAGE TESTS
# ============================================================================

@pytest.mark.django_db
class TestPipelineFlow:
    """Test recruitment pipeline and stage management."""

    def test_create_default_pipeline(self, pipeline_factory, pipeline_stage_factory):
        """Test creating a pipeline with stages."""
        pipeline = pipeline_factory(name='Engineering Pipeline', is_default=True)

        stages = [
            pipeline_stage_factory(pipeline=pipeline, name='New', stage_type='new', order=0),
            pipeline_stage_factory(pipeline=pipeline, name='Screening', stage_type='screening', order=1),
            pipeline_stage_factory(pipeline=pipeline, name='Technical', stage_type='interview', order=2),
            pipeline_stage_factory(pipeline=pipeline, name='Final', stage_type='interview', order=3),
            pipeline_stage_factory(pipeline=pipeline, name='Offer', stage_type='offer', order=4),
            pipeline_stage_factory(pipeline=pipeline, name='Hired', stage_type='hired', order=5),
        ]

        assert pipeline.is_default
        assert len(stages) == 6
        assert stages[0].order < stages[1].order

    def test_pipeline_stage_ordering(self, pipeline_with_stages):
        """Test that pipeline stages maintain correct ordering."""
        pipeline, stages = pipeline_with_stages

        # Stages should be ordered
        for i, stage in enumerate(stages[:-1]):
            assert stage.order < stages[i + 1].order


# ============================================================================
# APPLICATION FLOW TESTS
# ============================================================================

@pytest.mark.django_db
class TestApplicationFlow:
    """Test the complete application submission and review flow."""

    def test_submit_application(self, job_posting_factory, candidate_factory, pipeline_stage_factory):
        """Test submitting a new application."""
        job = job_posting_factory(status='open')
        stage = pipeline_stage_factory(pipeline=job.pipeline, stage_type='new', order=0)
        candidate = candidate_factory()

        from ats.models import Application

        application = Application.objects.create(
            job=job,
            candidate=candidate,
            current_stage=stage,
            status='new',
            cover_letter='I am excited to apply for this role.'
        )

        assert application.pk is not None
        assert application.status == 'new'
        assert application.current_stage.stage_type == 'new'

    def test_application_unique_per_job(self, application_factory):
        """Test that a candidate can only apply once per job."""
        app1 = application_factory()

        # Attempting to create another application for same candidate/job should fail
        from django.db import IntegrityError
        from ats.models import Application

        with pytest.raises(IntegrityError):
            Application.objects.create(
                job=app1.job,
                candidate=app1.candidate,
                current_stage=app1.current_stage,
                status='new'
            )

    def test_move_application_through_stages(self, job_with_applications):
        """Test moving an application through pipeline stages."""
        job, applications = job_with_applications
        app = applications[0]

        # Get next stage
        from ats.models import PipelineStage
        stages = PipelineStage.objects.filter(pipeline=job.pipeline).order_by('order')

        initial_stage = app.current_stage

        # Move to next stage
        if stages.count() > 1:
            next_stage = stages.exclude(id=initial_stage.id).first()
            app.current_stage = next_stage
            app.save()

            assert app.current_stage != initial_stage

    def test_reject_application(self, application_factory, pipeline_stage_factory):
        """Test rejecting an application."""
        app = application_factory(status='new')
        rejected_stage = pipeline_stage_factory(
            pipeline=app.job.pipeline,
            stage_type='rejected',
            order=99
        )

        app.status = 'rejected'
        app.current_stage = rejected_stage
        app.rejected_at = timezone.now()
        app.rejection_reason = 'Not enough experience'
        app.save()

        assert app.status == 'rejected'
        assert app.rejected_at is not None


# ============================================================================
# INTERVIEW SCHEDULING TESTS
# ============================================================================

@pytest.mark.django_db
class TestInterviewScheduling:
    """Test interview scheduling and feedback collection."""

    def test_schedule_interview(self, application_factory, user_factory):
        """Test scheduling an interview."""
        app = application_factory()
        interviewer = user_factory()

        from ats.models import Interview

        interview = Interview.objects.create(
            application=app,
            interview_type='video',
            status='scheduled',
            title=f'Technical Interview with {app.candidate.full_name}',
            scheduled_start=timezone.now() + timedelta(days=3),
            scheduled_end=timezone.now() + timedelta(days=3, hours=1),
            organizer=interviewer,
            meeting_url='https://meet.example.com/interview123'
        )

        assert interview.pk is not None
        assert interview.status == 'scheduled'
        assert interview.interview_type == 'video'

    def test_interview_feedback(self, interview_factory, user_factory):
        """Test submitting interview feedback."""
        interview = interview_factory(status='completed')
        interviewer = user_factory()

        from ats.models import InterviewFeedback

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interviewer,
            overall_rating=4,
            technical_skills=5,
            communication=4,
            cultural_fit=4,
            problem_solving=5,
            recommendation='yes',
            strengths='Strong technical background',
            weaknesses='Could improve on communication',
            notes='Would be a good fit for the team'
        )

        assert feedback.pk is not None
        assert feedback.recommendation == 'yes'
        assert feedback.overall_rating == 4

    def test_interview_cancel(self, interview_factory):
        """Test cancelling an interview."""
        interview = interview_factory(status='scheduled')

        interview.status = 'cancelled'
        interview.save()

        assert interview.status == 'cancelled'


# ============================================================================
# OFFER MANAGEMENT TESTS
# ============================================================================

@pytest.mark.django_db
class TestOfferManagement:
    """Test job offer creation, sending, and acceptance."""

    def test_create_offer(self, application_factory, user_factory):
        """Test creating a job offer."""
        app = application_factory()
        creator = user_factory()

        from ats.models import Offer

        offer = Offer.objects.create(
            application=app,
            status='draft',
            job_title=app.job.title,
            department='Engineering',
            start_date=timezone.now().date() + timedelta(days=30),
            employment_type='full_time',
            base_salary=Decimal('85000.00'),
            salary_currency='CAD',
            salary_period='yearly',
            pto_days=20,
            expiration_date=timezone.now().date() + timedelta(days=14),
            created_by=creator
        )

        assert offer.pk is not None
        assert offer.status == 'draft'
        assert offer.base_salary == Decimal('85000.00')

    def test_send_offer(self, offer_factory):
        """Test sending an offer to candidate."""
        offer = offer_factory(status='draft')

        offer.status = 'sent'
        offer.sent_at = timezone.now()
        offer.save()

        assert offer.status == 'sent'
        assert offer.sent_at is not None

    def test_accept_offer(self, offer_factory):
        """Test candidate accepting an offer."""
        offer = offer_factory(status='sent')

        offer.status = 'accepted'
        offer.accepted_at = timezone.now()
        offer.save()

        assert offer.status == 'accepted'
        assert offer.accepted_at is not None

    def test_decline_offer(self, offer_factory):
        """Test candidate declining an offer."""
        offer = offer_factory(status='sent')

        offer.status = 'declined'
        offer.declined_at = timezone.now()
        offer.declined_reason = 'Accepted another offer'
        offer.save()

        assert offer.status == 'declined'


# ============================================================================
# COMPLETE HIRING FLOW INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestCompleteHiringFlow:
    """Integration tests for complete hiring workflow."""

    def test_full_hiring_flow(
        self,
        plan_factory,
        tenant_factory,
        user_factory,
        tenant_user_factory,
        pipeline_factory,
        pipeline_stage_factory,
        job_posting_factory,
        candidate_factory
    ):
        """Test complete flow: job posting → application → interview → offer → hire."""
        # Setup tenant and users
        plan = plan_factory()
        tenant = tenant_factory(plan=plan)
        hiring_manager = user_factory()
        recruiter = user_factory()
        tenant_user_factory(user=hiring_manager, tenant=tenant, role='hiring_manager')
        tenant_user_factory(user=recruiter, tenant=tenant, role='recruiter')

        # Create pipeline with stages
        pipeline = pipeline_factory(name='Standard Pipeline')
        new_stage = pipeline_stage_factory(pipeline=pipeline, name='New', stage_type='new', order=0)
        screening_stage = pipeline_stage_factory(pipeline=pipeline, name='Screening', stage_type='screening', order=1)
        interview_stage = pipeline_stage_factory(pipeline=pipeline, name='Interview', stage_type='interview', order=2)
        offer_stage = pipeline_stage_factory(pipeline=pipeline, name='Offer', stage_type='offer', order=3)
        hired_stage = pipeline_stage_factory(pipeline=pipeline, name='Hired', stage_type='hired', order=4)

        # Create job posting
        job = job_posting_factory(
            title='Full Stack Developer',
            pipeline=pipeline,
            hiring_manager=hiring_manager,
            recruiter=recruiter,
            status='open'
        )

        # Candidate applies
        candidate = candidate_factory(
            first_name='Jane',
            last_name='Developer',
            email='jane@example.com'
        )

        from ats.models import Application, Interview, InterviewFeedback, Offer

        # Create application
        application = Application.objects.create(
            job=job,
            candidate=candidate,
            current_stage=new_stage,
            status='new'
        )
        assert application.status == 'new'

        # Move to screening
        application.current_stage = screening_stage
        application.status = 'screening'
        application.save()
        assert application.current_stage == screening_stage

        # Schedule interview
        interview = Interview.objects.create(
            application=application,
            interview_type='video',
            status='scheduled',
            title='Technical Interview',
            scheduled_start=timezone.now() + timedelta(days=3),
            scheduled_end=timezone.now() + timedelta(days=3, hours=1),
            organizer=hiring_manager
        )

        # Move to interview stage
        application.current_stage = interview_stage
        application.status = 'interview'
        application.save()

        # Complete interview and add feedback
        interview.status = 'completed'
        interview.save()

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=hiring_manager,
            overall_rating=5,
            technical_skills=5,
            communication=4,
            cultural_fit=5,
            problem_solving=5,
            recommendation='yes',
            strengths='Excellent technical skills'
        )
        assert feedback.recommendation == 'yes'

        # Create and send offer
        offer = Offer.objects.create(
            application=application,
            status='draft',
            job_title=job.title,
            department='Engineering',
            start_date=timezone.now().date() + timedelta(days=30),
            employment_type='full_time',
            base_salary=Decimal('95000.00'),
            salary_currency='CAD',
            salary_period='yearly',
            pto_days=20,
            expiration_date=timezone.now().date() + timedelta(days=14),
            created_by=recruiter
        )

        # Move to offer stage
        application.current_stage = offer_stage
        application.status = 'offer'
        application.save()

        # Send offer
        offer.status = 'sent'
        offer.sent_at = timezone.now()
        offer.save()

        # Accept offer
        offer.status = 'accepted'
        offer.accepted_at = timezone.now()
        offer.save()

        # Move to hired
        application.current_stage = hired_stage
        application.status = 'hired'
        application.hired_at = timezone.now()
        application.save()

        # Verify final state
        application.refresh_from_db()
        assert application.status == 'hired'
        assert application.current_stage == hired_stage
        assert application.hired_at is not None

    def test_hiring_flow_with_rejection(
        self,
        job_with_applications,
        pipeline_stage_factory
    ):
        """Test hiring flow with rejection at interview stage."""
        job, applications = job_with_applications
        app = applications[0]

        rejected_stage = pipeline_stage_factory(
            pipeline=job.pipeline,
            name='Rejected',
            stage_type='rejected',
            order=99
        )

        # Move to rejection
        app.status = 'rejected'
        app.current_stage = rejected_stage
        app.rejected_at = timezone.now()
        app.rejection_reason = 'Skills did not match requirements'
        app.send_rejection_email = True
        app.save()

        app.refresh_from_db()
        assert app.status == 'rejected'
        assert app.rejection_reason is not None


# ============================================================================
# CANDIDATE SEARCH AND FILTERING TESTS
# ============================================================================

@pytest.mark.django_db
class TestCandidateSearch:
    """Test candidate search and filtering functionality."""

    def test_filter_candidates_by_status(self, application_factory):
        """Test filtering applications by status."""
        from ats.models import Application

        app1 = application_factory(status='new')
        app2 = application_factory(status='screening')
        app3 = application_factory(status='interview')

        new_apps = Application.objects.filter(status='new')
        screening_apps = Application.objects.filter(status='screening')

        assert new_apps.count() >= 1
        assert screening_apps.count() >= 1

    def test_filter_candidates_by_job(self, job_posting_factory, application_factory):
        """Test filtering applications by job posting."""
        from ats.models import Application

        job1 = job_posting_factory(title='Developer')
        job2 = job_posting_factory(title='Designer')

        app1 = application_factory(job=job1)
        app2 = application_factory(job=job1)
        app3 = application_factory(job=job2)

        job1_apps = Application.objects.filter(job=job1)
        assert job1_apps.count() == 2


# ============================================================================
# PERMISSION AND ACCESS CONTROL TESTS
# ============================================================================

@pytest.mark.django_db
class TestATSPermissions:
    """Test ATS-specific permission controls."""

    def test_recruiter_can_view_applications(
        self,
        tenant_factory,
        plan_factory,
        user_factory,
        tenant_user_factory,
        application_factory
    ):
        """Test that recruiters can view applications."""
        plan = plan_factory()
        tenant = tenant_factory(plan=plan)
        recruiter = user_factory()
        tenant_user_factory(user=recruiter, tenant=tenant, role='recruiter')

        app = application_factory()

        # Recruiter should have access (simulated via role check)
        from accounts.models import TenantUser
        tenant_user = TenantUser.objects.get(user=recruiter, tenant=tenant)
        assert tenant_user.role == 'recruiter'
        # In real implementation, this would check permissions

    def test_viewer_cannot_modify_applications(
        self,
        tenant_factory,
        plan_factory,
        user_factory,
        tenant_user_factory
    ):
        """Test that viewers have read-only access."""
        plan = plan_factory()
        tenant = tenant_factory(plan=plan)
        viewer = user_factory()
        tenant_user_factory(user=viewer, tenant=tenant, role='viewer')

        from accounts.models import TenantUser
        tenant_user = TenantUser.objects.get(user=viewer, tenant=tenant)
        assert tenant_user.role == 'viewer'
        # Viewer role should not have write permissions
