"""
ATS Workflow Tests - End-to-end tests for complete hiring workflows

This module provides comprehensive workflow tests for:
- Complete hiring flow (apply -> interview -> offer -> hire)
- Rejection flow
- Withdrawal flow
- Bulk operations
- Pipeline progression
- Multiple applications handling
- Offer negotiation workflows

Tests are marked with @pytest.mark.workflow for easy categorization.
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone
from django.db import transaction
from rest_framework import status
from rest_framework.test import APIClient

from jobs.models import (
    JobCategory, Pipeline, PipelineStage, JobPosting,
    Candidate, Application, ApplicationActivity, ApplicationNote,
    Interview, InterviewFeedback, Offer
)


# ============================================================================
# FIXTURES FOR WORKFLOW TESTS
# ============================================================================

@pytest.fixture
def api_client():
    """Provide a DRF API test client."""
    return APIClient()


@pytest.fixture
def complete_pipeline(pipeline_factory, pipeline_stage_factory):
    """Create a complete pipeline with all standard stages."""
    pipeline = pipeline_factory(name='Standard Hiring Pipeline', is_default=True)
    stages = {
        'new': pipeline_stage_factory(
            pipeline=pipeline, name='New', stage_type='new', order=0, color='#3B82F6'
        ),
        'screening': pipeline_stage_factory(
            pipeline=pipeline, name='Screening', stage_type='screening', order=1, color='#8B5CF6'
        ),
        'interview': pipeline_stage_factory(
            pipeline=pipeline, name='Interview', stage_type='interview', order=2, color='#F59E0B'
        ),
        'offer': pipeline_stage_factory(
            pipeline=pipeline, name='Offer', stage_type='offer', order=3, color='#10B981'
        ),
        'hired': pipeline_stage_factory(
            pipeline=pipeline, name='Hired', stage_type='hired', order=4, color='#059669'
        ),
        'rejected': pipeline_stage_factory(
            pipeline=pipeline, name='Rejected', stage_type='rejected', order=5, color='#EF4444'
        ),
        'withdrawn': pipeline_stage_factory(
            pipeline=pipeline, name='Withdrawn', stage_type='withdrawn', order=6, color='#6B7280'
        ),
    }
    return pipeline, stages


@pytest.fixture
def open_job(job_posting_factory, complete_pipeline, job_category_factory, user_factory):
    """Create an open job posting with pipeline."""
    pipeline, stages = complete_pipeline
    category = job_category_factory(name='Engineering')
    recruiter = user_factory()
    hiring_manager = user_factory()

    job = job_posting_factory(
        title='Senior Python Developer',
        status='open',
        pipeline=pipeline,
        category=category,
        recruiter=recruiter,
        hiring_manager=hiring_manager,
        required_skills=['Python', 'Django', 'PostgreSQL'],
        preferred_skills=['React', 'TypeScript', 'AWS'],
        experience_level='senior',
        remote_policy='hybrid',
        salary_min=Decimal('90000'),
        salary_max=Decimal('130000'),
        positions_count=2
    )
    return job, stages, recruiter, hiring_manager


@pytest.fixture
def qualified_candidate(candidate_factory):
    """Create a qualified candidate."""
    return candidate_factory(
        first_name='John',
        last_name='Developer',
        email='john.developer@example.com',
        skills=['Python', 'Django', 'PostgreSQL', 'React'],
        years_experience=7,
        city='Toronto',
        country='Canada',
        source='linkedin'
    )


# ============================================================================
# COMPLETE HIRING WORKFLOW TESTS
# ============================================================================

@pytest.mark.workflow
@pytest.mark.django_db
class TestCompleteHiringWorkflow:
    """Test complete hiring workflow from application to hire."""

    def test_complete_hiring_flow_apply_to_hire(
        self, open_job, qualified_candidate, user_factory, application_factory,
        interview_factory, offer_factory
    ):
        """Test complete workflow: Apply -> Screen -> Interview -> Offer -> Hire."""
        job, stages, recruiter, hiring_manager = open_job
        candidate = qualified_candidate

        # Step 1: Candidate applies
        application = application_factory(
            candidate=candidate,
            job=job,
            current_stage=stages['new'],
            status='new',
            cover_letter='I am excited to apply for this position.'
        )

        assert application.status == 'new'
        assert application.current_stage == stages['new']

        # Step 2: Move to Screening
        application.move_to_stage(stages['screening'], user=recruiter)
        application.status = 'in_review'
        application.save()

        application.refresh_from_db()
        assert application.current_stage == stages['screening']
        assert application.status == 'in_review'

        # Verify activity was logged
        activity = application.activities.filter(activity_type='stage_change').first()
        assert activity is not None
        assert activity.new_value == 'Screening'

        # Step 3: Move to Interview stage
        application.move_to_stage(stages['interview'], user=recruiter)
        application.status = 'interviewing'
        application.save()

        application.refresh_from_db()
        assert application.current_stage == stages['interview']
        assert application.status == 'interviewing'

        # Step 4: Schedule interview
        scheduled_start = timezone.now() + timedelta(days=3)
        interview = interview_factory(
            application=application,
            interview_type='video',
            title='Technical Interview',
            status='scheduled',
            scheduled_start=scheduled_start,
            scheduled_end=scheduled_start + timedelta(hours=1),
            organizer=recruiter
        )
        interview.interviewers.add(hiring_manager)

        assert interview.status == 'scheduled'
        assert interview.interviewers.count() == 1

        # Step 5: Complete interview with feedback
        interview.status = 'completed'
        interview.actual_start = scheduled_start
        interview.actual_end = scheduled_start + timedelta(hours=1)
        interview.save()

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=hiring_manager,
            overall_rating=5,
            technical_skills=5,
            communication=4,
            cultural_fit=5,
            recommendation='strong_yes',
            strengths='Excellent Python skills, great problem solving',
            notes='Highly recommended for hire'
        )

        assert feedback.recommendation == 'strong_yes'

        # Step 6: Move to Offer stage and create offer
        application.move_to_stage(stages['offer'], user=recruiter)
        application.status = 'offer_pending'
        application.save()

        offer = offer_factory(
            application=application,
            status='approved',
            job_title='Senior Python Developer',
            base_salary=Decimal('110000'),
            signing_bonus=Decimal('10000'),
            start_date=(timezone.now() + timedelta(days=30)).date(),
            pto_days=20,
            created_by=recruiter
        )

        # Step 7: Send offer
        offer.send_to_candidate()

        offer.refresh_from_db()
        assert offer.status == 'sent'
        assert offer.sent_at is not None

        # Update application status
        application.status = 'offer_extended'
        application.save()

        # Step 8: Candidate accepts offer
        offer.accept()

        offer.refresh_from_db()
        application.refresh_from_db()

        assert offer.status == 'accepted'
        assert application.status == 'hired'
        assert application.hired_at is not None

        # Step 9: Move to Hired stage
        application.move_to_stage(stages['hired'], user=recruiter)

        application.refresh_from_db()
        assert application.current_stage == stages['hired']

    def test_hiring_flow_with_multiple_interviews(
        self, open_job, qualified_candidate, user_factory, application_factory,
        interview_factory
    ):
        """Test hiring flow with multiple interview rounds."""
        job, stages, recruiter, hiring_manager = open_job
        candidate = qualified_candidate
        interviewer2 = user_factory()
        interviewer3 = user_factory()

        # Create application in interview stage
        application = application_factory(
            candidate=candidate,
            job=job,
            current_stage=stages['interview'],
            status='interviewing'
        )

        # Schedule multiple interviews
        interviews = []
        interview_types = [
            ('phone', 'Phone Screen', recruiter),
            ('technical', 'Technical Interview', hiring_manager),
            ('panel', 'Panel Interview', interviewer2),
            ('final', 'Final Interview', interviewer3)
        ]

        base_time = timezone.now() + timedelta(days=1)
        for i, (itype, title, organizer) in enumerate(interview_types):
            interview = interview_factory(
                application=application,
                interview_type=itype,
                title=title,
                status='scheduled',
                scheduled_start=base_time + timedelta(days=i),
                scheduled_end=base_time + timedelta(days=i, hours=1),
                organizer=organizer
            )
            interviews.append(interview)

        assert application.interviews.count() == 4

        # Complete all interviews with positive feedback
        for interview in interviews:
            interview.status = 'completed'
            interview.save()

            InterviewFeedback.objects.create(
                interview=interview,
                interviewer=interview.organizer,
                overall_rating=4,
                recommendation='yes',
                strengths='Good candidate'
            )

        # Verify all feedback is positive
        feedbacks = InterviewFeedback.objects.filter(interview__application=application)
        assert feedbacks.count() == 4
        assert all(f.recommendation in ['yes', 'strong_yes'] for f in feedbacks)

    def test_hiring_flow_updates_job_positions_count(
        self, open_job, qualified_candidate, application_factory, offer_factory
    ):
        """Test that hiring updates available positions."""
        job, stages, recruiter, hiring_manager = open_job

        # Job has 2 positions
        assert job.positions_count == 2

        # Create and hire first candidate
        application1 = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['offer'],
            status='offer_pending'
        )

        offer1 = offer_factory(
            application=application1,
            status='sent',
            base_salary=Decimal('100000')
        )
        offer1.accept()

        application1.refresh_from_db()
        assert application1.status == 'hired'

        # Count hired applications
        hired_count = Application.objects.filter(job=job, status='hired').count()
        assert hired_count == 1

        # Remaining positions
        remaining = job.positions_count - hired_count
        assert remaining == 1


# ============================================================================
# REJECTION WORKFLOW TESTS
# ============================================================================

@pytest.mark.workflow
@pytest.mark.django_db
class TestRejectionWorkflow:
    """Test rejection workflows."""

    def test_reject_at_screening_stage(
        self, open_job, qualified_candidate, application_factory, user_factory
    ):
        """Test rejecting a candidate during screening."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['screening'],
            status='in_review'
        )

        # Reject the application
        application.reject(
            reason='Experience level does not match requirements',
            feedback='Thank you for your interest. We are looking for more senior candidates.',
            user=recruiter
        )

        application.refresh_from_db()
        assert application.status == 'rejected'
        assert application.rejection_reason == 'Experience level does not match requirements'
        assert application.rejected_at is not None

        # Verify activity was logged
        activities = application.activities.filter(activity_type='status_change')
        assert activities.exists()

    def test_reject_after_interview(
        self, open_job, qualified_candidate, application_factory,
        interview_factory, user_factory
    ):
        """Test rejecting a candidate after interview."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['interview'],
            status='interviewing'
        )

        # Complete interview with negative feedback
        interview = interview_factory(
            application=application,
            interview_type='technical',
            status='completed'
        )

        InterviewFeedback.objects.create(
            interview=interview,
            interviewer=hiring_manager,
            overall_rating=2,
            technical_skills=2,
            recommendation='no',
            weaknesses='Technical skills below requirements'
        )

        # Reject based on interview
        application.reject(
            reason='Technical skills assessment',
            feedback='We appreciate your time but have decided to move forward with other candidates.',
            user=recruiter
        )

        application.refresh_from_db()
        assert application.status == 'rejected'

        # Move to rejected stage
        application.move_to_stage(stages['rejected'], user=recruiter)

        application.refresh_from_db()
        assert application.current_stage == stages['rejected']

    def test_reject_multiple_candidates_same_job(
        self, open_job, candidate_factory, application_factory, user_factory
    ):
        """Test rejecting multiple candidates for the same job."""
        job, stages, recruiter, hiring_manager = open_job

        candidates = [
            candidate_factory(first_name=f'Candidate{i}', email=f'candidate{i}@example.com')
            for i in range(5)
        ]

        applications = [
            application_factory(
                candidate=candidate,
                job=job,
                current_stage=stages['screening'],
                status='in_review'
            )
            for candidate in candidates
        ]

        # Reject all candidates
        for app in applications:
            app.reject(reason='Position filled', user=recruiter)

        # Verify all rejected
        for app in applications:
            app.refresh_from_db()
            assert app.status == 'rejected'

        rejected_count = Application.objects.filter(job=job, status='rejected').count()
        assert rejected_count == 5


# ============================================================================
# WITHDRAWAL WORKFLOW TESTS
# ============================================================================

@pytest.mark.workflow
@pytest.mark.django_db
class TestWithdrawalWorkflow:
    """Test candidate withdrawal workflows."""

    def test_candidate_withdraws_application(
        self, open_job, qualified_candidate, application_factory
    ):
        """Test candidate withdrawing their application."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['interview'],
            status='interviewing'
        )

        # Candidate withdraws
        application.status = 'withdrawn'
        application.save()

        # Move to withdrawn stage
        application.move_to_stage(stages['withdrawn'], user=recruiter)

        application.refresh_from_db()
        assert application.status == 'withdrawn'
        assert application.current_stage == stages['withdrawn']

    def test_withdraw_after_receiving_offer(
        self, open_job, qualified_candidate, application_factory, offer_factory
    ):
        """Test candidate withdrawing after receiving offer."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['offer'],
            status='offer_extended'
        )

        offer = offer_factory(
            application=application,
            status='sent',
            base_salary=Decimal('100000')
        )

        # Candidate declines (withdraws)
        offer.decline(reason='Accepted another position')

        offer.refresh_from_db()
        assert offer.status == 'declined'
        assert offer.decline_reason == 'Accepted another position'

        # Update application
        application.status = 'withdrawn'
        application.save()

        application.refresh_from_db()
        assert application.status == 'withdrawn'


# ============================================================================
# BULK OPERATIONS WORKFLOW TESTS
# ============================================================================

@pytest.mark.workflow
@pytest.mark.django_db
class TestBulkOperationsWorkflow:
    """Test bulk operation workflows."""

    def test_bulk_move_stage(
        self, open_job, candidate_factory, application_factory
    ):
        """Test moving multiple applications to a new stage."""
        job, stages, recruiter, hiring_manager = open_job

        # Create multiple applications in new stage
        applications = []
        for i in range(10):
            candidate = candidate_factory(
                first_name=f'Bulk{i}',
                email=f'bulk{i}@example.com'
            )
            app = application_factory(
                candidate=candidate,
                job=job,
                current_stage=stages['new'],
                status='new'
            )
            applications.append(app)

        # Bulk move to screening
        app_ids = [app.id for app in applications]
        Application.objects.filter(id__in=app_ids).update(
            current_stage=stages['screening'],
            last_stage_change_at=timezone.now()
        )

        # Verify all moved
        for app in applications:
            app.refresh_from_db()
            assert app.current_stage == stages['screening']

    def test_bulk_reject(
        self, open_job, candidate_factory, application_factory
    ):
        """Test rejecting multiple applications at once."""
        job, stages, recruiter, hiring_manager = open_job

        applications = []
        for i in range(5):
            candidate = candidate_factory(
                first_name=f'Reject{i}',
                email=f'reject{i}@example.com'
            )
            app = application_factory(
                candidate=candidate,
                job=job,
                current_stage=stages['screening'],
                status='in_review'
            )
            applications.append(app)

        # Bulk reject
        app_ids = [app.id for app in applications]
        Application.objects.filter(id__in=app_ids).update(
            status='rejected',
            rejection_reason='Position closed',
            rejected_at=timezone.now()
        )

        # Verify all rejected
        for app in applications:
            app.refresh_from_db()
            assert app.status == 'rejected'

    def test_bulk_assign_to_recruiter(
        self, open_job, candidate_factory, application_factory, user_factory
    ):
        """Test assigning multiple applications to a recruiter."""
        job, stages, recruiter, hiring_manager = open_job
        new_recruiter = user_factory()

        applications = []
        for i in range(8):
            candidate = candidate_factory(
                first_name=f'Assign{i}',
                email=f'assign{i}@example.com'
            )
            app = application_factory(
                candidate=candidate,
                job=job,
                current_stage=stages['new'],
                status='new'
            )
            applications.append(app)

        # Bulk assign
        app_ids = [app.id for app in applications]
        Application.objects.filter(id__in=app_ids).update(
            assigned_to=new_recruiter
        )

        # Verify all assigned
        for app in applications:
            app.refresh_from_db()
            assert app.assigned_to == new_recruiter


# ============================================================================
# PIPELINE PROGRESSION WORKFLOW TESTS
# ============================================================================

@pytest.mark.workflow
@pytest.mark.django_db
class TestPipelineProgressionWorkflow:
    """Test pipeline progression workflows."""

    def test_sequential_stage_progression(
        self, open_job, qualified_candidate, application_factory
    ):
        """Test application progressing through all stages sequentially."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['new'],
            status='new'
        )

        # Progress through stages
        stage_sequence = ['new', 'screening', 'interview', 'offer', 'hired']
        status_sequence = ['new', 'in_review', 'interviewing', 'offer_pending', 'hired']

        for i, (stage_key, status_val) in enumerate(zip(stage_sequence[1:], status_sequence[1:])):
            application.move_to_stage(stages[stage_key], user=recruiter)
            application.status = status_val
            application.save()

            application.refresh_from_db()
            assert application.current_stage == stages[stage_key]
            assert application.status == status_val

        # Verify complete activity history
        activities = application.activities.filter(activity_type='stage_change')
        assert activities.count() == len(stage_sequence) - 1

    def test_skip_stage_progression(
        self, open_job, qualified_candidate, application_factory
    ):
        """Test application skipping stages (e.g., fast-track candidates)."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['new'],
            status='new'
        )

        # Skip directly to interview (fast-track referral)
        application.move_to_stage(stages['interview'], user=recruiter)
        application.status = 'interviewing'
        application.save()

        application.refresh_from_db()
        assert application.current_stage == stages['interview']

        # Verify activity shows direct jump
        activity = application.activities.filter(activity_type='stage_change').first()
        assert activity.old_value == 'New'
        assert activity.new_value == 'Interview'

    def test_backward_stage_movement(
        self, open_job, qualified_candidate, application_factory
    ):
        """Test moving application back to a previous stage."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['interview'],
            status='interviewing'
        )

        # Move back to screening (e.g., additional review needed)
        application.move_to_stage(stages['screening'], user=recruiter)
        application.status = 'in_review'
        application.save()

        application.refresh_from_db()
        assert application.current_stage == stages['screening']


# ============================================================================
# MULTIPLE APPLICATIONS WORKFLOW TESTS
# ============================================================================

@pytest.mark.workflow
@pytest.mark.django_db
class TestMultipleApplicationsWorkflow:
    """Test workflows for candidates with multiple applications."""

    def test_candidate_applies_to_multiple_jobs(
        self, complete_pipeline, job_posting_factory, candidate_factory,
        application_factory, job_category_factory
    ):
        """Test candidate applying to multiple open positions."""
        pipeline, stages = complete_pipeline
        candidate = candidate_factory(
            first_name='Multi',
            last_name='Applicant',
            email='multi@example.com'
        )

        # Create multiple jobs
        jobs = []
        for i in range(3):
            job = job_posting_factory(
                title=f'Position {i}',
                status='open',
                pipeline=pipeline
            )
            jobs.append(job)

        # Apply to all jobs
        applications = []
        for job in jobs:
            app = application_factory(
                candidate=candidate,
                job=job,
                current_stage=stages['new'],
                status='new'
            )
            applications.append(app)

        # Verify candidate has all applications
        assert candidate.applications.count() == 3

    def test_candidate_hired_for_one_withdraw_others(
        self, complete_pipeline, job_posting_factory, candidate_factory,
        application_factory, offer_factory
    ):
        """Test that when a candidate is hired, other applications can be withdrawn."""
        pipeline, stages = complete_pipeline
        candidate = candidate_factory(
            first_name='Winner',
            last_name='Candidate',
            email='winner@example.com'
        )

        # Create multiple jobs and applications
        jobs = [
            job_posting_factory(title=f'Job {i}', status='open', pipeline=pipeline)
            for i in range(3)
        ]

        applications = [
            application_factory(
                candidate=candidate,
                job=job,
                current_stage=stages['interview'],
                status='interviewing'
            )
            for job in jobs
        ]

        # Hire for first job
        offer = offer_factory(
            application=applications[0],
            status='sent',
            base_salary=Decimal('100000')
        )
        offer.accept()

        applications[0].refresh_from_db()
        assert applications[0].status == 'hired'

        # Withdraw other applications
        for app in applications[1:]:
            app.status = 'withdrawn'
            app.save()

        # Verify status
        hired_count = candidate.applications.filter(status='hired').count()
        withdrawn_count = candidate.applications.filter(status='withdrawn').count()

        assert hired_count == 1
        assert withdrawn_count == 2


# ============================================================================
# OFFER NEGOTIATION WORKFLOW TESTS
# ============================================================================

@pytest.mark.workflow
@pytest.mark.django_db
class TestOfferNegotiationWorkflow:
    """Test offer negotiation workflows."""

    def test_offer_negotiation_revised_offer(
        self, open_job, qualified_candidate, application_factory, offer_factory
    ):
        """Test creating revised offer after negotiation."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['offer'],
            status='offer_extended'
        )

        # Initial offer
        offer1 = offer_factory(
            application=application,
            status='sent',
            base_salary=Decimal('95000'),
            signing_bonus=Decimal('5000')
        )

        # Candidate requests higher salary - decline original
        offer1.decline(reason='Salary negotiation - requesting higher base')

        offer1.refresh_from_db()
        assert offer1.status == 'declined'

        # Create revised offer
        offer2 = Offer.objects.create(
            application=application,
            status='draft',
            job_title=job.title,
            base_salary=Decimal('105000'),
            signing_bonus=Decimal('10000'),
            salary_currency='CAD',
            salary_period='yearly',
            start_date=(timezone.now() + timedelta(days=30)).date()
        )

        # Send revised offer
        offer2.send_to_candidate()

        offer2.refresh_from_db()
        assert offer2.status == 'sent'
        assert offer2.base_salary == Decimal('105000')

        # Candidate accepts revised offer
        offer2.accept()

        offer2.refresh_from_db()
        application.refresh_from_db()

        assert offer2.status == 'accepted'
        assert application.status == 'hired'

    def test_offer_expired_then_renewed(
        self, open_job, qualified_candidate, application_factory, offer_factory
    ):
        """Test handling expired offer and creating new one."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['offer'],
            status='offer_extended'
        )

        # Create offer that has expired
        expired_offer = offer_factory(
            application=application,
            status='sent',
            base_salary=Decimal('100000'),
            expiration_date=(timezone.now() - timedelta(days=1)).date()
        )

        # Mark as expired
        expired_offer.status = 'expired'
        expired_offer.save()

        # Create new offer
        new_offer = Offer.objects.create(
            application=application,
            status='draft',
            job_title=job.title,
            base_salary=Decimal('100000'),
            salary_currency='CAD',
            salary_period='yearly',
            expiration_date=(timezone.now() + timedelta(days=14)).date()
        )

        new_offer.send_to_candidate()
        new_offer.accept()

        new_offer.refresh_from_db()
        assert new_offer.status == 'accepted'

        # Verify we have 2 offers for this application
        assert application.offers.count() == 2

    def test_offer_withdrawn_by_company(
        self, open_job, qualified_candidate, application_factory, offer_factory
    ):
        """Test company withdrawing an offer."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['offer'],
            status='offer_extended'
        )

        offer = offer_factory(
            application=application,
            status='sent',
            base_salary=Decimal('100000')
        )

        # Company withdraws offer (e.g., position no longer available)
        offer.status = 'withdrawn'
        offer.response_notes = 'Position has been eliminated due to budget constraints'
        offer.save()

        offer.refresh_from_db()
        assert offer.status == 'withdrawn'

        # Update application
        application.status = 'on_hold'
        application.save()

        application.refresh_from_db()
        assert application.status == 'on_hold'


# ============================================================================
# INTERVIEW SCHEDULING WORKFLOW TESTS
# ============================================================================

@pytest.mark.workflow
@pytest.mark.django_db
class TestInterviewSchedulingWorkflow:
    """Test interview scheduling and rescheduling workflows."""

    def test_schedule_interview_series(
        self, open_job, qualified_candidate, application_factory,
        interview_factory, user_factory
    ):
        """Test scheduling a series of interviews."""
        job, stages, recruiter, hiring_manager = open_job
        panel_member1 = user_factory()
        panel_member2 = user_factory()

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['interview'],
            status='interviewing'
        )

        base_date = timezone.now() + timedelta(days=3)

        # Phone screen
        phone_interview = interview_factory(
            application=application,
            interview_type='phone',
            title='Phone Screen',
            status='scheduled',
            scheduled_start=base_date,
            scheduled_end=base_date + timedelta(minutes=30)
        )

        # Technical interview (2 days later)
        tech_interview = interview_factory(
            application=application,
            interview_type='technical',
            title='Technical Interview',
            status='scheduled',
            scheduled_start=base_date + timedelta(days=2),
            scheduled_end=base_date + timedelta(days=2, hours=2)
        )

        # Panel interview (5 days later)
        panel_interview = interview_factory(
            application=application,
            interview_type='panel',
            title='Panel Interview',
            status='scheduled',
            scheduled_start=base_date + timedelta(days=5),
            scheduled_end=base_date + timedelta(days=5, hours=1, minutes=30)
        )
        panel_interview.interviewers.add(hiring_manager, panel_member1, panel_member2)

        # Verify all scheduled
        assert application.interviews.count() == 3
        assert panel_interview.interviewers.count() == 3

    def test_reschedule_interview(
        self, open_job, qualified_candidate, application_factory, interview_factory
    ):
        """Test rescheduling an interview."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['interview'],
            status='interviewing'
        )

        original_start = timezone.now() + timedelta(days=2)
        interview = interview_factory(
            application=application,
            interview_type='video',
            title='Technical Interview',
            status='scheduled',
            scheduled_start=original_start,
            scheduled_end=original_start + timedelta(hours=1)
        )

        # Reschedule
        new_start = timezone.now() + timedelta(days=5)
        interview.scheduled_start = new_start
        interview.scheduled_end = new_start + timedelta(hours=1)
        interview.status = 'rescheduled'
        interview.save()

        interview.refresh_from_db()
        assert interview.status == 'rescheduled'
        assert interview.scheduled_start == new_start

    def test_cancel_and_reschedule_interview(
        self, open_job, qualified_candidate, application_factory, interview_factory
    ):
        """Test cancelling an interview and scheduling a new one."""
        job, stages, recruiter, hiring_manager = open_job

        application = application_factory(
            candidate=qualified_candidate,
            job=job,
            current_stage=stages['interview'],
            status='interviewing'
        )

        # Original interview
        original_interview = interview_factory(
            application=application,
            interview_type='video',
            title='Technical Interview',
            status='scheduled',
            scheduled_start=timezone.now() + timedelta(days=2),
            scheduled_end=timezone.now() + timedelta(days=2, hours=1)
        )

        # Cancel it
        original_interview.status = 'cancelled'
        original_interview.save()

        # Schedule new one
        new_interview = interview_factory(
            application=application,
            interview_type='video',
            title='Technical Interview (Rescheduled)',
            status='scheduled',
            scheduled_start=timezone.now() + timedelta(days=4),
            scheduled_end=timezone.now() + timedelta(days=4, hours=1)
        )

        # Verify both exist
        assert application.interviews.count() == 2
        assert application.interviews.filter(status='cancelled').count() == 1
        assert application.interviews.filter(status='scheduled').count() == 1


# ============================================================================
# APPLICATION RATING WORKFLOW TESTS
# ============================================================================

@pytest.mark.workflow
@pytest.mark.django_db
class TestApplicationRatingWorkflow:
    """Test application rating and scoring workflows."""

    def test_rate_and_rank_applications(
        self, open_job, candidate_factory, application_factory
    ):
        """Test rating multiple applications and ranking them."""
        job, stages, recruiter, hiring_manager = open_job

        # Create applications with different ratings
        ratings = [4.5, 3.0, 5.0, 2.5, 4.0]
        applications = []

        for i, rating in enumerate(ratings):
            candidate = candidate_factory(
                first_name=f'Rated{i}',
                email=f'rated{i}@example.com'
            )
            app = application_factory(
                candidate=candidate,
                job=job,
                current_stage=stages['screening'],
                status='in_review',
                overall_rating=Decimal(str(rating))
            )
            applications.append(app)

        # Get top rated applications
        top_applications = Application.objects.filter(
            job=job
        ).order_by('-overall_rating')[:3]

        top_ratings = [float(app.overall_rating) for app in top_applications]
        assert top_ratings == sorted(ratings, reverse=True)[:3]

    def test_ai_match_score_ranking(
        self, open_job, candidate_factory, application_factory
    ):
        """Test ranking applications by AI match score."""
        job, stages, recruiter, hiring_manager = open_job

        # Create applications with AI scores
        ai_scores = [85.5, 92.0, 78.3, 95.0, 88.7]
        applications = []

        for i, score in enumerate(ai_scores):
            candidate = candidate_factory(
                first_name=f'AIMatch{i}',
                email=f'aimatch{i}@example.com'
            )
            app = application_factory(
                candidate=candidate,
                job=job,
                current_stage=stages['new'],
                status='new',
                ai_match_score=Decimal(str(score))
            )
            applications.append(app)

        # Get applications sorted by AI score
        ranked = Application.objects.filter(
            job=job
        ).order_by('-ai_match_score')

        ranked_scores = [float(app.ai_match_score) for app in ranked]
        assert ranked_scores == sorted(ai_scores, reverse=True)
