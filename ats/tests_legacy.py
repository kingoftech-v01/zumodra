"""
ATS (Applicant Tracking System) Tests

Tests for:
- Job posting CRUD operations
- Application workflow (apply, stage transitions)
- Interview scheduling
- Offer management
- Pipeline stage ordering
- Candidate management
- Search and filtering
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone
from django.db import IntegrityError

from ats.models import (
    JobCategory, Pipeline, PipelineStage, JobPosting,
    Candidate, Application, ApplicationActivity, ApplicationNote,
    Interview, InterviewFeedback, Offer, SavedSearch
)


# ============================================================================
# JOB CATEGORY TESTS
# ============================================================================

@pytest.mark.django_db
class TestJobCategoryModel:
    """Tests for JobCategory model."""

    def test_create_job_category(self, job_category_factory):
        """Test basic job category creation."""
        category = job_category_factory()
        assert category.pk is not None
        assert category.name is not None
        assert category.slug is not None

    def test_category_with_parent(self, job_category_factory):
        """Test category with parent (hierarchical)."""
        parent = job_category_factory(name='Engineering')
        child = job_category_factory(name='Backend', parent=parent)

        assert child.parent == parent
        assert 'Engineering' in str(child)
        assert 'Backend' in str(child)

    def test_category_ordering(self, job_category_factory):
        """Test category ordering by sort_order."""
        cat3 = job_category_factory(sort_order=3)
        cat1 = job_category_factory(sort_order=1)
        cat2 = job_category_factory(sort_order=2)

        categories = list(JobCategory.objects.all())
        assert categories[0].sort_order <= categories[1].sort_order


# ============================================================================
# PIPELINE TESTS
# ============================================================================

@pytest.mark.django_db
class TestPipelineModel:
    """Tests for Pipeline model."""

    def test_create_pipeline(self, pipeline_factory):
        """Test basic pipeline creation."""
        pipeline = pipeline_factory()
        assert pipeline.pk is not None
        assert pipeline.uuid is not None
        assert pipeline.name is not None

    def test_default_pipeline(self):
        """Test creating a default pipeline."""
        from conftest import DefaultPipelineFactory
        pipeline = DefaultPipelineFactory()
        assert pipeline.is_default is True

    def test_pipeline_string_representation(self, pipeline_factory):
        """Test pipeline string representation."""
        pipeline = pipeline_factory(name='Engineering Pipeline')
        assert str(pipeline) == 'Engineering Pipeline'

    def test_get_stages_ordered(self, pipeline_factory, pipeline_stage_factory):
        """Test getting ordered stages."""
        pipeline = pipeline_factory()
        stage3 = pipeline_stage_factory(pipeline=pipeline, order=3)
        stage1 = pipeline_stage_factory(pipeline=pipeline, order=1)
        stage2 = pipeline_stage_factory(pipeline=pipeline, order=2)

        ordered_stages = list(pipeline.get_stages_ordered())
        assert ordered_stages[0].order == 1
        assert ordered_stages[1].order == 2
        assert ordered_stages[2].order == 3


@pytest.mark.django_db
class TestPipelineStageModel:
    """Tests for PipelineStage model."""

    def test_create_pipeline_stage(self, pipeline_stage_factory):
        """Test basic pipeline stage creation."""
        stage = pipeline_stage_factory()
        assert stage.pk is not None
        assert stage.uuid is not None
        assert stage.pipeline is not None

    def test_stage_types(self, pipeline_stage_factory):
        """Test different stage types."""
        for stage_type, label in PipelineStage.StageType.choices:
            stage = pipeline_stage_factory(stage_type=stage_type)
            assert stage.stage_type == stage_type

    def test_stage_order_unique_per_pipeline(self, pipeline_factory, pipeline_stage_factory):
        """Test stage order is unique per pipeline."""
        pipeline = pipeline_factory()
        pipeline_stage_factory(pipeline=pipeline, order=1)

        with pytest.raises(IntegrityError):
            pipeline_stage_factory(pipeline=pipeline, order=1)

    def test_stage_string_representation(self, pipeline_factory, pipeline_stage_factory):
        """Test stage string representation."""
        pipeline = pipeline_factory(name='Default')
        stage = pipeline_stage_factory(pipeline=pipeline, name='Interview')
        assert 'Default' in str(stage)
        assert 'Interview' in str(stage)


@pytest.mark.django_db
class TestPipelineStageOrdering:
    """Tests for pipeline stage ordering."""

    def test_standard_pipeline_stages(self):
        """Test creating standard pipeline stages."""
        from conftest import (
            DefaultPipelineFactory, PipelineStageFactory
        )
        pipeline = DefaultPipelineFactory()

        stages_data = [
            ('New', 'new', 0),
            ('Screening', 'screening', 1),
            ('Phone Interview', 'interview', 2),
            ('Technical Interview', 'interview', 3),
            ('Final Interview', 'interview', 4),
            ('Offer', 'offer', 5),
            ('Hired', 'hired', 6),
            ('Rejected', 'rejected', 7),
        ]

        stages = []
        for name, stage_type, order in stages_data:
            stage = PipelineStageFactory(
                pipeline=pipeline,
                name=name,
                stage_type=stage_type,
                order=order
            )
            stages.append(stage)

        ordered = list(pipeline.get_stages_ordered())
        assert len(ordered) == 8
        assert ordered[0].name == 'New'
        assert ordered[-1].name == 'Rejected'

    def test_stage_reordering(self, pipeline_factory, pipeline_stage_factory):
        """Test reordering pipeline stages."""
        pipeline = pipeline_factory()
        stage1 = pipeline_stage_factory(pipeline=pipeline, name='First', order=0)
        stage2 = pipeline_stage_factory(pipeline=pipeline, name='Second', order=1)

        # Reorder
        stage1.order = 1
        stage1.save()
        stage2.order = 0
        stage2.save()

        ordered = list(pipeline.get_stages_ordered())
        assert ordered[0].name == 'Second'
        assert ordered[1].name == 'First'


# ============================================================================
# JOB POSTING TESTS
# ============================================================================

@pytest.mark.django_db
class TestJobPostingModel:
    """Tests for JobPosting model."""

    def test_create_job_posting(self, job_posting_factory):
        """Test basic job posting creation."""
        job = job_posting_factory()
        assert job.pk is not None
        assert job.uuid is not None
        assert job.reference_code is not None

    def test_job_posting_statuses(self, job_posting_factory):
        """Test different job posting statuses."""
        for status, label in JobPosting.JobStatus.choices:
            job = job_posting_factory(status=status)
            assert job.status == status

    def test_job_posting_types(self, job_posting_factory):
        """Test different job types."""
        for job_type, label in JobPosting.JobType.choices:
            job = job_posting_factory(job_type=job_type)
            assert job.job_type == job_type

    def test_job_posting_experience_levels(self, job_posting_factory):
        """Test different experience levels."""
        for level, label in JobPosting.ExperienceLevel.choices:
            job = job_posting_factory(experience_level=level)
            assert job.experience_level == level

    def test_job_posting_remote_policies(self, job_posting_factory):
        """Test different remote policies."""
        for policy, label in JobPosting.RemotePolicy.choices:
            job = job_posting_factory(remote_policy=policy)
            assert job.remote_policy == policy

    def test_job_posting_is_open_property(self, job_posting_factory):
        """Test is_open property."""
        open_job = job_posting_factory(status='open')
        draft_job = job_posting_factory(status='draft')
        closed_job = job_posting_factory(status='closed')

        assert open_job.is_open is True
        assert draft_job.is_open is False
        assert closed_job.is_open is False

    def test_job_posting_salary_range_display(self, job_posting_factory):
        """Test salary range display."""
        # Range
        job_with_range = job_posting_factory(
            salary_min=Decimal('60000'),
            salary_max=Decimal('90000'),
            salary_currency='CAD'
        )
        assert 'CAD' in job_with_range.salary_range_display
        assert '60,000' in job_with_range.salary_range_display
        assert '90,000' in job_with_range.salary_range_display

        # No salary
        job_no_salary = job_posting_factory(
            salary_min=None,
            salary_max=None
        )
        assert job_no_salary.salary_range_display is None

    def test_job_posting_publish(self, job_posting_factory):
        """Test publishing a job posting."""
        job = job_posting_factory(status='draft')

        job.publish()

        assert job.status == 'open'
        assert job.published_at is not None

    def test_job_posting_close(self, job_posting_factory):
        """Test closing a job posting."""
        job = job_posting_factory(status='open')

        job.close(reason='filled')

        assert job.status == 'filled'
        assert job.closed_at is not None

    def test_job_posting_unique_reference_code(self, job_posting_factory):
        """Test reference code is unique."""
        job_posting_factory(reference_code='JOB-001')
        with pytest.raises(IntegrityError):
            job_posting_factory(reference_code='JOB-001')

    def test_job_posting_string_representation(self, job_posting_factory):
        """Test job posting string representation."""
        job = job_posting_factory(title='Senior Developer', reference_code='JOB-100')
        assert 'Senior Developer' in str(job)
        assert 'JOB-100' in str(job)


@pytest.mark.django_db
class TestJobPostingCRUD:
    """Tests for job posting CRUD operations."""

    def test_create_draft_job_posting(self):
        """Test creating a draft job posting."""
        from conftest import DraftJobPostingFactory
        job = DraftJobPostingFactory()

        assert job.status == 'draft'
        assert job.published_at is None

    def test_update_job_posting(self, job_posting_factory):
        """Test updating a job posting."""
        job = job_posting_factory(title='Original Title')

        job.title = 'Updated Title'
        job.salary_min = Decimal('70000')
        job.save()

        job.refresh_from_db()
        assert job.title == 'Updated Title'
        assert job.salary_min == Decimal('70000')

    def test_delete_job_posting(self, job_posting_factory):
        """Test deleting a job posting."""
        job = job_posting_factory()
        job_id = job.pk

        job.delete()

        assert not JobPosting.objects.filter(pk=job_id).exists()

    def test_filter_open_jobs(self, job_posting_factory):
        """Test filtering open jobs."""
        job_posting_factory(status='open')
        job_posting_factory(status='open')
        job_posting_factory(status='draft')
        job_posting_factory(status='closed')

        open_jobs = JobPosting.objects.filter(status='open')
        assert open_jobs.count() == 2


# ============================================================================
# CANDIDATE TESTS
# ============================================================================

@pytest.mark.django_db
class TestCandidateModel:
    """Tests for Candidate model."""

    def test_create_candidate(self, candidate_factory):
        """Test basic candidate creation."""
        candidate = candidate_factory()
        assert candidate.pk is not None
        assert candidate.uuid is not None
        assert candidate.email is not None

    def test_candidate_full_name_property(self, candidate_factory):
        """Test full_name property."""
        candidate = candidate_factory(first_name='John', last_name='Doe')
        assert candidate.full_name == 'John Doe'

    def test_candidate_sources(self, candidate_factory):
        """Test different candidate sources."""
        for source, label in Candidate.Source.choices:
            candidate = candidate_factory(source=source)
            assert candidate.source == source

    def test_candidate_with_skills(self, candidate_factory):
        """Test candidate with skills."""
        candidate = candidate_factory()
        candidate.skills = ['Python', 'Django', 'PostgreSQL']
        candidate.save()

        candidate.refresh_from_db()
        assert 'Python' in candidate.skills
        assert len(candidate.skills) == 3

    def test_candidate_gdpr_consent(self, candidate_factory):
        """Test GDPR consent tracking."""
        candidate = candidate_factory(
            consent_to_store=True,
            consent_date=timezone.now()
        )

        assert candidate.consent_to_store is True
        assert candidate.consent_date is not None

    def test_candidate_string_representation(self, candidate_factory):
        """Test candidate string representation."""
        candidate = candidate_factory(first_name='Jane', last_name='Smith')
        assert str(candidate) == 'Jane Smith'


# ============================================================================
# APPLICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestApplicationModel:
    """Tests for Application model."""

    def test_create_application(self, application_factory):
        """Test basic application creation."""
        application = application_factory()
        assert application.pk is not None
        assert application.uuid is not None
        assert application.candidate is not None
        assert application.job is not None

    def test_application_statuses(self, application_factory):
        """Test different application statuses."""
        for status, label in Application.ApplicationStatus.choices:
            application = application_factory(status=status)
            assert application.status == status

    def test_application_unique_per_job(
        self, candidate_factory, job_posting_factory, application_factory
    ):
        """Test candidate can only apply once per job."""
        candidate = candidate_factory()
        job = job_posting_factory()
        application_factory(candidate=candidate, job=job)

        with pytest.raises(IntegrityError):
            application_factory(candidate=candidate, job=job)

    def test_application_string_representation(self, application_factory):
        """Test application string representation."""
        application = application_factory()
        assert '->' in str(application)


@pytest.mark.django_db
class TestApplicationWorkflow:
    """Tests for application workflow."""

    def test_new_application_starts_at_first_stage(self, pipeline_with_stages):
        """Test new application starts at first stage."""
        from conftest import ApplicationFactory
        pipeline, stages = pipeline_with_stages

        # Create job with pipeline
        from conftest import JobPostingFactory
        job = JobPostingFactory(pipeline=pipeline)

        application = ApplicationFactory(job=job, current_stage=stages[0])

        assert application.status == 'new'
        assert application.current_stage.stage_type == 'new'

    def test_move_application_to_stage(
        self, application_factory, pipeline_factory, pipeline_stage_factory, user_factory
    ):
        """Test moving application to different stage."""
        pipeline = pipeline_factory()
        stage1 = pipeline_stage_factory(pipeline=pipeline, name='New', order=0)
        stage2 = pipeline_stage_factory(pipeline=pipeline, name='Screening', order=1)

        application = application_factory(current_stage=stage1)
        user = user_factory()

        application.move_to_stage(stage2, user=user)

        assert application.current_stage == stage2
        assert application.last_stage_change_at is not None

        # Check activity log
        activity = application.activities.first()
        assert activity.activity_type == 'stage_change'
        assert activity.new_value == 'Screening'

    def test_reject_application(self, application_factory, user_factory):
        """Test rejecting an application."""
        application = application_factory(status='in_review')
        user = user_factory()

        application.reject(
            reason='Not enough experience',
            feedback='Thank you for applying.',
            user=user
        )

        assert application.status == 'rejected'
        assert application.rejection_reason == 'Not enough experience'
        assert application.rejected_at is not None

    def test_application_stage_transitions(self, pipeline_with_stages):
        """Test application moving through all stages."""
        from conftest import ApplicationFactory, JobPostingFactory
        pipeline, stages = pipeline_with_stages

        job = JobPostingFactory(pipeline=pipeline)
        application = ApplicationFactory(job=job, current_stage=stages[0])

        # Move through stages
        for stage in stages[1:5]:  # New -> Screening -> Interview -> Offer -> Hired
            application.move_to_stage(stage)

        assert application.activities.count() >= 4


# ============================================================================
# APPLICATION ACTIVITY TESTS
# ============================================================================

@pytest.mark.django_db
class TestApplicationActivityModel:
    """Tests for ApplicationActivity model."""

    def test_create_application_activity(self):
        """Test basic application activity creation."""
        from conftest import ApplicationActivityFactory
        activity = ApplicationActivityFactory()

        assert activity.pk is not None
        assert activity.uuid is not None
        assert activity.application is not None

    def test_activity_types(self):
        """Test different activity types."""
        from conftest import ApplicationActivityFactory
        for activity_type, label in ApplicationActivity.ActivityType.choices:
            activity = ApplicationActivityFactory(activity_type=activity_type)
            assert activity.activity_type == activity_type

    def test_activity_string_representation(self):
        """Test activity string representation."""
        from conftest import ApplicationActivityFactory
        activity = ApplicationActivityFactory(activity_type='created')
        assert 'Application Created' in str(activity)


# ============================================================================
# APPLICATION NOTE TESTS
# ============================================================================

@pytest.mark.django_db
class TestApplicationNoteModel:
    """Tests for ApplicationNote model."""

    def test_create_application_note(self):
        """Test basic application note creation."""
        from conftest import ApplicationNoteFactory
        note = ApplicationNoteFactory()

        assert note.pk is not None
        assert note.uuid is not None
        assert note.content is not None

    def test_private_note(self):
        """Test private note flag."""
        from conftest import ApplicationNoteFactory
        private_note = ApplicationNoteFactory(is_private=True)
        public_note = ApplicationNoteFactory(is_private=False)

        assert private_note.is_private is True
        assert public_note.is_private is False


# ============================================================================
# INTERVIEW TESTS
# ============================================================================

@pytest.mark.django_db
class TestInterviewModel:
    """Tests for Interview model."""

    def test_create_interview(self, interview_factory):
        """Test basic interview creation."""
        interview = interview_factory()
        assert interview.pk is not None
        assert interview.uuid is not None
        assert interview.application is not None

    def test_interview_types(self, interview_factory):
        """Test different interview types."""
        for interview_type, label in Interview.InterviewType.choices:
            interview = interview_factory(interview_type=interview_type)
            assert interview.interview_type == interview_type

    def test_interview_statuses(self, interview_factory):
        """Test different interview statuses."""
        for status, label in Interview.InterviewStatus.choices:
            interview = interview_factory(status=status)
            assert interview.status == status

    def test_interview_duration_minutes(self, interview_factory):
        """Test duration calculation."""
        now = timezone.now()
        interview = interview_factory(
            scheduled_start=now,
            scheduled_end=now + timedelta(hours=1)
        )

        assert interview.duration_minutes == 60

    def test_interview_string_representation(self, interview_factory, candidate_factory):
        """Test interview string representation."""
        interview = interview_factory()
        assert interview.application.candidate.full_name in str(interview)


@pytest.mark.django_db
class TestInterviewScheduling:
    """Tests for interview scheduling."""

    def test_schedule_interview(
        self, application_factory, interview_factory, user_factory
    ):
        """Test scheduling an interview."""
        application = application_factory()
        organizer = user_factory()
        scheduled_time = timezone.now() + timedelta(days=3)

        interview = interview_factory(
            application=application,
            interview_type='video',
            scheduled_start=scheduled_time,
            scheduled_end=scheduled_time + timedelta(hours=1),
            organizer=organizer,
            status='scheduled'
        )

        assert interview.status == 'scheduled'
        assert interview.organizer == organizer

    def test_add_interviewers(
        self, interview_factory, user_factory
    ):
        """Test adding interviewers to interview."""
        interview = interview_factory()
        interviewer1 = user_factory()
        interviewer2 = user_factory()

        interview.interviewers.add(interviewer1, interviewer2)

        assert interview.interviewers.count() == 2

    def test_interview_with_meeting_details(self, interview_factory):
        """Test interview with meeting details."""
        interview = interview_factory(
            meeting_url='https://meet.google.com/abc-defg-hij',
            meeting_id='abc-defg-hij',
            meeting_password='123456'
        )

        assert interview.meeting_url is not None
        assert interview.meeting_id == 'abc-defg-hij'

    def test_cancel_interview(self, interview_factory):
        """Test cancelling an interview."""
        interview = interview_factory(status='scheduled')

        interview.status = 'cancelled'
        interview.save()

        assert interview.status == 'cancelled'

    def test_complete_interview(self, interview_factory):
        """Test completing an interview."""
        interview = interview_factory(status='scheduled')

        interview.status = 'completed'
        interview.actual_start = timezone.now()
        interview.actual_end = timezone.now() + timedelta(minutes=45)
        interview.save()

        assert interview.status == 'completed'


# ============================================================================
# INTERVIEW FEEDBACK TESTS
# ============================================================================

@pytest.mark.django_db
class TestInterviewFeedbackModel:
    """Tests for InterviewFeedback model."""

    def test_create_interview_feedback(self, interview_feedback_factory):
        """Test basic interview feedback creation."""
        feedback = interview_feedback_factory()
        assert feedback.pk is not None
        assert feedback.uuid is not None
        assert feedback.interview is not None

    def test_feedback_ratings(self, interview_feedback_factory):
        """Test feedback ratings."""
        feedback = interview_feedback_factory(
            overall_rating=4,
            technical_skills=5,
            communication=4,
            cultural_fit=3,
            problem_solving=4
        )

        assert feedback.overall_rating == 4
        assert feedback.technical_skills == 5
        assert feedback.communication == 4

    def test_feedback_recommendations(self, interview_feedback_factory):
        """Test feedback recommendations."""
        recommendations = [
            ('strong_yes', 'Strong Yes'),
            ('yes', 'Yes'),
            ('maybe', 'Maybe'),
            ('no', 'No'),
            ('strong_no', 'Strong No'),
        ]

        for rec, label in recommendations:
            feedback = interview_feedback_factory(recommendation=rec)
            assert feedback.recommendation == rec

    def test_feedback_unique_per_interviewer(
        self, interview_factory, user_factory, interview_feedback_factory
    ):
        """Test one feedback per interviewer per interview."""
        interview = interview_factory()
        interviewer = user_factory()

        interview_feedback_factory(interview=interview, interviewer=interviewer)

        with pytest.raises(IntegrityError):
            interview_feedback_factory(interview=interview, interviewer=interviewer)


# ============================================================================
# OFFER TESTS
# ============================================================================

@pytest.mark.django_db
class TestOfferModel:
    """Tests for Offer model."""

    def test_create_offer(self, offer_factory):
        """Test basic offer creation."""
        offer = offer_factory()
        assert offer.pk is not None
        assert offer.uuid is not None
        assert offer.application is not None

    def test_offer_statuses(self, offer_factory):
        """Test different offer statuses."""
        for status, label in Offer.OfferStatus.choices:
            offer = offer_factory(status=status)
            assert offer.status == status

    def test_offer_compensation_details(self, offer_factory):
        """Test offer compensation details."""
        offer = offer_factory(
            base_salary=Decimal('80000'),
            salary_currency='CAD',
            signing_bonus=Decimal('10000'),
            pto_days=25
        )

        assert offer.base_salary == Decimal('80000')
        assert offer.signing_bonus == Decimal('10000')
        assert offer.pto_days == 25

    def test_offer_string_representation(self, offer_factory):
        """Test offer string representation."""
        offer = offer_factory()
        assert 'Offer to' in str(offer)


@pytest.mark.django_db
class TestOfferManagement:
    """Tests for offer management workflow."""

    def test_send_offer(self, offer_factory):
        """Test sending an offer."""
        from conftest import SentOfferFactory
        offer = SentOfferFactory()

        assert offer.status == 'sent'
        assert offer.sent_at is not None

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

        offer.decline(reason='Accepted another position')

        assert offer.status == 'declined'
        assert offer.decline_reason == 'Accepted another position'
        assert offer.responded_at is not None

    def test_offer_approval_workflow(self, offer_factory, user_factory):
        """Test offer approval workflow."""
        offer = offer_factory(status='pending_approval')
        approver = user_factory()

        offer.status = 'approved'
        offer.approved_by = approver
        offer.approved_at = timezone.now()
        offer.save()

        assert offer.status == 'approved'
        assert offer.approved_by == approver

    def test_offer_expiration(self, offer_factory):
        """Test offer expiration."""
        # Expired offer
        offer = offer_factory(
            status='sent',
            expiration_date=timezone.now().date() - timedelta(days=1)
        )

        # The status should be updated to expired by a background task
        # For now, we just test the expiration date
        assert offer.expiration_date < timezone.now().date()


# ============================================================================
# SAVED SEARCH TESTS
# ============================================================================

@pytest.mark.django_db
class TestSavedSearchModel:
    """Tests for SavedSearch model."""

    def test_create_saved_search(self):
        """Test basic saved search creation."""
        from conftest import SavedSearchFactory
        search = SavedSearchFactory()

        assert search.pk is not None
        assert search.uuid is not None
        assert search.user is not None

    def test_saved_search_with_filters(self):
        """Test saved search with filters."""
        from conftest import SavedSearchFactory
        search = SavedSearchFactory(
            filters={
                'skills': ['Python', 'Django'],
                'experience_years': '3-5',
                'location': 'Toronto',
                'remote': True
            }
        )

        assert search.filters['skills'] == ['Python', 'Django']
        assert search.filters['remote'] is True

    def test_saved_search_with_alerts(self):
        """Test saved search with alert enabled."""
        from conftest import SavedSearchFactory
        search = SavedSearchFactory(
            is_alert_enabled=True,
            alert_frequency='instant'
        )

        assert search.is_alert_enabled is True
        assert search.alert_frequency == 'instant'


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestATSIntegration:
    """Integration tests for ATS functionality."""

    def test_complete_hiring_flow(self, pipeline_with_stages, user_factory):
        """Test complete hiring flow from application to hire."""
        from conftest import (
            JobPostingFactory, CandidateFactory, ApplicationFactory,
            InterviewFactory, InterviewFeedbackFactory, OfferFactory
        )

        pipeline, stages = pipeline_with_stages
        recruiter = user_factory()

        # Create job
        job = JobPostingFactory(pipeline=pipeline, status='open')

        # Create candidate and application
        candidate = CandidateFactory()
        application = ApplicationFactory(
            job=job,
            candidate=candidate,
            current_stage=stages[0]  # New
        )

        # Move through stages
        application.move_to_stage(stages[1], user=recruiter)  # Screening
        application.move_to_stage(stages[2], user=recruiter)  # Interview

        # Schedule and complete interview
        interview = InterviewFactory(
            application=application,
            status='completed'
        )
        InterviewFeedbackFactory(
            interview=interview,
            interviewer=recruiter,
            recommendation='strong_yes'
        )

        # Move to offer stage
        application.move_to_stage(stages[3], user=recruiter)  # Offer

        # Create and send offer
        offer = OfferFactory(
            application=application,
            status='sent'
        )

        # Accept offer
        offer.accept()

        # Move to hired
        application.move_to_stage(stages[4], user=recruiter)  # Hired

        assert application.status == 'hired'
        assert offer.status == 'accepted'

    def test_multiple_applications_per_job(self, job_posting_factory, candidate_factory, application_factory):
        """Test multiple candidates applying for same job."""
        job = job_posting_factory()

        candidates = [candidate_factory() for _ in range(5)]
        applications = [
            application_factory(job=job, candidate=c)
            for c in candidates
        ]

        assert job.applications.count() == 5

    def test_candidate_multiple_applications(self, candidate_factory, job_posting_factory, application_factory):
        """Test candidate applying to multiple jobs."""
        candidate = candidate_factory()

        jobs = [job_posting_factory() for _ in range(3)]
        applications = [
            application_factory(job=j, candidate=candidate)
            for j in jobs
        ]

        assert candidate.applications.count() == 3

    def test_filter_applications_by_stage(self, pipeline_with_stages):
        """Test filtering applications by pipeline stage."""
        from conftest import JobPostingFactory, ApplicationFactory

        pipeline, stages = pipeline_with_stages
        job = JobPostingFactory(pipeline=pipeline)

        # Create applications at different stages
        ApplicationFactory(job=job, current_stage=stages[0])  # New
        ApplicationFactory(job=job, current_stage=stages[0])  # New
        ApplicationFactory(job=job, current_stage=stages[1])  # Screening
        ApplicationFactory(job=job, current_stage=stages[2])  # Interview

        new_applications = Application.objects.filter(
            job=job,
            current_stage__stage_type='new'
        )
        interview_applications = Application.objects.filter(
            job=job,
            current_stage__stage_type='interview'
        )

        assert new_applications.count() == 2
        assert interview_applications.count() == 1
