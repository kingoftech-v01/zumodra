"""
ATS Model Tests - Unit tests for Applicant Tracking System models

This module provides comprehensive unit tests for:
- JobCategory model
- Pipeline and PipelineStage models
- JobPosting model
- Candidate model
- Application and related models
- Interview and InterviewFeedback models
- Offer model
- SavedSearch model

Tests are marked with @pytest.mark.unit for easy categorization.
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone
from django.db import IntegrityError
from django.core.exceptions import ValidationError

from jobs.models import (
    JobCategory, Pipeline, PipelineStage, JobPosting,
    Candidate, Application, ApplicationActivity, ApplicationNote,
    Interview, InterviewFeedback, Offer, SavedSearch
)


# ============================================================================
# JOB CATEGORY UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestJobCategoryModel:
    """Unit tests for JobCategory model."""

    def test_create_job_category(self, job_category_factory):
        """Test basic job category creation."""
        category = job_category_factory()
        assert category.pk is not None
        assert category.name is not None
        assert category.slug is not None
        assert category.is_active is True

    def test_category_with_parent(self, job_category_factory):
        """Test category with parent (hierarchical)."""
        parent = job_category_factory(name='Engineering')
        child = job_category_factory(name='Backend', parent=parent)

        assert child.parent == parent
        assert child.parent.name == 'Engineering'
        assert parent.children.count() == 1
        assert parent.children.first() == child

    def test_category_string_representation_with_parent(self, job_category_factory):
        """Test string representation includes parent."""
        parent = job_category_factory(name='Engineering')
        child = job_category_factory(name='Backend', parent=parent)

        assert 'Engineering' in str(child)
        assert 'Backend' in str(child)

    def test_category_string_representation_without_parent(self, job_category_factory):
        """Test string representation without parent."""
        category = job_category_factory(name='Sales')
        assert str(category) == 'Sales'

    def test_category_ordering(self, job_category_factory):
        """Test category ordering by sort_order."""
        cat3 = job_category_factory(sort_order=3, name='Cat3')
        cat1 = job_category_factory(sort_order=1, name='Cat1')
        cat2 = job_category_factory(sort_order=2, name='Cat2')

        categories = list(JobCategory.objects.all())
        # Should be ordered by sort_order then name
        assert categories[0].sort_order <= categories[1].sort_order

    def test_category_inactive(self, job_category_factory):
        """Test inactive category."""
        category = job_category_factory(is_active=False)
        assert category.is_active is False

    def test_category_color_field(self, job_category_factory):
        """Test category color field."""
        category = job_category_factory(color='#FF5733')
        assert category.color == '#FF5733'


# ============================================================================
# PIPELINE UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestPipelineModel:
    """Unit tests for Pipeline model."""

    def test_create_pipeline(self, pipeline_factory):
        """Test basic pipeline creation."""
        pipeline = pipeline_factory()
        assert pipeline.pk is not None
        assert pipeline.uuid is not None
        assert pipeline.name is not None
        assert pipeline.is_active is True

    def test_default_pipeline(self):
        """Test creating a default pipeline."""
        from conftest import DefaultPipelineFactory
        pipeline = DefaultPipelineFactory()
        assert pipeline.is_default is True

    def test_pipeline_string_representation(self, pipeline_factory):
        """Test pipeline string representation."""
        pipeline = pipeline_factory(name='Engineering Pipeline')
        assert str(pipeline) == 'Engineering Pipeline'

    def test_pipeline_created_by(self, pipeline_factory, user_factory):
        """Test pipeline creator relationship."""
        user = user_factory()
        pipeline = pipeline_factory(created_by=user)
        assert pipeline.created_by == user

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

    def test_get_stages_ordered_excludes_inactive(self, pipeline_factory, pipeline_stage_factory):
        """Test get_stages_ordered excludes inactive stages."""
        pipeline = pipeline_factory()
        active_stage = pipeline_stage_factory(pipeline=pipeline, order=1, is_active=True)
        inactive_stage = pipeline_stage_factory(pipeline=pipeline, order=2, is_active=False)

        ordered_stages = list(pipeline.get_stages_ordered())
        assert len(ordered_stages) == 1
        assert ordered_stages[0] == active_stage

    def test_pipeline_timestamps(self, pipeline_factory):
        """Test pipeline auto timestamps."""
        pipeline = pipeline_factory()
        assert pipeline.created_at is not None
        assert pipeline.updated_at is not None


# ============================================================================
# PIPELINE STAGE UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestPipelineStageModel:
    """Unit tests for PipelineStage model."""

    def test_create_pipeline_stage(self, pipeline_stage_factory):
        """Test basic pipeline stage creation."""
        stage = pipeline_stage_factory()
        assert stage.pk is not None
        assert stage.uuid is not None
        assert stage.pipeline is not None
        assert stage.is_active is True

    def test_stage_types(self, pipeline_stage_factory):
        """Test all stage types are valid."""
        for stage_type, label in PipelineStage.StageType.choices:
            stage = pipeline_stage_factory(stage_type=stage_type)
            assert stage.stage_type == stage_type

    def test_stage_order_unique_per_pipeline(self, pipeline_factory, pipeline_stage_factory):
        """Test stage order is unique per pipeline."""
        pipeline = pipeline_factory()
        pipeline_stage_factory(pipeline=pipeline, order=1)

        with pytest.raises(IntegrityError):
            pipeline_stage_factory(pipeline=pipeline, order=1)

    def test_stage_order_same_across_pipelines(self, pipeline_factory, pipeline_stage_factory):
        """Test same order can exist in different pipelines."""
        pipeline1 = pipeline_factory()
        pipeline2 = pipeline_factory()

        stage1 = pipeline_stage_factory(pipeline=pipeline1, order=1)
        stage2 = pipeline_stage_factory(pipeline=pipeline2, order=1)

        assert stage1.order == stage2.order

    def test_stage_string_representation(self, pipeline_factory, pipeline_stage_factory):
        """Test stage string representation."""
        pipeline = pipeline_factory(name='Default')
        stage = pipeline_stage_factory(pipeline=pipeline, name='Interview')

        assert 'Default' in str(stage)
        assert 'Interview' in str(stage)

    def test_stage_auto_reject_settings(self, pipeline_stage_factory):
        """Test auto-reject settings."""
        stage = pipeline_stage_factory(
            auto_reject_after_days=30,
            send_email_on_enter=True,
            email_template_id='template_123'
        )

        assert stage.auto_reject_after_days == 30
        assert stage.send_email_on_enter is True
        assert stage.email_template_id == 'template_123'


# ============================================================================
# JOB POSTING UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestJobPostingModel:
    """Unit tests for JobPosting model."""

    def test_create_job_posting(self, job_posting_factory):
        """Test basic job posting creation."""
        job = job_posting_factory()
        assert job.pk is not None
        assert job.uuid is not None
        assert job.reference_code is not None

    def test_job_posting_statuses(self, job_posting_factory):
        """Test all job posting statuses."""
        for status, label in JobPosting.JobStatus.choices:
            job = job_posting_factory(status=status)
            assert job.status == status

    def test_job_posting_types(self, job_posting_factory):
        """Test all job types."""
        for job_type, label in JobPosting.JobType.choices:
            job = job_posting_factory(job_type=job_type)
            assert job.job_type == job_type

    def test_job_posting_experience_levels(self, job_posting_factory):
        """Test all experience levels."""
        for level, label in JobPosting.ExperienceLevel.choices:
            job = job_posting_factory(experience_level=level)
            assert job.experience_level == level

    def test_job_posting_remote_policies(self, job_posting_factory):
        """Test all remote policies."""
        for policy, label in JobPosting.RemotePolicy.choices:
            job = job_posting_factory(remote_policy=policy)
            assert job.remote_policy == policy

    def test_job_posting_is_open_property(self, job_posting_factory):
        """Test is_open property returns correct values."""
        open_job = job_posting_factory(status='open')
        draft_job = job_posting_factory(status='draft')
        closed_job = job_posting_factory(status='closed')
        filled_job = job_posting_factory(status='filled')

        assert open_job.is_open is True
        assert draft_job.is_open is False
        assert closed_job.is_open is False
        assert filled_job.is_open is False

    def test_salary_range_display_with_range(self, job_posting_factory):
        """Test salary range display with both min and max."""
        job = job_posting_factory(
            salary_min=Decimal('60000'),
            salary_max=Decimal('90000'),
            salary_currency='CAD'
        )
        display = job.salary_range_display
        assert 'CAD' in display
        assert '60,000' in display
        assert '90,000' in display

    def test_salary_range_display_min_only(self, job_posting_factory):
        """Test salary range display with min only."""
        job = job_posting_factory(
            salary_min=Decimal('60000'),
            salary_max=None,
            salary_currency='CAD'
        )
        display = job.salary_range_display
        assert '60,000' in display
        assert '+' in display

    def test_salary_range_display_max_only(self, job_posting_factory):
        """Test salary range display with max only."""
        job = job_posting_factory(
            salary_min=None,
            salary_max=Decimal('90000'),
            salary_currency='CAD'
        )
        display = job.salary_range_display
        assert 'Up to' in display
        assert '90,000' in display

    def test_salary_range_display_none(self, job_posting_factory):
        """Test salary range display with no salary."""
        job = job_posting_factory(salary_min=None, salary_max=None)
        assert job.salary_range_display is None

    def test_job_posting_publish(self, job_posting_factory):
        """Test publishing a job posting."""
        job = job_posting_factory(status='draft')
        job.publish()

        assert job.status == 'open'
        assert job.published_at is not None

    def test_job_posting_close_filled(self, job_posting_factory):
        """Test closing a job as filled."""
        job = job_posting_factory(status='open')
        job.close(reason='filled')

        assert job.status == 'filled'
        assert job.closed_at is not None

    def test_job_posting_close_cancelled(self, job_posting_factory):
        """Test closing a job as cancelled."""
        job = job_posting_factory(status='open')
        job.close(reason='cancelled')

        assert job.status == 'cancelled'

    def test_job_posting_close_default(self, job_posting_factory):
        """Test closing a job with unknown reason defaults to closed."""
        job = job_posting_factory(status='open')
        job.close(reason='unknown')

        assert job.status == 'closed'

    def test_job_posting_unique_reference_code(self, job_posting_factory):
        """Test reference code must be unique."""
        job_posting_factory(reference_code='JOB-001')
        with pytest.raises(IntegrityError):
            job_posting_factory(reference_code='JOB-001')

    def test_job_posting_string_representation(self, job_posting_factory):
        """Test job posting string representation."""
        job = job_posting_factory(title='Senior Developer', reference_code='JOB-100')
        assert 'Senior Developer' in str(job)
        assert 'JOB-100' in str(job)

    def test_job_posting_with_skills(self, job_posting_factory):
        """Test job posting with skills arrays."""
        job = job_posting_factory()
        job.required_skills = ['Python', 'Django']
        job.preferred_skills = ['React', 'TypeScript']
        job.save()

        job.refresh_from_db()
        assert 'Python' in job.required_skills
        assert 'React' in job.preferred_skills


# ============================================================================
# CANDIDATE UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestCandidateModel:
    """Unit tests for Candidate model."""

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
        """Test all candidate sources."""
        for source, label in Candidate.Source.choices:
            candidate = candidate_factory(source=source)
            assert candidate.source == source

    def test_candidate_with_skills(self, candidate_factory):
        """Test candidate with skills array."""
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

    def test_candidate_with_linked_user(self, candidate_factory, user_factory):
        """Test candidate linked to user account."""
        user = user_factory()
        candidate = candidate_factory(user=user)
        assert candidate.user == user

    def test_candidate_tags(self, candidate_factory):
        """Test candidate tags array."""
        candidate = candidate_factory()
        candidate.tags = ['priority', 'experienced', 'remote']
        candidate.save()

        candidate.refresh_from_db()
        assert 'priority' in candidate.tags


# ============================================================================
# APPLICATION UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestApplicationModel:
    """Unit tests for Application model."""

    def test_create_application(self, application_factory):
        """Test basic application creation."""
        application = application_factory()
        assert application.pk is not None
        assert application.uuid is not None
        assert application.candidate is not None
        assert application.job is not None

    def test_application_statuses(self, application_factory):
        """Test all application statuses."""
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

    def test_application_move_to_stage(
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

    def test_application_move_to_stage_creates_activity(
        self, application_factory, pipeline_factory, pipeline_stage_factory, user_factory
    ):
        """Test moving stage creates activity log."""
        pipeline = pipeline_factory()
        stage1 = pipeline_stage_factory(pipeline=pipeline, name='New', order=0)
        stage2 = pipeline_stage_factory(pipeline=pipeline, name='Screening', order=1)

        application = application_factory(current_stage=stage1)
        user = user_factory()

        application.move_to_stage(stage2, user=user)

        activity = application.activities.first()
        assert activity is not None
        assert activity.activity_type == 'stage_change'
        assert activity.new_value == 'Screening'

    def test_application_reject(self, application_factory, user_factory):
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


# ============================================================================
# APPLICATION ACTIVITY UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestApplicationActivityModel:
    """Unit tests for ApplicationActivity model."""

    def test_create_application_activity(self):
        """Test basic application activity creation."""
        from conftest import ApplicationActivityFactory
        activity = ApplicationActivityFactory()

        assert activity.pk is not None
        assert activity.uuid is not None
        assert activity.application is not None

    def test_activity_types(self):
        """Test all activity types."""
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
# APPLICATION NOTE UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestApplicationNoteModel:
    """Unit tests for ApplicationNote model."""

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
# INTERVIEW UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestInterviewModel:
    """Unit tests for Interview model."""

    def test_create_interview(self, interview_factory):
        """Test basic interview creation."""
        interview = interview_factory()
        assert interview.pk is not None
        assert interview.uuid is not None
        assert interview.application is not None

    def test_interview_types(self, interview_factory):
        """Test all interview types."""
        for interview_type, label in Interview.InterviewType.choices:
            interview = interview_factory(interview_type=interview_type)
            assert interview.interview_type == interview_type

    def test_interview_statuses(self, interview_factory):
        """Test all interview statuses."""
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

    def test_interview_duration_minutes_30_min(self, interview_factory):
        """Test 30-minute duration."""
        now = timezone.now()
        interview = interview_factory(
            scheduled_start=now,
            scheduled_end=now + timedelta(minutes=30)
        )
        assert interview.duration_minutes == 30

    def test_interview_string_representation(self, interview_factory):
        """Test interview string representation."""
        interview = interview_factory()
        assert interview.application.candidate.full_name in str(interview)


# ============================================================================
# INTERVIEW FEEDBACK UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestInterviewFeedbackModel:
    """Unit tests for InterviewFeedback model."""

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
        assert feedback.cultural_fit == 3
        assert feedback.problem_solving == 4

    def test_feedback_recommendations(self, interview_feedback_factory):
        """Test all feedback recommendations."""
        recommendations = ['strong_yes', 'yes', 'maybe', 'no', 'strong_no']
        for rec in recommendations:
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
# OFFER UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestOfferModel:
    """Unit tests for Offer model."""

    def test_create_offer(self, offer_factory):
        """Test basic offer creation."""
        offer = offer_factory()
        assert offer.pk is not None
        assert offer.uuid is not None
        assert offer.application is not None

    def test_offer_statuses(self, offer_factory):
        """Test all offer statuses."""
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

    def test_offer_send_to_candidate(self, offer_factory):
        """Test sending offer to candidate."""
        offer = offer_factory(status='approved')
        offer.send_to_candidate()

        assert offer.status == 'sent'
        assert offer.sent_at is not None

    def test_offer_accept(self, offer_factory):
        """Test accepting an offer."""
        offer = offer_factory(status='sent')
        offer.accept()

        assert offer.status == 'accepted'
        assert offer.responded_at is not None
        assert offer.application.status == 'hired'

    def test_offer_decline(self, offer_factory):
        """Test declining an offer."""
        offer = offer_factory(status='sent')
        offer.decline(reason='Accepted another position')

        assert offer.status == 'declined'
        assert offer.decline_reason == 'Accepted another position'
        assert offer.responded_at is not None


# ============================================================================
# SAVED SEARCH UNIT TESTS
# ============================================================================

@pytest.mark.unit
@pytest.mark.django_db
class TestSavedSearchModel:
    """Unit tests for SavedSearch model."""

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

    def test_saved_search_string_representation(self, user_factory):
        """Test saved search string representation."""
        from conftest import SavedSearchFactory
        user = user_factory()
        search = SavedSearchFactory(user=user, name='Python Developers')

        assert 'Python Developers' in str(search)
        assert user.email in str(search)
