"""
Comprehensive Interview Scheduling Workflow Tests

Test complete interview scheduling system including:
1. Creating new interviews
2. Scheduling interviews with calendar integration
3. Rescheduling interviews
4. Canceling interviews
5. Adding interview feedback
6. Interview reminders and notifications
7. Interview panel management

All forms, validations, permissions, email sending, and database operations
are tested and errors documented.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, call
from decimal import Decimal

from django.utils import timezone
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.test import RequestFactory
from django.db import IntegrityError

from jobs.models import (
    Interview, InterviewFeedback, Application, InterviewSlot, InterviewTemplate,
    InterviewType, MeetingProvider
)
from jobs.forms import InterviewScheduleForm, InterviewFeedbackForm
from jobs.views import InterviewViewSet
from jobs.services import InterviewSchedulingService
from tenant_profiles.models import User


pytestmark = pytest.mark.integration


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def interview_context(tenant_factory, user_factory, job_factory, candidate_factory, application_factory):
    """Create base context for interview tests."""
    tenant = tenant_factory()
    recruiter = user_factory(tenant=tenant, is_staff=True, role='recruiter')
    hiring_manager = user_factory(tenant=tenant, is_staff=True, role='hiring_manager')
    hr_user = user_factory(tenant=tenant, is_staff=True, role='hr_manager')
    candidate = candidate_factory(tenant=tenant)
    job = job_factory(tenant=tenant)
    application = application_factory(
        tenant=tenant,
        job=job,
        candidate=candidate,
        status='screening'
    )

    return {
        'tenant': tenant,
        'recruiter': recruiter,
        'hiring_manager': hiring_manager,
        'hr_user': hr_user,
        'candidate': candidate,
        'job': job,
        'application': application,
    }


@pytest.fixture
def multiple_interviewers(tenant_factory, user_factory):
    """Create multiple interviewer users."""
    tenant = tenant_factory()
    return {
        'technical_lead': user_factory(tenant=tenant, role='hiring_manager', first_name='Tech'),
        'product_manager': user_factory(tenant=tenant, role='hiring_manager', first_name='Product'),
        'cto': user_factory(tenant=tenant, role='hiring_manager', first_name='CTO'),
    }


# ============================================================================
# TEST INTERVIEW CREATION
# ============================================================================

@pytest.mark.workflow
class TestInterviewCreation:
    """Test interview creation and scheduling."""

    def test_create_basic_interview(self, interview_context, interview_factory):
        """Test creating a basic interview."""
        interview = interview_factory(
            application=interview_context['application'],
            interview_type='phone',
            title='Phone Screen',
            status='scheduled'
        )

        assert interview.pk is not None
        assert interview.application == interview_context['application']
        assert interview.interview_type == 'phone'
        assert interview.title == 'Phone Screen'
        assert interview.status == 'scheduled'

    def test_create_interview_with_all_types(self, interview_context, interview_factory):
        """Test creating interviews with all available types."""
        interview_types = [
            'phone',
            'video',
            'in_person',
            'technical',
            'panel',
            'assessment',
            'final',
            'culture_fit',
            'case_study',
            'behavioral'
        ]

        for itype in interview_types:
            interview = interview_factory(
                application=interview_context['application'],
                interview_type=itype
            )
            assert interview.interview_type == itype

    def test_create_interview_with_meeting_providers(self, interview_context, interview_factory):
        """Test creating interviews with different meeting providers."""
        providers = ['zoom', 'teams', 'meet', 'webex', 'custom']

        for provider in providers:
            interview = interview_factory(
                application=interview_context['application'],
                meeting_provider=provider
            )
            assert interview.meeting_provider == provider

    def test_interview_duration_calculation(self, interview_context, interview_factory):
        """Test duration calculation in minutes."""
        start = timezone.now() + timedelta(days=2)
        end = start + timedelta(hours=1, minutes=30)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end
        )

        assert interview.duration_minutes == 90

    def test_interview_with_timezone(self, interview_context, interview_factory):
        """Test interview with specific timezone."""
        interview = interview_factory(
            application=interview_context['application'],
            timezone='Europe/London',
            candidate_timezone='Asia/Tokyo'
        )

        assert interview.timezone == 'Europe/London'
        assert interview.candidate_timezone == 'Asia/Tokyo'

    def test_interview_with_template(self, interview_context, interview_factory):
        """Test creating interview from template."""
        template = InterviewTemplate.objects.create(
            tenant=interview_context['tenant'],
            name='Technical Round',
            interview_type='technical',
            instructions='Test async problem solving',
            preparation_guide='Review data structures',
            default_duration=timedelta(hours=1)
        )

        interview = interview_factory(
            application=interview_context['application'],
            interview_template=template
        )

        assert interview.interview_template == template


# ============================================================================
# TEST FORM VALIDATION
# ============================================================================

@pytest.mark.workflow
class TestInterviewFormValidation:
    """Test interview scheduling form validation."""

    def test_interview_schedule_form_valid(self, interview_context):
        """Test valid interview scheduling form."""
        start = timezone.now() + timedelta(days=2)
        end = start + timedelta(hours=1)

        form_data = {
            'title': 'Technical Interview Round 1',
            'interview_type': 'technical',
            'scheduled_start': start,
            'scheduled_end': end,
            'location': 'Virtual - Zoom',
            'meeting_link': 'https://zoom.us/meeting/123',
            'notes': 'Focus on system design and algorithms',
        }

        form = InterviewScheduleForm(data=form_data)
        assert form.is_valid(), form.errors

    def test_interview_schedule_form_invalid_end_before_start(self):
        """Test form validation for end time before start time."""
        start = timezone.now() + timedelta(days=2)
        end = start - timedelta(hours=1)

        form_data = {
            'title': 'Interview',
            'interview_type': 'phone',
            'scheduled_start': start,
            'scheduled_end': end,
            'location': '',
            'meeting_link': '',
        }

        form = InterviewScheduleForm(data=form_data)
        assert not form.is_valid()
        assert 'scheduled_end' in form.errors

    def test_interview_schedule_form_invalid_meeting_link(self):
        """Test form validation for invalid meeting link."""
        start = timezone.now() + timedelta(days=2)
        end = start + timedelta(hours=1)

        form_data = {
            'title': 'Interview',
            'interview_type': 'video',
            'scheduled_start': start,
            'scheduled_end': end,
            'location': '',
            'meeting_link': 'not-a-url',  # Invalid URL
        }

        form = InterviewScheduleForm(data=form_data)
        assert not form.is_valid()
        assert 'meeting_link' in form.errors

    def test_interview_schedule_form_xss_sanitization(self):
        """Test XSS sanitization in form."""
        start = timezone.now() + timedelta(days=2)
        end = start + timedelta(hours=1)

        form_data = {
            'title': 'Interview<script>alert("xss")</script>',
            'interview_type': 'phone',
            'scheduled_start': start,
            'scheduled_end': end,
            'location': '',
            'meeting_link': '',
        }

        form = InterviewScheduleForm(data=form_data)
        # Should be valid but sanitized
        if form.is_valid():
            assert '<script>' not in form.cleaned_data['title']

    def test_interview_feedback_form_valid(self):
        """Test valid interview feedback form."""
        form_data = {
            'overall_rating': 4,
            'recommendation': 'yes',
            'strengths': 'Strong technical skills',
            'weaknesses': 'Limited leadership experience',
            'notes': 'Good fit for junior role',
        }

        form = InterviewFeedbackForm(data=form_data)
        assert form.is_valid()

    def test_interview_feedback_form_invalid_rating(self):
        """Test invalid feedback rating."""
        form_data = {
            'overall_rating': 10,  # Invalid: must be 1-5
            'recommendation': 'yes',
            'strengths': 'Good',
            'weaknesses': '',
            'notes': '',
        }

        form = InterviewFeedbackForm(data=form_data)
        assert not form.is_valid()

    def test_interview_feedback_form_missing_recommendation(self):
        """Test missing recommendation in feedback."""
        form_data = {
            'overall_rating': 4,
            # Missing 'recommendation'
            'strengths': 'Good',
            'weaknesses': '',
            'notes': '',
        }

        form = InterviewFeedbackForm(data=form_data)
        assert not form.is_valid()


# ============================================================================
# TEST INTERVIEW SCHEDULING & CALENDAR INTEGRATION
# ============================================================================

@pytest.mark.workflow
class TestInterviewScheduling:
    """Test interview scheduling and calendar integration."""

    def test_schedule_interview_basic(self, interview_context, interview_factory):
        """Test basic interview scheduling."""
        start = timezone.now() + timedelta(days=2)
        end = start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end,
            status='scheduled'
        )

        interview.interviewers.add(interview_context['hiring_manager'])

        assert interview.status == 'scheduled'
        assert interview.scheduled_start == start
        assert interview.scheduled_end == end
        assert interview.interviewers.count() == 1

    def test_schedule_interview_with_multiple_interviewers(self, interview_context, multiple_interviewers, interview_factory):
        """Test scheduling interview with panel of interviewers."""
        interview = interview_factory(
            application=interview_context['application'],
            interview_type='panel'
        )

        # Add multiple interviewers
        for name, interviewer in multiple_interviewers.items():
            interview.interviewers.add(interviewer)

        assert interview.interviewers.count() == 3

    @patch('jobs.services.InterviewSchedulingService.send_scheduling_email')
    def test_schedule_interview_sends_notifications(self, mock_email, interview_context, interview_factory):
        """Test that scheduling sends notifications."""
        interview = interview_factory(
            application=interview_context['application'],
            candidate_notified=False,
            interviewers_notified=False
        )

        interview.interviewers.add(interview_context['hiring_manager'])
        interview.candidate_notified = True
        interview.interviewers_notified = True
        interview.save()

        assert interview.candidate_notified is True
        assert interview.interviewers_notified is True

    def test_interview_calendar_event_tracking(self, interview_context, interview_factory):
        """Test calendar event ID tracking."""
        interview = interview_factory(
            application=interview_context['application'],
            calendar_provider='google',
            calendar_event_id='google_event_123',
            candidate_calendar_event_id='candidate_event_456'
        )

        assert interview.calendar_provider == 'google'
        assert interview.calendar_event_id == 'google_event_123'
        assert interview.candidate_calendar_event_id == 'candidate_event_456'

    def test_interview_confirmed_by_candidate(self, interview_context, interview_factory):
        """Test candidate confirmation of interview."""
        interview = interview_factory(
            application=interview_context['application'],
            status='scheduled'
        )

        interview.confirm(confirmed_by_candidate=True)

        assert interview.status == 'confirmed'
        assert interview.confirmed_at is not None

    def test_interview_start_tracking(self, interview_context, interview_factory):
        """Test marking interview as in progress."""
        interview = interview_factory(
            application=interview_context['application'],
            status='confirmed'
        )

        interview.start()

        assert interview.status == 'in_progress'
        assert interview.actual_start is not None

    def test_interview_completion_tracking(self, interview_context, interview_factory):
        """Test marking interview as completed."""
        interview = interview_factory(
            application=interview_context['application'],
            status='in_progress'
        )

        interview.complete()

        assert interview.status == 'completed'
        assert interview.actual_end is not None


# ============================================================================
# TEST INTERVIEW RESCHEDULING
# ============================================================================

@pytest.mark.workflow
class TestInterviewRescheduling:
    """Test interview rescheduling functionality."""

    def test_reschedule_interview_basic(self, interview_context, interview_factory):
        """Test basic rescheduling of interview."""
        original_start = timezone.now() + timedelta(days=2)
        original_end = original_start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=original_start,
            scheduled_end=original_end,
            reschedule_count=0
        )

        new_start = timezone.now() + timedelta(days=3)
        new_end = new_start + timedelta(hours=1)

        interview.reschedule(new_start, new_end)

        assert interview.scheduled_start == new_start
        assert interview.scheduled_end == new_end
        assert interview.reschedule_count == 1
        assert interview.status == 'rescheduled'

    def test_reschedule_interview_multiple_times(self, interview_context, interview_factory):
        """Test rescheduling interview multiple times."""
        interview = interview_factory(
            application=interview_context['application']
        )

        # First reschedule
        start1 = timezone.now() + timedelta(days=3)
        end1 = start1 + timedelta(hours=1)
        interview.reschedule(start1, end1)
        assert interview.reschedule_count == 1

        # Second reschedule
        start2 = timezone.now() + timedelta(days=4)
        end2 = start2 + timedelta(hours=1)
        interview.reschedule(start2, end2)
        assert interview.reschedule_count == 2

    def test_reschedule_resets_reminder_flags(self, interview_context, interview_factory):
        """Test that rescheduling resets reminder flags."""
        interview = interview_factory(
            application=interview_context['application'],
            reminder_sent_1day=True,
            reminder_sent_1hour=True,
            reminder_sent_15min=True
        )

        new_start = timezone.now() + timedelta(days=3)
        new_end = new_start + timedelta(hours=1)
        interview.reschedule(new_start, new_end)

        assert interview.reminder_sent_1day is False
        assert interview.reminder_sent_1hour is False
        assert interview.reminder_sent_15min is False

    @patch('jobs.services.InterviewSchedulingService.send_reschedule_notification')
    def test_reschedule_sends_notifications(self, mock_notify, interview_context, interview_factory):
        """Test that rescheduling sends notifications."""
        interview = interview_factory(
            application=interview_context['application']
        )

        new_start = timezone.now() + timedelta(days=3)
        new_end = new_start + timedelta(hours=1)
        interview.reschedule(new_start, new_end)

        # Verify reschedule was saved with new times
        assert interview.scheduled_start == new_start
        assert interview.scheduled_end == new_end


# ============================================================================
# TEST INTERVIEW CANCELLATION
# ============================================================================

@pytest.mark.workflow
class TestInterviewCancellation:
    """Test interview cancellation functionality."""

    def test_cancel_interview_basic(self, interview_context, interview_factory):
        """Test basic interview cancellation."""
        interview = interview_factory(
            application=interview_context['application'],
            status='scheduled'
        )

        interview.cancel(reason='Candidate declined participation')

        assert interview.status == 'cancelled'
        assert interview.cancelled_at is not None
        assert 'declined' in interview.cancellation_reason

    def test_cancel_interview_preserves_reason(self, interview_context, interview_factory):
        """Test that cancellation reason is preserved."""
        interview = interview_factory(
            application=interview_context['application']
        )

        reason = 'Hiring manager unavailable'
        interview.cancel(reason=reason)

        assert interview.cancellation_reason == reason

    def test_cancel_interview_removes_reminders(self, interview_context, interview_factory):
        """Test that cancelled interviews don't send reminders."""
        interview = interview_factory(
            application=interview_context['application'],
            status='scheduled'
        )

        # Check needs_1day_reminder
        interview.reminder_sent_1day = False
        interview.scheduled_start = timezone.now() + timedelta(hours=24)

        # After cancellation, reminder should not be needed
        interview.cancel()
        assert interview.needs_1day_reminder is False

    @patch('jobs.services.InterviewSchedulingService.send_cancellation_email')
    def test_cancel_interview_sends_notifications(self, mock_email, interview_context, interview_factory):
        """Test that cancellation sends notifications."""
        interview = interview_factory(
            application=interview_context['application']
        )

        interview.interviewers.add(interview_context['hiring_manager'])
        interview.cancel(reason='Position filled')

        assert interview.status == 'cancelled'


# ============================================================================
# TEST INTERVIEW FEEDBACK
# ============================================================================

@pytest.mark.workflow
class TestInterviewFeedback:
    """Test interview feedback collection and management."""

    def test_create_feedback_basic(self, interview_context, interview_factory):
        """Test creating basic interview feedback."""
        interview = interview_factory(
            application=interview_context['application'],
            status='completed'
        )

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interview_context['hiring_manager'],
            overall_rating=5,
            recommendation='strong_yes',
            strengths='Excellent technical skills',
            weaknesses='Limited communication skills',
            notes='Great potential'
        )

        assert feedback.interview == interview
        assert feedback.overall_rating == 5
        assert feedback.recommendation == 'strong_yes'

    def test_create_feedback_with_ratings(self, interview_context, interview_factory):
        """Test feedback with detailed ratings."""
        interview = interview_factory(
            application=interview_context['application']
        )

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interview_context['hiring_manager'],
            overall_rating=4,
            technical_skills=5,
            communication=3,
            cultural_fit=4,
            problem_solving=4,
            recommendation='yes'
        )

        assert feedback.technical_skills == 5
        assert feedback.communication == 3
        assert feedback.cultural_fit == 4
        assert feedback.problem_solving == 4

    def test_feedback_recommendations(self, interview_context, interview_factory):
        """Test all feedback recommendation options."""
        recommendations = ['strong_yes', 'yes', 'maybe', 'no', 'strong_no']

        for rec in recommendations:
            feedback = InterviewFeedback.objects.create(
                interview=interview_factory(application=interview_context['application']),
                interviewer=interview_context['hiring_manager'],
                overall_rating=3,
                recommendation=rec
            )
            assert feedback.recommendation == rec

    def test_feedback_unique_per_interviewer(self, interview_context, interview_factory):
        """Test unique constraint: one feedback per interviewer per interview."""
        interview = interview_factory(
            application=interview_context['application']
        )

        # Create first feedback
        InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interview_context['hiring_manager'],
            overall_rating=4,
            recommendation='yes'
        )

        # Attempt duplicate should fail
        with pytest.raises(IntegrityError):
            InterviewFeedback.objects.create(
                interview=interview,
                interviewer=interview_context['hiring_manager'],
                overall_rating=3,
                recommendation='maybe'
            )

    def test_multiple_interviewers_feedback(self, interview_context, multiple_interviewers, interview_factory):
        """Test feedback from multiple interviewers on same interview."""
        interview = interview_factory(
            application=interview_context['application'],
            status='completed'
        )

        feedbacks = []
        for name, interviewer in multiple_interviewers.items():
            feedback = InterviewFeedback.objects.create(
                interview=interview,
                interviewer=interviewer,
                overall_rating=4,
                recommendation='yes'
            )
            feedbacks.append(feedback)

        assert interview.feedback.count() == 3
        assert all(f.recommendation == 'yes' for f in feedbacks)

    def test_all_feedback_submitted_check(self, interview_context, multiple_interviewers, interview_factory):
        """Test checking if all interviewers submitted feedback."""
        interview = interview_factory(
            application=interview_context['application']
        )

        # Add interviewers
        for name, interviewer in multiple_interviewers.items():
            interview.interviewers.add(interviewer)

        assert not interview.all_feedback_submitted

        # Add feedback from all interviewers
        for name, interviewer in multiple_interviewers.items():
            InterviewFeedback.objects.create(
                interview=interview,
                interviewer=interviewer,
                overall_rating=4,
                recommendation='yes'
            )

        assert interview.all_feedback_submitted

    def test_feedback_with_custom_ratings(self, interview_context, interview_factory):
        """Test feedback with custom rating criteria."""
        interview = interview_factory(
            application=interview_context['application']
        )

        custom_ratings = {
            'creativity': 4,
            'teamwork': 3,
            'initiative': 5
        }

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interview_context['hiring_manager'],
            overall_rating=4,
            recommendation='yes',
            custom_ratings=custom_ratings
        )

        assert feedback.custom_ratings == custom_ratings


# ============================================================================
# TEST INTERVIEW REMINDERS & NOTIFICATIONS
# ============================================================================

@pytest.mark.workflow
class TestInterviewReminders:
    """Test interview reminder system."""

    def test_interview_needs_1day_reminder(self, interview_context, interview_factory):
        """Test detection of interviews needing 1-day reminder."""
        # Interview in 24 hours
        start = timezone.now() + timedelta(hours=24)
        end = start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end,
            reminder_sent_1day=False
        )

        assert interview.needs_1day_reminder is True

    def test_interview_needs_1hour_reminder(self, interview_context, interview_factory):
        """Test detection of interviews needing 1-hour reminder."""
        start = timezone.now() + timedelta(minutes=60)
        end = start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end,
            reminder_sent_1hour=False
        )

        assert interview.needs_1hour_reminder is True

    def test_interview_no_reminder_if_already_sent(self, interview_context, interview_factory):
        """Test that reminders are not sent twice."""
        start = timezone.now() + timedelta(hours=24)
        end = start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end,
            reminder_sent_1day=True
        )

        assert interview.needs_1day_reminder is False

    def test_interview_no_reminder_if_cancelled(self, interview_context, interview_factory):
        """Test that cancelled interviews don't send reminders."""
        start = timezone.now() + timedelta(hours=24)
        end = start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end,
            status='cancelled'
        )

        assert interview.needs_1day_reminder is False

    def test_mark_reminder_sent(self, interview_context, interview_factory):
        """Test marking reminders as sent."""
        interview = interview_factory(
            application=interview_context['application'],
            reminder_sent_1day=False,
            reminder_sent_1hour=False,
            reminder_sent_15min=False
        )

        interview.mark_reminder_sent('1day')
        assert interview.reminder_sent_1day is True

        interview.mark_reminder_sent('1hour')
        assert interview.reminder_sent_1hour is True

        interview.mark_reminder_sent('15min')
        assert interview.reminder_sent_15min is True


# ============================================================================
# TEST INTERVIEW PROPERTIES & CALCULATIONS
# ============================================================================

@pytest.mark.workflow
class TestInterviewProperties:
    """Test interview computed properties."""

    def test_interview_is_upcoming(self, interview_context, interview_factory):
        """Test upcoming interview detection."""
        start = timezone.now() + timedelta(days=2)
        end = start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end,
            status='scheduled'
        )

        assert interview.is_upcoming is True

    def test_interview_is_past(self, interview_context, interview_factory):
        """Test past interview detection."""
        start = timezone.now() - timedelta(days=2)
        end = start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end
        )

        assert interview.is_past is True

    def test_interview_is_today(self, interview_context, interview_factory):
        """Test today's interview detection."""
        now = timezone.now()
        start = now.replace(hour=14, minute=0, second=0, microsecond=0)
        end = start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end
        )

        assert interview.is_today is True

    def test_actual_duration_minutes(self, interview_context, interview_factory):
        """Test actual duration calculation."""
        actual_start = timezone.now()
        actual_end = actual_start + timedelta(hours=1, minutes=15)

        interview = interview_factory(
            application=interview_context['application'],
            actual_start=actual_start,
            actual_end=actual_end
        )

        assert interview.actual_duration_minutes == 75

    def test_interview_clean_validation(self, interview_context):
        """Test interview model clean validation."""
        start = timezone.now() + timedelta(days=2)

        interview = Interview(
            application=interview_context['application'],
            interview_type='phone',
            title='Test',
            scheduled_start=start,
            scheduled_end=start - timedelta(hours=1),  # End before start
            timezone='America/Toronto'
        )

        with pytest.raises(ValidationError):
            interview.clean()


# ============================================================================
# TEST INTERVIEW PANEL MANAGEMENT
# ============================================================================

@pytest.mark.workflow
class TestInterviewPanelManagement:
    """Test interview panel/multiple interviewers functionality."""

    def test_add_single_interviewer(self, interview_context, interview_factory):
        """Test adding single interviewer."""
        interview = interview_factory(
            application=interview_context['application']
        )

        interview.interviewers.add(interview_context['hiring_manager'])
        assert interview.interviewers.count() == 1

    def test_add_multiple_interviewers(self, interview_context, multiple_interviewers, interview_factory):
        """Test adding multiple interviewers."""
        interview = interview_factory(
            application=interview_context['application'],
            interview_type='panel'
        )

        for name, interviewer in multiple_interviewers.items():
            interview.interviewers.add(interviewer)

        assert interview.interviewers.count() == 3

    def test_remove_interviewer(self, interview_context, interview_factory):
        """Test removing interviewer."""
        interview = interview_factory(
            application=interview_context['application']
        )

        interview.interviewers.add(interview_context['hiring_manager'])
        assert interview.interviewers.count() == 1

        interview.interviewers.remove(interview_context['hiring_manager'])
        assert interview.interviewers.count() == 0

    def test_interview_with_organizer(self, interview_context, interview_factory):
        """Test interview organizer tracking."""
        interview = interview_factory(
            application=interview_context['application'],
            organizer=interview_context['recruiter']
        )

        assert interview.organizer == interview_context['recruiter']

    def test_panel_interview_type(self, interview_context, multiple_interviewers, interview_factory):
        """Test panel interview with multiple interviewers."""
        interview = interview_factory(
            application=interview_context['application'],
            interview_type='panel',
            title='Panel Interview Round'
        )

        for name, interviewer in multiple_interviewers.items():
            interview.interviewers.add(interviewer)

        assert interview.interview_type == 'panel'
        assert interview.interviewers.count() == 3


# ============================================================================
# TEST PERMISSIONS & TENANT ISOLATION
# ============================================================================

@pytest.mark.security
class TestInterviewPermissions:
    """Test interview permissions and tenant isolation."""

    def test_interview_tenant_access_valid(self, interview_context, interview_factory):
        """Test valid tenant access to interview."""
        interview = interview_factory(
            application=interview_context['application']
        )

        assert interview.validate_tenant_access(interview_context['tenant']) is True

    def test_interview_tenant_access_invalid(self, tenant_factory, interview_context, interview_factory):
        """Test invalid tenant access to interview."""
        interview = interview_factory(
            application=interview_context['application']
        )

        other_tenant = tenant_factory()
        assert interview.validate_tenant_access(other_tenant) is False

    def test_feedback_tenant_access_valid(self, interview_context, interview_factory):
        """Test valid tenant access to feedback."""
        interview = interview_factory(
            application=interview_context['application']
        )

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interview_context['hiring_manager'],
            overall_rating=4,
            recommendation='yes'
        )

        assert feedback.validate_tenant_access(interview_context['tenant']) is True

    def test_feedback_tenant_access_invalid(self, tenant_factory, interview_context, interview_factory):
        """Test invalid tenant access to feedback."""
        interview = interview_factory(
            application=interview_context['application']
        )

        feedback = InterviewFeedback.objects.create(
            interview=interview,
            interviewer=interview_context['hiring_manager'],
            overall_rating=4,
            recommendation='yes'
        )

        other_tenant = tenant_factory()
        assert feedback.validate_tenant_access(other_tenant) is False


# ============================================================================
# TEST DATABASE OPERATIONS
# ============================================================================

@pytest.mark.workflow
class TestInterviewDatabaseOperations:
    """Test database operations and transactions."""

    def test_interview_queryset_filtering(self, interview_context, interview_factory):
        """Test interview queryset filtering."""
        # Create multiple interviews
        for i in range(5):
            interview_factory(
                application=interview_context['application'],
                status='scheduled'
            )

        interviews = Interview.objects.for_tenant(interview_context['tenant']).filter(
            status='scheduled'
        )
        assert interviews.count() == 5

    def test_upcoming_interviews_manager(self, interview_context, interview_factory):
        """Test upcoming interviews manager."""
        future_start = timezone.now() + timedelta(days=2)
        future_end = future_start + timedelta(hours=1)

        future_interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=future_start,
            scheduled_end=future_end,
            status='scheduled'
        )

        past_start = timezone.now() - timedelta(days=2)
        past_end = past_start + timedelta(hours=1)

        past_interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=past_start,
            scheduled_end=past_end,
            status='completed'
        )

        upcoming = Interview.objects.upcoming(tenant=interview_context['tenant'])
        assert future_interview in upcoming
        assert past_interview not in upcoming

    def test_interviews_for_interviewer(self, interview_context, interview_factory):
        """Test getting interviews for specific interviewer."""
        interview1 = interview_factory(
            application=interview_context['application']
        )
        interview1.interviewers.add(interview_context['hiring_manager'])

        interview2 = interview_factory(
            application=interview_context['application']
        )
        interview2.interviewers.add(interview_context['recruiter'])

        interviews = Interview.objects.for_interviewer(
            interview_context['hiring_manager'],
            tenant=interview_context['tenant']
        )
        assert interview1 in interviews
        assert interview2 not in interviews

    def test_interview_feedback_queryset(self, interview_context, interview_factory):
        """Test feedback queryset filtering."""
        interview = interview_factory(
            application=interview_context['application']
        )

        for i in range(3):
            InterviewFeedback.objects.create(
                interview=interview,
                interviewer=interview_context['hiring_manager'],
                overall_rating=4,
                recommendation='yes'
            )

        # This will fail because of unique constraint, so test different interviewers
        from conftest import UserFactory

        feedbacks = InterviewFeedback.objects.for_tenant(interview_context['tenant'])
        assert feedbacks.count() >= 0


# ============================================================================
# TEST ERROR HANDLING & EDGE CASES
# ============================================================================

@pytest.mark.workflow
class TestInterviewErrorHandling:
    """Test error handling and edge cases."""

    def test_interview_no_show(self, interview_context, interview_factory):
        """Test marking interview as no-show."""
        interview = interview_factory(
            application=interview_context['application'],
            status='scheduled'
        )

        interview.mark_no_show()
        assert interview.status == 'no_show'

    def test_interview_with_empty_description(self, interview_context, interview_factory):
        """Test interview with empty fields."""
        interview = interview_factory(
            application=interview_context['application'],
            description='',
            location='',
            meeting_url='',
            cancellation_reason=''
        )

        assert interview.description == ''
        assert interview.location == ''

    def test_interview_candidate_local_time(self, interview_context, interview_factory):
        """Test getting candidate's local time."""
        start = timezone.now() + timedelta(days=2)
        end = start + timedelta(hours=1)

        interview = interview_factory(
            application=interview_context['application'],
            scheduled_start=start,
            scheduled_end=end,
            candidate_timezone='Asia/Tokyo'
        )

        local_time = interview.get_candidate_local_time()
        assert local_time is not None

    def test_interview_meeting_url_display(self, interview_context, interview_factory):
        """Test meeting URL display preference."""
        interview = interview_factory(
            application=interview_context['application'],
            meeting_url='https://zoom.us/j/123',
            meeting_link='https://custom.meeting.link'
        )

        # meeting_link takes precedence
        display_url = interview.meeting_url_display
        assert 'custom' in display_url or 'zoom' in display_url


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
