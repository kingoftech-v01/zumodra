"""
ATS Validators - Business Rule Validation

This module provides validator classes for enforcing business rules
in the ATS (Applicant Tracking System) module:

- ApplicationValidator: Validates application actions and state
- JobPostingValidator: Validates job posting state and publishability
- CandidateValidator: Validates candidate data

Validators provide a clean separation of validation logic from models,
making rules explicit, testable, and reusable across views and services.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .models import (
    Application,
    Candidate,
    JobPosting,
    Pipeline,
    PipelineStage,
)


# =============================================================================
# VALIDATION RESULTS
# =============================================================================

@dataclass
class ValidationResult:
    """Result of a validation check."""
    is_valid: bool
    errors: Dict[str, List[str]]
    warnings: Dict[str, List[str]]

    def __init__(self):
        self.is_valid = True
        self.errors = {}
        self.warnings = {}

    def add_error(self, field: str, message: str):
        """Add an error for a field."""
        self.is_valid = False
        if field not in self.errors:
            self.errors[field] = []
        self.errors[field].append(message)

    def add_warning(self, field: str, message: str):
        """Add a warning for a field."""
        if field not in self.warnings:
            self.warnings[field] = []
        self.warnings[field].append(message)

    def merge(self, other: 'ValidationResult'):
        """Merge another validation result into this one."""
        if not other.is_valid:
            self.is_valid = False
        for field, messages in other.errors.items():
            for message in messages:
                self.add_error(field, message)
        for field, messages in other.warnings.items():
            for message in messages:
                self.add_warning(field, message)

    def raise_if_invalid(self):
        """Raise ValidationError if validation failed."""
        if not self.is_valid:
            raise ValidationError(self.errors)


# =============================================================================
# APPLICATION VALIDATOR
# =============================================================================

class ApplicationValidator:
    """
    Validator for job applications.

    Provides validation for:
    - Application eligibility
    - Stage advancement
    - Status transitions
    """

    # Status transitions that are allowed
    ALLOWED_TRANSITIONS = {
        Application.ApplicationStatus.NEW: {
            Application.ApplicationStatus.IN_REVIEW,
            Application.ApplicationStatus.SHORTLISTED,
            Application.ApplicationStatus.REJECTED,
            Application.ApplicationStatus.WITHDRAWN,
            Application.ApplicationStatus.ON_HOLD,
        },
        Application.ApplicationStatus.IN_REVIEW: {
            Application.ApplicationStatus.SHORTLISTED,
            Application.ApplicationStatus.INTERVIEWING,
            Application.ApplicationStatus.REJECTED,
            Application.ApplicationStatus.WITHDRAWN,
            Application.ApplicationStatus.ON_HOLD,
        },
        Application.ApplicationStatus.SHORTLISTED: {
            Application.ApplicationStatus.INTERVIEWING,
            Application.ApplicationStatus.REJECTED,
            Application.ApplicationStatus.WITHDRAWN,
            Application.ApplicationStatus.ON_HOLD,
        },
        Application.ApplicationStatus.INTERVIEWING: {
            Application.ApplicationStatus.OFFER_PENDING,
            Application.ApplicationStatus.REJECTED,
            Application.ApplicationStatus.WITHDRAWN,
            Application.ApplicationStatus.ON_HOLD,
        },
        Application.ApplicationStatus.OFFER_PENDING: {
            Application.ApplicationStatus.OFFER_EXTENDED,
            Application.ApplicationStatus.REJECTED,
            Application.ApplicationStatus.WITHDRAWN,
            Application.ApplicationStatus.ON_HOLD,
        },
        Application.ApplicationStatus.OFFER_EXTENDED: {
            Application.ApplicationStatus.HIRED,
            Application.ApplicationStatus.REJECTED,
            Application.ApplicationStatus.WITHDRAWN,
        },
        Application.ApplicationStatus.ON_HOLD: {
            Application.ApplicationStatus.IN_REVIEW,
            Application.ApplicationStatus.SHORTLISTED,
            Application.ApplicationStatus.INTERVIEWING,
            Application.ApplicationStatus.REJECTED,
            Application.ApplicationStatus.WITHDRAWN,
        },
        # Terminal statuses - no transitions allowed
        Application.ApplicationStatus.HIRED: set(),
        Application.ApplicationStatus.REJECTED: set(),
        Application.ApplicationStatus.WITHDRAWN: set(),
    }

    @classmethod
    def can_apply(
        cls,
        candidate: Candidate,
        job: JobPosting,
        tenant=None
    ) -> ValidationResult:
        """
        Validate if a candidate can apply for a job.

        Checks:
        - Job is accepting applications
        - Job has positions remaining
        - Candidate hasn't already applied
        - Candidate has valid consent
        - Application deadline not passed

        Args:
            candidate: The candidate wanting to apply
            job: The job posting
            tenant: Optional tenant context

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        # Check job status
        if not job.is_open:
            result.add_error(
                'job',
                _('This job is not currently accepting applications.')
            )

        # Check positions remaining
        if job.positions_remaining <= 0:
            result.add_error(
                'job',
                _('All positions for this job have been filled.')
            )

        # Check application deadline
        if job.application_deadline:
            if job.application_deadline < timezone.now():
                result.add_error(
                    'job',
                    _('The application deadline has passed.')
                )

        # Check for existing application
        existing = Application.objects.filter(
            candidate=candidate,
            job=job
        ).first()

        if existing:
            result.add_error(
                'candidate',
                _('You have already applied for this job.')
            )
            if existing.status == Application.ApplicationStatus.REJECTED:
                result.add_warning(
                    'candidate',
                    _('Your previous application was rejected.')
                )
            elif existing.status == Application.ApplicationStatus.WITHDRAWN:
                result.add_warning(
                    'candidate',
                    _('Your previous application was withdrawn.')
                )

        # Check candidate consent
        if not candidate.has_valid_consent:
            result.add_error(
                'candidate',
                _('Valid data storage consent is required.')
            )

        # Check tenant match if tenant provided
        if tenant:
            if job.tenant != tenant:
                result.add_error(
                    'tenant',
                    _('Job does not belong to this tenant.')
                )
            if candidate.tenant != tenant:
                result.add_error(
                    'tenant',
                    _('Candidate does not belong to this tenant.')
                )

        # Warnings (non-blocking)
        if job.require_resume and not candidate.resume:
            result.add_warning(
                'resume',
                _('This job requires a resume. Please ensure you have one uploaded.')
            )

        if job.require_cover_letter:
            result.add_warning(
                'cover_letter',
                _('This job requires a cover letter.')
            )

        return result

    @classmethod
    def can_advance(cls, application: Application) -> ValidationResult:
        """
        Validate if an application can advance to the next stage.

        Checks:
        - Application is not in a terminal status
        - Current stage allows advancement
        - There is a next stage available

        Args:
            application: The application to check

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        # Check terminal status
        if application.is_terminal:
            result.add_error(
                'status',
                _('Applications in terminal status cannot be advanced.')
            )
            return result

        # Check if current stage is terminal
        if application.current_stage and application.current_stage.is_terminal:
            result.add_error(
                'stage',
                _('Current stage is a terminal stage.')
            )
            return result

        # Check for next stage
        if application.current_stage:
            next_stage = application.current_stage.get_next_stage()
            if not next_stage:
                result.add_error(
                    'stage',
                    _('No next stage available in the pipeline.')
                )

        # Warnings
        if application.days_in_current_stage and application.days_in_current_stage < 1:
            result.add_warning(
                'timing',
                _('Application has been in current stage for less than a day.')
            )

        if not application.overall_rating:
            result.add_warning(
                'rating',
                _('Application has not been rated yet.')
            )

        return result

    @classmethod
    def can_transition(
        cls,
        application: Application,
        new_status: str
    ) -> ValidationResult:
        """
        Validate if an application can transition to a new status.

        Args:
            application: The application
            new_status: The desired new status

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        current_status = application.status
        allowed = cls.ALLOWED_TRANSITIONS.get(current_status, set())

        if new_status not in allowed:
            result.add_error(
                'status',
                _('Cannot transition from {} to {}.').format(
                    current_status, new_status
                )
            )

        return result

    @classmethod
    def can_reject(cls, application: Application) -> ValidationResult:
        """
        Validate if an application can be rejected.

        Args:
            application: The application to check

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        if application.status == Application.ApplicationStatus.REJECTED:
            result.add_error(
                'status',
                _('Application is already rejected.')
            )
        elif application.status == Application.ApplicationStatus.HIRED:
            result.add_error(
                'status',
                _('Cannot reject a hired application.')
            )
        elif application.status == Application.ApplicationStatus.WITHDRAWN:
            result.add_error(
                'status',
                _('Cannot reject a withdrawn application.')
            )

        # Warnings
        if application.has_pending_interviews:
            result.add_warning(
                'interviews',
                _('Application has pending interviews that will need to be cancelled.')
            )

        return result

    @classmethod
    def can_hire(cls, application: Application) -> ValidationResult:
        """
        Validate if an application can be marked as hired.

        Args:
            application: The application to check

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        if application.status == Application.ApplicationStatus.HIRED:
            result.add_error(
                'status',
                _('Application is already hired.')
            )
            return result

        if application.is_terminal:
            result.add_error(
                'status',
                _('Application is in a terminal status.')
            )
            return result

        # Check job has positions remaining
        job = application.job
        if job.positions_remaining <= 0:
            result.add_warning(
                'positions',
                _('All positions have been filled. Hiring will exceed the position count.')
            )

        # Check for offer stage
        if application.status not in {
            Application.ApplicationStatus.OFFER_PENDING,
            Application.ApplicationStatus.OFFER_EXTENDED
        }:
            result.add_warning(
                'status',
                _('Application is not in an offer stage.')
            )

        return result

    @classmethod
    def validate_stage_change(
        cls,
        application: Application,
        target_stage: PipelineStage
    ) -> ValidationResult:
        """
        Validate a stage change.

        Args:
            application: The application
            target_stage: The target stage

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        # Check application is not terminal
        if application.is_terminal:
            result.add_error(
                'status',
                _('Cannot change stage of terminal application.')
            )
            return result

        # Check stage belongs to job's pipeline
        if application.job.pipeline:
            if target_stage.pipeline != application.job.pipeline:
                result.add_error(
                    'stage',
                    _('Stage does not belong to the job pipeline.')
                )

        # Check stage is active
        if not target_stage.is_active:
            result.add_error(
                'stage',
                _('Target stage is not active.')
            )

        # Warning for backwards movement
        if application.current_stage:
            if target_stage.order < application.current_stage.order:
                result.add_warning(
                    'stage',
                    _('Moving application backwards in pipeline.')
                )

        return result


# =============================================================================
# JOB POSTING VALIDATOR
# =============================================================================

class JobPostingValidator:
    """
    Validator for job postings.

    Provides validation for:
    - Publishability
    - Data completeness
    - Business rules
    """

    # Required fields for publishing
    REQUIRED_FOR_PUBLISH = ['title', 'description', 'pipeline']

    # Recommended fields (warnings)
    RECOMMENDED_FIELDS = [
        'category', 'job_type', 'experience_level', 'location_city',
        'required_skills', 'responsibilities'
    ]

    @classmethod
    def is_publishable(cls, job: JobPosting) -> ValidationResult:
        """
        Validate if a job posting can be published.

        Checks:
        - Required fields are filled
        - Job is in draft or on-hold status
        - Pipeline is configured
        - No validation errors

        Args:
            job: The job posting to validate

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        # Check required fields
        if not job.title or not job.title.strip():
            result.add_error('title', _('Title is required.'))

        if not job.description or not job.description.strip():
            result.add_error('description', _('Description is required.'))

        if not job.pipeline:
            result.add_error('pipeline', _('A recruitment pipeline must be selected.'))

        # Check status
        if job.status not in {JobPosting.JobStatus.DRAFT, JobPosting.JobStatus.ON_HOLD}:
            result.add_error(
                'status',
                _('Job must be in draft or on-hold status to publish.')
            )

        # Check salary validity
        if job.salary_min and job.salary_max:
            if job.salary_min > job.salary_max:
                result.add_error(
                    'salary_min',
                    _('Minimum salary cannot exceed maximum salary.')
                )

        # Check positions count
        if job.positions_count < 1:
            result.add_error(
                'positions_count',
                _('At least 1 position is required.')
            )

        # Check deadline
        if job.application_deadline:
            if job.application_deadline <= timezone.now():
                result.add_error(
                    'application_deadline',
                    _('Application deadline must be in the future.')
                )

        # Recommended field warnings
        if not job.category:
            result.add_warning(
                'category',
                _('Consider adding a category for better organization.')
            )

        if not job.required_skills:
            result.add_warning(
                'required_skills',
                _('Consider adding required skills for better candidate matching.')
            )

        if not job.location_city and job.remote_policy != JobPosting.RemotePolicy.REMOTE:
            result.add_warning(
                'location_city',
                _('Consider adding a location for non-remote positions.')
            )

        if not job.hiring_manager:
            result.add_warning(
                'hiring_manager',
                _('Consider assigning a hiring manager.')
            )

        return result

    @classmethod
    def validate_job_data(cls, data: Dict) -> ValidationResult:
        """
        Validate job posting data (for create/update).

        Args:
            data: Dictionary of job data

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        # Title validation
        title = data.get('title', '')
        if not title or not title.strip():
            result.add_error('title', _('Title is required.'))
        elif len(title) > 200:
            result.add_error('title', _('Title cannot exceed 200 characters.'))

        # Description validation
        description = data.get('description', '')
        if len(description) > 50000:
            result.add_error(
                'description',
                _('Description is too long.')
            )

        # Salary validation
        salary_min = data.get('salary_min')
        salary_max = data.get('salary_max')

        if salary_min is not None and salary_min < 0:
            result.add_error('salary_min', _('Salary cannot be negative.'))
        if salary_max is not None and salary_max < 0:
            result.add_error('salary_max', _('Salary cannot be negative.'))
        if salary_min and salary_max and salary_min > salary_max:
            result.add_error(
                'salary_min',
                _('Minimum salary cannot exceed maximum.')
            )

        # Positions validation
        positions_count = data.get('positions_count', 1)
        if positions_count < 1:
            result.add_error(
                'positions_count',
                _('At least 1 position is required.')
            )
        elif positions_count > 1000:
            result.add_warning(
                'positions_count',
                _('Unusually high number of positions.')
            )

        # Deadline validation
        deadline = data.get('application_deadline')
        if deadline and isinstance(deadline, datetime):
            if deadline <= timezone.now():
                result.add_error(
                    'application_deadline',
                    _('Application deadline must be in the future.')
                )
            elif deadline > timezone.now() + timedelta(days=365):
                result.add_warning(
                    'application_deadline',
                    _('Application deadline is more than a year away.')
                )

        return result

    @classmethod
    def can_close(cls, job: JobPosting) -> ValidationResult:
        """
        Validate if a job can be closed.

        Args:
            job: The job posting

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        if job.is_closed:
            result.add_error(
                'status',
                _('Job is already closed.')
            )
            return result

        # Check for active applications
        active_apps = job.applications.filter(
            status__in=Application.ACTIVE_STATUSES
        ).count()

        if active_apps > 0:
            result.add_warning(
                'applications',
                _('There are {} active applications that will remain in their current state.').format(
                    active_apps
                )
            )

        # Check for pending interviews
        pending_interviews = job.applications.filter(
            interviews__status__in=['scheduled', 'confirmed']
        ).distinct().count()

        if pending_interviews > 0:
            result.add_warning(
                'interviews',
                _('There are {} applications with pending interviews.').format(
                    pending_interviews
                )
            )

        return result

    @classmethod
    def can_reopen(cls, job: JobPosting) -> ValidationResult:
        """
        Validate if a job can be reopened.

        Args:
            job: The job posting

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        if job.status not in {
            JobPosting.JobStatus.CLOSED,
            JobPosting.JobStatus.ON_HOLD
        }:
            result.add_error(
                'status',
                _('Only closed or on-hold jobs can be reopened.')
            )

        # Check if all positions are filled
        hired_count = job.applications.filter(status='hired').count()
        if hired_count >= job.positions_count:
            result.add_warning(
                'positions',
                _('All positions have been filled. Consider increasing position count.')
            )

        # Check deadline
        if job.application_deadline and job.application_deadline < timezone.now():
            result.add_warning(
                'application_deadline',
                _('Application deadline has passed. Consider updating it.')
            )

        return result


# =============================================================================
# CANDIDATE VALIDATOR
# =============================================================================

class CandidateValidator:
    """
    Validator for candidate data.

    Provides validation for:
    - Data completeness
    - Consent validity
    - Deduplication checks
    """

    @classmethod
    def validate_candidate_data(cls, data: Dict) -> ValidationResult:
        """
        Validate candidate data for create/update.

        Args:
            data: Dictionary of candidate data

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        # Name validation
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')

        if not first_name or not first_name.strip():
            result.add_error('first_name', _('First name is required.'))
        if not last_name or not last_name.strip():
            result.add_error('last_name', _('Last name is required.'))

        # Email validation
        email = data.get('email', '')
        if not email or not email.strip():
            result.add_error('email', _('Email is required.'))
        elif '@' not in email:
            result.add_error('email', _('Invalid email format.'))

        # Phone validation (optional but validate format if present)
        phone = data.get('phone', '')
        if phone:
            # Simple length check
            cleaned_phone = ''.join(filter(str.isdigit, phone))
            if len(cleaned_phone) < 7 or len(cleaned_phone) > 15:
                result.add_warning(
                    'phone',
                    _('Phone number format may be invalid.')
                )

        # Salary validation
        salary_min = data.get('desired_salary_min')
        salary_max = data.get('desired_salary_max')

        if salary_min is not None and salary_min < 0:
            result.add_error(
                'desired_salary_min',
                _('Salary cannot be negative.')
            )
        if salary_max is not None and salary_max < 0:
            result.add_error(
                'desired_salary_max',
                _('Salary cannot be negative.')
            )
        if salary_min and salary_max and salary_min > salary_max:
            result.add_error(
                'desired_salary_min',
                _('Minimum salary cannot exceed maximum.')
            )

        # Profile completeness warnings
        if not data.get('skills'):
            result.add_warning(
                'skills',
                _('Adding skills improves job matching.')
            )

        if not data.get('resume'):
            result.add_warning(
                'resume',
                _('A resume is recommended for applications.')
            )

        return result

    @classmethod
    def check_consent(cls, candidate: Candidate) -> ValidationResult:
        """
        Validate candidate's data storage consent.

        Args:
            candidate: The candidate to check

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        if not candidate.consent_to_store:
            result.add_error(
                'consent',
                _('Data storage consent has not been given.')
            )

        if candidate.data_retention_until:
            if candidate.data_retention_until < timezone.now().date():
                result.add_error(
                    'consent',
                    _('Data retention period has expired.')
                )
            elif candidate.data_retention_until < (timezone.now().date() + timedelta(days=30)):
                result.add_warning(
                    'consent',
                    _('Data retention period expires soon.')
                )

        return result

    @classmethod
    def can_merge(
        cls,
        primary: Candidate,
        secondary: Candidate
    ) -> ValidationResult:
        """
        Validate if two candidates can be merged.

        Args:
            primary: The primary candidate (to keep)
            secondary: The secondary candidate (to merge from)

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        # Cannot merge same candidate
        if primary.id == secondary.id:
            result.add_error(
                'candidate',
                _('Cannot merge a candidate with itself.')
            )
            return result

        # Must be same tenant
        if primary.tenant != secondary.tenant:
            result.add_error(
                'tenant',
                _('Candidates must belong to the same tenant.')
            )

        # Warning for different emails
        if primary.email.lower() != secondary.email.lower():
            result.add_warning(
                'email',
                _('Candidates have different email addresses.')
            )

        # Warning for different names
        if (primary.first_name.lower() != secondary.first_name.lower() or
                primary.last_name.lower() != secondary.last_name.lower()):
            result.add_warning(
                'name',
                _('Candidates have different names.')
            )

        # Check for conflicting active applications
        primary_jobs = set(
            primary.applications.filter(
                status__in=Application.ACTIVE_STATUSES
            ).values_list('job_id', flat=True)
        )
        secondary_jobs = set(
            secondary.applications.filter(
                status__in=Application.ACTIVE_STATUSES
            ).values_list('job_id', flat=True)
        )

        conflicts = primary_jobs & secondary_jobs
        if conflicts:
            result.add_warning(
                'applications',
                _('Both candidates have active applications for {} jobs.').format(
                    len(conflicts)
                )
            )

        return result


# =============================================================================
# PIPELINE VALIDATOR
# =============================================================================

class PipelineValidator:
    """
    Validator for recruitment pipelines.

    Provides validation for:
    - Pipeline structure
    - Stage configuration
    """

    @classmethod
    def validate_pipeline(cls, pipeline: Pipeline) -> ValidationResult:
        """
        Validate a pipeline's configuration.

        Args:
            pipeline: The pipeline to validate

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        # Check for stages
        stages = pipeline.stages.filter(is_active=True).order_by('order')

        if not stages.exists():
            result.add_error(
                'stages',
                _('Pipeline must have at least one stage.')
            )
            return result

        # Check for initial stage
        initial_stages = stages.filter(stage_type='new')
        if not initial_stages.exists():
            result.add_warning(
                'stages',
                _('Pipeline has no initial (New) stage.')
            )

        # Check for terminal stages
        hired_stages = stages.filter(stage_type='hired')
        rejected_stages = stages.filter(stage_type='rejected')

        if not hired_stages.exists():
            result.add_warning(
                'stages',
                _('Pipeline has no Hired stage.')
            )
        if not rejected_stages.exists():
            result.add_warning(
                'stages',
                _('Pipeline has no Rejected stage.')
            )

        # Check stage order uniqueness
        orders = list(stages.values_list('order', flat=True))
        if len(orders) != len(set(orders)):
            result.add_error(
                'stages',
                _('Stage orders must be unique.')
            )

        # Warning for too many stages
        if stages.count() > 15:
            result.add_warning(
                'stages',
                _('Pipeline has many stages. Consider simplifying.')
            )

        return result

    @classmethod
    def can_delete_stage(
        cls,
        stage: PipelineStage
    ) -> ValidationResult:
        """
        Validate if a pipeline stage can be deleted.

        Args:
            stage: The stage to validate

        Returns:
            ValidationResult with any errors or warnings
        """
        result = ValidationResult()

        # Check for applications in this stage
        app_count = Application.objects.filter(current_stage=stage).count()

        if app_count > 0:
            result.add_error(
                'applications',
                _('Cannot delete stage with {} active applications.').format(
                    app_count
                )
            )

        # Check if it's the only stage
        active_stages = stage.pipeline.stages.filter(is_active=True)
        if active_stages.count() <= 1:
            result.add_error(
                'pipeline',
                _('Cannot delete the only stage in a pipeline.')
            )

        return result
