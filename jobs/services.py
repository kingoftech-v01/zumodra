"""
ATS Services - Business Logic Layer

This module provides service classes that encapsulate business logic
for the ATS (Applicant Tracking System) module:

- ApplicationService: Handle application lifecycle
- CandidateService: Candidate management and deduplication
- JobPostingService: Job posting lifecycle management
- PipelineService: Pipeline and stage operations

Services provide a clean separation between views/serializers and models,
making the business logic testable and reusable.

Security Notes:
- All sensitive operations verify user permissions before execution
- Tenant isolation is enforced at the service layer
- Exception details are logged but not exposed to clients
"""

import csv
import logging
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from io import StringIO
from typing import Any, Dict, List, Optional, Tuple, Union

from django.core.exceptions import ValidationError, PermissionDenied
from django.db import transaction
from django.db.models import Avg, Count, F, Q, QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .models import (
    Application,
    ApplicationActivity,
    Candidate,
    Interview,
    InterviewFeedback,
    JobPosting,
    Pipeline,
    PipelineStage,
)

logger = logging.getLogger(__name__)


# =============================================================================
# PERMISSION CHECKING UTILITIES
# =============================================================================

class ATSPermissions:
    """
    Permission checking utilities for ATS operations.

    Provides methods to verify user permissions before sensitive operations.
    Uses Django's built-in permission system with ATS-specific checks.
    """

    # Permission codenames
    CAN_CREATE_APPLICATION = 'jobs.add_application'
    CAN_CHANGE_APPLICATION = 'jobs.change_application'
    CAN_DELETE_APPLICATION = 'jobs.delete_application'
    CAN_VIEW_APPLICATION = 'jobs.view_application'

    CAN_CREATE_CANDIDATE = 'jobs.add_candidate'
    CAN_CHANGE_CANDIDATE = 'jobs.change_candidate'
    CAN_DELETE_CANDIDATE = 'jobs.delete_candidate'
    CAN_MERGE_CANDIDATES = 'jobs.merge_candidate'
    CAN_BULK_IMPORT = 'jobs.bulk_import_candidate'

    CAN_CREATE_JOB = 'jobs.add_jobposting'
    CAN_CHANGE_JOB = 'jobs.change_jobposting'
    CAN_DELETE_JOB = 'jobs.delete_jobposting'
    CAN_PUBLISH_JOB = 'jobs.publish_jobposting'
    CAN_CLOSE_JOB = 'jobs.close_jobposting'

    CAN_HIRE_CANDIDATE = 'jobs.hire_application'
    CAN_REJECT_APPLICATION = 'jobs.reject_application'
    CAN_ADVANCE_APPLICATION = 'jobs.advance_application'

    @staticmethod
    def check_permission(user, permission: str, raise_exception: bool = True) -> bool:
        """
        Check if user has the specified permission.

        Args:
            user: The user to check permissions for
            permission: The permission codename to check
            raise_exception: If True, raises PermissionDenied on failure

        Returns:
            True if user has permission, False otherwise

        Raises:
            PermissionDenied: If raise_exception is True and user lacks permission
        """
        if user is None:
            if raise_exception:
                raise PermissionDenied(_('Authentication required.'))
            return False

        if not user.is_authenticated:
            if raise_exception:
                raise PermissionDenied(_('Authentication required.'))
            return False

        # Superusers always have permission
        if user.is_superuser:
            return True

        # Check specific permission
        has_perm = user.has_perm(permission)

        if not has_perm and raise_exception:
            logger.warning(
                f"Permission denied: user={user.id}, permission={permission}"
            )
            raise PermissionDenied(
                _('You do not have permission to perform this action.')
            )

        return has_perm

    @staticmethod
    def check_object_permission(
        user,
        obj,
        permission: str,
        raise_exception: bool = True
    ) -> bool:
        """
        Check if user has permission for a specific object.

        Verifies both the permission and tenant ownership.

        Args:
            user: The user to check
            obj: The object to check access for
            permission: The permission codename
            raise_exception: If True, raises on failure

        Returns:
            True if user has permission for the object
        """
        # First check basic permission
        if not ATSPermissions.check_permission(user, permission, raise_exception=False):
            if raise_exception:
                raise PermissionDenied(
                    _('You do not have permission to perform this action.')
                )
            return False

        # Verify tenant ownership if object has a tenant
        if hasattr(obj, 'tenant') and hasattr(user, 'tenant'):
            if obj.tenant_id != user.tenant_id:
                if raise_exception:
                    logger.warning(
                        f"Tenant mismatch: user={user.id} tried to access "
                        f"object={obj.__class__.__name__}:{obj.id} from different tenant"
                    )
                    raise PermissionDenied(
                        _('You do not have access to this resource.')
                    )
                return False

        return True

    @staticmethod
    def verify_application_access(user, application: 'Application') -> bool:
        """
        Verify user can access an application.

        Args:
            user: The user
            application: The application to check

        Returns:
            True if user can access the application
        """
        return ATSPermissions.check_object_permission(
            user, application, ATSPermissions.CAN_VIEW_APPLICATION
        )

    @staticmethod
    def verify_candidate_access(user, candidate: 'Candidate') -> bool:
        """
        Verify user can access a candidate.

        Args:
            user: The user
            candidate: The candidate to check

        Returns:
            True if user can access the candidate
        """
        return ATSPermissions.check_object_permission(
            user, candidate, 'jobs.view_candidate'
        )

    @staticmethod
    def verify_job_access(user, job: 'JobPosting') -> bool:
        """
        Verify user can access a job posting.

        Args:
            user: The user
            job: The job posting to check

        Returns:
            True if user can access the job posting
        """
        return ATSPermissions.check_object_permission(
            user, job, 'jobs.view_jobposting'
        )


# =============================================================================
# DATA CLASSES FOR SERVICE RESULTS
# =============================================================================

@dataclass
class ServiceResult:
    """Base result class for service operations."""
    success: bool
    message: str = ''
    data: Any = None
    errors: Dict[str, Any] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = {}


@dataclass
class PipelineMetrics:
    """Metrics for a pipeline."""
    total_applications: int
    applications_by_stage: Dict[str, int]
    average_time_to_hire: Optional[timedelta]
    conversion_rate: float
    stage_metrics: List[Dict[str, Any]]


@dataclass
class CandidateMatchResult:
    """Result of candidate matching against a job."""
    candidate_id: str
    candidate_name: str
    match_score: float
    skill_match_percentage: float
    matched_skills: List[str]
    missing_skills: List[str]


# =============================================================================
# APPLICATION SERVICE
# =============================================================================

class ApplicationService:
    """
    Service for managing job applications.

    Handles:
    - Creating new applications
    - Advancing applications through stages
    - Rejection and withdrawal
    - Bulk operations
    """

    @staticmethod
    @transaction.atomic
    def apply(
        tenant,
        candidate: Candidate,
        job: JobPosting,
        cover_letter: str = '',
        custom_answers: Dict = None,
        source: str = '',
        utm_params: Dict = None,
        user=None
    ) -> ServiceResult:
        """
        Submit a new job application.

        Args:
            tenant: The tenant for the application
            candidate: The candidate applying
            job: The job being applied to
            cover_letter: Optional cover letter text
            custom_answers: Answers to custom questions
            source: Source of the application
            utm_params: UTM tracking parameters
            user: User creating the application

        Returns:
            ServiceResult with the created application
        """
        # Validate job can accept applications
        if not job.can_accept_applications:
            return ServiceResult(
                success=False,
                message=_('This job is not accepting applications.'),
                errors={'job': _('Job is closed or positions are filled.')}
            )

        # Check for existing application
        existing = Application.objects.filter(
            tenant=tenant,
            candidate=candidate,
            job=job
        ).first()

        if existing:
            return ServiceResult(
                success=False,
                message=_('Candidate has already applied for this job.'),
                errors={'candidate': _('Duplicate application.')},
                data=existing
            )

        # Create the application
        try:
            application = Application.objects.create(
                tenant=tenant,
                candidate=candidate,
                job=job,
                cover_letter=cover_letter,
                custom_answers=custom_answers or {},
                utm_source=utm_params.get('source', '') if utm_params else '',
                utm_medium=utm_params.get('medium', '') if utm_params else '',
                utm_campaign=utm_params.get('campaign', '') if utm_params else '',
            )

            # Set initial stage if pipeline exists
            if job.pipeline:
                first_stage = job.pipeline.stages.filter(
                    is_active=True
                ).order_by('order').first()
                if first_stage:
                    application.current_stage = first_stage
                    application.save(update_fields=['current_stage'])

            # Calculate AI match score
            if candidate.skills and job.required_skills:
                match_score = candidate.get_skill_match_score(job)
                application.ai_match_score = Decimal(str(match_score))
                application.save(update_fields=['ai_match_score'])

            # Log the application
            ApplicationActivity.objects.create(
                application=application,
                activity_type=ApplicationActivity.ActivityType.APPLIED,
                performed_by=user,
                notes=f'Applied via {source}' if source else 'Application submitted',
            )

            # Update candidate last activity
            candidate.update_last_activity()

            logger.info(
                f"Application created: {candidate.full_name} -> {job.title} "
                f"(tenant: {tenant.id})"
            )

            return ServiceResult(
                success=True,
                message=_('Application submitted successfully.'),
                data=application
            )

        except Exception as e:
            # Log the full exception for debugging, but return generic message to client
            logger.exception(f"Error creating application: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to create application. Please try again or contact support.'),
                errors={'__all__': _('An unexpected error occurred.')}
            )

    @staticmethod
    @transaction.atomic
    def advance(
        application: Application,
        user=None,
        notes: str = '',
        skip_validation: bool = False
    ) -> ServiceResult:
        """
        Advance an application to the next pipeline stage.

        Args:
            application: The application to advance
            user: User performing the action
            notes: Optional notes for the stage change
            skip_validation: Skip validation checks

        Returns:
            ServiceResult indicating success/failure
        """
        # Permission check
        try:
            ATSPermissions.check_object_permission(
                user, application, ATSPermissions.CAN_ADVANCE_APPLICATION
            )
        except PermissionDenied as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'permission': str(e)}
            )

        if not skip_validation and not application.can_advance:
            return ServiceResult(
                success=False,
                message=_('Application cannot be advanced.'),
                errors={'status': _('Application is in a terminal state.')}
            )

        try:
            application.advance_to_next_stage(user=user, notes=notes)
            return ServiceResult(
                success=True,
                message=_('Application advanced to next stage.'),
                data={
                    'new_stage': application.current_stage.name if application.current_stage else None,
                    'application_id': str(application.id)
                }
            )
        except ValidationError as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'stage': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def move_to_stage(
        application: Application,
        stage: PipelineStage,
        user=None,
        notes: str = ''
    ) -> ServiceResult:
        """
        Move an application to a specific stage.

        Args:
            application: The application to move
            stage: The target stage
            user: User performing the action
            notes: Optional notes

        Returns:
            ServiceResult indicating success/failure
        """
        if application.is_terminal:
            return ServiceResult(
                success=False,
                message=_('Cannot move a terminal application.'),
                errors={'status': _('Application is in a terminal state.')}
            )

        # Validate stage belongs to the job's pipeline
        if application.job.pipeline and stage.pipeline != application.job.pipeline:
            return ServiceResult(
                success=False,
                message=_('Stage does not belong to the job pipeline.'),
                errors={'stage': _('Invalid stage for this job.')}
            )

        try:
            application.move_to_stage(stage, user=user, notes=notes)
            return ServiceResult(
                success=True,
                message=_('Application moved to stage: {}').format(stage.name),
                data={'new_stage': stage.name}
            )
        except ValidationError as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'stage': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def reject(
        application: Application,
        reason: str = '',
        feedback: str = '',
        user=None,
        send_email: bool = True
    ) -> ServiceResult:
        """
        Reject an application.

        Args:
            application: The application to reject
            reason: Rejection reason code/category
            feedback: Detailed feedback
            user: User performing the action
            send_email: Whether to send rejection email

        Returns:
            ServiceResult indicating success/failure
        """
        # Permission check
        try:
            ATSPermissions.check_object_permission(
                user, application, ATSPermissions.CAN_REJECT_APPLICATION
            )
        except PermissionDenied as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'permission': str(e)}
            )

        if not application.can_reject:
            return ServiceResult(
                success=False,
                message=_('Application cannot be rejected.'),
                errors={'status': _('Application is already in a terminal state.')}
            )

        try:
            application.reject(
                reason=reason,
                feedback=feedback,
                user=user,
                send_email=send_email
            )
            return ServiceResult(
                success=True,
                message=_('Application rejected.'),
                data={'application_id': str(application.id)}
            )
        except ValidationError as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'rejection': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def withdraw(
        application: Application,
        reason: str = '',
        user=None
    ) -> ServiceResult:
        """
        Withdraw an application (candidate-initiated).

        Args:
            application: The application to withdraw
            reason: Reason for withdrawal
            user: User performing the action

        Returns:
            ServiceResult indicating success/failure
        """
        if not application.can_withdraw:
            return ServiceResult(
                success=False,
                message=_('Application cannot be withdrawn.'),
                errors={'status': _('Application is already in a terminal state.')}
            )

        try:
            application.withdraw(reason=reason, user=user)
            return ServiceResult(
                success=True,
                message=_('Application withdrawn.'),
                data={'application_id': str(application.id)}
            )
        except ValidationError as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'withdrawal': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def hire(application: Application, user=None) -> ServiceResult:
        """
        Mark an application as hired.

        Args:
            application: The application
            user: User performing the action

        Returns:
            ServiceResult indicating success/failure
        """
        # Permission check - hiring is a sensitive operation
        try:
            ATSPermissions.check_object_permission(
                user, application, ATSPermissions.CAN_HIRE_CANDIDATE
            )
        except PermissionDenied as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'permission': str(e)}
            )

        if application.status == Application.ApplicationStatus.HIRED:
            return ServiceResult(
                success=False,
                message=_('Application is already hired.'),
                errors={'status': _('Already hired.')}
            )

        try:
            application.hire(user=user)

            # Check if all positions are now filled
            job = application.job
            hired_count = job.applications.filter(status='hired').count()
            if hired_count >= job.positions_count:
                job.close(reason='filled', user=user)

            return ServiceResult(
                success=True,
                message=_('Candidate hired successfully.'),
                data={
                    'application_id': str(application.id),
                    'hired_at': application.hired_at.isoformat()
                }
            )
        except Exception as e:
            # Log the full exception for debugging, but return generic message to client
            logger.exception(f"Error hiring candidate: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to complete hire. Please try again or contact support.'),
                errors={'hire': _('An unexpected error occurred.')}
            )

    @staticmethod
    @transaction.atomic
    def bulk_reject(
        applications: QuerySet,
        reason: str = '',
        feedback: str = '',
        user=None,
        send_email: bool = True
    ) -> ServiceResult:
        """
        Reject multiple applications at once.

        Args:
            applications: QuerySet of applications to reject
            reason: Rejection reason
            feedback: Feedback message
            user: User performing the action
            send_email: Send rejection emails

        Returns:
            ServiceResult with counts
        """
        rejected_count = 0
        failed_count = 0
        failed_ids = []

        for app in applications:
            result = ApplicationService.reject(
                app, reason=reason, feedback=feedback,
                user=user, send_email=send_email
            )
            if result.success:
                rejected_count += 1
            else:
                failed_count += 1
                failed_ids.append(str(app.id))

        return ServiceResult(
            success=failed_count == 0,
            message=_('Rejected {} applications, {} failed.').format(
                rejected_count, failed_count
            ),
            data={
                'rejected_count': rejected_count,
                'failed_count': failed_count,
                'failed_ids': failed_ids
            }
        )

    @staticmethod
    def calculate_match_score(candidate: Candidate, job: JobPosting) -> float:
        """
        Calculate match score between candidate and job.

        Args:
            candidate: The candidate
            job: The job posting

        Returns:
            Match score as a percentage (0-100)
        """
        return candidate.get_skill_match_score(job)


# =============================================================================
# CANDIDATE SERVICE
# =============================================================================

class CandidateService:
    """
    Service for managing candidates.

    Handles:
    - Candidate creation and updates
    - Merging duplicate candidates
    - Deduplication detection
    - Bulk import operations
    """

    @staticmethod
    @transaction.atomic
    def merge(
        primary: Candidate,
        secondary: Candidate,
        delete_secondary: bool = True,
        user=None
    ) -> ServiceResult:
        """
        Merge two candidate records.

        The secondary candidate's data is merged into the primary,
        and applications are transferred.

        Args:
            primary: The candidate to keep
            secondary: The candidate to merge from
            delete_secondary: Whether to delete the secondary candidate
            user: User performing the action

        Returns:
            ServiceResult indicating success/failure
        """
        # Permission check - merging is a sensitive operation
        try:
            ATSPermissions.check_permission(
                user, ATSPermissions.CAN_MERGE_CANDIDATES
            )
            # Also verify access to both candidates
            ATSPermissions.verify_candidate_access(user, primary)
            ATSPermissions.verify_candidate_access(user, secondary)
        except PermissionDenied as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'permission': str(e)}
            )

        if primary.tenant != secondary.tenant:
            return ServiceResult(
                success=False,
                message=_('Candidates must belong to the same tenant.'),
                errors={'tenant': _('Tenant mismatch.')}
            )

        if primary.id == secondary.id:
            return ServiceResult(
                success=False,
                message=_('Cannot merge a candidate with itself.'),
                errors={'candidate': _('Same candidate.')}
            )

        try:
            # Count items being transferred
            apps_count = secondary.applications.count()

            # Perform the merge
            primary.merge_from(secondary, delete_other=delete_secondary)

            logger.info(
                f"Merged candidate {secondary.id} into {primary.id} "
                f"(transferred {apps_count} applications)"
            )

            return ServiceResult(
                success=True,
                message=_('Candidates merged successfully.'),
                data={
                    'primary_id': str(primary.id),
                    'applications_transferred': apps_count,
                    'secondary_deleted': delete_secondary
                }
            )
        except Exception as e:
            # Log the full exception for debugging, but return generic message to client
            logger.exception(f"Error merging candidates: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to merge candidates. Please try again or contact support.'),
                errors={'merge': _('An unexpected error occurred during merge.')}
            )

    @staticmethod
    def find_duplicates(
        tenant,
        candidate: Candidate = None,
        email: str = None,
        threshold: float = 0.8
    ) -> List[Tuple[Candidate, float]]:
        """
        Find potential duplicate candidates.

        Args:
            tenant: The tenant to search in
            candidate: Reference candidate (if checking existing)
            email: Email to check for duplicates
            threshold: Similarity threshold (0-1)

        Returns:
            List of (candidate, similarity_score) tuples
        """
        duplicates = []

        # Exact email match
        if email:
            matches = Candidate.objects.filter(
                tenant=tenant,
                email__iexact=email
            )
            if candidate:
                matches = matches.exclude(pk=candidate.pk)
            for match in matches:
                duplicates.append((match, 1.0))

        # Name-based matching if candidate provided
        if candidate:
            # Exact name match
            name_matches = Candidate.objects.filter(
                tenant=tenant,
                first_name__iexact=candidate.first_name,
                last_name__iexact=candidate.last_name
            ).exclude(pk=candidate.pk)

            for match in name_matches:
                if match not in [d[0] for d in duplicates]:
                    duplicates.append((match, 0.9))

            # Phone match
            if candidate.phone:
                phone_matches = Candidate.objects.filter(
                    tenant=tenant,
                    phone=candidate.phone
                ).exclude(pk=candidate.pk)

                for match in phone_matches:
                    if match not in [d[0] for d in duplicates]:
                        duplicates.append((match, 0.85))

        # Filter by threshold and sort by score
        duplicates = [(c, s) for c, s in duplicates if s >= threshold]
        duplicates.sort(key=lambda x: x[1], reverse=True)

        return duplicates

    @staticmethod
    def deduplicate_batch(
        tenant,
        dry_run: bool = True
    ) -> ServiceResult:
        """
        Find and optionally merge duplicate candidates.

        Args:
            tenant: The tenant to process
            dry_run: If True, only report duplicates without merging

        Returns:
            ServiceResult with duplicate groups
        """
        # Group candidates by email
        email_groups = {}
        candidates = Candidate.objects.filter(tenant=tenant)

        for candidate in candidates:
            if candidate.email:
                email_lower = candidate.email.lower()
                if email_lower not in email_groups:
                    email_groups[email_lower] = []
                email_groups[email_lower].append(candidate)

        # Find groups with duplicates
        duplicate_groups = {
            email: cands for email, cands in email_groups.items()
            if len(cands) > 1
        }

        merge_results = []

        if not dry_run:
            for email, candidates_list in duplicate_groups.items():
                # Keep the oldest as primary
                candidates_list.sort(key=lambda c: c.created_at)
                primary = candidates_list[0]

                for secondary in candidates_list[1:]:
                    result = CandidateService.merge(
                        primary, secondary, delete_secondary=True
                    )
                    merge_results.append({
                        'primary_id': str(primary.id),
                        'secondary_id': str(secondary.id),
                        'success': result.success
                    })

        return ServiceResult(
            success=True,
            message=_('Found {} duplicate groups.').format(len(duplicate_groups)),
            data={
                'duplicate_groups_count': len(duplicate_groups),
                'duplicate_groups': {
                    email: [str(c.id) for c in cands]
                    for email, cands in duplicate_groups.items()
                },
                'merge_results': merge_results if not dry_run else []
            }
        )

    @staticmethod
    @transaction.atomic
    def bulk_import(
        tenant,
        csv_data: str,
        source: str = 'imported',
        user=None,
        update_existing: bool = False
    ) -> ServiceResult:
        """
        Import candidates from CSV data.

        Expected CSV columns:
        - first_name (required)
        - last_name (required)
        - email (required)
        - phone
        - headline
        - skills (comma-separated)
        - city
        - state
        - country

        Args:
            tenant: The tenant to import into
            csv_data: CSV string data
            source: Source identifier for tracking
            user: User performing the import
            update_existing: Update existing candidates if email matches

        Returns:
            ServiceResult with import statistics
        """
        # Permission check - bulk import is a sensitive operation
        try:
            ATSPermissions.check_permission(
                user, ATSPermissions.CAN_BULK_IMPORT
            )
        except PermissionDenied as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'permission': str(e)}
            )

        created_count = 0
        updated_count = 0
        failed_count = 0
        failed_rows = []

        try:
            reader = csv.DictReader(StringIO(csv_data))

            for row_num, row in enumerate(reader, start=2):
                try:
                    # Validate required fields
                    if not row.get('first_name') or not row.get('last_name'):
                        raise ValueError('first_name and last_name are required')
                    if not row.get('email'):
                        raise ValueError('email is required')

                    email = row['email'].strip().lower()

                    # Check for existing
                    existing = Candidate.objects.filter(
                        tenant=tenant,
                        email__iexact=email
                    ).first()

                    if existing:
                        if update_existing:
                            # Update existing candidate
                            existing.first_name = row['first_name'].strip()
                            existing.last_name = row['last_name'].strip()
                            if row.get('phone'):
                                existing.phone = row['phone'].strip()
                            if row.get('headline'):
                                existing.headline = row['headline'].strip()
                            if row.get('skills'):
                                skills = [s.strip() for s in row['skills'].split(',')]
                                existing.skills = list(set(existing.skills + skills))
                            if row.get('city'):
                                existing.city = row['city'].strip()
                            if row.get('state'):
                                existing.state = row['state'].strip()
                            if row.get('country'):
                                existing.country = row['country'].strip()
                            existing.save()
                            updated_count += 1
                        else:
                            # Skip existing
                            failed_count += 1
                            failed_rows.append({
                                'row': row_num,
                                'email': email,
                                'error': 'Candidate already exists'
                            })
                    else:
                        # Create new candidate
                        skills = []
                        if row.get('skills'):
                            skills = [s.strip() for s in row['skills'].split(',')]

                        Candidate.objects.create(
                            tenant=tenant,
                            first_name=row['first_name'].strip(),
                            last_name=row['last_name'].strip(),
                            email=email,
                            phone=row.get('phone', '').strip(),
                            headline=row.get('headline', '').strip(),
                            skills=skills,
                            city=row.get('city', '').strip(),
                            state=row.get('state', '').strip(),
                            country=row.get('country', '').strip(),
                            source=source,
                            source_detail=f'CSV Import by {user}' if user else 'CSV Import'
                        )
                        created_count += 1

                except Exception as e:
                    failed_count += 1
                    failed_rows.append({
                        'row': row_num,
                        'email': row.get('email', 'unknown'),
                        'error': str(e)
                    })

            logger.info(
                f"Bulk import completed: {created_count} created, "
                f"{updated_count} updated, {failed_count} failed"
            )

            return ServiceResult(
                success=failed_count == 0,
                message=_('Import completed: {} created, {} updated, {} failed.').format(
                    created_count, updated_count, failed_count
                ),
                data={
                    'created_count': created_count,
                    'updated_count': updated_count,
                    'failed_count': failed_count,
                    'failed_rows': failed_rows
                }
            )

        except Exception as e:
            # Log the full exception for debugging, but return generic message to client
            logger.exception(f"Error during bulk import: {e}")
            return ServiceResult(
                success=False,
                message=_('Import failed. Please check your data format and try again.'),
                errors={'import': _('An unexpected error occurred during import.')}
            )

    @staticmethod
    def get_best_matches(
        tenant,
        job: JobPosting,
        limit: int = 10,
        min_score: float = 50.0
    ) -> List[CandidateMatchResult]:
        """
        Find best matching candidates for a job.

        Args:
            tenant: The tenant
            job: The job posting
            limit: Maximum number of matches to return
            min_score: Minimum match score (0-100)

        Returns:
            List of CandidateMatchResult objects
        """
        results = []

        # Get candidates who haven't applied - optimized query with tenant filter
        applied_ids = Application.objects.filter(
            job=job,
            job__tenant=tenant
        ).values_list('candidate_id', flat=True)

        # Prefetch only candidates with skills for better matching performance
        candidates = Candidate.objects.filter(
            tenant=tenant,
            is_active=True
        ).exclude(id__in=applied_ids).only(
            'id', 'first_name', 'last_name', 'skills'
        )

        for candidate in candidates:
            match_score = candidate.get_skill_match_score(job)

            if match_score >= min_score:
                candidate_skills = set(s.lower() for s in candidate.skills)
                required_skills = set(s.lower() for s in job.required_skills)

                matched = candidate_skills & required_skills
                missing = required_skills - candidate_skills

                results.append(CandidateMatchResult(
                    candidate_id=str(candidate.id),
                    candidate_name=candidate.full_name,
                    match_score=match_score,
                    skill_match_percentage=match_score,
                    matched_skills=list(matched),
                    missing_skills=list(missing)
                ))

        # Sort by score and limit
        results.sort(key=lambda x: x.match_score, reverse=True)
        return results[:limit]


# =============================================================================
# JOB POSTING SERVICE
# =============================================================================

class JobPostingService:
    """
    Service for managing job postings.

    Handles:
    - Publishing and closing jobs
    - Cloning job postings
    - Job metrics and statistics
    """

    @staticmethod
    @transaction.atomic
    def publish(job: JobPosting, user=None) -> ServiceResult:
        """
        Publish a job posting.

        Args:
            job: The job posting to publish
            user: User performing the action

        Returns:
            ServiceResult indicating success/failure
        """
        # Permission check
        try:
            ATSPermissions.check_object_permission(
                user, job, ATSPermissions.CAN_PUBLISH_JOB
            )
        except PermissionDenied as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'permission': str(e)}
            )

        if not job.is_publishable:
            errors = {}
            if not job.title:
                errors['title'] = _('Title is required.')
            if not job.description:
                errors['description'] = _('Description is required.')
            if not job.pipeline:
                errors['pipeline'] = _('Pipeline is required.')
            if job.status not in {JobPosting.JobStatus.DRAFT, JobPosting.JobStatus.ON_HOLD}:
                errors['status'] = _('Job must be in draft or on-hold status.')

            return ServiceResult(
                success=False,
                message=_('Job cannot be published.'),
                errors=errors
            )

        try:
            job.publish(user=user)
            logger.info(f"Job published: {job.title} (ID: {job.id})")

            return ServiceResult(
                success=True,
                message=_('Job published successfully.'),
                data={
                    'job_id': str(job.id),
                    'published_at': job.published_at.isoformat()
                }
            )
        except ValidationError as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'publish': str(e)}
            )

    @staticmethod
    @transaction.atomic
    def close(
        job: JobPosting,
        reason: str = 'closed',
        user=None
    ) -> ServiceResult:
        """
        Close a job posting.

        Args:
            job: The job posting to close
            reason: Reason for closing ('filled', 'cancelled', 'closed')
            user: User performing the action

        Returns:
            ServiceResult indicating success/failure
        """
        # Permission check
        try:
            ATSPermissions.check_object_permission(
                user, job, ATSPermissions.CAN_CLOSE_JOB
            )
        except PermissionDenied as e:
            return ServiceResult(
                success=False,
                message=str(e),
                errors={'permission': str(e)}
            )

        if job.is_closed:
            return ServiceResult(
                success=False,
                message=_('Job is already closed.'),
                errors={'status': _('Already closed.')}
            )

        try:
            job.close(reason=reason, user=user)
            logger.info(f"Job closed: {job.title} (reason: {reason})")

            return ServiceResult(
                success=True,
                message=_('Job closed successfully.'),
                data={
                    'job_id': str(job.id),
                    'reason': reason,
                    'closed_at': job.closed_at.isoformat()
                }
            )
        except Exception as e:
            # Log the full exception for debugging, but return generic message to client
            logger.exception(f"Error closing job: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to close job. Please try again or contact support.'),
                errors={'close': _('An unexpected error occurred.')}
            )

    @staticmethod
    @transaction.atomic
    def clone(
        job: JobPosting,
        new_title: str = None,
        new_reference_code: str = None,
        user=None
    ) -> ServiceResult:
        """
        Clone a job posting.

        Args:
            job: The job posting to clone
            new_title: Title for the new job
            new_reference_code: Reference code for the new job
            user: User creating the clone

        Returns:
            ServiceResult with the cloned job
        """
        try:
            new_job = job.clone(
                new_title=new_title,
                new_reference_code=new_reference_code,
                created_by=user
            )

            logger.info(
                f"Job cloned: {job.title} -> {new_job.title} (ID: {new_job.id})"
            )

            return ServiceResult(
                success=True,
                message=_('Job cloned successfully.'),
                data=new_job
            )
        except Exception as e:
            # Log the full exception for debugging, but return generic message to client
            logger.exception(f"Error cloning job: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to clone job. Please try again or contact support.'),
                errors={'clone': _('An unexpected error occurred.')}
            )

    @staticmethod
    def get_job_metrics(job: JobPosting) -> Dict[str, Any]:
        """
        Get comprehensive metrics for a job posting.

        Args:
            job: The job posting

        Returns:
            Dictionary of metrics
        """
        applications = job.applications.all()

        # Basic counts
        total_applications = applications.count()
        active_applications = applications.filter(
            status__in=Application.ACTIVE_STATUSES
        ).count()
        rejected_count = applications.filter(status='rejected').count()
        hired_count = applications.filter(status='hired').count()

        # Source breakdown
        source_breakdown = dict(
            applications.values('candidate__source').annotate(
                count=Count('id')
            ).values_list('candidate__source', 'count')
        )

        # Stage breakdown
        stage_breakdown = job.get_applications_by_stage()

        # Time metrics
        avg_time_to_hire = None
        hired_apps = applications.filter(
            status='hired',
            hired_at__isnull=False
        )
        if hired_apps.exists():
            total_days = sum(
                (app.hired_at - app.applied_at).days
                for app in hired_apps
            )
            avg_time_to_hire = total_days / hired_apps.count()

        # Rating metrics
        avg_rating = applications.filter(
            overall_rating__isnull=False
        ).aggregate(avg=Avg('overall_rating'))['avg']

        return {
            'total_applications': total_applications,
            'active_applications': active_applications,
            'rejected_count': rejected_count,
            'hired_count': hired_count,
            'positions_remaining': job.positions_remaining,
            'days_open': job.days_open,
            'source_breakdown': source_breakdown,
            'stage_breakdown': stage_breakdown,
            'average_time_to_hire_days': avg_time_to_hire,
            'average_rating': float(avg_rating) if avg_rating else None,
            'conversion_rate': (hired_count / total_applications * 100)
            if total_applications > 0 else 0.0
        }


# =============================================================================
# PIPELINE SERVICE
# =============================================================================

class PipelineService:
    """
    Service for managing recruitment pipelines.

    Handles:
    - Pipeline CRUD operations
    - Stage management
    - Pipeline metrics and analytics
    """

    @staticmethod
    @transaction.atomic
    def move_stage(
        application: Application,
        target_stage: PipelineStage,
        user=None,
        notes: str = ''
    ) -> ServiceResult:
        """
        Move an application to a specific stage.

        Delegates to ApplicationService.move_to_stage.
        """
        return ApplicationService.move_to_stage(
            application, target_stage, user=user, notes=notes
        )

    @staticmethod
    def get_metrics(pipeline: Pipeline) -> PipelineMetrics:
        """
        Get comprehensive metrics for a pipeline.

        Args:
            pipeline: The pipeline to analyze

        Returns:
            PipelineMetrics object with all metrics
        """
        # Total applications using this pipeline with optimized query
        applications = Application.objects.filter(
            job__pipeline=pipeline
        ).select_related('current_stage', 'job')
        total = applications.count()

        # Applications by stage - use aggregation for efficiency
        stage_counts = {}
        stages = pipeline.stages.filter(is_active=True).prefetch_related('applications')
        for stage in stages:
            stage_counts[stage.name] = applications.filter(
                current_stage=stage
            ).count()

        # Average time to hire
        avg_time_to_hire = pipeline.average_time_to_hire

        # Conversion rate
        conversion_rate = pipeline.conversion_rate

        # Detailed stage metrics
        stage_metrics = pipeline.get_stage_metrics()

        return PipelineMetrics(
            total_applications=total,
            applications_by_stage=stage_counts,
            average_time_to_hire=avg_time_to_hire,
            conversion_rate=conversion_rate,
            stage_metrics=stage_metrics
        )

    @staticmethod
    def get_bottlenecks(pipeline: Pipeline) -> List[Dict[str, Any]]:
        """
        Identify bottleneck stages in the pipeline.

        Bottlenecks are stages where applications spend too much time
        or have high rejection rates.

        Args:
            pipeline: The pipeline to analyze

        Returns:
            List of bottleneck stage information
        """
        bottlenecks = []

        # Prefetch related data for efficiency
        stages = pipeline.stages.filter(is_active=True).prefetch_related('applications')
        for stage in stages:
            if stage.is_terminal:
                continue

            # Calculate average time in stage
            avg_time = stage.calculate_average_time()
            app_count = stage.application_count

            # Get rejection rate from this stage
            total_exits = ApplicationActivity.objects.filter(
                activity_type='stage_change',
                old_value=stage.name
            ).count()

            rejections = Application.objects.filter(
                current_stage=stage,
                status='rejected'
            ).count()

            rejection_rate = (rejections / total_exits * 100) if total_exits > 0 else 0

            # Flag as bottleneck if avg time > 7 days or rejection rate > 50%
            is_bottleneck = False
            reasons = []

            if avg_time and avg_time.days > 7:
                is_bottleneck = True
                reasons.append(f'Average time: {avg_time.days} days')

            if rejection_rate > 50:
                is_bottleneck = True
                reasons.append(f'High rejection rate: {rejection_rate:.1f}%')

            if app_count > 10 and is_bottleneck:
                bottlenecks.append({
                    'stage_id': str(stage.id),
                    'stage_name': stage.name,
                    'average_time_days': avg_time.days if avg_time else None,
                    'rejection_rate': rejection_rate,
                    'application_count': app_count,
                    'reasons': reasons
                })

        return bottlenecks

    @staticmethod
    @transaction.atomic
    def reorder_stages(
        pipeline: Pipeline,
        stage_order: List[str]
    ) -> ServiceResult:
        """
        Reorder stages in a pipeline.

        Args:
            pipeline: The pipeline to reorder
            stage_order: List of stage IDs in desired order

        Returns:
            ServiceResult indicating success/failure
        """
        try:
            for index, stage_id in enumerate(stage_order):
                PipelineStage.objects.filter(
                    pipeline=pipeline,
                    id=stage_id
                ).update(order=index)

            return ServiceResult(
                success=True,
                message=_('Stages reordered successfully.'),
                data={'stage_order': stage_order}
            )
        except Exception as e:
            # Log the full exception for debugging, but return generic message to client
            logger.exception(f"Error reordering stages: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to reorder stages. Please try again or contact support.'),
                errors={'reorder': _('An unexpected error occurred.')}
            )

    @staticmethod
    @transaction.atomic
    def clone_pipeline(
        pipeline: Pipeline,
        new_name: str = None,
        user=None
    ) -> ServiceResult:
        """
        Clone a pipeline with all its stages.

        Args:
            pipeline: The pipeline to clone
            new_name: Name for the new pipeline
            user: User creating the clone

        Returns:
            ServiceResult with the cloned pipeline
        """
        try:
            new_pipeline = pipeline.clone(new_name=new_name, created_by=user)

            logger.info(
                f"Pipeline cloned: {pipeline.name} -> {new_pipeline.name}"
            )

            return ServiceResult(
                success=True,
                message=_('Pipeline cloned successfully.'),
                data=new_pipeline
            )
        except Exception as e:
            # Log the full exception for debugging, but return generic message to client
            logger.exception(f"Error cloning pipeline: {e}")
            return ServiceResult(
                success=False,
                message=_('Failed to clone pipeline. Please try again or contact support.'),
                errors={'clone': _('An unexpected error occurred.')}
            )

    @staticmethod
    def get_funnel_metrics(
        pipeline: Pipeline,
        job: JobPosting = None,
        date_from=None,
        date_to=None
    ) -> Dict[str, Any]:
        """
        Get funnel metrics for a pipeline.

        Shows how applications move through stages and where they drop off.

        Args:
            pipeline: The pipeline
            job: Optional specific job to filter by
            date_from: Start date filter
            date_to: End date filter

        Returns:
            Funnel metrics dictionary
        """
        # Optimized query with select_related for job data
        applications = Application.objects.filter(
            job__pipeline=pipeline
        ).select_related('current_stage', 'job')

        if job:
            applications = applications.filter(job=job)
        if date_from:
            applications = applications.filter(applied_at__gte=date_from)
        if date_to:
            applications = applications.filter(applied_at__lte=date_to)

        total = applications.count()
        funnel = []

        # Prefetch stages for efficiency
        stages = pipeline.stages.filter(is_active=True).order_by('order').prefetch_related('applications')
        for stage in stages:
            # Count applications that reached this stage
            reached = ApplicationActivity.objects.filter(
                application__in=applications,
                activity_type='stage_change',
                new_value=stage.name
            ).values('application').distinct().count()

            # Count currently in this stage
            current = applications.filter(current_stage=stage).count()

            # Calculate conversion from previous stage
            prev_stage_count = funnel[-1]['reached'] if funnel else total
            conversion = (reached / prev_stage_count * 100) if prev_stage_count > 0 else 0

            funnel.append({
                'stage_name': stage.name,
                'stage_type': stage.stage_type,
                'reached': reached,
                'current': current,
                'conversion_rate': round(conversion, 2),
                'drop_off_rate': round(100 - conversion, 2)
            })

        return {
            'total_applications': total,
            'funnel': funnel,
            'overall_conversion': (
                funnel[-1]['reached'] / total * 100
            ) if total > 0 and funnel else 0
        }
