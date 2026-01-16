"""
Background Check Service

Handles pre-employment screening through third-party providers
(Checkr, Sterling, HireRight).

This service provides a unified interface for:
- Initiating background checks
- Processing webhook results
- Retrieving reports
- Managing check status
"""
import logging
from typing import Dict, Any, Optional

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from .models import Application, BackgroundCheck, BackgroundCheckDocument
from integrations.models import Integration
from integrations.providers.background_check import CheckrProvider, SterlingProvider

logger = logging.getLogger(__name__)


class BackgroundCheckService:
    """
    Service for managing background checks.

    Integrates with background check providers (Checkr, Sterling, HireRight)
    to conduct pre-employment screening.

    Usage:
        service = BackgroundCheckService(tenant=request.tenant)

        # Initiate a check
        bg_check = service.initiate_check(
            application=application,
            package='standard',
            initiated_by=request.user
        )

        # Process webhook result
        service.handle_webhook_result(report_id, payload)

        # Get report
        report = service.get_report(bg_check.id)
    """

    def __init__(self, tenant):
        """
        Initialize service for a specific tenant.

        Args:
            tenant: Tenant instance
        """
        self.tenant = tenant
        self._provider_instance = None

    def _get_provider(self, provider_name: Optional[str] = None):
        """
        Get configured background check provider for tenant.

        Args:
            provider_name: Specific provider to use ('checkr', 'sterling', 'hireright')
                          If None, uses tenant's default provider

        Returns:
            Provider instance (CheckrProvider or SterlingProvider)

        Raises:
            ValueError: If no provider is configured
        """
        if self._provider_instance:
            return self._provider_instance

        # Get provider name from settings or parameter
        provider_name = provider_name or getattr(
            settings, 'DEFAULT_BACKGROUND_CHECK_PROVIDER', 'checkr'
        )

        try:
            # Get integration for this provider
            integration = Integration.objects.get(
                tenant=self.tenant,
                provider_name=provider_name,
                is_active=True
            )

            # Instantiate appropriate provider
            if provider_name == 'checkr':
                self._provider_instance = CheckrProvider(integration)
            elif provider_name == 'sterling':
                self._provider_instance = SterlingProvider(integration)
            else:
                raise ValueError(f"Unsupported provider: {provider_name}")

            return self._provider_instance

        except Integration.DoesNotExist:
            raise ValueError(
                f"No active {provider_name} integration found for tenant {self.tenant}"
            )

    @transaction.atomic
    def initiate_check(
        self,
        application: Application,
        package: str = 'standard',
        initiated_by: Optional[Any] = None,
        provider_name: Optional[str] = None
    ) -> BackgroundCheck:
        """
        Initiate background check for a candidate.

        Args:
            application: Application instance
            package: Screening package ('basic', 'standard', 'pro', 'comprehensive')
            initiated_by: User who initiated the check
            provider_name: Specific provider to use (optional)

        Returns:
            BackgroundCheck instance

        Raises:
            PermissionDenied: If background checks not enabled for tenant
            ValueError: If provider not configured
        """
        # 1. Check feature flag
        if not self.tenant.plan.feature_background_checks:
            raise PermissionDenied("Background checks are not enabled for your plan")

        # 2. Check if already exists
        existing_check = BackgroundCheck.objects.filter(
            tenant=self.tenant,
            application=application
        ).first()

        if existing_check and existing_check.is_in_progress():
            logger.warning(
                f"Background check already in progress for application {application.id}"
            )
            return existing_check

        # 3. Get provider
        provider = self._get_provider(provider_name)
        provider_name = provider_name or 'checkr'

        # 4. Create candidate in provider system
        candidate_data = {
            'first_name': application.candidate.first_name,
            'last_name': application.candidate.last_name,
            'email': application.candidate.email,
            'phone': application.candidate.phone or '',
            'dob': getattr(application.candidate, 'date_of_birth', None),
            'ssn': getattr(application.candidate, 'ssn_last_4', None),
            'zipcode': getattr(application.candidate, 'zipcode', ''),
        }

        try:
            provider_candidate = provider.create_candidate(candidate_data)
        except Exception as e:
            logger.error(f"Failed to create candidate in {provider_name}: {e}")
            raise

        # 5. Create background check record
        background_check = BackgroundCheck.objects.create(
            tenant=self.tenant,
            application=application,
            provider=provider_name,
            external_candidate_id=provider_candidate.get('id', ''),
            package=package,
            status='pending',
            initiated_by=initiated_by,
        )

        # 6. Send invitation to candidate
        try:
            invitation = provider.create_invitation(
                candidate_id=provider_candidate['id'],
                package=package
            )

            background_check.external_report_id = invitation.get('report_id', '')
            background_check.status = 'invited'
            background_check.save(update_fields=['external_report_id', 'status', 'updated_at'])

        except Exception as e:
            logger.error(f"Failed to create invitation: {e}")
            background_check.status = 'failed'
            background_check.notes = f"Failed to send invitation: {str(e)}"
            background_check.save(update_fields=['status', 'notes', 'updated_at'])
            raise

        # 7. Update application status
        application.status = Application.ApplicationStatus.BACKGROUND_CHECK_IN_PROGRESS
        application.save(update_fields=['status', 'updated_at'])

        # 8. Send notification to candidate
        try:
            from notifications.services import notification_service
            notification_service.send_notification(
                recipient=application.candidate.user,
                notification_type='background_check_initiated',
                title='Background Check Initiated',
                message=(
                    f'A background check has been initiated for your application '
                    f'to {application.job.title}. You will receive an email with '
                    f'instructions to complete the process.'
                ),
                channels=['email', 'in_app'],
                action_url=f'/applications/{application.uuid}/',
                context={
                    'application_id': application.id,
                    'job_title': application.job.title,
                    'package': package,
                }
            )
        except Exception as e:
            logger.warning(f"Failed to send notification: {e}")

        logger.info(
            f"Background check initiated for application {application.id}, "
            f"check_id={background_check.id}, provider={provider_name}"
        )

        return background_check

    @transaction.atomic
    def handle_webhook_result(
        self,
        report_id: str,
        payload: Dict[str, Any],
        provider_name: Optional[str] = None
    ):
        """
        Process webhook when check completes.

        Args:
            report_id: External report ID from provider
            payload: Full payload from provider webhook
            provider_name: Provider that sent the webhook

        Raises:
            BackgroundCheck.DoesNotExist: If check not found
        """
        try:
            # Find background check by report ID
            background_check = BackgroundCheck.objects.get(
                external_report_id=report_id
            )

            # Extract result from payload
            result = self._extract_result_from_payload(payload, provider_name or background_check.provider)

            # Update background check
            background_check.status = 'completed'
            background_check.result = result['result']
            background_check.completed_at = timezone.now()
            background_check.report_data = payload
            background_check.report_url = result.get('report_url', '')
            background_check.save(update_fields=[
                'status', 'result', 'completed_at', 'report_data', 'report_url', 'updated_at'
            ])

            # Create documents for individual screenings
            for document_data in result.get('documents', []):
                BackgroundCheckDocument.objects.create(
                    tenant=background_check.tenant,
                    background_check=background_check,
                    document_type=document_data.get('type', 'other'),
                    status='completed',
                    result=document_data.get('result', ''),
                    document_data=document_data,
                    findings_summary=document_data.get('summary', ''),
                )

            # Update application status
            application = background_check.application
            if background_check.result == 'clear':
                application.status = Application.ApplicationStatus.BACKGROUND_CHECK_CLEARED
            else:
                application.status = Application.ApplicationStatus.BACKGROUND_CHECK_FAILED
            application.save(update_fields=['status', 'updated_at'])

            # Send notification to recruiter/hiring manager
            try:
                from notifications.services import notification_service
                notification_service.send_notification(
                    recipient=application.created_by or application.job.created_by,
                    notification_type='background_check_completed',
                    title=f'Background Check {result["result"].title()}',
                    message=(
                        f'Background check for {application.candidate} '
                        f'has completed with result: {result["result"].upper()}'
                    ),
                    channels=['email', 'in_app'],
                    action_url=f'/applications/{application.uuid}/background-check/',
                    context={
                        'application_id': application.id,
                        'candidate_name': str(application.candidate),
                        'result': result['result'],
                        'job_title': application.job.title,
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to send notification: {e}")

            logger.info(
                f"Background check completed: check_id={background_check.id}, "
                f"result={background_check.result}"
            )

        except BackgroundCheck.DoesNotExist:
            logger.error(f"Background check not found for report_id={report_id}")
            raise

        except Exception as e:
            logger.error(f"Error processing webhook for report_id={report_id}: {e}")
            raise

    def _extract_result_from_payload(
        self,
        payload: Dict[str, Any],
        provider_name: str
    ) -> Dict[str, Any]:
        """
        Extract standardized result from provider-specific payload.

        Args:
            payload: Webhook payload from provider
            provider_name: Provider name ('checkr', 'sterling')

        Returns:
            Dict with 'result', 'report_url', and 'documents'
        """
        if provider_name == 'checkr':
            # Checkr-specific extraction
            data = payload.get('data', {}).get('object', {})
            result_status = data.get('status', '').lower()

            # Map Checkr status to our result
            if result_status == 'clear':
                result = 'clear'
            elif result_status == 'consider':
                result = 'consider'
            else:
                result = 'suspended'

            return {
                'result': result,
                'report_url': data.get('report_url', ''),
                'documents': data.get('screenings', []),
            }

        elif provider_name == 'sterling':
            # Sterling-specific extraction
            data = payload.get('screening', {})
            result_status = data.get('status', '').lower()

            # Map Sterling status to our result
            if result_status in ['complete', 'clear']:
                result = 'clear'
            elif result_status == 'review':
                result = 'consider'
            else:
                result = 'suspended'

            return {
                'result': result,
                'report_url': data.get('report_url', ''),
                'documents': data.get('components', []),
            }

        else:
            # Generic extraction
            return {
                'result': payload.get('result', 'consider'),
                'report_url': payload.get('report_url', ''),
                'documents': [],
            }

    def get_report(self, background_check_id: int) -> Dict[str, Any]:
        """
        Retrieve full report from provider.

        Args:
            background_check_id: ID of BackgroundCheck instance

        Returns:
            Full report data from provider

        Raises:
            BackgroundCheck.DoesNotExist: If check not found
        """
        background_check = BackgroundCheck.objects.get(
            id=background_check_id,
            tenant=self.tenant
        )

        if not background_check.is_complete():
            return {
                'status': 'pending',
                'message': 'Background check is not yet complete'
            }

        # Get provider
        provider = self._get_provider(background_check.provider)

        try:
            # Fetch report from provider
            report = provider.get_report(background_check.external_report_id)
            return report

        except Exception as e:
            logger.error(f"Failed to retrieve report: {e}")
            # Return cached data if API call fails
            return background_check.report_data or {
                'error': 'Unable to retrieve report from provider'
            }

    def get_status(self, background_check_id: int) -> Dict[str, Any]:
        """
        Get current status of background check.

        Args:
            background_check_id: ID of BackgroundCheck instance

        Returns:
            Dict with status information
        """
        background_check = BackgroundCheck.objects.select_related(
            'application__candidate',
            'application__job'
        ).prefetch_related('documents').get(
            id=background_check_id,
            tenant=self.tenant
        )

        return {
            'id': background_check.id,
            'status': background_check.status,
            'result': background_check.result,
            'provider': background_check.provider,
            'package': background_check.package,
            'initiated_at': background_check.initiated_at.isoformat(),
            'completed_at': background_check.completed_at.isoformat() if background_check.completed_at else None,
            'report_url': background_check.report_url,
            'documents': [
                {
                    'type': doc.document_type,
                    'status': doc.status,
                    'result': doc.result,
                    'summary': doc.findings_summary,
                }
                for doc in background_check.documents.all()
            ],
            'application': {
                'id': background_check.application.id,
                'candidate': str(background_check.application.candidate),
                'job': background_check.application.job.title,
            }
        }

    def cancel_check(self, background_check_id: int, reason: str = '') -> bool:
        """
        Cancel an in-progress background check.

        Args:
            background_check_id: ID of BackgroundCheck instance
            reason: Reason for cancellation

        Returns:
            True if cancelled successfully

        Raises:
            ValueError: If check cannot be cancelled
        """
        background_check = BackgroundCheck.objects.get(
            id=background_check_id,
            tenant=self.tenant
        )

        if not background_check.is_in_progress():
            raise ValueError("Background check is not in progress and cannot be cancelled")

        # Update status
        background_check.status = 'cancelled'
        background_check.notes = f"Cancelled: {reason}"
        background_check.save(update_fields=['status', 'notes', 'updated_at'])

        # Revert application status
        background_check.application.status = Application.ApplicationStatus.OFFER_EXTENDED
        background_check.application.save(update_fields=['status', 'updated_at'])

        logger.info(f"Background check cancelled: check_id={background_check_id}, reason={reason}")

        return True


__all__ = ['BackgroundCheckService']
