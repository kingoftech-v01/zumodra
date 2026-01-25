"""
GDPR/Privacy Compliance Celery Tasks for Zumodra ATS/HR Platform

This module provides Celery tasks for automated GDPR compliance:
- process_data_subject_requests: Daily DSR processing
- apply_data_retention: Nightly data cleanup
- send_consent_renewal_reminders: Before consent expiry
- audit_data_processing_compliance: Weekly compliance checks

All tasks are tenant-aware and maintain audit trails.
"""

import logging
from datetime import timedelta
from typing import Dict, Any, List, Optional

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.db import transaction
from django.template.loader import render_to_string
from django.utils import timezone

from tenants.models import Tenant

logger = logging.getLogger(__name__)
User = get_user_model()


@shared_task(
    bind=True,
    name='privacy.process_data_subject_requests',
    max_retries=3,
    default_retry_delay=300,
)
def process_data_subject_requests(self) -> Dict[str, Any]:
    """
    Process pending Data Subject Requests daily.

    This task:
    - Processes verified access/portability requests
    - Generates data exports for completed requests
    - Sends notifications for overdue requests
    - Updates request statuses

    Returns:
        Dictionary with processing results.
    """
    from core.privacy.models import DataSubjectRequest, PrivacyAuditLog
    from core.privacy.exporters import DataExportRequest

    results = {
        'processed': 0,
        'exports_generated': 0,
        'notifications_sent': 0,
        'errors': [],
    }

    try:
        # Process each tenant
        for tenant in Tenant.objects.filter(status='active'):
            tenant_results = _process_tenant_dsrs(tenant)
            results['processed'] += tenant_results.get('processed', 0)
            results['exports_generated'] += tenant_results.get('exports_generated', 0)
            results['notifications_sent'] += tenant_results.get('notifications_sent', 0)
            results['errors'].extend(tenant_results.get('errors', []))

        logger.info(f"DSR processing completed: {results}")

    except Exception as e:
        logger.exception(f"Error in DSR processing task: {e}")
        results['errors'].append(str(e))
        raise self.retry(exc=e)

    return results


def _process_tenant_dsrs(tenant: Tenant) -> Dict[str, Any]:
    """Process DSRs for a specific tenant."""
    from core.privacy.models import DataSubjectRequest
    from core.privacy.exporters import DataExportRequest

    results = {
        'processed': 0,
        'exports_generated': 0,
        'notifications_sent': 0,
        'errors': [],
    }

    # Get verified requests ready for processing
    pending_requests = DataSubjectRequest.objects.filter(
        tenant=tenant,
        status=DataSubjectRequest.RequestStatus.VERIFIED,
    )

    for dsr in pending_requests:
        try:
            if dsr.request_type in [
                DataSubjectRequest.RequestType.ACCESS,
                DataSubjectRequest.RequestType.PORTABILITY,
            ]:
                # Generate data export
                if dsr.user:
                    export_request = DataExportRequest(dsr)
                    export_result = export_request.process(
                        format='json',
                        include_formats=['json', 'csv'],
                    )
                    if export_result['success']:
                        results['exports_generated'] += 1
                        # Send notification to user
                        _send_dsr_completion_notification(dsr)
                        results['notifications_sent'] += 1
                    else:
                        results['errors'].append(
                            f"Export failed for DSR {dsr.uuid}: {export_result.get('error')}"
                        )

            results['processed'] += 1

        except Exception as e:
            logger.exception(f"Error processing DSR {dsr.uuid}")
            results['errors'].append(f"DSR {dsr.uuid}: {str(e)}")

    # Check for overdue requests and send notifications
    overdue_requests = DataSubjectRequest.objects.filter(
        tenant=tenant,
        status__in=[
            DataSubjectRequest.RequestStatus.PENDING,
            DataSubjectRequest.RequestStatus.VERIFIED,
            DataSubjectRequest.RequestStatus.IN_PROGRESS,
        ],
        due_date__lt=timezone.now(),
    )

    for dsr in overdue_requests:
        _send_overdue_notification(dsr, tenant)
        results['notifications_sent'] += 1

    return results


def _send_dsr_completion_notification(dsr) -> None:
    """Send notification when a DSR is completed."""
    if not dsr.user or not dsr.user.email:
        return

    try:
        subject = f"Your Data Request ({dsr.get_request_type_display()}) is Complete"
        context = {
            'user': dsr.user,
            'request': dsr,
            'request_type': dsr.get_request_type_display(),
        }

        html_message = render_to_string(
            'privacy/emails/dsr_completed.html',
            context
        )
        text_message = render_to_string(
            'privacy/emails/dsr_completed.txt',
            context
        )

        send_mail(
            subject=subject,
            message=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[dsr.user.email],
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"DSR completion notification sent for {dsr.uuid}")

    except Exception as e:
        logger.exception(f"Failed to send DSR notification: {e}")


def _send_overdue_notification(dsr, tenant: Tenant) -> None:
    """Send notification for overdue DSR to admins."""
    # Get tenant admins or privacy officers
    try:
        # Send to tenant owner/admins
        admin_emails = [tenant.owner_email] if tenant.owner_email else []

        if admin_emails:
            subject = f"URGENT: Overdue Data Subject Request - {dsr.uuid.hex[:8]}"
            context = {
                'request': dsr,
                'tenant': tenant,
                'days_overdue': (timezone.now() - dsr.due_date).days,
            }

            html_message = render_to_string(
                'privacy/emails/dsr_overdue.html',
                context
            )

            send_mail(
                subject=subject,
                message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                html_message=html_message,
                fail_silently=True,
            )

    except Exception as e:
        logger.warning(f"Failed to send overdue notification: {e}")


@shared_task(
    bind=True,
    name='privacy.apply_data_retention',
    max_retries=3,
    default_retry_delay=600,
)
def apply_data_retention(self, dry_run: bool = False) -> Dict[str, Any]:
    """
    Apply data retention policies nightly.

    This task:
    - Finds data past retention period
    - Applies configured deletion strategy (delete, anonymize, archive)
    - Respects legal holds
    - Logs all retention actions

    Args:
        dry_run: If True, only report what would be done.

    Returns:
        Dictionary with retention results.
    """
    from core.privacy.services import DataRetentionService

    results = {
        'tenants_processed': 0,
        'policies_applied': 0,
        'records_affected': 0,
        'errors': [],
    }

    try:
        for tenant in Tenant.objects.filter(status='active'):
            try:
                retention_service = DataRetentionService(tenant)
                tenant_results = retention_service.apply_retention_policies(
                    dry_run=dry_run
                )

                results['tenants_processed'] += 1
                results['policies_applied'] += tenant_results.get('policies_executed', 0)
                results['records_affected'] += tenant_results.get('total_records_affected', 0)

                # Log any errors from this tenant
                for detail in tenant_results.get('details', []):
                    if detail.get('status') == 'error':
                        results['errors'].append(
                            f"Tenant {tenant.name}: {detail.get('error')}"
                        )

            except Exception as e:
                logger.exception(f"Error processing retention for tenant {tenant.id}")
                results['errors'].append(f"Tenant {tenant.name}: {str(e)}")

        logger.info(f"Data retention completed: {results}")

    except Exception as e:
        logger.exception(f"Error in data retention task: {e}")
        results['errors'].append(str(e))
        raise self.retry(exc=e)

    return results


@shared_task(
    bind=True,
    name='privacy.send_consent_renewal_reminders',
    max_retries=3,
    default_retry_delay=300,
)
def send_consent_renewal_reminders(
    self,
    days_before_expiry: int = 14
) -> Dict[str, Any]:
    """
    Send reminders for consents expiring soon.

    This task:
    - Finds consents expiring within specified days
    - Sends renewal reminder emails
    - Updates consent records with reminder status

    Args:
        days_before_expiry: Days before expiry to send reminder.

    Returns:
        Dictionary with reminder results.
    """
    from core.privacy.models import ConsentRecord

    results = {
        'reminders_sent': 0,
        'users_notified': 0,
        'errors': [],
    }

    expiry_threshold = timezone.now() + timedelta(days=days_before_expiry)

    try:
        for tenant in Tenant.objects.filter(status='active'):
            # Find expiring consents
            expiring_consents = ConsentRecord.objects.filter(
                tenant=tenant,
                granted=True,
                withdrawn=False,
                expires_at__isnull=False,
                expires_at__lte=expiry_threshold,
                expires_at__gt=timezone.now(),
            ).select_related('user')

            # Group by user
            users_consents = {}
            for consent in expiring_consents:
                if consent.user_id not in users_consents:
                    users_consents[consent.user_id] = {
                        'user': consent.user,
                        'consents': []
                    }
                users_consents[consent.user_id]['consents'].append(consent)

            # Send one email per user
            for user_id, data in users_consents.items():
                try:
                    _send_consent_renewal_email(
                        user=data['user'],
                        consents=data['consents'],
                        tenant=tenant,
                    )
                    results['reminders_sent'] += len(data['consents'])
                    results['users_notified'] += 1

                except Exception as e:
                    logger.warning(f"Failed to send consent reminder to user {user_id}: {e}")
                    results['errors'].append(f"User {user_id}: {str(e)}")

        logger.info(f"Consent renewal reminders sent: {results}")

    except Exception as e:
        logger.exception(f"Error in consent renewal task: {e}")
        results['errors'].append(str(e))
        raise self.retry(exc=e)

    return results


def _send_consent_renewal_email(user, consents: list, tenant: Tenant) -> None:
    """Send consent renewal reminder email."""
    if not user or not user.email:
        return

    subject = f"Action Required: Review Your Privacy Consents - {tenant.name}"
    context = {
        'user': user,
        'consents': consents,
        'tenant': tenant,
        'renewal_url': f"https://{tenant.domains.filter(is_primary=True).first().domain if tenant.domains.exists() else ''}/privacy/dashboard/",
    }

    html_message = render_to_string(
        'privacy/emails/consent_renewal.html',
        context
    )
    text_message = render_to_string(
        'privacy/emails/consent_renewal.txt',
        context
    )

    send_mail(
        subject=subject,
        message=text_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
        fail_silently=False,
    )


@shared_task(
    bind=True,
    name='privacy.audit_data_processing_compliance',
    max_retries=2,
    default_retry_delay=600,
)
def audit_data_processing_compliance(self) -> Dict[str, Any]:
    """
    Perform weekly compliance audit.

    This task:
    - Checks for processing without valid consent
    - Identifies data access anomalies
    - Verifies retention policy compliance
    - Generates compliance report

    Returns:
        Dictionary with audit results.
    """
    from core.privacy.models import (
        ConsentRecord,
        DataProcessingPurpose,
        DataSubjectRequest,
        PrivacyAuditLog,
    )

    results = {
        'tenants_audited': 0,
        'issues_found': 0,
        'reports_generated': 0,
        'findings': [],
    }

    try:
        for tenant in Tenant.objects.filter(status='active'):
            tenant_findings = _audit_tenant_compliance(tenant)
            results['tenants_audited'] += 1
            results['issues_found'] += len(tenant_findings)
            results['findings'].extend(tenant_findings)

            # Log the audit
            PrivacyAuditLog.objects.create(
                tenant=tenant,
                action='compliance_audit',
                description=f"Weekly compliance audit completed",
                context={
                    'findings_count': len(tenant_findings),
                    'findings': tenant_findings[:10],  # Store first 10 findings
                },
            )

            # Send report if issues found
            if tenant_findings:
                _send_compliance_report(tenant, tenant_findings)
                results['reports_generated'] += 1

        logger.info(f"Compliance audit completed: {results}")

    except Exception as e:
        logger.exception(f"Error in compliance audit task: {e}")
        results['errors'] = [str(e)]
        raise self.retry(exc=e)

    return results


def _audit_tenant_compliance(tenant: Tenant) -> List[Dict[str, Any]]:
    """Perform compliance audit for a tenant."""
    from core.privacy.models import (
        ConsentRecord,
        DataSubjectRequest,
        DataRetentionPolicy,
    )
    from tenant_profiles.models import DataAccessLog

    findings = []

    # Check 1: Overdue DSRs
    overdue_dsrs = DataSubjectRequest.objects.filter(
        tenant=tenant,
        status__in=[
            DataSubjectRequest.RequestStatus.PENDING,
            DataSubjectRequest.RequestStatus.VERIFIED,
            DataSubjectRequest.RequestStatus.IN_PROGRESS,
        ],
        due_date__lt=timezone.now(),
    ).count()

    if overdue_dsrs > 0:
        findings.append({
            'type': 'overdue_dsr',
            'severity': 'high',
            'message': f"{overdue_dsrs} Data Subject Request(s) are overdue",
            'recommendation': 'Process these requests immediately to avoid GDPR violations',
        })

    # Check 2: Expired consents still active
    expired_consents = ConsentRecord.objects.filter(
        tenant=tenant,
        granted=True,
        withdrawn=False,
        expires_at__lt=timezone.now(),
    ).count()

    if expired_consents > 0:
        findings.append({
            'type': 'expired_consents',
            'severity': 'medium',
            'message': f"{expired_consents} consent(s) have expired but are still marked active",
            'recommendation': 'Update expired consents and request renewal from users',
        })

    # Check 3: Retention policies not executed recently
    stale_policies = DataRetentionPolicy.objects.filter(
        tenant=tenant,
        is_enabled=True,
        legal_hold_enabled=False,
    ).filter(
        models.Q(last_executed_at__isnull=True) |
        models.Q(last_executed_at__lt=timezone.now() - timedelta(days=7))
    ).count()

    if stale_policies > 0:
        findings.append({
            'type': 'stale_retention',
            'severity': 'medium',
            'message': f"{stale_policies} retention policy(ies) haven't been executed in 7+ days",
            'recommendation': 'Check retention task execution and fix any errors',
        })

    # Check 4: High volume data access patterns (potential anomaly)
    one_day_ago = timezone.now() - timedelta(days=1)
    try:
        high_access_users = DataAccessLog.objects.filter(
            accessor_tenant=tenant,
            accessed_at__gte=one_day_ago,
        ).values('accessor').annotate(
            access_count=models.Count('id')
        ).filter(access_count__gt=100)

        if high_access_users.exists():
            findings.append({
                'type': 'unusual_access',
                'severity': 'medium',
                'message': f"{len(high_access_users)} user(s) with unusually high data access",
                'recommendation': 'Review these access patterns for potential data breaches',
            })
    except Exception:
        pass  # DataAccessLog might not exist in all setups

    # Check 5: Missing privacy policy
    from core.privacy.models import PrivacyPolicy
    has_current_policy = PrivacyPolicy.objects.filter(
        tenant=tenant,
        is_current=True,
        is_published=True,
    ).exists()

    if not has_current_policy:
        findings.append({
            'type': 'missing_policy',
            'severity': 'high',
            'message': 'No current published privacy policy found',
            'recommendation': 'Publish a privacy policy immediately',
        })

    return findings


def _send_compliance_report(tenant: Tenant, findings: List[Dict]) -> None:
    """Send compliance report to tenant admins."""
    try:
        admin_emails = [tenant.owner_email] if tenant.owner_email else []

        if admin_emails:
            subject = f"Privacy Compliance Report - {tenant.name}"
            context = {
                'tenant': tenant,
                'findings': findings,
                'report_date': timezone.now(),
                'high_severity': [f for f in findings if f.get('severity') == 'high'],
                'medium_severity': [f for f in findings if f.get('severity') == 'medium'],
            }

            html_message = render_to_string(
                'privacy/emails/compliance_report.html',
                context
            )

            send_mail(
                subject=subject,
                message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                html_message=html_message,
                fail_silently=True,
            )

    except Exception as e:
        logger.warning(f"Failed to send compliance report: {e}")


@shared_task(
    bind=True,
    name='privacy.process_single_dsr',
    max_retries=3,
    default_retry_delay=60,
)
def process_single_dsr(
    self,
    dsr_id: str,
    processor_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Process a single DSR asynchronously.

    Args:
        dsr_id: UUID of the DSR to process.
        processor_id: User ID of the processor (optional).

    Returns:
        Dictionary with processing result.
    """
    from core.privacy.models import DataSubjectRequest
    from core.privacy.exporters import DataExportRequest
    from core.privacy.services import AnonymizationService

    try:
        dsr = DataSubjectRequest.objects.get(id=dsr_id)

        if dsr.request_type == DataSubjectRequest.RequestType.ACCESS:
            # Generate data export
            export_request = DataExportRequest(dsr)
            result = export_request.process(
                format='json',
                include_formats=['json', 'csv'],
            )
            _send_dsr_completion_notification(dsr)
            return result

        elif dsr.request_type == DataSubjectRequest.RequestType.PORTABILITY:
            # Generate portable export
            export_request = DataExportRequest(dsr)
            result = export_request.process(
                format=dsr.response_data.get('export_format', 'json'),
                include_formats=['json', 'csv', 'xml'],
            )
            _send_dsr_completion_notification(dsr)
            return result

        elif dsr.request_type == DataSubjectRequest.RequestType.ERASURE:
            # Anonymize user data
            if dsr.user:
                anonymization_service = AnonymizationService(dsr.tenant)
                result = anonymization_service.anonymize_user(
                    dsr.user,
                    delete_account=True,
                )
                dsr.status = DataSubjectRequest.RequestStatus.COMPLETED
                dsr.completed_at = timezone.now()
                dsr.response_data = result
                dsr.save()
                _send_dsr_completion_notification(dsr)
                return {'success': True, 'result': result}

        return {'success': False, 'error': 'Unsupported request type'}

    except DataSubjectRequest.DoesNotExist:
        logger.error(f"DSR not found: {dsr_id}")
        return {'success': False, 'error': 'Request not found'}

    except Exception as e:
        logger.exception(f"Error processing DSR {dsr_id}")
        raise self.retry(exc=e)


@shared_task(name='privacy.cleanup_expired_exports')
def cleanup_expired_exports(days_old: int = 30) -> Dict[str, Any]:
    """
    Clean up old data export files.

    Args:
        days_old: Delete exports older than this many days.

    Returns:
        Dictionary with cleanup results.
    """
    from core.privacy.models import DataSubjectRequest
    from django.core.files.storage import default_storage

    results = {
        'files_deleted': 0,
        'space_freed_bytes': 0,
        'errors': [],
    }

    cutoff = timezone.now() - timedelta(days=days_old)

    old_exports = DataSubjectRequest.objects.filter(
        status=DataSubjectRequest.RequestStatus.COMPLETED,
        completed_at__lt=cutoff,
        response_file__isnull=False,
    ).exclude(response_file='')

    for dsr in old_exports:
        try:
            if dsr.response_file:
                file_path = dsr.response_file.name
                if default_storage.exists(file_path):
                    file_size = default_storage.size(file_path)
                    default_storage.delete(file_path)
                    results['files_deleted'] += 1
                    results['space_freed_bytes'] += file_size

                # Clear the file reference
                dsr.response_file = ''
                dsr.save(update_fields=['response_file'])

        except Exception as e:
            results['errors'].append(f"DSR {dsr.uuid}: {str(e)}")

    logger.info(f"Export cleanup completed: {results}")
    return results


# Import models here to avoid circular imports
from django.db import models
