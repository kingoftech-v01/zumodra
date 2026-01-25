"""
GDPR/Privacy Compliance Services for Zumodra ATS/HR Platform

This module provides service classes for GDPR compliance:
- ConsentService: Manage user consents with versioning
- DataSubjectRequestService: Process DSR requests
- DataRetentionService: Apply retention policies
- AnonymizationService: Anonymize/pseudonymize user data

All services are tenant-aware and maintain audit trails.
"""

import uuid
import hashlib
import secrets
import logging
from typing import Optional, List, Dict, Any, Type, Tuple
from datetime import datetime, timedelta

from django.db import models, transaction
from django.db.models import Q
from django.conf import settings
from django.apps import apps
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError, PermissionDenied

from core.privacy.models import (
    ConsentRecord,
    DataProcessingPurpose,
    DataSubjectRequest,
    DataRetentionPolicy,
    PrivacyPolicy,
    PrivacyAuditLog,
)

logger = logging.getLogger(__name__)
User = get_user_model()


class ConsentService:
    """
    Service for managing user consents.

    Provides methods for:
    - Recording new consents
    - Withdrawing consents
    - Checking consent status
    - Getting consent history
    - Versioning consent texts
    """

    def __init__(self, tenant):
        """
        Initialize consent service for a tenant.

        Args:
            tenant: The tenant instance for tenant-scoped operations.
        """
        self.tenant = tenant

    def record_consent(
        self,
        user,
        consent_type: str,
        granted: bool,
        consent_text: str,
        consent_text_version: str,
        ip_address: Optional[str] = None,
        user_agent: str = '',
        collection_method: str = 'web_form',
        purpose: Optional[DataProcessingPurpose] = None,
        privacy_policy: Optional[PrivacyPolicy] = None,
        expires_at: Optional[datetime] = None,
    ) -> ConsentRecord:
        """
        Record a consent decision from a user.

        Args:
            user: The user giving consent.
            consent_type: Type of consent (from ConsentRecord.ConsentType).
            granted: Whether consent was granted.
            consent_text: The exact text shown to the user.
            consent_text_version: Version identifier for the consent text.
            ip_address: IP address of the request.
            user_agent: User agent string.
            collection_method: How consent was collected.
            purpose: Associated DataProcessingPurpose.
            privacy_policy: Associated PrivacyPolicy version.
            expires_at: When this consent expires.

        Returns:
            The created ConsentRecord instance.
        """
        with transaction.atomic():
            # Mark any existing consents for this type as historical
            existing = ConsentRecord.objects.filter(
                tenant=self.tenant,
                user=user,
                consent_type=consent_type,
                withdrawn=False,
            )

            # Only withdraw if the new consent is granted
            # (denial of consent is a separate record)
            if granted:
                for record in existing:
                    record.withdrawn = True
                    record.withdrawn_at = timezone.now()
                    record.save(update_fields=['withdrawn', 'withdrawn_at'])

            # Get current privacy policy if not provided
            if not privacy_policy:
                privacy_policy = PrivacyPolicy.objects.filter(
                    tenant=self.tenant,
                    is_current=True
                ).first()

            # Create the new consent record
            consent = ConsentRecord.objects.create(
                tenant=self.tenant,
                user=user,
                consent_type=consent_type,
                granted=granted,
                consent_text=consent_text,
                consent_text_version=consent_text_version,
                ip_address=ip_address,
                user_agent=user_agent,
                collection_method=collection_method,
                purpose=purpose,
                privacy_policy=privacy_policy,
                expires_at=expires_at,
            )

            # Log the action
            self._log_consent_action(
                action=PrivacyAuditLog.ActionType.CONSENT_GRANTED if granted
                       else PrivacyAuditLog.ActionType.CONSENT_WITHDRAWN,
                user=user,
                consent=consent,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            logger.info(
                f"Consent {'granted' if granted else 'denied'} for user {user.id}, "
                f"type: {consent_type}, version: {consent_text_version}"
            )

            return consent

    def withdraw_consent(
        self,
        user,
        consent_type: str,
        ip_address: Optional[str] = None,
        reason: str = '',
    ) -> List[ConsentRecord]:
        """
        Withdraw all active consents of a specific type for a user.

        Args:
            user: The user withdrawing consent.
            consent_type: Type of consent to withdraw.
            ip_address: IP address of the request.
            reason: Reason for withdrawal.

        Returns:
            List of withdrawn ConsentRecord instances.
        """
        withdrawn_records = []

        with transaction.atomic():
            active_consents = ConsentRecord.objects.filter(
                tenant=self.tenant,
                user=user,
                consent_type=consent_type,
                granted=True,
                withdrawn=False,
            ).select_for_update()

            for consent in active_consents:
                consent.withdrawn = True
                consent.withdrawn_at = timezone.now()
                consent.withdrawal_ip_address = ip_address
                consent.save(update_fields=[
                    'withdrawn', 'withdrawn_at', 'withdrawal_ip_address', 'updated_at'
                ])
                withdrawn_records.append(consent)

                # Log the withdrawal
                self._log_consent_action(
                    action=PrivacyAuditLog.ActionType.CONSENT_WITHDRAWN,
                    user=user,
                    consent=consent,
                    ip_address=ip_address,
                    context={'reason': reason},
                )

            logger.info(
                f"Consent withdrawn for user {user.id}, type: {consent_type}, "
                f"records affected: {len(withdrawn_records)}"
            )

        return withdrawn_records

    def check_consent(
        self,
        user,
        consent_type: str,
        purpose_code: Optional[str] = None,
    ) -> bool:
        """
        Check if a user has active consent for a specific type.

        Args:
            user: The user to check.
            consent_type: Type of consent to check.
            purpose_code: Optional purpose code to check against.

        Returns:
            True if valid consent exists, False otherwise.
        """
        query = Q(
            tenant=self.tenant,
            user=user,
            consent_type=consent_type,
            granted=True,
            withdrawn=False,
        )

        # Check expiry
        query &= Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())

        if purpose_code:
            query &= Q(purpose__code=purpose_code)

        return ConsentRecord.objects.filter(query).exists()

    def get_consent_history(
        self,
        user,
        consent_type: Optional[str] = None,
        include_withdrawn: bool = True,
    ) -> List[ConsentRecord]:
        """
        Get consent history for a user.

        Args:
            user: The user to get history for.
            consent_type: Optional filter by consent type.
            include_withdrawn: Whether to include withdrawn consents.

        Returns:
            List of ConsentRecord instances.
        """
        query = Q(tenant=self.tenant, user=user)

        if consent_type:
            query &= Q(consent_type=consent_type)

        if not include_withdrawn:
            query &= Q(withdrawn=False)

        return list(ConsentRecord.objects.filter(query).order_by('-created_at'))

    def get_active_consents(self, user) -> Dict[str, ConsentRecord]:
        """
        Get all active consents for a user.

        Args:
            user: The user to get consents for.

        Returns:
            Dictionary mapping consent type to active ConsentRecord.
        """
        active = ConsentRecord.objects.filter(
            tenant=self.tenant,
            user=user,
            granted=True,
            withdrawn=False,
        ).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
        )

        return {record.consent_type: record for record in active}

    def get_expiring_consents(self, days_ahead: int = 30) -> List[ConsentRecord]:
        """
        Get consents expiring within the specified number of days.

        Args:
            days_ahead: Number of days to look ahead.

        Returns:
            List of expiring ConsentRecord instances.
        """
        expiry_threshold = timezone.now() + timedelta(days=days_ahead)

        return list(ConsentRecord.objects.filter(
            tenant=self.tenant,
            granted=True,
            withdrawn=False,
            expires_at__isnull=False,
            expires_at__lte=expiry_threshold,
            expires_at__gt=timezone.now(),
        ).select_related('user'))

    def _log_consent_action(
        self,
        action: str,
        user,
        consent: ConsentRecord,
        ip_address: Optional[str] = None,
        user_agent: str = '',
        context: Optional[Dict] = None,
    ):
        """Log a consent-related action to the audit log."""
        PrivacyAuditLog.objects.create(
            tenant=self.tenant,
            action=action,
            description=f"{action} for consent type {consent.consent_type}",
            actor=user,
            data_subject=user,
            related_content_type=ContentType.objects.get_for_model(ConsentRecord),
            related_object_id=str(consent.id),
            ip_address=ip_address,
            user_agent=user_agent,
            context=context or {},
        )


class DataSubjectRequestService:
    """
    Service for handling GDPR Data Subject Requests.

    Provides methods for:
    - Creating access requests
    - Creating erasure requests
    - Creating rectification requests
    - Creating portability requests
    - Processing and completing requests
    """

    def __init__(self, tenant):
        """
        Initialize DSR service for a tenant.

        Args:
            tenant: The tenant instance.
        """
        self.tenant = tenant

    def create_access_request(
        self,
        user=None,
        requester_email: str = '',
        requester_name: str = '',
        description: str = '',
        data_categories: Optional[List[str]] = None,
        ip_address: Optional[str] = None,
        user_agent: str = '',
    ) -> DataSubjectRequest:
        """
        Create a data access request (GDPR Article 15).

        Args:
            user: The user making the request (if registered).
            requester_email: Email for non-registered requesters.
            requester_name: Name for non-registered requesters.
            description: Additional description.
            data_categories: Specific categories requested.
            ip_address: Submission IP.
            user_agent: User agent string.

        Returns:
            The created DataSubjectRequest.
        """
        return self._create_request(
            request_type=DataSubjectRequest.RequestType.ACCESS,
            user=user,
            requester_email=requester_email,
            requester_name=requester_name,
            description=description,
            data_categories=data_categories,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def create_erasure_request(
        self,
        user=None,
        requester_email: str = '',
        requester_name: str = '',
        description: str = '',
        data_categories: Optional[List[str]] = None,
        ip_address: Optional[str] = None,
        user_agent: str = '',
    ) -> DataSubjectRequest:
        """
        Create a data erasure request (GDPR Article 17 - Right to be Forgotten).

        Args:
            user: The user making the request.
            requester_email: Email for non-registered requesters.
            requester_name: Name for non-registered requesters.
            description: Reason/description for erasure.
            data_categories: Specific categories to erase.
            ip_address: Submission IP.
            user_agent: User agent string.

        Returns:
            The created DataSubjectRequest.
        """
        return self._create_request(
            request_type=DataSubjectRequest.RequestType.ERASURE,
            user=user,
            requester_email=requester_email,
            requester_name=requester_name,
            description=description,
            data_categories=data_categories,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def create_rectification_request(
        self,
        user=None,
        requester_email: str = '',
        requester_name: str = '',
        rectification_details: Optional[Dict[str, Any]] = None,
        description: str = '',
        ip_address: Optional[str] = None,
        user_agent: str = '',
    ) -> DataSubjectRequest:
        """
        Create a data rectification request (GDPR Article 16).

        Args:
            user: The user making the request.
            requester_email: Email for non-registered requesters.
            requester_name: Name for non-registered requesters.
            rectification_details: Dict of fields to correct and new values.
            description: Additional description.
            ip_address: Submission IP.
            user_agent: User agent string.

        Returns:
            The created DataSubjectRequest.
        """
        request = self._create_request(
            request_type=DataSubjectRequest.RequestType.RECTIFICATION,
            user=user,
            requester_email=requester_email,
            requester_name=requester_name,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        if rectification_details:
            request.rectification_details = rectification_details
            request.save(update_fields=['rectification_details'])

        return request

    def create_portability_request(
        self,
        user=None,
        requester_email: str = '',
        requester_name: str = '',
        description: str = '',
        data_categories: Optional[List[str]] = None,
        export_format: str = 'json',
        ip_address: Optional[str] = None,
        user_agent: str = '',
    ) -> DataSubjectRequest:
        """
        Create a data portability request (GDPR Article 20).

        Args:
            user: The user making the request.
            requester_email: Email for non-registered requesters.
            requester_name: Name for non-registered requesters.
            description: Additional description.
            data_categories: Specific categories to export.
            export_format: Desired export format (json, csv, xml).
            ip_address: Submission IP.
            user_agent: User agent string.

        Returns:
            The created DataSubjectRequest.
        """
        request = self._create_request(
            request_type=DataSubjectRequest.RequestType.PORTABILITY,
            user=user,
            requester_email=requester_email,
            requester_name=requester_name,
            description=description,
            data_categories=data_categories,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Store export format in response_data
        request.response_data = {'export_format': export_format}
        request.save(update_fields=['response_data'])

        return request

    def _create_request(
        self,
        request_type: str,
        user=None,
        requester_email: str = '',
        requester_name: str = '',
        description: str = '',
        data_categories: Optional[List[str]] = None,
        ip_address: Optional[str] = None,
        user_agent: str = '',
    ) -> DataSubjectRequest:
        """
        Internal method to create a DSR request.
        """
        with transaction.atomic():
            request = DataSubjectRequest.objects.create(
                tenant=self.tenant,
                user=user,
                requester_email=requester_email or (user.email if user else ''),
                requester_name=requester_name or (
                    f"{user.first_name} {user.last_name}".strip() if user else ''
                ),
                request_type=request_type,
                description=description,
                data_categories_requested=data_categories or [],
                ip_address=ip_address,
                user_agent=user_agent,
            )

            # Auto-verify if user is authenticated
            if user:
                request.identity_verified = True
                request.verification_method = 'authenticated_session'
                request.verified_at = timezone.now()
                request.status = DataSubjectRequest.RequestStatus.VERIFIED
                request.save(update_fields=[
                    'identity_verified', 'verification_method', 'verified_at', 'status'
                ])

            # Log the submission
            PrivacyAuditLog.objects.create(
                tenant=self.tenant,
                action=PrivacyAuditLog.ActionType.DSR_SUBMITTED,
                description=f"Data Subject Request submitted: {request.get_request_type_display()}",
                actor=user,
                data_subject=user,
                related_content_type=ContentType.objects.get_for_model(DataSubjectRequest),
                related_object_id=str(request.id),
                ip_address=ip_address,
                user_agent=user_agent,
                context={'request_type': request_type},
            )

            logger.info(
                f"DSR created: {request.uuid}, type: {request_type}, "
                f"user: {user.id if user else requester_email}"
            )

            return request

    def process_request(
        self,
        request: DataSubjectRequest,
        processor,
        notes: str = '',
    ) -> DataSubjectRequest:
        """
        Mark a request as in progress.

        Args:
            request: The DSR to process.
            processor: The user processing the request.
            notes: Processing notes.

        Returns:
            Updated DataSubjectRequest.
        """
        request.status = DataSubjectRequest.RequestStatus.IN_PROGRESS
        request.processed_by = processor
        request.processing_notes = notes
        request.save(update_fields=['status', 'processed_by', 'processing_notes', 'updated_at'])

        PrivacyAuditLog.objects.create(
            tenant=self.tenant,
            action=PrivacyAuditLog.ActionType.DSR_PROCESSED,
            description=f"DSR processing started: {request.uuid}",
            actor=processor,
            data_subject=request.user,
            related_content_type=ContentType.objects.get_for_model(DataSubjectRequest),
            related_object_id=str(request.id),
            context={'notes': notes},
        )

        logger.info(f"DSR processing started: {request.uuid} by {processor.id}")

        return request

    def get_request_status(self, request_uuid: str) -> Optional[DataSubjectRequest]:
        """
        Get the status of a DSR by UUID.

        Args:
            request_uuid: The UUID of the request.

        Returns:
            DataSubjectRequest instance or None.
        """
        try:
            return DataSubjectRequest.objects.get(
                tenant=self.tenant,
                uuid=request_uuid,
            )
        except DataSubjectRequest.DoesNotExist:
            return None

    def get_pending_requests(self) -> List[DataSubjectRequest]:
        """Get all pending DSRs for the tenant."""
        return list(DataSubjectRequest.objects.filter(
            tenant=self.tenant,
            status__in=[
                DataSubjectRequest.RequestStatus.PENDING,
                DataSubjectRequest.RequestStatus.VERIFIED,
                DataSubjectRequest.RequestStatus.IN_PROGRESS,
            ]
        ).order_by('due_date'))

    def get_overdue_requests(self) -> List[DataSubjectRequest]:
        """Get all overdue DSRs for the tenant."""
        return list(DataSubjectRequest.objects.filter(
            tenant=self.tenant,
            status__in=[
                DataSubjectRequest.RequestStatus.PENDING,
                DataSubjectRequest.RequestStatus.VERIFIED,
                DataSubjectRequest.RequestStatus.IN_PROGRESS,
            ],
            due_date__lt=timezone.now(),
        ).order_by('due_date'))


class DataRetentionService:
    """
    Service for applying data retention policies.

    Provides methods for:
    - Applying retention policies
    - Getting retention schedules
    - Exempting records from retention
    - Legal hold management
    """

    def __init__(self, tenant):
        """
        Initialize retention service for a tenant.

        Args:
            tenant: The tenant instance.
        """
        self.tenant = tenant

    def apply_retention_policies(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Apply all enabled retention policies.

        Args:
            dry_run: If True, only report what would be done.

        Returns:
            Dictionary with results for each policy.
        """
        results = {
            'policies_executed': 0,
            'total_records_affected': 0,
            'details': [],
        }

        policies = DataRetentionPolicy.objects.filter(
            tenant=self.tenant,
            is_enabled=True,
            legal_hold_enabled=False,
        )

        for policy in policies:
            if policy.is_under_legal_hold:
                results['details'].append({
                    'policy': policy.name,
                    'status': 'skipped',
                    'reason': 'Under legal hold',
                })
                continue

            try:
                policy_result = self._apply_single_policy(policy, dry_run)
                results['details'].append(policy_result)
                results['policies_executed'] += 1
                results['total_records_affected'] += policy_result.get('records_affected', 0)
            except Exception as e:
                logger.exception(f"Error applying retention policy {policy.id}")
                results['details'].append({
                    'policy': policy.name,
                    'status': 'error',
                    'error': str(e),
                })

        return results

    def _apply_single_policy(
        self,
        policy: DataRetentionPolicy,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Apply a single retention policy.

        Args:
            policy: The retention policy to apply.
            dry_run: If True, don't actually modify records.

        Returns:
            Dictionary with policy execution results.
        """
        result = {
            'policy': policy.name,
            'model': policy.model_name,
            'strategy': policy.deletion_strategy,
            'records_affected': 0,
            'status': 'success',
        }

        try:
            # Get the model class
            model_class = apps.get_model(policy.model_name)
        except LookupError:
            result['status'] = 'error'
            result['error'] = f"Model {policy.model_name} not found"
            return result

        # Calculate retention cutoff date
        cutoff_date = timezone.now() - timedelta(days=policy.retention_days)

        # Build query for expired records
        retention_field = policy.retention_field or 'created_at'
        queryset = model_class.objects.filter(**{
            f'{retention_field}__lt': cutoff_date
        })

        # Apply tenant filter if model is tenant-aware
        if hasattr(model_class, 'tenant_id'):
            queryset = queryset.filter(tenant=self.tenant)

        # Apply additional filter conditions
        if policy.filter_conditions:
            queryset = queryset.filter(**policy.filter_conditions)

        # Apply exempt conditions
        if policy.exempt_conditions:
            queryset = queryset.exclude(**policy.exempt_conditions)

        records_count = queryset.count()
        result['records_affected'] = records_count

        if dry_run:
            result['status'] = 'dry_run'
            return result

        if records_count == 0:
            return result

        # Apply the deletion strategy
        with transaction.atomic():
            if policy.deletion_strategy == DataRetentionPolicy.DeletionStrategy.HARD_DELETE:
                queryset.delete()

            elif policy.deletion_strategy == DataRetentionPolicy.DeletionStrategy.SOFT_DELETE:
                if hasattr(model_class, 'is_deleted'):
                    queryset.update(is_deleted=True, deleted_at=timezone.now())
                else:
                    queryset.delete()

            elif policy.deletion_strategy == DataRetentionPolicy.DeletionStrategy.ANONYMIZE:
                anonymization_service = AnonymizationService(self.tenant)
                for record in queryset.iterator():
                    anonymization_service.anonymize_record(
                        record,
                        fields=policy.fields_to_anonymize
                    )

            elif policy.deletion_strategy == DataRetentionPolicy.DeletionStrategy.PSEUDONYMIZE:
                anonymization_service = AnonymizationService(self.tenant)
                for record in queryset.iterator():
                    anonymization_service.pseudonymize_record(
                        record,
                        fields=policy.fields_to_anonymize
                    )

            # Update policy execution stats
            policy.last_executed_at = timezone.now()
            policy.records_processed += records_count
            policy.save(update_fields=['last_executed_at', 'records_processed'])

            # Log the retention execution
            PrivacyAuditLog.objects.create(
                tenant=self.tenant,
                action=PrivacyAuditLog.ActionType.RETENTION_EXECUTED,
                description=f"Retention policy executed: {policy.name}",
                context={
                    'policy_id': str(policy.id),
                    'strategy': policy.deletion_strategy,
                    'records_affected': records_count,
                },
            )

        logger.info(
            f"Retention policy {policy.name} executed: "
            f"{records_count} records affected using {policy.deletion_strategy}"
        )

        return result

    def get_retention_schedule(self) -> List[Dict[str, Any]]:
        """
        Get the retention schedule for all policies.

        Returns:
            List of policy schedules with next execution info.
        """
        policies = DataRetentionPolicy.objects.filter(
            tenant=self.tenant,
            is_enabled=True,
        )

        schedule = []
        for policy in policies:
            schedule.append({
                'policy_id': str(policy.id),
                'policy_name': policy.name,
                'model': policy.model_name,
                'retention_days': policy.retention_days,
                'strategy': policy.deletion_strategy,
                'last_executed': policy.last_executed_at,
                'records_processed': policy.records_processed,
                'legal_hold': policy.is_under_legal_hold,
            })

        return schedule

    def exempt_from_retention(
        self,
        policy: DataRetentionPolicy,
        record_ids: List[str],
        reason: str,
        until: Optional[datetime] = None,
    ) -> bool:
        """
        Exempt specific records from retention.

        Args:
            policy: The retention policy.
            record_ids: List of record IDs to exempt.
            reason: Reason for exemption.
            until: When the exemption expires.

        Returns:
            True if successful.
        """
        exempt_conditions = policy.exempt_conditions or {}
        if 'id__in' not in exempt_conditions:
            exempt_conditions['id__in'] = []

        exempt_conditions['id__in'].extend(record_ids)
        policy.exempt_conditions = exempt_conditions
        policy.save(update_fields=['exempt_conditions'])

        logger.info(
            f"Records exempted from retention policy {policy.id}: "
            f"{len(record_ids)} records, reason: {reason}"
        )

        return True

    def set_legal_hold(
        self,
        policy: DataRetentionPolicy,
        reason: str,
        until: Optional[datetime] = None,
    ):
        """
        Set a legal hold on a retention policy.

        Args:
            policy: The policy to hold.
            reason: Reason for the hold.
            until: When the hold expires (None for indefinite).
        """
        policy.legal_hold_enabled = True
        policy.legal_hold_reason = reason
        policy.legal_hold_until = until
        policy.save(update_fields=[
            'legal_hold_enabled', 'legal_hold_reason', 'legal_hold_until'
        ])

        logger.info(f"Legal hold set on retention policy {policy.id}: {reason}")

    def release_legal_hold(self, policy: DataRetentionPolicy):
        """Release a legal hold on a retention policy."""
        policy.legal_hold_enabled = False
        policy.legal_hold_reason = ''
        policy.legal_hold_until = None
        policy.save(update_fields=[
            'legal_hold_enabled', 'legal_hold_reason', 'legal_hold_until'
        ])

        logger.info(f"Legal hold released on retention policy {policy.id}")


class AnonymizationService:
    """
    Service for anonymizing and pseudonymizing user data.

    Provides methods for:
    - Full user anonymization
    - Reversible pseudonymization
    - Field-level anonymization
    """

    # Default anonymization values - use centralized domain config
    @property
    def ANONYMOUS_EMAIL_DOMAIN(self):
        from django.conf import settings
        domain = getattr(settings, 'ANONYMIZED_EMAIL_DOMAIN', '')
        if not domain:
            primary = getattr(settings, 'PRIMARY_DOMAIN', 'localhost')
            domain = f"anonymized.{primary}"
        return domain

    _ANONYMOUS_EMAIL_DOMAIN = None  # Backwards compatibility placeholder
    ANONYMOUS_PHONE = '+10000000000'
    ANONYMOUS_STRING = '[ANONYMIZED]'
    ANONYMOUS_IP = '0.0.0.0'

    # Field type mappings for anonymization
    FIELD_ANONYMIZERS = {
        'email': lambda self, _: f"anon-{uuid.uuid4().hex[:12]}@{self.ANONYMOUS_EMAIL_DOMAIN}",
        'first_name': lambda self, _: self.ANONYMOUS_STRING,
        'last_name': lambda self, _: self.ANONYMOUS_STRING,
        'phone': lambda self, _: self.ANONYMOUS_PHONE,
        'address': lambda self, _: self.ANONYMOUS_STRING,
        'city': lambda self, _: self.ANONYMOUS_STRING,
        'postal_code': lambda self, _: '00000',
        'ip_address': lambda self, _: self.ANONYMOUS_IP,
        'date_of_birth': lambda self, _: None,
        'ssn': lambda self, _: self.ANONYMOUS_STRING,
        'bio': lambda self, _: '',
    }

    def __init__(self, tenant):
        """
        Initialize anonymization service for a tenant.

        Args:
            tenant: The tenant instance.
        """
        self.tenant = tenant
        self._pseudonym_map = {}

    def anonymize_user(self, user, delete_account: bool = False) -> Dict[str, Any]:
        """
        Anonymize all PII for a user across all models.

        Args:
            user: The user to anonymize.
            delete_account: Whether to deactivate the account.

        Returns:
            Dictionary with anonymization results.
        """
        results = {
            'user_id': str(user.id),
            'models_processed': [],
            'fields_anonymized': 0,
        }

        with transaction.atomic():
            # Anonymize the user model itself
            user_result = self._anonymize_user_model(user)
            results['models_processed'].append(user_result)
            results['fields_anonymized'] += user_result.get('fields', 0)

            # Find and anonymize related models
            related_results = self._anonymize_related_models(user)
            results['models_processed'].extend(related_results)
            for r in related_results:
                results['fields_anonymized'] += r.get('fields', 0)

            # Optionally deactivate the account
            if delete_account:
                user.is_active = False
                user.save(update_fields=['is_active'])
                results['account_deactivated'] = True

            # Log the anonymization
            PrivacyAuditLog.objects.create(
                tenant=self.tenant,
                action=PrivacyAuditLog.ActionType.DATA_ANONYMIZED,
                description=f"User data anonymized: {user.id}",
                data_subject=user,
                context=results,
            )

        logger.info(f"User {user.id} anonymized: {results['fields_anonymized']} fields")

        return results

    def _anonymize_user_model(self, user) -> Dict[str, Any]:
        """Anonymize the user model fields."""
        result = {'model': 'User', 'fields': 0}

        pii_fields = [
            'first_name', 'last_name', 'email', 'phone',
            'address', 'city', 'postal_code', 'date_of_birth'
        ]

        for field_name in pii_fields:
            if hasattr(user, field_name):
                self._anonymize_field(user, field_name)
                result['fields'] += 1

        # Generate anonymous username if exists
        if hasattr(user, 'username'):
            user.username = f"anon_{uuid.uuid4().hex[:12]}"
            result['fields'] += 1

        user.save()
        return result

    def _anonymize_related_models(self, user) -> List[Dict[str, Any]]:
        """Find and anonymize related models containing user PII."""
        results = []

        # Models to check for user-related data
        models_to_check = [
            ('tenant_profiles.UserProfile', 'user'),
            ('tenant_profiles.LoginHistory', 'user'),
            ('tenant_profiles.DataAccessLog', 'accessor'),
            ('jobs.Candidate', 'email'),
            ('hr_core.Employee', 'user'),
        ]

        for model_path, user_field in models_to_check:
            try:
                model_class = apps.get_model(model_path)
                result = self._anonymize_model_records(model_class, user, user_field)
                if result:
                    results.append(result)
            except LookupError:
                continue  # Model doesn't exist
            except Exception as e:
                logger.warning(f"Error anonymizing {model_path}: {e}")

        return results

    def _anonymize_model_records(
        self,
        model_class: Type[models.Model],
        user,
        user_field: str,
    ) -> Optional[Dict[str, Any]]:
        """Anonymize records in a specific model."""
        result = {'model': model_class.__name__, 'fields': 0, 'records': 0}

        try:
            if user_field == 'email':
                records = model_class.objects.filter(email=user.email)
            else:
                records = model_class.objects.filter(**{user_field: user})

            if hasattr(model_class, 'tenant_id'):
                records = records.filter(tenant=self.tenant)

            for record in records:
                fields_anonymized = self._anonymize_record_fields(record)
                result['fields'] += fields_anonymized
                result['records'] += 1

            return result if result['records'] > 0 else None

        except Exception as e:
            logger.warning(f"Error processing {model_class.__name__}: {e}")
            return None

    def _anonymize_record_fields(self, record) -> int:
        """Anonymize PII fields in a record."""
        fields_anonymized = 0
        pii_field_patterns = [
            'email', 'phone', 'first_name', 'last_name', 'name',
            'address', 'city', 'ip_address', 'ssn', 'sin',
        ]

        for field in record._meta.fields:
            field_name = field.name
            for pattern in pii_field_patterns:
                if pattern in field_name.lower():
                    try:
                        self._anonymize_field(record, field_name)
                        fields_anonymized += 1
                    except Exception:
                        pass
                    break

        record.save()
        return fields_anonymized

    def pseudonymize_user(
        self,
        user,
        pseudonym_key: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], str]:
        """
        Pseudonymize user data (reversible with key).

        Args:
            user: The user to pseudonymize.
            pseudonym_key: Key for reversing (generated if not provided).

        Returns:
            Tuple of (results dict, pseudonym_key).
        """
        if not pseudonym_key:
            pseudonym_key = secrets.token_hex(32)

        results = {
            'user_id': str(user.id),
            'fields_pseudonymized': 0,
        }

        with transaction.atomic():
            # Store original values encrypted with the key
            original_data = {}
            pii_fields = ['first_name', 'last_name', 'email', 'phone']

            for field_name in pii_fields:
                if hasattr(user, field_name):
                    original_value = getattr(user, field_name)
                    if original_value:
                        # Store hash of original + key
                        hash_key = hashlib.sha256(
                            f"{pseudonym_key}:{field_name}".encode()
                        ).hexdigest()[:12]

                        original_data[hash_key] = str(original_value)

                        # Set pseudonymized value
                        pseudonym = f"[PSEUDONYMIZED:{hash_key}]"
                        if 'email' in field_name:
                            pseudonym = f"pseudo-{hash_key}@{self.ANONYMOUS_EMAIL_DOMAIN}"

                        setattr(user, field_name, pseudonym)
                        results['fields_pseudonymized'] += 1

            user.save()

            # Store mapping securely (in practice, this would be encrypted storage)
            self._pseudonym_map[str(user.id)] = {
                'key': pseudonym_key,
                'data': original_data,
            }

        logger.info(
            f"User {user.id} pseudonymized: {results['fields_pseudonymized']} fields"
        )

        return results, pseudonym_key

    def anonymize_record(
        self,
        record: models.Model,
        fields: Optional[List[str]] = None,
    ) -> int:
        """
        Anonymize specific fields in a record.

        Args:
            record: The record to anonymize.
            fields: List of fields to anonymize (all PII if None).

        Returns:
            Number of fields anonymized.
        """
        fields_anonymized = 0

        if fields is None:
            # Auto-detect PII fields
            fields = self._detect_pii_fields(record)

        for field_name in fields:
            if hasattr(record, field_name):
                try:
                    self._anonymize_field(record, field_name)
                    fields_anonymized += 1
                except Exception as e:
                    logger.warning(f"Could not anonymize field {field_name}: {e}")

        record.save()
        return fields_anonymized

    def pseudonymize_record(
        self,
        record: models.Model,
        fields: Optional[List[str]] = None,
    ) -> int:
        """
        Pseudonymize specific fields in a record.

        Args:
            record: The record to pseudonymize.
            fields: List of fields to pseudonymize.

        Returns:
            Number of fields pseudonymized.
        """
        fields_pseudonymized = 0

        if fields is None:
            fields = self._detect_pii_fields(record)

        for field_name in fields:
            if hasattr(record, field_name):
                original_value = getattr(record, field_name)
                if original_value:
                    hash_key = hashlib.sha256(
                        f"{record.pk}:{field_name}".encode()
                    ).hexdigest()[:12]
                    setattr(record, field_name, f"[PSEUDO:{hash_key}]")
                    fields_pseudonymized += 1

        record.save()
        return fields_pseudonymized

    def anonymize_field(self, record: models.Model, field_name: str) -> bool:
        """
        Anonymize a single field in a record.

        Args:
            record: The record containing the field.
            field_name: Name of the field to anonymize.

        Returns:
            True if successful.
        """
        return self._anonymize_field(record, field_name)

    def _anonymize_field(self, record: models.Model, field_name: str) -> bool:
        """Internal method to anonymize a single field."""
        if not hasattr(record, field_name):
            return False

        # Get field type for appropriate anonymization
        field = record._meta.get_field(field_name)
        value = getattr(record, field_name)

        if value is None:
            return True  # Already null

        # Determine anonymization strategy based on field name/type
        for pattern, anonymizer in self.FIELD_ANONYMIZERS.items():
            if pattern in field_name.lower():
                setattr(record, field_name, anonymizer(self, value))
                return True

        # Default: clear or set to anonymous string based on type
        if isinstance(field, (models.CharField, models.TextField)):
            setattr(record, field_name, self.ANONYMOUS_STRING)
        elif isinstance(field, models.EmailField):
            setattr(record, field_name, f"anon-{uuid.uuid4().hex[:12]}@{self.ANONYMOUS_EMAIL_DOMAIN}")
        elif isinstance(field, models.DateField):
            setattr(record, field_name, None)
        elif isinstance(field, models.GenericIPAddressField):
            setattr(record, field_name, self.ANONYMOUS_IP)
        else:
            setattr(record, field_name, None)

        return True

    def _detect_pii_fields(self, record: models.Model) -> List[str]:
        """Auto-detect potential PII fields in a model."""
        pii_patterns = [
            'email', 'phone', 'name', 'first', 'last', 'address',
            'city', 'postal', 'zip', 'ssn', 'sin', 'birth', 'dob',
            'ip', 'location', 'lat', 'lng', 'password',
        ]

        pii_fields = []
        for field in record._meta.fields:
            field_name_lower = field.name.lower()
            for pattern in pii_patterns:
                if pattern in field_name_lower:
                    pii_fields.append(field.name)
                    break

        return pii_fields
