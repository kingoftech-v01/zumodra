"""
GDPR/Privacy Compliance Models for Zumodra ATS/HR Platform

This module defines the data models for GDPR compliance:
- ConsentRecord: Tracks user consents with versioning
- DataProcessingPurpose: Defines lawful bases for data processing
- DataSubjectRequest: Handles DSR (access, erasure, rectification, portability)
- PrivacyPolicy: Versioned privacy policies per tenant
- DataRetentionPolicy: Automated data retention and deletion rules

All models are tenant-aware and support full audit trails.
"""

import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType

from core.db.models import TenantAwareModel, FullAuditModel


class DataProcessingPurpose(TenantAwareModel):
    """
    Defines the lawful purposes for processing personal data.

    Each purpose must have a legal basis under GDPR (Article 6):
    - Consent
    - Contract
    - Legal obligation
    - Vital interests
    - Public task
    - Legitimate interests
    """

    class LegalBasis(models.TextChoices):
        CONSENT = 'consent', _('Consent (Art. 6(1)(a))')
        CONTRACT = 'contract', _('Contract Performance (Art. 6(1)(b))')
        LEGAL_OBLIGATION = 'legal_obligation', _('Legal Obligation (Art. 6(1)(c))')
        VITAL_INTERESTS = 'vital_interests', _('Vital Interests (Art. 6(1)(d))')
        PUBLIC_TASK = 'public_task', _('Public Task (Art. 6(1)(e))')
        LEGITIMATE_INTERESTS = 'legitimate_interests', _('Legitimate Interests (Art. 6(1)(f))')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(
        max_length=100,
        verbose_name=_('Purpose Name'),
        help_text=_('Short name for the processing purpose')
    )
    code = models.CharField(
        max_length=50,
        verbose_name=_('Purpose Code'),
        help_text=_('Unique identifier code for programmatic use')
    )
    description = models.TextField(
        verbose_name=_('Description'),
        help_text=_('Detailed description of the processing purpose')
    )
    legal_basis = models.CharField(
        max_length=30,
        choices=LegalBasis.choices,
        verbose_name=_('Legal Basis'),
        help_text=_('GDPR Article 6 legal basis for processing')
    )
    retention_days = models.PositiveIntegerField(
        default=365,
        verbose_name=_('Retention Period (days)'),
        help_text=_('How long data can be retained for this purpose')
    )

    # Data categories processed under this purpose
    data_categories = models.JSONField(
        default=list,
        blank=True,
        verbose_name=_('Data Categories'),
        help_text=_('List of data categories processed under this purpose')
    )

    # Third-party sharing
    third_party_sharing = models.BooleanField(
        default=False,
        verbose_name=_('Third-Party Sharing'),
        help_text=_('Whether data may be shared with third parties')
    )
    third_party_recipients = models.JSONField(
        default=list,
        blank=True,
        verbose_name=_('Third-Party Recipients'),
        help_text=_('List of third-party categories that may receive data')
    )

    # Cross-border transfer
    cross_border_transfer = models.BooleanField(
        default=False,
        verbose_name=_('Cross-Border Transfer'),
        help_text=_('Whether data may be transferred outside EEA')
    )
    transfer_safeguards = models.TextField(
        blank=True,
        verbose_name=_('Transfer Safeguards'),
        help_text=_('Safeguards for cross-border transfers (SCCs, BCRs, etc.)')
    )

    # Status
    is_mandatory = models.BooleanField(
        default=False,
        verbose_name=_('Mandatory'),
        help_text=_('Whether this purpose is mandatory for service use')
    )
    requires_explicit_consent = models.BooleanField(
        default=True,
        verbose_name=_('Requires Explicit Consent'),
        help_text=_('Whether explicit consent is required for this purpose')
    )

    class Meta:
        verbose_name = _('Data Processing Purpose')
        verbose_name_plural = _('Data Processing Purposes')
        unique_together = ['tenant', 'code']
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.get_legal_basis_display()})"


class PrivacyPolicy(TenantAwareModel):
    """
    Versioned privacy policy documents per tenant.

    Each tenant can have multiple policy versions, with only one
    being active at a time. Users must accept the current policy
    to continue using the platform.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    version = models.CharField(
        max_length=20,
        verbose_name=_('Version'),
        help_text=_('Policy version number (e.g., 1.0, 2.1)')
    )
    title = models.CharField(
        max_length=200,
        default='Privacy Policy',
        verbose_name=_('Title')
    )
    content = models.TextField(
        verbose_name=_('Content'),
        help_text=_('Full privacy policy text (supports HTML/Markdown)')
    )
    summary = models.TextField(
        blank=True,
        verbose_name=_('Summary'),
        help_text=_('Brief summary of key changes from previous version')
    )

    # Effective date management
    effective_date = models.DateTimeField(
        verbose_name=_('Effective Date'),
        help_text=_('When this policy version becomes effective')
    )
    expiry_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Expiry Date'),
        help_text=_('When this policy version expires (if superseded)')
    )

    # Status
    is_current = models.BooleanField(
        default=False,
        verbose_name=_('Is Current'),
        help_text=_('Whether this is the currently active policy')
    )
    is_published = models.BooleanField(
        default=False,
        verbose_name=_('Is Published'),
        help_text=_('Whether this policy is publicly visible')
    )

    # Document metadata
    language = models.CharField(
        max_length=10,
        default='en',
        verbose_name=_('Language')
    )
    document_hash = models.CharField(
        max_length=64,
        blank=True,
        verbose_name=_('Document Hash'),
        help_text=_('SHA-256 hash of the policy content for integrity verification')
    )

    # Audit
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_privacy_policies',
        verbose_name=_('Approved By')
    )
    approved_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Approved At')
    )

    class Meta:
        verbose_name = _('Privacy Policy')
        verbose_name_plural = _('Privacy Policies')
        unique_together = ['tenant', 'version', 'language']
        ordering = ['-effective_date']

    def __str__(self):
        return f"{self.title} v{self.version} ({self.tenant.name})"

    def save(self, *args, **kwargs):
        """Generate document hash before saving."""
        import hashlib
        self.document_hash = hashlib.sha256(
            self.content.encode('utf-8')
        ).hexdigest()
        super().save(*args, **kwargs)

    def make_current(self):
        """Make this policy the current active policy."""
        # Deactivate other policies for this tenant
        PrivacyPolicy.objects.filter(
            tenant=self.tenant,
            is_current=True
        ).update(is_current=False)

        self.is_current = True
        self.is_published = True
        self.save(update_fields=['is_current', 'is_published'])


class ConsentRecord(FullAuditModel):
    """
    Records individual user consent decisions.

    Each consent record tracks:
    - The user giving consent
    - The purpose/type of processing consented to
    - Whether consent was granted or withdrawn
    - Timestamp and IP for audit purposes
    - The version of the consent text shown
    """

    class ConsentType(models.TextChoices):
        PRIVACY_POLICY = 'privacy_policy', _('Privacy Policy Acceptance')
        MARKETING_EMAIL = 'marketing_email', _('Marketing Emails')
        MARKETING_SMS = 'marketing_sms', _('Marketing SMS')
        ANALYTICS = 'analytics', _('Analytics & Tracking')
        PROFILING = 'profiling', _('Profiling & Personalization')
        THIRD_PARTY = 'third_party', _('Third-Party Sharing')
        CROSS_BORDER = 'cross_border', _('Cross-Border Transfer')
        RECRUITMENT = 'recruitment', _('Recruitment Processing')
        HR_PROCESSING = 'hr_processing', _('HR Data Processing')
        BACKGROUND_CHECK = 'background_check', _('Background Check Authorization')
        REFERENCES = 'references', _('Reference Check Authorization')
        COOKIES_ESSENTIAL = 'cookies_essential', _('Essential Cookies')
        COOKIES_ANALYTICS = 'cookies_analytics', _('Analytics Cookies')
        COOKIES_MARKETING = 'cookies_marketing', _('Marketing Cookies')
        CUSTOM = 'custom', _('Custom Purpose')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='consent_records',
        verbose_name=_('User')
    )

    # Consent details
    consent_type = models.CharField(
        max_length=30,
        choices=ConsentType.choices,
        verbose_name=_('Consent Type')
    )
    purpose = models.ForeignKey(
        DataProcessingPurpose,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='consent_records',
        verbose_name=_('Processing Purpose')
    )

    # Consent status
    granted = models.BooleanField(
        default=False,
        verbose_name=_('Consent Granted'),
        help_text=_('Whether consent was granted or denied')
    )

    # Versioning for consent text
    consent_text_version = models.CharField(
        max_length=50,
        verbose_name=_('Consent Text Version'),
        help_text=_('Version of the consent text shown to user')
    )
    consent_text = models.TextField(
        blank=True,
        verbose_name=_('Consent Text'),
        help_text=_('Exact text of consent shown to user')
    )

    # Privacy policy reference
    privacy_policy = models.ForeignKey(
        PrivacyPolicy,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='consent_records',
        verbose_name=_('Privacy Policy Version')
    )

    # Collection details for audit
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_('IP Address')
    )
    user_agent = models.TextField(
        blank=True,
        verbose_name=_('User Agent')
    )
    collection_method = models.CharField(
        max_length=50,
        default='web_form',
        verbose_name=_('Collection Method'),
        help_text=_('How consent was collected (web_form, api, import, etc.)')
    )

    # Withdrawal tracking
    withdrawn = models.BooleanField(
        default=False,
        verbose_name=_('Withdrawn'),
        help_text=_('Whether this consent has been withdrawn')
    )
    withdrawn_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Withdrawn At')
    )
    withdrawal_ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_('Withdrawal IP Address')
    )

    # Expiry
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Expires At'),
        help_text=_('When this consent expires (if applicable)')
    )

    class Meta:
        verbose_name = _('Consent Record')
        verbose_name_plural = _('Consent Records')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'consent_type']),
            models.Index(fields=['tenant', 'consent_type', 'granted']),
            models.Index(fields=['user', 'granted', 'withdrawn']),
        ]

    def __str__(self):
        status = 'Granted' if self.granted and not self.withdrawn else 'Withdrawn/Denied'
        return f"{self.user.email} - {self.get_consent_type_display()}: {status}"

    @property
    def is_valid(self):
        """Check if consent is currently valid."""
        if not self.granted or self.withdrawn:
            return False
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True

    def withdraw(self, ip_address=None):
        """Withdraw this consent."""
        self.withdrawn = True
        self.withdrawn_at = timezone.now()
        if ip_address:
            self.withdrawal_ip_address = ip_address
        self.save(update_fields=['withdrawn', 'withdrawn_at', 'withdrawal_ip_address', 'updated_at'])


class DataSubjectRequest(FullAuditModel):
    """
    Handles GDPR Data Subject Requests (DSR).

    Types of requests:
    - Access (Art. 15): Right to obtain copy of personal data
    - Rectification (Art. 16): Right to correct inaccurate data
    - Erasure (Art. 17): Right to be forgotten
    - Portability (Art. 20): Right to receive data in machine-readable format
    - Restriction (Art. 18): Right to restrict processing
    - Objection (Art. 21): Right to object to processing
    """

    class RequestType(models.TextChoices):
        ACCESS = 'access', _('Data Access Request (Art. 15)')
        RECTIFICATION = 'rectification', _('Data Rectification Request (Art. 16)')
        ERASURE = 'erasure', _('Data Erasure Request (Art. 17)')
        PORTABILITY = 'portability', _('Data Portability Request (Art. 20)')
        RESTRICTION = 'restriction', _('Processing Restriction Request (Art. 18)')
        OBJECTION = 'objection', _('Processing Objection (Art. 21)')

    class RequestStatus(models.TextChoices):
        PENDING = 'pending', _('Pending Review')
        VERIFIED = 'verified', _('Identity Verified')
        IN_PROGRESS = 'in_progress', _('In Progress')
        COMPLETED = 'completed', _('Completed')
        REJECTED = 'rejected', _('Rejected')
        CANCELLED = 'cancelled', _('Cancelled by User')
        PARTIALLY_COMPLETED = 'partially_completed', _('Partially Completed')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # The data subject making the request
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='data_subject_requests',
        verbose_name=_('Data Subject')
    )
    # For non-registered users submitting requests
    requester_email = models.EmailField(
        blank=True,
        verbose_name=_('Requester Email')
    )
    requester_name = models.CharField(
        max_length=200,
        blank=True,
        verbose_name=_('Requester Name')
    )

    # Request details
    request_type = models.CharField(
        max_length=20,
        choices=RequestType.choices,
        verbose_name=_('Request Type')
    )
    status = models.CharField(
        max_length=20,
        choices=RequestStatus.choices,
        default=RequestStatus.PENDING,
        verbose_name=_('Status')
    )

    # Request specifics
    description = models.TextField(
        blank=True,
        verbose_name=_('Description'),
        help_text=_('Additional details about the request')
    )
    data_categories_requested = models.JSONField(
        default=list,
        blank=True,
        verbose_name=_('Data Categories'),
        help_text=_('Specific data categories requested (if applicable)')
    )
    rectification_details = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Rectification Details'),
        help_text=_('Fields to correct and their new values')
    )

    # Identity verification
    identity_verified = models.BooleanField(
        default=False,
        verbose_name=_('Identity Verified')
    )
    verification_method = models.CharField(
        max_length=50,
        blank=True,
        verbose_name=_('Verification Method')
    )
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='verified_dsr_requests',
        verbose_name=_('Verified By')
    )
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Verified At')
    )

    # Processing details
    processed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='processed_dsr_requests',
        verbose_name=_('Processed By')
    )
    processing_notes = models.TextField(
        blank=True,
        verbose_name=_('Processing Notes')
    )

    # Timestamps
    submitted_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Submitted At')
    )
    due_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Due Date'),
        help_text=_('GDPR requires response within 30 days')
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Completed At')
    )

    # Response
    response_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Response Data'),
        help_text=_('Data compiled in response to access/portability requests')
    )
    response_file = models.FileField(
        upload_to='dsr_responses/',
        blank=True,
        null=True,
        verbose_name=_('Response File'),
        help_text=_('Exported data file for portability requests')
    )
    rejection_reason = models.TextField(
        blank=True,
        verbose_name=_('Rejection Reason')
    )

    # Request metadata
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_('Submission IP')
    )
    user_agent = models.TextField(
        blank=True,
        verbose_name=_('User Agent')
    )

    class Meta:
        verbose_name = _('Data Subject Request')
        verbose_name_plural = _('Data Subject Requests')
        ordering = ['-submitted_at']
        indexes = [
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['user', 'request_type']),
            models.Index(fields=['status', 'due_date']),
        ]

    def __str__(self):
        email = self.user.email if self.user else self.requester_email
        return f"DSR-{self.uuid.hex[:8]}: {self.get_request_type_display()} from {email}"

    def save(self, *args, **kwargs):
        """Set due date on creation (30 days per GDPR)."""
        if not self.pk and not self.due_date:
            self.due_date = timezone.now() + timezone.timedelta(days=30)
        super().save(*args, **kwargs)

    @property
    def is_overdue(self):
        """Check if the request is past its due date."""
        if not self.due_date:
            return False
        if self.status in [self.RequestStatus.COMPLETED, self.RequestStatus.REJECTED,
                          self.RequestStatus.CANCELLED]:
            return False
        return timezone.now() > self.due_date

    @property
    def days_remaining(self):
        """Days remaining until due date."""
        if not self.due_date:
            return None
        if self.status in [self.RequestStatus.COMPLETED, self.RequestStatus.REJECTED,
                          self.RequestStatus.CANCELLED]:
            return 0
        delta = self.due_date - timezone.now()
        return max(0, delta.days)

    def verify_identity(self, verified_by, method='email'):
        """Mark identity as verified."""
        self.identity_verified = True
        self.verified_by = verified_by
        self.verified_at = timezone.now()
        self.verification_method = method
        self.status = self.RequestStatus.VERIFIED
        self.save(update_fields=[
            'identity_verified', 'verified_by', 'verified_at',
            'verification_method', 'status', 'updated_at'
        ])

    def complete(self, processed_by, response_data=None, response_file=None, notes=''):
        """Mark request as completed."""
        self.status = self.RequestStatus.COMPLETED
        self.completed_at = timezone.now()
        self.processed_by = processed_by
        if response_data:
            self.response_data = response_data
        if response_file:
            self.response_file = response_file
        if notes:
            self.processing_notes = notes
        self.save()

    def reject(self, processed_by, reason):
        """Reject the request with a reason."""
        self.status = self.RequestStatus.REJECTED
        self.completed_at = timezone.now()
        self.processed_by = processed_by
        self.rejection_reason = reason
        self.save(update_fields=[
            'status', 'completed_at', 'processed_by', 'rejection_reason', 'updated_at'
        ])


class DataRetentionPolicy(TenantAwareModel):
    """
    Defines data retention policies for different data types.

    Configures how long data should be retained and what happens
    when the retention period expires (anonymize, delete, archive).
    """

    class DeletionStrategy(models.TextChoices):
        HARD_DELETE = 'hard_delete', _('Permanent Deletion')
        SOFT_DELETE = 'soft_delete', _('Soft Deletion (Recoverable)')
        ANONYMIZE = 'anonymize', _('Anonymization')
        ARCHIVE = 'archive', _('Archive to Cold Storage')
        PSEUDONYMIZE = 'pseudonymize', _('Pseudonymization')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # What this policy applies to
    name = models.CharField(
        max_length=100,
        verbose_name=_('Policy Name')
    )
    description = models.TextField(
        blank=True,
        verbose_name=_('Description')
    )

    # Target model/data type
    model_name = models.CharField(
        max_length=200,
        verbose_name=_('Model Name'),
        help_text=_('Django model path (e.g., accounts.UserProfile)')
    )
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='retention_policies',
        verbose_name=_('Content Type')
    )

    # Retention configuration
    retention_days = models.PositiveIntegerField(
        default=365,
        verbose_name=_('Retention Period (days)'),
        help_text=_('Number of days to retain data before applying deletion strategy')
    )
    deletion_strategy = models.CharField(
        max_length=20,
        choices=DeletionStrategy.choices,
        default=DeletionStrategy.ANONYMIZE,
        verbose_name=_('Deletion Strategy')
    )

    # Field-level configuration
    retention_field = models.CharField(
        max_length=100,
        default='created_at',
        verbose_name=_('Retention Field'),
        help_text=_('Date field used to calculate retention (e.g., created_at, last_login)')
    )
    fields_to_anonymize = models.JSONField(
        default=list,
        blank=True,
        verbose_name=_('Fields to Anonymize'),
        help_text=_('List of field names to anonymize (for anonymize strategy)')
    )

    # Filter conditions
    filter_conditions = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Filter Conditions'),
        help_text=_('Additional filter conditions for selecting records')
    )

    # Exceptions
    exempt_conditions = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Exempt Conditions'),
        help_text=_('Conditions that exempt records from this policy')
    )

    # Legal hold
    legal_hold_enabled = models.BooleanField(
        default=False,
        verbose_name=_('Legal Hold'),
        help_text=_('Suspend retention for legal proceedings')
    )
    legal_hold_reason = models.TextField(
        blank=True,
        verbose_name=_('Legal Hold Reason')
    )
    legal_hold_until = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Legal Hold Until')
    )

    # Scheduling
    is_enabled = models.BooleanField(
        default=True,
        verbose_name=_('Enabled')
    )
    last_executed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Last Executed')
    )
    records_processed = models.PositiveIntegerField(
        default=0,
        verbose_name=_('Records Processed'),
        help_text=_('Total records processed by this policy')
    )

    # Notification
    notify_before_days = models.PositiveIntegerField(
        default=0,
        verbose_name=_('Notify Before (days)'),
        help_text=_('Send notification X days before retention expires')
    )
    notification_recipients = models.JSONField(
        default=list,
        blank=True,
        verbose_name=_('Notification Recipients'),
        help_text=_('Email addresses to notify')
    )

    class Meta:
        verbose_name = _('Data Retention Policy')
        verbose_name_plural = _('Data Retention Policies')
        unique_together = ['tenant', 'model_name']
        ordering = ['model_name']

    def __str__(self):
        return f"{self.name}: {self.model_name} ({self.retention_days} days)"

    @property
    def is_under_legal_hold(self):
        """Check if policy is under legal hold."""
        if not self.legal_hold_enabled:
            return False
        if self.legal_hold_until and timezone.now() > self.legal_hold_until:
            return False
        return True


class PrivacyAuditLog(models.Model):
    """
    Audit log specifically for privacy-related actions.

    Tracks all privacy operations for compliance reporting:
    - Consent changes
    - DSR processing
    - Data access/export
    - Retention policy execution
    """

    class ActionType(models.TextChoices):
        CONSENT_GRANTED = 'consent_granted', _('Consent Granted')
        CONSENT_WITHDRAWN = 'consent_withdrawn', _('Consent Withdrawn')
        DSR_SUBMITTED = 'dsr_submitted', _('DSR Submitted')
        DSR_PROCESSED = 'dsr_processed', _('DSR Processed')
        DSR_COMPLETED = 'dsr_completed', _('DSR Completed')
        DSR_REJECTED = 'dsr_rejected', _('DSR Rejected')
        DATA_ACCESSED = 'data_accessed', _('Data Accessed')
        DATA_EXPORTED = 'data_exported', _('Data Exported')
        DATA_DELETED = 'data_deleted', _('Data Deleted')
        DATA_ANONYMIZED = 'data_anonymized', _('Data Anonymized')
        RETENTION_EXECUTED = 'retention_executed', _('Retention Policy Executed')
        POLICY_UPDATED = 'policy_updated', _('Privacy Policy Updated')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='privacy_audit_logs',
        verbose_name=_('Tenant')
    )

    # Action details
    action = models.CharField(
        max_length=30,
        choices=ActionType.choices,
        verbose_name=_('Action')
    )
    description = models.TextField(
        verbose_name=_('Description')
    )

    # Users involved
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='privacy_actions_performed',
        verbose_name=_('Actor'),
        help_text=_('User who performed the action')
    )
    data_subject = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='privacy_actions_received',
        verbose_name=_('Data Subject'),
        help_text=_('User whose data was affected')
    )

    # Related objects
    related_content_type = models.ForeignKey(
        ContentType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    related_object_id = models.CharField(max_length=100, blank=True)
    related_object = GenericForeignKey('related_content_type', 'related_object_id')

    # Additional context
    context = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Context'),
        help_text=_('Additional context data')
    )

    # Request metadata
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_('IP Address')
    )
    user_agent = models.TextField(
        blank=True,
        verbose_name=_('User Agent')
    )

    # Timestamp
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name=_('Timestamp')
    )

    class Meta:
        verbose_name = _('Privacy Audit Log')
        verbose_name_plural = _('Privacy Audit Logs')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['tenant', 'timestamp']),
            models.Index(fields=['tenant', 'action']),
            models.Index(fields=['data_subject', 'timestamp']),
            models.Index(fields=['actor', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.get_action_display()} at {self.timestamp}"
