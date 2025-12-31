"""
Django Admin Configuration for Privacy Module

Provides admin interfaces for:
- Data Processing Purposes
- Privacy Policies
- Consent Records
- Data Subject Requests
- Data Retention Policies
- Privacy Audit Logs
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from core.privacy.models import (
    DataProcessingPurpose,
    PrivacyPolicy,
    ConsentRecord,
    DataSubjectRequest,
    DataRetentionPolicy,
    PrivacyAuditLog,
)


@admin.register(DataProcessingPurpose)
class DataProcessingPurposeAdmin(admin.ModelAdmin):
    """Admin for Data Processing Purposes."""

    list_display = [
        'name', 'code', 'legal_basis', 'retention_days',
        'is_mandatory', 'requires_explicit_consent', 'tenant', 'is_active',
    ]
    list_filter = ['legal_basis', 'is_mandatory', 'requires_explicit_consent', 'tenant']
    search_fields = ['name', 'code', 'description']
    readonly_fields = ['uuid', 'created_at', 'updated_at']

    fieldsets = (
        (None, {
            'fields': ('tenant', 'name', 'code', 'description')
        }),
        (_('Legal Basis'), {
            'fields': ('legal_basis', 'retention_days')
        }),
        (_('Data Categories'), {
            'fields': ('data_categories',),
            'classes': ('collapse',),
        }),
        (_('Third-Party Sharing'), {
            'fields': ('third_party_sharing', 'third_party_recipients'),
            'classes': ('collapse',),
        }),
        (_('Cross-Border Transfer'), {
            'fields': ('cross_border_transfer', 'transfer_safeguards'),
            'classes': ('collapse',),
        }),
        (_('Consent Requirements'), {
            'fields': ('is_mandatory', 'requires_explicit_consent')
        }),
        (_('Metadata'), {
            'fields': ('uuid', 'is_active', 'created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )


@admin.register(PrivacyPolicy)
class PrivacyPolicyAdmin(admin.ModelAdmin):
    """Admin for Privacy Policies."""

    list_display = [
        'title', 'version', 'tenant', 'effective_date',
        'is_current', 'is_published', 'language',
    ]
    list_filter = ['is_current', 'is_published', 'language', 'tenant']
    search_fields = ['title', 'version', 'content']
    readonly_fields = ['uuid', 'document_hash', 'created_at', 'updated_at']
    date_hierarchy = 'effective_date'

    fieldsets = (
        (None, {
            'fields': ('tenant', 'title', 'version', 'language')
        }),
        (_('Content'), {
            'fields': ('content', 'summary'),
        }),
        (_('Dates'), {
            'fields': ('effective_date', 'expiry_date')
        }),
        (_('Status'), {
            'fields': ('is_current', 'is_published')
        }),
        (_('Approval'), {
            'fields': ('approved_by', 'approved_at'),
            'classes': ('collapse',),
        }),
        (_('Metadata'), {
            'fields': ('uuid', 'document_hash', 'created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )

    actions = ['make_current']

    def make_current(self, request, queryset):
        """Make selected policy the current one."""
        if queryset.count() != 1:
            self.message_user(
                request,
                _('Please select only one policy to make current.'),
                level='error'
            )
            return

        policy = queryset.first()
        policy.make_current()
        self.message_user(
            request,
            _('Policy %(version)s is now the current policy.') % {'version': policy.version}
        )

    make_current.short_description = _('Make selected policy current')


@admin.register(ConsentRecord)
class ConsentRecordAdmin(admin.ModelAdmin):
    """Admin for Consent Records."""

    list_display = [
        'user', 'consent_type', 'granted_status', 'consent_text_version',
        'collection_method', 'created_at', 'tenant',
    ]
    list_filter = [
        'consent_type', 'granted', 'withdrawn', 'collection_method', 'tenant'
    ]
    search_fields = ['user__email', 'consent_text']
    readonly_fields = [
        'uuid', 'created_at', 'updated_at', 'withdrawn_at', 'ip_address', 'user_agent'
    ]
    date_hierarchy = 'created_at'
    raw_id_fields = ['user', 'purpose', 'privacy_policy']

    fieldsets = (
        (None, {
            'fields': ('tenant', 'user', 'consent_type', 'purpose')
        }),
        (_('Consent Status'), {
            'fields': ('granted', 'withdrawn', 'withdrawn_at')
        }),
        (_('Consent Text'), {
            'fields': ('consent_text_version', 'consent_text', 'privacy_policy'),
        }),
        (_('Collection Details'), {
            'fields': ('ip_address', 'user_agent', 'collection_method'),
            'classes': ('collapse',),
        }),
        (_('Withdrawal'), {
            'fields': ('withdrawal_ip_address', 'expires_at'),
            'classes': ('collapse',),
        }),
        (_('Metadata'), {
            'fields': ('uuid', 'created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )

    def granted_status(self, obj):
        if obj.withdrawn:
            return format_html(
                '<span style="color: #999;">Withdrawn</span>'
            )
        if obj.granted:
            return format_html(
                '<span style="color: green;">Granted</span>'
            )
        return format_html(
            '<span style="color: red;">Denied</span>'
        )

    granted_status.short_description = _('Status')


@admin.register(DataSubjectRequest)
class DataSubjectRequestAdmin(admin.ModelAdmin):
    """Admin for Data Subject Requests."""

    list_display = [
        'uuid_short', 'request_type', 'status_colored', 'requester_display',
        'submitted_at', 'due_date', 'days_remaining_display', 'tenant',
    ]
    list_filter = ['request_type', 'status', 'identity_verified', 'tenant']
    search_fields = ['uuid', 'user__email', 'requester_email', 'requester_name']
    readonly_fields = [
        'uuid', 'submitted_at', 'due_date', 'completed_at',
        'ip_address', 'user_agent', 'is_overdue', 'days_remaining',
    ]
    date_hierarchy = 'submitted_at'
    raw_id_fields = ['user', 'verified_by', 'processed_by']

    fieldsets = (
        (None, {
            'fields': ('tenant', 'user', 'requester_email', 'requester_name')
        }),
        (_('Request Details'), {
            'fields': ('request_type', 'status', 'description', 'data_categories_requested')
        }),
        (_('Rectification'), {
            'fields': ('rectification_details',),
            'classes': ('collapse',),
        }),
        (_('Identity Verification'), {
            'fields': ('identity_verified', 'verification_method', 'verified_by', 'verified_at'),
        }),
        (_('Processing'), {
            'fields': ('processed_by', 'processing_notes'),
        }),
        (_('Dates'), {
            'fields': ('submitted_at', 'due_date', 'completed_at', 'is_overdue', 'days_remaining'),
        }),
        (_('Response'), {
            'fields': ('response_data', 'response_file', 'rejection_reason'),
            'classes': ('collapse',),
        }),
        (_('Metadata'), {
            'fields': ('uuid', 'ip_address', 'user_agent'),
            'classes': ('collapse',),
        }),
    )

    actions = ['mark_verified', 'mark_completed', 'mark_rejected']

    def uuid_short(self, obj):
        return obj.uuid.hex[:8]

    uuid_short.short_description = _('ID')

    def requester_display(self, obj):
        if obj.user:
            return obj.user.email
        return obj.requester_email

    requester_display.short_description = _('Requester')

    def status_colored(self, obj):
        colors = {
            'pending': 'orange',
            'verified': 'blue',
            'in_progress': 'blue',
            'completed': 'green',
            'rejected': 'red',
            'cancelled': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_status_display()
        )

    status_colored.short_description = _('Status')

    def days_remaining_display(self, obj):
        if obj.is_overdue:
            return format_html('<span style="color: red;">OVERDUE</span>')
        if obj.days_remaining is None:
            return '-'
        return f'{obj.days_remaining} days'

    days_remaining_display.short_description = _('Due In')

    def mark_verified(self, request, queryset):
        count = queryset.filter(
            status=DataSubjectRequest.RequestStatus.PENDING
        ).update(
            status=DataSubjectRequest.RequestStatus.VERIFIED,
            identity_verified=True,
            verified_by=request.user,
        )
        self.message_user(request, _('%(count)d request(s) marked as verified.') % {'count': count})

    mark_verified.short_description = _('Mark as identity verified')

    def mark_completed(self, request, queryset):
        from django.utils import timezone
        count = queryset.exclude(
            status__in=[DataSubjectRequest.RequestStatus.COMPLETED, DataSubjectRequest.RequestStatus.CANCELLED]
        ).update(
            status=DataSubjectRequest.RequestStatus.COMPLETED,
            completed_at=timezone.now(),
            processed_by=request.user,
        )
        self.message_user(request, _('%(count)d request(s) marked as completed.') % {'count': count})

    mark_completed.short_description = _('Mark as completed')

    def mark_rejected(self, request, queryset):
        from django.utils import timezone
        count = queryset.exclude(
            status__in=[DataSubjectRequest.RequestStatus.COMPLETED, DataSubjectRequest.RequestStatus.CANCELLED]
        ).update(
            status=DataSubjectRequest.RequestStatus.REJECTED,
            completed_at=timezone.now(),
            processed_by=request.user,
        )
        self.message_user(request, _('%(count)d request(s) marked as rejected.') % {'count': count})

    mark_rejected.short_description = _('Mark as rejected')


@admin.register(DataRetentionPolicy)
class DataRetentionPolicyAdmin(admin.ModelAdmin):
    """Admin for Data Retention Policies."""

    list_display = [
        'name', 'model_name', 'retention_days', 'deletion_strategy',
        'is_enabled', 'legal_hold_status', 'last_executed_at', 'records_processed', 'tenant',
    ]
    list_filter = ['is_enabled', 'deletion_strategy', 'legal_hold_enabled', 'tenant']
    search_fields = ['name', 'model_name', 'description']
    readonly_fields = ['uuid', 'last_executed_at', 'records_processed', 'created_at', 'updated_at']

    fieldsets = (
        (None, {
            'fields': ('tenant', 'name', 'description', 'model_name', 'content_type')
        }),
        (_('Retention Settings'), {
            'fields': ('retention_days', 'retention_field', 'deletion_strategy')
        }),
        (_('Anonymization'), {
            'fields': ('fields_to_anonymize',),
            'classes': ('collapse',),
        }),
        (_('Filters'), {
            'fields': ('filter_conditions', 'exempt_conditions'),
            'classes': ('collapse',),
        }),
        (_('Legal Hold'), {
            'fields': ('legal_hold_enabled', 'legal_hold_reason', 'legal_hold_until'),
        }),
        (_('Scheduling'), {
            'fields': ('is_enabled', 'last_executed_at', 'records_processed'),
        }),
        (_('Notifications'), {
            'fields': ('notify_before_days', 'notification_recipients'),
            'classes': ('collapse',),
        }),
        (_('Metadata'), {
            'fields': ('uuid', 'created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )

    def legal_hold_status(self, obj):
        if obj.is_under_legal_hold:
            return format_html('<span style="color: red;">ON HOLD</span>')
        return format_html('<span style="color: green;">Normal</span>')

    legal_hold_status.short_description = _('Legal Hold')


@admin.register(PrivacyAuditLog)
class PrivacyAuditLogAdmin(admin.ModelAdmin):
    """Admin for Privacy Audit Logs (read-only)."""

    list_display = [
        'timestamp', 'action', 'actor', 'data_subject', 'description', 'tenant',
    ]
    list_filter = ['action', 'timestamp', 'tenant']
    search_fields = ['description', 'actor__email', 'data_subject__email']
    readonly_fields = [
        'uuid', 'tenant', 'action', 'description', 'actor', 'data_subject',
        'related_content_type', 'related_object_id', 'context',
        'ip_address', 'user_agent', 'timestamp',
    ]
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
