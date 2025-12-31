"""
GDPR/Privacy Compliance Serializers for Zumodra ATS/HR Platform

This module provides DRF serializers for privacy-related API endpoints:
- ConsentRecordSerializer: For consent records
- DataSubjectRequestSerializer: For DSR requests
- PrivacyPolicySerializer: For privacy policies
- DataProcessingPurposeSerializer: For processing purposes
"""

from rest_framework import serializers

from core.privacy.models import (
    ConsentRecord,
    DataProcessingPurpose,
    DataSubjectRequest,
    PrivacyPolicy,
    PrivacyAuditLog,
)


class DataProcessingPurposeSerializer(serializers.ModelSerializer):
    """Serializer for DataProcessingPurpose model."""

    legal_basis_display = serializers.CharField(
        source='get_legal_basis_display',
        read_only=True
    )

    class Meta:
        model = DataProcessingPurpose
        fields = [
            'id', 'uuid', 'name', 'code', 'description',
            'legal_basis', 'legal_basis_display',
            'retention_days', 'data_categories',
            'third_party_sharing', 'third_party_recipients',
            'cross_border_transfer', 'transfer_safeguards',
            'is_mandatory', 'requires_explicit_consent',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'uuid', 'created_at', 'updated_at']


class PrivacyPolicySerializer(serializers.ModelSerializer):
    """Serializer for PrivacyPolicy model."""

    class Meta:
        model = PrivacyPolicy
        fields = [
            'id', 'uuid', 'version', 'title', 'content', 'summary',
            'effective_date', 'expiry_date', 'is_current', 'is_published',
            'language', 'document_hash', 'approved_at',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'uuid', 'document_hash', 'approved_at',
            'created_at', 'updated_at',
        ]


class ConsentRecordSerializer(serializers.ModelSerializer):
    """Serializer for ConsentRecord model."""

    consent_type_display = serializers.CharField(
        source='get_consent_type_display',
        read_only=True
    )
    purpose_name = serializers.CharField(
        source='purpose.name',
        read_only=True,
        allow_null=True
    )
    privacy_policy_version = serializers.CharField(
        source='privacy_policy.version',
        read_only=True,
        allow_null=True
    )
    is_valid = serializers.BooleanField(read_only=True)

    class Meta:
        model = ConsentRecord
        fields = [
            'id', 'uuid', 'user',
            'consent_type', 'consent_type_display',
            'purpose', 'purpose_name',
            'granted', 'consent_text_version', 'consent_text',
            'privacy_policy', 'privacy_policy_version',
            'ip_address', 'collection_method',
            'withdrawn', 'withdrawn_at',
            'expires_at', 'is_valid',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'uuid', 'user', 'ip_address', 'user_agent',
            'withdrawn', 'withdrawn_at', 'withdrawal_ip_address',
            'created_at', 'updated_at',
        ]


class ConsentCreateSerializer(serializers.Serializer):
    """Serializer for creating new consent records."""

    consent_type = serializers.ChoiceField(
        choices=ConsentRecord.ConsentType.choices
    )
    granted = serializers.BooleanField()
    consent_text = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=10000
    )
    purpose_code = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=50
    )


class ConsentWithdrawSerializer(serializers.Serializer):
    """Serializer for withdrawing consent."""

    reason = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=1000
    )


class DataSubjectRequestSerializer(serializers.ModelSerializer):
    """Serializer for DataSubjectRequest model."""

    request_type_display = serializers.CharField(
        source='get_request_type_display',
        read_only=True
    )
    status_display = serializers.CharField(
        source='get_status_display',
        read_only=True
    )
    is_overdue = serializers.BooleanField(read_only=True)
    days_remaining = serializers.IntegerField(read_only=True)
    user_email = serializers.EmailField(
        source='user.email',
        read_only=True,
        allow_null=True
    )

    class Meta:
        model = DataSubjectRequest
        fields = [
            'id', 'uuid', 'user', 'user_email',
            'requester_email', 'requester_name',
            'request_type', 'request_type_display',
            'status', 'status_display',
            'description', 'data_categories_requested',
            'rectification_details',
            'identity_verified', 'verification_method', 'verified_at',
            'submitted_at', 'due_date', 'completed_at',
            'is_overdue', 'days_remaining',
            'rejection_reason',
            'response_data',
        ]
        read_only_fields = [
            'id', 'uuid', 'user', 'requester_email', 'requester_name',
            'status', 'identity_verified', 'verification_method',
            'verified_at', 'processed_by', 'processing_notes',
            'submitted_at', 'due_date', 'completed_at',
            'response_data', 'response_file', 'rejection_reason',
        ]


class DataSubjectRequestCreateSerializer(serializers.Serializer):
    """Serializer for creating new DSR requests."""

    request_type = serializers.ChoiceField(
        choices=DataSubjectRequest.RequestType.choices
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=5000
    )
    data_categories = serializers.ListField(
        child=serializers.CharField(max_length=100),
        required=False,
        default=list
    )
    rectification_details = serializers.DictField(
        required=False,
        default=dict
    )
    export_format = serializers.ChoiceField(
        choices=[('json', 'JSON'), ('csv', 'CSV'), ('xml', 'XML')],
        required=False,
        default='json'
    )


class DataSubjectRequestStatusSerializer(serializers.Serializer):
    """Serializer for DSR status response."""

    request_id = serializers.UUIDField()
    status = serializers.CharField()
    status_display = serializers.CharField()
    request_type = serializers.CharField()
    submitted_at = serializers.DateTimeField()
    due_date = serializers.DateTimeField(allow_null=True)
    days_remaining = serializers.IntegerField(allow_null=True)
    is_overdue = serializers.BooleanField()
    completed_at = serializers.DateTimeField(allow_null=True)


class PrivacyAuditLogSerializer(serializers.ModelSerializer):
    """Serializer for PrivacyAuditLog model."""

    action_display = serializers.CharField(
        source='get_action_display',
        read_only=True
    )
    actor_email = serializers.EmailField(
        source='actor.email',
        read_only=True,
        allow_null=True
    )
    data_subject_email = serializers.EmailField(
        source='data_subject.email',
        read_only=True,
        allow_null=True
    )

    class Meta:
        model = PrivacyAuditLog
        fields = [
            'id', 'uuid', 'tenant',
            'action', 'action_display', 'description',
            'actor', 'actor_email',
            'data_subject', 'data_subject_email',
            'context', 'ip_address',
            'timestamp',
        ]
        read_only_fields = fields


class PrivacyDashboardSerializer(serializers.Serializer):
    """Serializer for the privacy dashboard summary."""

    active_consents = ConsentRecordSerializer(many=True)
    pending_requests = DataSubjectRequestSerializer(many=True)
    current_policy = PrivacyPolicySerializer(allow_null=True)
    policy_accepted = serializers.BooleanField()
    data_categories = serializers.ListField(
        child=serializers.CharField()
    )
    last_export = serializers.DateTimeField(allow_null=True)


class BulkConsentSerializer(serializers.Serializer):
    """Serializer for bulk consent operations."""

    consents = serializers.ListField(
        child=ConsentCreateSerializer()
    )


class ConsentExportSerializer(serializers.Serializer):
    """Serializer for exporting consent records."""

    from_date = serializers.DateTimeField(required=False)
    to_date = serializers.DateTimeField(required=False)
    consent_types = serializers.ListField(
        child=serializers.ChoiceField(choices=ConsentRecord.ConsentType.choices),
        required=False
    )
    include_withdrawn = serializers.BooleanField(default=True)
    format = serializers.ChoiceField(
        choices=[('json', 'JSON'), ('csv', 'CSV')],
        default='json'
    )
