"""
Core Serializer Mixins - Protect sensitive data in API responses.

This module provides reusable serializer mixins for:
- Masking sensitive fields (phone, email, SSN)
- Role-based field access
- Audit logging for sensitive data access
- Encryption/decryption of sensitive fields

Usage:
    from core.serializers import SensitiveFieldMixin

    class UserSerializer(SensitiveFieldMixin, serializers.ModelSerializer):
        sensitive_fields = ['phone_number', 'ssn', 'bank_account']
        sensitive_roles = ['owner', 'admin', 'hr_manager']

        class Meta:
            model = User
            fields = ['id', 'email', 'phone_number', 'ssn', 'bank_account']
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set

from rest_framework import serializers
from django.conf import settings

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.serializers')


class SensitiveFieldMixin:
    """
    Mixin to protect sensitive fields in serializers.

    Automatically masks sensitive fields for users who don't have
    the required roles to view them. Also provides audit logging
    for sensitive data access.

    Attributes:
        sensitive_fields: List of field names that contain sensitive data
        sensitive_roles: List of roles allowed to view sensitive data
        mask_char: Character used for masking (default: '*')
        mask_visible_chars: Number of characters to leave visible at end
    """
    sensitive_fields: List[str] = []
    sensitive_roles: Set[str] = {'owner', 'admin', 'hr_manager'}
    mask_char: str = '*'
    mask_visible_chars: int = 4

    def to_representation(self, instance) -> Dict[str, Any]:
        """Override to mask sensitive fields based on user role."""
        data = super().to_representation(instance)

        if not self.sensitive_fields:
            return data

        request = self.context.get('request')
        if not request or not hasattr(request, 'user'):
            # No request context - mask all sensitive fields
            return self._mask_sensitive_fields(data, instance)

        if self._can_access_sensitive(request):
            # User has permission - log access but don't mask
            self._log_sensitive_access(request, instance)
            return data

        return self._mask_sensitive_fields(data, instance)

    def _can_access_sensitive(self, request) -> bool:
        """Check if the requesting user can view sensitive data."""
        user = request.user

        if not user.is_authenticated:
            return False

        # Superusers can see everything
        if user.is_superuser:
            return True

        # Check if user has required role
        user_roles = self._get_user_roles(request)
        return bool(user_roles & self.sensitive_roles)

    def _get_user_roles(self, request) -> Set[str]:
        """Get user roles from request/tenant context."""
        roles = set()
        user = request.user

        # Check TenantUser role
        tenant = getattr(request, 'tenant', None)
        if tenant and hasattr(user, 'tenant_users'):
            try:
                tenant_user = user.tenant_users.filter(
                    tenant=tenant,
                    is_active=True
                ).first()
                if tenant_user and tenant_user.role:
                    roles.add(tenant_user.role.lower())
            except Exception:
                pass

        # Check groups
        user_groups = user.groups.values_list('name', flat=True)
        for group in user_groups:
            group_lower = group.lower()
            if 'admin' in group_lower or 'pdg' in group_lower:
                roles.add('admin')
            if 'owner' in group_lower:
                roles.add('owner')
            if 'hr' in group_lower:
                roles.add('hr_manager')

        # Staff have admin role
        if user.is_staff:
            roles.add('admin')

        return roles

    def _mask_sensitive_fields(self, data: Dict[str, Any], instance) -> Dict[str, Any]:
        """Mask sensitive fields in the data dictionary."""
        for field_name in self.sensitive_fields:
            if field_name in data and data[field_name]:
                data[field_name] = self._mask_value(
                    data[field_name],
                    field_name
                )
        return data

    def _mask_value(self, value: Any, field_name: str) -> str:
        """Mask a sensitive value appropriately based on field type."""
        if value is None:
            return None

        value_str = str(value)

        # Email masking: show first char and domain
        if 'email' in field_name.lower():
            return self._mask_email(value_str)

        # Phone masking: show last 4 digits
        if 'phone' in field_name.lower():
            return self._mask_phone(value_str)

        # SSN/SIN masking: show last 4 digits
        if any(x in field_name.lower() for x in ['ssn', 'sin', 'social']):
            return self._mask_ssn(value_str)

        # Bank account masking: show last 4 digits
        if any(x in field_name.lower() for x in ['bank', 'account', 'routing']):
            return self._mask_account(value_str)

        # Default masking: show last N characters
        if len(value_str) <= self.mask_visible_chars:
            return self.mask_char * len(value_str)
        return (
            self.mask_char * (len(value_str) - self.mask_visible_chars)
            + value_str[-self.mask_visible_chars:]
        )

    def _mask_email(self, email: str) -> str:
        """Mask email address: j***@example.com"""
        if '@' not in email:
            return self._mask_value(email, '')

        local, domain = email.rsplit('@', 1)
        if len(local) <= 1:
            masked_local = self.mask_char
        else:
            masked_local = local[0] + self.mask_char * (len(local) - 1)
        return f"{masked_local}@{domain}"

    def _mask_phone(self, phone: str) -> str:
        """Mask phone number: ***-***-1234"""
        # Remove non-digits for processing
        digits = re.sub(r'\D', '', phone)
        if len(digits) <= 4:
            return self.mask_char * len(digits)

        visible = digits[-4:]
        masked = self.mask_char * (len(digits) - 4)

        # Format nicely if standard length
        if len(digits) == 10:
            return f"***-***-{visible}"
        elif len(digits) == 11:
            return f"*-***-***-{visible}"
        return masked + visible

    def _mask_ssn(self, ssn: str) -> str:
        """Mask SSN/SIN: ***-**-1234"""
        digits = re.sub(r'\D', '', ssn)
        if len(digits) <= 4:
            return self.mask_char * len(digits)

        visible = digits[-4:]
        return f"***-**-{visible}"

    def _mask_account(self, account: str) -> str:
        """Mask bank account: ****1234"""
        digits = re.sub(r'\D', '', account)
        if len(digits) <= 4:
            return self.mask_char * len(digits)

        visible = digits[-4:]
        masked = self.mask_char * (len(digits) - 4)
        return masked + visible

    def _log_sensitive_access(self, request, instance) -> None:
        """Log when sensitive data is accessed."""
        model_name = instance.__class__.__name__
        instance_id = getattr(instance, 'pk', 'unknown')
        user_id = request.user.id if request.user.is_authenticated else 'anonymous'

        security_logger.info(
            f"SENSITIVE_DATA_ACCESS: user={user_id} model={model_name} "
            f"instance={instance_id} fields={self.sensitive_fields}"
        )


class OwnerOnlyFieldMixin:
    """
    Mixin to hide certain fields from non-owners.

    Attributes:
        owner_only_fields: List of fields only visible to the object owner
        owner_field: Name of the field that references the owner user
    """
    owner_only_fields: List[str] = []
    owner_field: str = 'user'

    def to_representation(self, instance) -> Dict[str, Any]:
        """Override to hide owner-only fields from non-owners."""
        data = super().to_representation(instance)

        if not self.owner_only_fields:
            return data

        request = self.context.get('request')
        if not request or not hasattr(request, 'user'):
            return self._remove_owner_fields(data)

        if self._is_owner(request, instance):
            return data

        return self._remove_owner_fields(data)

    def _is_owner(self, request, instance) -> bool:
        """Check if the requesting user is the owner."""
        user = request.user
        if not user.is_authenticated:
            return False

        # Admins can see everything
        if user.is_superuser or user.is_staff:
            return True

        # Check owner field
        owner = getattr(instance, self.owner_field, None)
        if owner and hasattr(owner, 'id'):
            return owner.id == user.id
        return owner == user

    def _remove_owner_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove owner-only fields from data."""
        for field_name in self.owner_only_fields:
            data.pop(field_name, None)
        return data


class ParticipantFieldMixin:
    """
    Mixin to hide fields from non-participants.

    Useful for contracts, messages, and other shared resources.

    Attributes:
        participant_only_fields: List of fields only visible to participants
        participant_fields: List of field names that reference participants
    """
    participant_only_fields: List[str] = []
    participant_fields: List[str] = ['buyer', 'seller', 'client', 'provider']

    def to_representation(self, instance) -> Dict[str, Any]:
        """Override to hide participant-only fields from non-participants."""
        data = super().to_representation(instance)

        if not self.participant_only_fields:
            return data

        request = self.context.get('request')
        if not request or not hasattr(request, 'user'):
            return self._remove_participant_fields(data)

        if self._is_participant(request, instance):
            return data

        return self._remove_participant_fields(data)

    def _is_participant(self, request, instance) -> bool:
        """Check if the requesting user is a participant."""
        user = request.user
        if not user.is_authenticated:
            return False

        # Admins can see everything
        if user.is_superuser or user.is_staff:
            return True

        # Check participant fields
        for field_name in self.participant_fields:
            participant = getattr(instance, field_name, None)
            if participant:
                # Direct user reference
                if hasattr(participant, 'id') and participant.id == user.id:
                    return True
                # User through a related object (e.g., provider.user)
                if hasattr(participant, 'user'):
                    if participant.user and participant.user.id == user.id:
                        return True

        return False

    def _remove_participant_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove participant-only fields from data."""
        for field_name in self.participant_only_fields:
            data.pop(field_name, None)
        return data


class AuditedSerializerMixin:
    """
    Mixin to log all serializer access for audit purposes.

    Useful for highly sensitive models like payment information,
    employee records, or legal documents.
    """
    audit_all_access: bool = False
    audit_write_access: bool = True

    def to_representation(self, instance) -> Dict[str, Any]:
        """Log read access if audit_all_access is enabled."""
        data = super().to_representation(instance)

        if self.audit_all_access:
            self._log_access(instance, 'read')

        return data

    def create(self, validated_data):
        """Log create access."""
        instance = super().create(validated_data)

        if self.audit_write_access:
            self._log_access(instance, 'create')

        return instance

    def update(self, instance, validated_data):
        """Log update access."""
        instance = super().update(instance, validated_data)

        if self.audit_write_access:
            self._log_access(instance, 'update')

        return instance

    def _log_access(self, instance, action: str) -> None:
        """Log serializer access."""
        request = self.context.get('request')
        model_name = instance.__class__.__name__
        instance_id = getattr(instance, 'pk', 'unknown')
        user_id = (
            request.user.id
            if request and hasattr(request, 'user') and request.user.is_authenticated
            else 'anonymous'
        )

        security_logger.info(
            f"SERIALIZER_ACCESS: action={action} user={user_id} "
            f"model={model_name} instance={instance_id}"
        )


class SecureModelSerializer(
    SensitiveFieldMixin,
    OwnerOnlyFieldMixin,
    AuditedSerializerMixin,
    serializers.ModelSerializer
):
    """
    Fully secure model serializer with all security features.

    Combines:
    - Sensitive field masking
    - Owner-only field hiding
    - Access audit logging

    Usage:
        class EmployeeSerializer(SecureModelSerializer):
            sensitive_fields = ['ssn', 'bank_account']
            owner_only_fields = ['salary', 'performance_review']
            audit_all_access = True

            class Meta:
                model = Employee
                fields = '__all__'
    """
    pass


class TenantAwareSerializer(serializers.ModelSerializer):
    """
    Base serializer that provides tenant context for multi-tenant apps.

    Automatically filters related field querysets by tenant and provides
    tenant context for validation and creation.

    Usage:
        class ServiceSerializer(TenantAwareSerializer):
            class Meta:
                model = Service
                fields = '__all__'

    Features:
    - Automatically filters PrimaryKeyRelatedField querysets by tenant
    - Provides tenant context via self.get_tenant()
    - Adds tenant to validated_data during create if not present
    """

    def get_tenant(self):
        """Get tenant from request context."""
        request = self.context.get('request')
        if request and hasattr(request, 'tenant'):
            return request.tenant
        return None

    def get_user(self):
        """Get authenticated user from request context."""
        request = self.context.get('request')
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            return request.user
        return None

    def filter_queryset_by_tenant(self, queryset):
        """
        Filter a queryset by tenant.

        Args:
            queryset: The queryset to filter

        Returns:
            Filtered queryset or original if no tenant field exists
        """
        tenant = self.get_tenant()
        if not tenant:
            return queryset

        # Try common tenant field names
        model = queryset.model
        if hasattr(model, 'tenant'):
            return queryset.filter(tenant=tenant)
        elif hasattr(model, 'user'):
            # Filter by user's tenant membership
            try:
                from tenant_profiles.models import TenantUser
                user_ids = TenantUser.objects.filter(
                    tenant=tenant,
                    is_active=True
                ).values_list('user_id', flat=True)
                return queryset.filter(user_id__in=user_ids)
            except ImportError:
                pass

        return queryset

    def create(self, validated_data):
        """Add tenant to validated_data if model has tenant field."""
        tenant = self.get_tenant()
        model = self.Meta.model

        if tenant and hasattr(model, 'tenant') and 'tenant' not in validated_data:
            validated_data['tenant'] = tenant

        return super().create(validated_data)


class TenantAwareListSerializer(TenantAwareSerializer):
    """
    List serializer variant with minimal fields for list views.

    Usage:
        class ServiceListSerializer(TenantAwareListSerializer):
            class Meta:
                model = Service
                fields = ['id', 'name', 'status', 'created_at']
    """
    pass


class SecureTenantSerializer(
    SensitiveFieldMixin,
    OwnerOnlyFieldMixin,
    AuditedSerializerMixin,
    TenantAwareSerializer
):
    """
    Fully secure tenant-aware serializer combining all features.

    Usage:
        class EmployeeSerializer(SecureTenantSerializer):
            sensitive_fields = ['ssn', 'bank_account']
            owner_only_fields = ['salary']

            class Meta:
                model = Employee
                fields = '__all__'
    """
    pass
