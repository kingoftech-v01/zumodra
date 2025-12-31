"""
API Base Serializers - Tenant-Aware Serializer Foundation for Zumodra API

This module provides base serializer classes with tenant awareness:
- TenantAwareSerializer: Base serializer with tenant context
- AuditFieldsMixin: Automatic audit field handling
- NestedSerializerMixin: Helpers for nested serializers
- TenantWritableSerializer: For create/update with tenant assignment
- ReadOnlyFieldsMixin: Common read-only field patterns

All serializers ensure proper tenant isolation and audit trail.
"""

import logging
from typing import Any, Dict, List, Optional, Type

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)
User = get_user_model()


# =============================================================================
# MIXINS
# =============================================================================

class TenantContextMixin:
    """
    Mixin providing tenant context utilities for serializers.
    """

    @property
    def tenant(self):
        """Get tenant from serializer context."""
        return self.context.get('tenant')

    @property
    def current_user(self):
        """Get current user from serializer context."""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            return request.user
        return self.context.get('user')

    @property
    def request(self):
        """Get request from serializer context."""
        return self.context.get('request')

    def get_tenant_or_error(self):
        """Get tenant or raise validation error."""
        tenant = self.tenant
        if not tenant:
            raise ValidationError(
                "Tenant context required for this operation."
            )
        return tenant


class AuditFieldsMixin:
    """
    Mixin for handling audit fields (created_by, updated_by, etc.).

    Automatically sets:
    - created_by: User who created the record (on create)
    - updated_by: User who last updated the record (on update)
    - created_at: Timestamp (read-only)
    - updated_at: Timestamp (read-only)

    Usage:
        class MySerializer(AuditFieldsMixin, TenantAwareSerializer):
            class Meta:
                model = MyModel
                fields = [..., 'created_by', 'updated_by', 'created_at', 'updated_at']
                audit_fields = ['created_by', 'updated_by']  # Optional: customize
    """

    # Default audit field names - can be overridden in Meta
    CREATED_BY_FIELD = 'created_by'
    UPDATED_BY_FIELD = 'updated_by'
    CREATED_AT_FIELD = 'created_at'
    UPDATED_AT_FIELD = 'updated_at'

    def get_audit_fields(self) -> List[str]:
        """Get list of audit field names from Meta or defaults."""
        meta = getattr(self, 'Meta', None)
        if meta and hasattr(meta, 'audit_fields'):
            return meta.audit_fields
        return [
            self.CREATED_BY_FIELD,
            self.UPDATED_BY_FIELD,
            self.CREATED_AT_FIELD,
            self.UPDATED_AT_FIELD,
        ]

    def create(self, validated_data: Dict) -> Any:
        """Set created_by on create."""
        user = self.current_user if hasattr(self, 'current_user') else None

        if user and user.is_authenticated:
            # Set created_by if field exists on model
            model = getattr(self.Meta, 'model', None)
            if model and hasattr(model, self.CREATED_BY_FIELD):
                if self.CREATED_BY_FIELD not in validated_data:
                    validated_data[self.CREATED_BY_FIELD] = user

        return super().create(validated_data)

    def update(self, instance: Any, validated_data: Dict) -> Any:
        """Set updated_by on update."""
        user = self.current_user if hasattr(self, 'current_user') else None

        if user and user.is_authenticated:
            # Set updated_by if field exists on model
            model = getattr(self.Meta, 'model', None)
            if model and hasattr(model, self.UPDATED_BY_FIELD):
                validated_data[self.UPDATED_BY_FIELD] = user

        return super().update(instance, validated_data)


class ReadOnlyFieldsMixin:
    """
    Mixin for marking common fields as read-only.

    Automatically marks these fields as read-only:
    - id, uuid, pk
    - created_at, updated_at
    - created_by, updated_by
    """

    COMMON_READ_ONLY_FIELDS = (
        'id', 'pk', 'uuid',
        'created_at', 'updated_at',
        'created_by', 'updated_by',
    )

    def get_fields(self):
        """Mark common fields as read-only."""
        fields = super().get_fields()

        for field_name in self.COMMON_READ_ONLY_FIELDS:
            if field_name in fields:
                fields[field_name].read_only = True

        return fields


class NestedSerializerMixin:
    """
    Mixin for handling nested serializer patterns.

    Provides utilities for:
    - Writable nested serializers
    - Creating/updating related objects
    - Handling foreign key representations

    Usage:
        class OrderSerializer(NestedSerializerMixin, TenantAwareSerializer):
            items = OrderItemSerializer(many=True, nested_write=True)

            class Meta:
                model = Order
                fields = ['id', 'customer', 'items']
                nested_fields = ['items']  # Fields to handle in nested create/update
    """

    def get_nested_fields(self) -> List[str]:
        """Get list of nested field names from Meta."""
        meta = getattr(self, 'Meta', None)
        return getattr(meta, 'nested_fields', [])

    def create(self, validated_data: Dict) -> Any:
        """Handle nested object creation."""
        nested_fields = self.get_nested_fields()
        nested_data = {}

        # Extract nested data
        for field_name in nested_fields:
            if field_name in validated_data:
                nested_data[field_name] = validated_data.pop(field_name)

        # Create main instance
        instance = super().create(validated_data)

        # Create nested objects
        for field_name, items_data in nested_data.items():
            self._create_nested(instance, field_name, items_data)

        return instance

    def update(self, instance: Any, validated_data: Dict) -> Any:
        """Handle nested object update."""
        nested_fields = self.get_nested_fields()
        nested_data = {}

        # Extract nested data
        for field_name in nested_fields:
            if field_name in validated_data:
                nested_data[field_name] = validated_data.pop(field_name)

        # Update main instance
        instance = super().update(instance, validated_data)

        # Update nested objects
        for field_name, items_data in nested_data.items():
            self._update_nested(instance, field_name, items_data)

        return instance

    def _create_nested(self, instance: Any, field_name: str, items_data: List[Dict]):
        """Create nested objects."""
        field = self.fields.get(field_name)
        if not field:
            return

        # Get the related manager
        related_manager = getattr(instance, field_name, None)
        if not related_manager:
            return

        # Get the child serializer
        child_serializer = field.child if hasattr(field, 'child') else None
        if not child_serializer:
            return

        for item_data in items_data:
            child_serializer_class = type(child_serializer)
            serializer = child_serializer_class(
                data=item_data,
                context=self.context
            )
            serializer.is_valid(raise_exception=True)

            # Add the foreign key to parent
            model = related_manager.model
            fk_field = self._get_fk_field(model, instance)
            if fk_field:
                serializer.validated_data[fk_field] = instance

            serializer.save()

    def _update_nested(self, instance: Any, field_name: str, items_data: List[Dict]):
        """Update nested objects (replace strategy)."""
        related_manager = getattr(instance, field_name, None)
        if not related_manager:
            return

        # Clear existing
        related_manager.all().delete()

        # Recreate
        self._create_nested(instance, field_name, items_data)

    def _get_fk_field(self, model: Type[models.Model], parent_instance: Any) -> Optional[str]:
        """Get the foreign key field name pointing to parent."""
        parent_model = type(parent_instance)
        for field in model._meta.get_fields():
            if isinstance(field, models.ForeignKey):
                if field.related_model == parent_model:
                    return field.name
        return None


# =============================================================================
# BASE SERIALIZERS
# =============================================================================

class TenantAwareSerializer(TenantContextMixin, serializers.ModelSerializer):
    """
    Base ModelSerializer with tenant awareness.

    Features:
    - Automatic tenant context from request
    - Tenant validation for related objects
    - User context for audit fields

    Usage:
        class EmployeeSerializer(TenantAwareSerializer):
            class Meta:
                model = Employee
                fields = ['uuid', 'first_name', 'last_name', 'department']
    """

    def validate_related_tenant(self, value: Any, field_name: str):
        """
        Validate that a related object belongs to the same tenant.

        Usage:
            def validate_department(self, value):
                return self.validate_related_tenant(value, 'department')
        """
        if value is None:
            return value

        tenant = self.tenant
        if not tenant:
            return value

        # Check if related object has tenant field
        if hasattr(value, 'tenant'):
            if value.tenant != tenant:
                raise ValidationError(
                    f"Selected {field_name} does not belong to your organization."
                )
        elif hasattr(value, 'tenant_id'):
            if value.tenant_id != tenant.pk:
                raise ValidationError(
                    f"Selected {field_name} does not belong to your organization."
                )

        return value

    def to_representation(self, instance):
        """Add tenant context to nested serializers."""
        # Ensure context is passed to nested serializers
        for field_name, field in self.fields.items():
            if hasattr(field, 'context'):
                field.context.update({
                    'tenant': self.tenant,
                    'request': self.request,
                })

        return super().to_representation(instance)


class TenantWritableSerializer(AuditFieldsMixin, TenantAwareSerializer):
    """
    Serializer for writable operations with automatic tenant assignment.

    Features:
    - Automatically sets tenant on create
    - Validates tenant ownership on update
    - Handles audit fields

    Usage:
        class JobPostingSerializer(TenantWritableSerializer):
            class Meta:
                model = JobPosting
                fields = ['uuid', 'title', 'description', ...]
                tenant_field = 'tenant'  # Optional: customize tenant field name
    """

    def get_tenant_field(self) -> str:
        """Get the tenant field name from Meta or default."""
        meta = getattr(self, 'Meta', None)
        return getattr(meta, 'tenant_field', 'tenant')

    def create(self, validated_data: Dict) -> Any:
        """Automatically set tenant on create."""
        tenant_field = self.get_tenant_field()
        tenant = self.get_tenant_or_error()

        # Set tenant if not already provided
        if tenant_field not in validated_data:
            validated_data[tenant_field] = tenant

        return super().create(validated_data)

    def update(self, instance: Any, validated_data: Dict) -> Any:
        """Validate tenant ownership on update."""
        tenant = self.tenant
        tenant_field = self.get_tenant_field()

        if tenant and hasattr(instance, tenant_field):
            instance_tenant = getattr(instance, tenant_field)
            if instance_tenant and instance_tenant != tenant:
                raise ValidationError(
                    "Cannot modify resources from another organization."
                )

        # Don't allow changing tenant
        if tenant_field in validated_data:
            del validated_data[tenant_field]

        return super().update(instance, validated_data)


class AuditableSerializer(AuditFieldsMixin, ReadOnlyFieldsMixin, TenantAwareSerializer):
    """
    Serializer with full audit trail support.

    Features:
    - Created/Updated by user tracking
    - Timestamp tracking
    - Read-only for audit fields

    Usage:
        class ContractSerializer(AuditableSerializer):
            class Meta:
                model = Contract
                fields = ['uuid', 'title', 'amount', 'created_by', 'created_at']
    """
    pass


# =============================================================================
# SPECIALIZED SERIALIZERS
# =============================================================================

class SlimSerializer(TenantAwareSerializer):
    """
    Base for lightweight serializers used in list views and dropdowns.

    Use for:
    - Select/dropdown options
    - List views with many items
    - References in other serializers

    Usage:
        class DepartmentSlimSerializer(SlimSerializer):
            class Meta:
                model = Department
                fields = ['uuid', 'name']  # Minimal fields only
    """

    class Meta:
        abstract = True


class DetailSerializer(AuditableSerializer):
    """
    Base for detailed serializers used in retrieve views.

    Use for:
    - Single object detail views
    - Full representation with nested data
    - Admin views

    Usage:
        class EmployeeDetailSerializer(DetailSerializer):
            department = DepartmentSerializer()
            manager = EmployeeSlimSerializer()

            class Meta:
                model = Employee
                fields = '__all__'
    """

    class Meta:
        abstract = True


class BulkSerializer(TenantWritableSerializer):
    """
    Serializer for bulk operations.

    Features:
    - Optimized for batch create/update
    - Validation caching
    - Transaction handling

    Usage:
        class BulkCandidateSerializer(BulkSerializer):
            class Meta:
                model = Candidate
                fields = ['email', 'first_name', 'last_name', 'source']
                bulk_create_fields = ['email']  # Fields to check for duplicates
    """

    def get_bulk_create_fields(self) -> List[str]:
        """Get fields to check for duplicates in bulk create."""
        meta = getattr(self, 'Meta', None)
        return getattr(meta, 'bulk_create_fields', [])

    def validate_bulk_unique(self, data_list: List[Dict]):
        """Validate uniqueness within the batch."""
        unique_fields = self.get_bulk_create_fields()
        if not unique_fields:
            return

        seen = {}
        for idx, item in enumerate(data_list):
            key = tuple(item.get(f) for f in unique_fields)
            if key in seen:
                raise ValidationError({
                    'non_field_errors': [
                        f"Duplicate entry at index {idx}: already seen at {seen[key]}"
                    ]
                })
            seen[key] = idx


# =============================================================================
# FIELD SERIALIZERS
# =============================================================================

class TenantPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    """
    PrimaryKeyRelatedField that filters queryset by tenant.

    Usage:
        class AssignmentSerializer(TenantAwareSerializer):
            employee = TenantPrimaryKeyRelatedField(
                queryset=Employee.objects.all()
            )
    """

    def get_queryset(self):
        queryset = super().get_queryset()

        if queryset is None:
            return queryset

        # Get tenant from context
        request = self.context.get('request')
        tenant = self.context.get('tenant')

        if not tenant and request:
            tenant = getattr(request, 'tenant', None)

        if tenant and hasattr(queryset.model, 'tenant'):
            queryset = queryset.filter(tenant=tenant)

        return queryset


class TenantSlugRelatedField(serializers.SlugRelatedField):
    """
    SlugRelatedField that filters queryset by tenant.

    Usage:
        class JobSerializer(TenantAwareSerializer):
            department = TenantSlugRelatedField(
                slug_field='uuid',
                queryset=Department.objects.all()
            )
    """

    def get_queryset(self):
        queryset = super().get_queryset()

        if queryset is None:
            return queryset

        tenant = self.context.get('tenant')
        request = self.context.get('request')

        if not tenant and request:
            tenant = getattr(request, 'tenant', None)

        if tenant and hasattr(queryset.model, 'tenant'):
            queryset = queryset.filter(tenant=tenant)

        return queryset


class CurrentTenantDefault:
    """
    Default value that uses the current tenant from context.

    Usage:
        class MySerializer(TenantAwareSerializer):
            tenant = serializers.HiddenField(
                default=CurrentTenantDefault()
            )
    """

    requires_context = True

    def __call__(self, serializer_field):
        tenant = serializer_field.context.get('tenant')
        if not tenant:
            request = serializer_field.context.get('request')
            if request:
                tenant = getattr(request, 'tenant', None)
        return tenant


class CurrentUserDefault:
    """
    Default value that uses the current user from context.

    Usage:
        class CommentSerializer(TenantAwareSerializer):
            author = serializers.HiddenField(
                default=CurrentUserDefault()
            )
    """

    requires_context = True

    def __call__(self, serializer_field):
        request = serializer_field.context.get('request')
        if request and hasattr(request, 'user'):
            return request.user
        return serializer_field.context.get('user')


# =============================================================================
# UTILITY SERIALIZERS
# =============================================================================

class EmptySerializer(serializers.Serializer):
    """
    Empty serializer for endpoints that don't require input/output.

    Usage:
        class RefreshTokenView(TenantAwareAPIView):
            serializer_class = EmptySerializer
    """
    pass


class MessageSerializer(serializers.Serializer):
    """
    Simple message response serializer.

    Usage:
        return Response(MessageSerializer({'message': 'Success'}).data)
    """
    message = serializers.CharField()


class IdListSerializer(serializers.Serializer):
    """
    Serializer for list of IDs (bulk operations).

    Usage:
        class BulkDeleteView(TenantAwareAPIView):
            def post(self, request):
                serializer = IdListSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                ids = serializer.validated_data['ids']
    """
    ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=1,
        max_length=100
    )


class UUIDListSerializer(serializers.Serializer):
    """
    Serializer for list of UUIDs (bulk operations).
    """
    uuids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
        max_length=100
    )


class PaginationSerializer(serializers.Serializer):
    """
    Serializer for pagination metadata.
    """
    count = serializers.IntegerField()
    page = serializers.IntegerField()
    page_size = serializers.IntegerField()
    total_pages = serializers.IntegerField()
    next = serializers.URLField(allow_null=True)
    previous = serializers.URLField(allow_null=True)


# =============================================================================
# DYNAMIC SERIALIZERS
# =============================================================================

def create_slim_serializer(model_class: Type[models.Model], fields: List[str] = None):
    """
    Factory function to create slim serializers dynamically.

    Usage:
        EmployeeSlim = create_slim_serializer(Employee, ['uuid', 'full_name'])
    """
    if fields is None:
        fields = ['id', 'uuid'] if hasattr(model_class, 'uuid') else ['id']
        if hasattr(model_class, 'name'):
            fields.append('name')
        if hasattr(model_class, '__str__'):
            fields.append('__str__')

    class DynamicSlimSerializer(SlimSerializer):
        class Meta:
            model = model_class
            fields = fields

        if '__str__' in fields:
            display = serializers.SerializerMethodField()

            def get_display(self, obj):
                return str(obj)

    return DynamicSlimSerializer


def make_serializer_read_only(serializer_class: Type[serializers.Serializer]):
    """
    Create a read-only version of a serializer.

    Usage:
        ReadOnlyEmployeeSerializer = make_serializer_read_only(EmployeeSerializer)
    """
    class ReadOnlySerializer(serializer_class):
        def get_fields(self):
            fields = super().get_fields()
            for field in fields.values():
                field.read_only = True
            return fields

    ReadOnlySerializer.__name__ = f'ReadOnly{serializer_class.__name__}'
    return ReadOnlySerializer
