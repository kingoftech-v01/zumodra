"""
Tenants Mixins - Reusable tenant-aware model and view mixins.

This module provides mixins for:
- TenantAwareModel: Base mixin for models that should be tenant-isolated
- TenantQuerySetMixin: QuerySet filtering by current tenant
- TenantAdminMixin: Admin classes with tenant awareness
- TenantViewMixin: View classes with tenant context
- TenantSerializerMixin: DRF serializers with tenant handling

Usage:
    from tenants.mixins import TenantAwareModelMixin

    class MyModel(TenantAwareModelMixin, models.Model):
        name = models.CharField(max_length=100)
        # tenant field added automatically

        class Meta:
            # Will add tenant to unique_together constraints
            pass
"""

import logging
from typing import Optional, TYPE_CHECKING, Any
from django.conf import settings
from django.db import models
from django.db.models import QuerySet
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from tenants.models import Tenant

logger = logging.getLogger(__name__)


# =============================================================================
# MODEL MIXINS
# =============================================================================

class TenantAwareManager(models.Manager):
    """
    Manager that automatically filters by current tenant.

    Use this as the default manager for tenant-isolated models.
    """

    def get_queryset(self) -> QuerySet:
        """
        Return queryset filtered by current tenant.

        SECURITY: Returns empty queryset when no tenant context is set
        to prevent data leakage. Use all_tenants() or for_tenant() for
        cross-tenant operations.
        """
        from tenants.context import get_current_tenant

        qs = super().get_queryset()
        tenant = get_current_tenant()

        if tenant is not None:
            return qs.filter(tenant=tenant)

        # CRITICAL: Fail-safe - return empty queryset when no tenant context
        # to prevent accidental data exposure across tenants
        logger.warning(
            "TenantAwareManager.get_queryset() called without tenant context. "
            "Returning empty queryset for security. Use all_tenants() for cross-tenant queries."
        )
        return qs.none()

    def for_tenant(self, tenant: 'Tenant') -> QuerySet:
        """
        Get queryset for a specific tenant.

        Args:
            tenant: The tenant to filter by.

        Returns:
            Filtered QuerySet.
        """
        return super().get_queryset().filter(tenant=tenant)

    def all_tenants(self) -> QuerySet:
        """
        Get queryset across all tenants.

        Use with caution - bypasses tenant isolation.
        Useful for admin operations and analytics.
        """
        return super().get_queryset()


class TenantAwareModelMixin(models.Model):
    """
    Mixin that adds tenant awareness to models.

    Provides:
    - Foreign key to Tenant model
    - Automatic tenant assignment on save
    - Manager that filters by current tenant
    - Validation to prevent cross-tenant operations

    Usage:
        class Job(TenantAwareModelMixin, models.Model):
            title = models.CharField(max_length=200)
            # tenant field is added automatically

            class Meta:
                pass  # Can add additional meta options
    """

    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='%(app_label)s_%(class)s_set',
        help_text=_('Tenant this object belongs to'),
        db_index=True,
    )

    # Managers
    objects = TenantAwareManager()
    all_objects = models.Manager()  # Bypass tenant filtering when needed

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """
        Save with automatic tenant assignment.

        If tenant is not set, attempts to get it from:
        1. Thread-local context
        2. Raises ValidationError if not found
        """
        if not self.tenant_id:
            from tenants.context import get_current_tenant
            tenant = get_current_tenant()

            if tenant is not None:
                self.tenant = tenant
            else:
                raise ValidationError(
                    _("Cannot save %(model)s without tenant context.") %
                    {'model': self.__class__.__name__}
                )

        super().save(*args, **kwargs)

    def clean(self):
        """Validate tenant context."""
        super().clean()

        if not self.tenant_id:
            from tenants.context import get_current_tenant
            if get_current_tenant() is None:
                raise ValidationError(
                    {'tenant': _('Tenant is required.')}
                )

    @classmethod
    def get_tenant_field_name(cls) -> str:
        """Return the name of the tenant field."""
        return 'tenant'


class TenantScopedModelMixin(TenantAwareModelMixin):
    """
    Extended tenant mixin with additional scope fields.

    Adds soft-delete support and created_by/updated_by tracking.
    Useful for models that need audit trails within tenant context.
    """

    # Soft delete
    is_deleted = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Soft delete flag')
    )
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(app_label)s_%(class)s_deleted',
    )

    # Audit tracking
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(app_label)s_%(class)s_created',
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(app_label)s_%(class)s_updated',
    )

    class Meta:
        abstract = True

    def soft_delete(self, user=None):
        """Mark as deleted without removing from database."""
        from django.utils import timezone
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = user
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by'])

    def restore(self):
        """Restore a soft-deleted record."""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by'])


class TenantScopedManager(TenantAwareManager):
    """Manager that also filters out soft-deleted objects."""

    def get_queryset(self) -> QuerySet:
        """Return queryset filtered by tenant and not deleted."""
        return super().get_queryset().filter(is_deleted=False)

    def with_deleted(self) -> QuerySet:
        """Include soft-deleted objects."""
        from tenants.context import get_current_tenant
        qs = models.Manager.get_queryset(self)
        tenant = get_current_tenant()
        if tenant is not None:
            return qs.filter(tenant=tenant)
        return qs

    def only_deleted(self) -> QuerySet:
        """Only soft-deleted objects."""
        return self.with_deleted().filter(is_deleted=True)


class TimestampMixin(models.Model):
    """
    Mixin that adds created_at and updated_at timestamps.
    """

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text=_('When this record was created')
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text=_('When this record was last updated')
    )

    class Meta:
        abstract = True
        ordering = ['-created_at']


class UUIDMixin(models.Model):
    """
    Mixin that adds a UUID field for external references.

    Useful when you don't want to expose auto-increment IDs.
    """
    import uuid

    uuid = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
        help_text=_('Unique identifier for external use')
    )

    class Meta:
        abstract = True


class TenantBaseModel(UUIDMixin, TimestampMixin, TenantAwareModelMixin):
    """
    Comprehensive base model combining common mixins.

    Includes:
    - UUID for external identification
    - Created/updated timestamps
    - Tenant isolation

    Usage:
        class MyModel(TenantBaseModel):
            name = models.CharField(max_length=100)

            class Meta(TenantBaseModel.Meta):
                pass
    """

    class Meta:
        abstract = True
        ordering = ['-created_at']


class TenantFullModel(UUIDMixin, TimestampMixin, TenantScopedModelMixin):
    """
    Full-featured tenant model with soft delete and audit tracking.

    Usage:
        class ImportantModel(TenantFullModel):
            name = models.CharField(max_length=100)

            objects = TenantScopedManager()
    """

    objects = TenantScopedManager()

    class Meta:
        abstract = True
        ordering = ['-created_at']


# =============================================================================
# VIEW MIXINS
# =============================================================================

class TenantViewMixin:
    """
    Mixin for Django views that need tenant context.

    Provides:
    - Access to current tenant
    - Tenant-scoped queryset filtering
    - Permission checking based on tenant role
    """

    def get_tenant(self) -> Optional['Tenant']:
        """Get the current tenant from request."""
        return getattr(self.request, 'tenant', None)

    def get_tenant_or_fail(self) -> 'Tenant':
        """Get tenant or raise 404."""
        from django.http import Http404
        tenant = self.get_tenant()
        if tenant is None:
            raise Http404("No tenant context")
        return tenant

    def get_queryset(self) -> QuerySet:
        """Filter queryset by current tenant."""
        qs = super().get_queryset()
        tenant = self.get_tenant()

        if tenant and hasattr(qs.model, 'tenant'):
            return qs.filter(tenant=tenant)

        return qs


class TenantListMixin(TenantViewMixin):
    """
    Mixin for list views with tenant filtering.

    Automatically filters queryset by current tenant.
    """

    def get_queryset(self) -> QuerySet:
        """Get tenant-filtered queryset for list views."""
        return super().get_queryset()


class TenantCreateMixin(TenantViewMixin):
    """
    Mixin for create views that auto-assign tenant.
    """

    def form_valid(self, form):
        """Set tenant before saving."""
        form.instance.tenant = self.get_tenant_or_fail()
        return super().form_valid(form)


class TenantUpdateMixin(TenantViewMixin):
    """
    Mixin for update views with tenant validation.
    """

    def get_object(self):
        """Ensure object belongs to current tenant."""
        obj = super().get_object()
        tenant = self.get_tenant()

        if tenant and hasattr(obj, 'tenant') and obj.tenant != tenant:
            from django.http import Http404
            raise Http404("Object not found")

        return obj


class TenantCRUDMixin(TenantCreateMixin, TenantUpdateMixin, TenantListMixin):
    """
    Combined mixin for CRUD views with tenant awareness.
    """
    pass


# =============================================================================
# ADMIN MIXINS
# =============================================================================

class TenantAdminMixin:
    """
    Mixin for Django admin classes with tenant awareness.

    Provides:
    - Automatic tenant filtering in admin
    - Tenant field auto-assignment
    - Custom admin actions scoped to tenant
    """

    def get_queryset(self, request):
        """Filter admin queryset by current tenant."""
        qs = super().get_queryset(request)
        tenant = getattr(request, 'tenant', None)

        if tenant and hasattr(qs.model, 'tenant'):
            return qs.filter(tenant=tenant)

        return qs

    def save_model(self, request, obj, form, change):
        """Auto-assign tenant on save."""
        if not change and hasattr(obj, 'tenant'):
            tenant = getattr(request, 'tenant', None)
            if tenant and not obj.tenant_id:
                obj.tenant = tenant

        super().save_model(request, obj, form, change)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Filter foreign key choices by tenant."""
        tenant = getattr(request, 'tenant', None)

        if tenant:
            related_model = db_field.related_model
            if hasattr(related_model, 'tenant'):
                kwargs['queryset'] = related_model.objects.filter(tenant=tenant)

        return super().formfield_for_foreignkey(db_field, request, **kwargs)


class TenantReadOnlyAdminMixin(TenantAdminMixin):
    """
    Admin mixin that makes tenant field read-only.
    """

    def get_readonly_fields(self, request, obj=None):
        """Add tenant to readonly fields."""
        readonly = list(super().get_readonly_fields(request, obj))
        if 'tenant' not in readonly and hasattr(self.model, 'tenant'):
            readonly.append('tenant')
        return readonly


# =============================================================================
# SERIALIZER MIXINS
# =============================================================================

class TenantSerializerMixin:
    """
    Mixin for DRF serializers with tenant handling.

    Provides:
    - Automatic tenant assignment from request context
    - Tenant field hiding from API responses
    - Related object filtering by tenant
    """

    def get_tenant(self) -> Optional['Tenant']:
        """Get tenant from serializer context."""
        request = self.context.get('request')
        if request:
            return getattr(request, 'tenant', None)
        return None

    def create(self, validated_data):
        """Set tenant on create."""
        tenant = self.get_tenant()
        if tenant and 'tenant' not in validated_data:
            validated_data['tenant'] = tenant
        return super().create(validated_data)

    def validate(self, attrs):
        """Validate tenant context exists."""
        attrs = super().validate(attrs)

        # Check if model requires tenant
        model = getattr(self.Meta, 'model', None)
        if model and hasattr(model, 'tenant'):
            if not self.get_tenant() and not attrs.get('tenant'):
                from rest_framework import serializers
                raise serializers.ValidationError(
                    {'tenant': 'Tenant context is required.'}
                )

        return attrs


class TenantHiddenFieldMixin:
    """
    Mixin that hides the tenant field from serialized output.

    Use when you don't want to expose tenant info in API responses.
    """

    def to_representation(self, instance):
        """Remove tenant from response."""
        data = super().to_representation(instance)
        data.pop('tenant', None)
        data.pop('tenant_id', None)
        return data


class TenantNestedSerializerMixin(TenantSerializerMixin):
    """
    Mixin for serializers with nested tenant-aware objects.

    Ensures nested creates/updates respect tenant isolation.
    """

    def create(self, validated_data):
        """Handle nested objects with tenant assignment."""
        tenant = self.get_tenant()

        # Process nested objects
        for field_name, field in self.fields.items():
            if hasattr(field, 'child') and isinstance(field.child, TenantSerializerMixin):
                nested_data = validated_data.get(field_name, [])
                for item in nested_data:
                    if 'tenant' not in item and tenant:
                        item['tenant'] = tenant

        return super().create(validated_data)


# =============================================================================
# FORM MIXINS
# =============================================================================

class TenantFormMixin:
    """
    Mixin for Django forms with tenant handling.
    """

    def __init__(self, *args, tenant=None, **kwargs):
        self.tenant = tenant
        super().__init__(*args, **kwargs)

        # Filter foreign key choices by tenant
        if self.tenant:
            self._filter_choices_by_tenant()

    def _filter_choices_by_tenant(self):
        """Filter form field choices by tenant."""
        for field_name, field in self.fields.items():
            if hasattr(field, 'queryset'):
                model = field.queryset.model
                if hasattr(model, 'tenant'):
                    field.queryset = field.queryset.filter(tenant=self.tenant)

    def save(self, commit=True):
        """Set tenant before saving."""
        instance = super().save(commit=False)

        if hasattr(instance, 'tenant') and not instance.tenant_id:
            if self.tenant:
                instance.tenant = self.tenant

        if commit:
            instance.save()
            self.save_m2m()

        return instance


class TenantModelFormMixin(TenantFormMixin):
    """
    Mixin specifically for ModelForms with tenant handling.
    """

    def __init__(self, *args, **kwargs):
        tenant = kwargs.pop('tenant', None)
        super().__init__(*args, tenant=tenant, **kwargs)

        # Hide tenant field if present
        if 'tenant' in self.fields:
            self.fields['tenant'].widget = self.fields['tenant'].hidden_widget()
            if self.tenant:
                self.fields['tenant'].initial = self.tenant


# =============================================================================
# PERMISSION MIXINS
# =============================================================================

class TenantPermissionMixin:
    """
    Mixin for permission classes that need tenant context.
    """

    def get_tenant_from_request(self, request) -> Optional['Tenant']:
        """Extract tenant from request."""
        return getattr(request, 'tenant', None)

    def get_tenant_user(self, request):
        """Get TenantUser for current user in current tenant."""
        from tenant_profiles.models import TenantUser

        if not request.user.is_authenticated:
            return None

        tenant = self.get_tenant_from_request(request)
        if not tenant:
            return None

        try:
            return TenantUser.objects.get(
                user=request.user,
                tenant=tenant,
                is_active=True
            )
        except TenantUser.DoesNotExist:
            return None


class FeatureGateMixin:
    """
    Mixin to check tenant plan features.
    """

    required_feature: Optional[str] = None

    def has_feature(self, request, feature: str = None) -> bool:
        """Check if tenant plan has a feature."""
        tenant = getattr(request, 'tenant', None)
        if not tenant or not tenant.plan:
            return False

        feature_name = feature or self.required_feature
        if not feature_name:
            return True

        feature_attr = f'feature_{feature_name}'
        return getattr(tenant.plan, feature_attr, False)

    def check_feature(self, request):
        """Check feature and raise if not available."""
        if self.required_feature and not self.has_feature(request):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied(
                f"Your plan does not include the {self.required_feature} feature."
            )


class LimitCheckMixin:
    """
    Mixin to check tenant plan limits.
    """

    def check_limit(self, request, resource: str, increment: int = 1) -> bool:
        """Check if tenant is within limits for a resource."""
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return False

        from tenants.services import TenantService
        return TenantService.check_limit(tenant, resource, increment)

    def enforce_limit(self, request, resource: str, increment: int = 1):
        """Raise exception if limit exceeded."""
        if not self.check_limit(request, resource, increment):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied(
                f"You have reached your plan's limit for {resource}. "
                "Please upgrade your plan to add more."
            )
