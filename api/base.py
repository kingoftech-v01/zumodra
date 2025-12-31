"""
API Base Classes - Tenant-Aware Foundation for Zumodra API

This module provides the foundational classes for building tenant-aware REST APIs:
- TenantAwareAPIView: Base APIView with tenant context
- TenantAwareViewSet: Base ViewSet with tenant scoping
- Standard response format helpers
- Pagination classes with tenant awareness
- Global exception handlers
- Query optimization mixins for N+1 prevention
- ETag caching for bandwidth optimization
- Response compression support

All API views should inherit from these base classes to ensure:
1. Proper tenant isolation
2. Consistent response formats
3. Audit logging integration
4. Permission enforcement
5. Optimized database queries
6. Efficient caching
"""

import hashlib
import logging
import gzip
from typing import Any, Dict, List, Optional, Type, Tuple

from django.db.models import QuerySet, Prefetch, Max
from django.utils import timezone
from django.conf import settings
from django.http import HttpResponse

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet, GenericViewSet
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.pagination import PageNumberPagination, CursorPagination, LimitOffsetPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import (
    APIException, NotFound, PermissionDenied, ValidationError as DRFValidationError
)

logger = logging.getLogger(__name__)


# =============================================================================
# STANDARD RESPONSE HELPERS
# =============================================================================

class APIResponse:
    """
    Standardized API response format for consistent client handling.

    All responses follow this structure:
    {
        "success": bool,
        "data": {...} | [...],
        "message": str | null,
        "errors": [...] | null,
        "meta": {
            "timestamp": "ISO8601",
            "request_id": str,
            "tenant": str | null,
            "pagination": {...} | null
        }
    }
    """

    @staticmethod
    def success(
        data: Any = None,
        message: str = None,
        status_code: int = status.HTTP_200_OK,
        meta: Dict = None,
        headers: Dict = None,
        request: Request = None
    ) -> Response:
        """Create a successful response."""
        response_meta = {
            "timestamp": timezone.now().isoformat(),
            **(meta or {})
        }

        # Include request ID if available
        if request and hasattr(request, 'request_id'):
            response_meta["request_id"] = request.request_id

        response_data = {
            "success": True,
            "data": data,
            "message": message,
            "errors": None,
            "meta": response_meta
        }
        return Response(response_data, status=status_code, headers=headers)

    @staticmethod
    def created(
        data: Any = None,
        message: str = "Resource created successfully",
        meta: Dict = None
    ) -> Response:
        """Create a 201 Created response."""
        return APIResponse.success(
            data=data,
            message=message,
            status_code=status.HTTP_201_CREATED,
            meta=meta
        )

    @staticmethod
    def updated(
        data: Any = None,
        message: str = "Resource updated successfully",
        meta: Dict = None
    ) -> Response:
        """Create a successful update response."""
        return APIResponse.success(
            data=data,
            message=message,
            status_code=status.HTTP_200_OK,
            meta=meta
        )

    @staticmethod
    def deleted(
        message: str = "Resource deleted successfully",
        meta: Dict = None
    ) -> Response:
        """Create a 204 No Content response for deletions."""
        return Response(status=status.HTTP_204_NO_CONTENT)

    @staticmethod
    def error(
        message: str = "An error occurred",
        errors: List[Dict] = None,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        error_code: str = None,
        meta: Dict = None,
        request: Request = None
    ) -> Response:
        """Create an error response."""
        response_meta = {
            "timestamp": timezone.now().isoformat(),
            **(meta or {})
        }

        # Include request ID if available
        if request and hasattr(request, 'request_id'):
            response_meta["request_id"] = request.request_id

        response_data = {
            "success": False,
            "data": None,
            "message": message,
            "errors": errors or [],
            "error_code": error_code,
            "meta": response_meta
        }
        return Response(response_data, status=status_code)

    @staticmethod
    def not_found(
        message: str = "Resource not found",
        resource_type: str = None
    ) -> Response:
        """Create a 404 Not Found response."""
        return APIResponse.error(
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="NOT_FOUND",
            meta={"resource_type": resource_type} if resource_type else None
        )

    @staticmethod
    def forbidden(
        message: str = "Permission denied",
        required_permission: str = None
    ) -> Response:
        """Create a 403 Forbidden response."""
        return APIResponse.error(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="FORBIDDEN",
            meta={"required_permission": required_permission} if required_permission else None
        )

    @staticmethod
    def validation_error(
        errors: Dict[str, List[str]],
        message: str = "Validation failed"
    ) -> Response:
        """Create a 422 Validation Error response."""
        formatted_errors = [
            {"field": field, "messages": msgs}
            for field, msgs in errors.items()
        ]
        return APIResponse.error(
            message=message,
            errors=formatted_errors,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="VALIDATION_ERROR"
        )

    @staticmethod
    def paginated(
        data: List,
        page_info: Dict,
        message: str = None
    ) -> Response:
        """Create a paginated response."""
        return APIResponse.success(
            data=data,
            message=message,
            meta={"pagination": page_info}
        )


# =============================================================================
# PAGINATION CLASSES
# =============================================================================

class StandardPagination(PageNumberPagination):
    """
    Standard page-number based pagination with configurable page size.

    Query params:
    - page: Page number (1-indexed)
    - page_size: Items per page (default: 20, max: 100)
    """
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            "success": True,
            "data": data,
            "message": None,
            "errors": None,
            "meta": {
                "timestamp": timezone.now().isoformat(),
                "pagination": {
                    "count": self.page.paginator.count,
                    "page": self.page.number,
                    "page_size": self.get_page_size(self.request),
                    "total_pages": self.page.paginator.num_pages,
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                }
            }
        })


class LargeResultsPagination(PageNumberPagination):
    """
    Pagination for large result sets with higher limits.
    Use for admin/export views that need more data per page.
    """
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 500

    def get_paginated_response(self, data):
        return Response({
            "success": True,
            "data": data,
            "message": None,
            "errors": None,
            "meta": {
                "timestamp": timezone.now().isoformat(),
                "pagination": {
                    "count": self.page.paginator.count,
                    "page": self.page.number,
                    "page_size": self.get_page_size(self.request),
                    "total_pages": self.page.paginator.num_pages,
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                }
            }
        })


class CursorBasedPagination(CursorPagination):
    """
    Cursor-based pagination for real-time data and infinite scroll.
    More efficient for large datasets, prevents duplicate/missing items.

    Query params:
    - cursor: Encoded cursor position
    - page_size: Items per page
    """
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    ordering = '-created_at'  # Default ordering

    def get_paginated_response(self, data):
        return Response({
            "success": True,
            "data": data,
            "message": None,
            "errors": None,
            "meta": {
                "timestamp": timezone.now().isoformat(),
                "pagination": {
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                    "page_size": self.get_page_size(self.request),
                }
            }
        })


class TenantAwarePagination(StandardPagination):
    """
    Pagination that respects tenant plan limits.
    Adjusts max_page_size based on tenant's subscription tier.
    """

    def paginate_queryset(self, queryset, request, view=None):
        # Adjust max page size based on tenant plan
        tenant = getattr(request, 'tenant', None)
        if tenant and tenant.plan:
            plan_type = tenant.plan.plan_type
            if plan_type == 'enterprise':
                self.max_page_size = 500
            elif plan_type == 'professional':
                self.max_page_size = 200
            else:
                self.max_page_size = 100

        return super().paginate_queryset(queryset, request, view)


class ScalableCursorPagination(CursorPagination):
    """
    Cursor-based pagination optimized for 1M+ row tables.

    Advantages over offset pagination:
    - O(1) performance regardless of page number
    - Consistent results during concurrent writes
    - No duplicate/missing items when data changes

    Usage:
        class LargeDataViewSet(TenantAwareViewSet):
            pagination_class = ScalableCursorPagination
            cursor_ordering = '-created_at'  # Must be indexed
    """
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200
    ordering = '-created_at'  # Default, override via cursor_ordering

    def get_paginated_response(self, data):
        return Response({
            "success": True,
            "data": data,
            "message": None,
            "errors": None,
            "meta": {
                "timestamp": timezone.now().isoformat(),
                "pagination": {
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                    "page_size": self.get_page_size(self.request),
                    "cursor": self.cursor.position if hasattr(self, 'cursor') and self.cursor else None,
                }
            }
        })


# =============================================================================
# TENANT-AWARE BASE CLASSES
# =============================================================================

class TenantContextMixin:
    """
    Mixin providing tenant context utilities for views.
    """

    def get_tenant(self) -> Optional[Any]:
        """Get the current tenant from request."""
        return getattr(self.request, 'tenant', None)

    def get_tenant_or_404(self) -> Any:
        """Get the current tenant or raise NotFound."""
        tenant = self.get_tenant()
        if not tenant:
            raise NotFound("No tenant context found. Please access via a tenant domain.")
        return tenant

    def check_tenant_feature(self, feature_name: str) -> bool:
        """Check if the current tenant has access to a feature."""
        tenant = self.get_tenant()
        if not tenant or not tenant.plan:
            return False

        feature_attr = f'feature_{feature_name}'
        return getattr(tenant.plan, feature_attr, False)

    def require_tenant_feature(self, feature_name: str) -> None:
        """Raise PermissionDenied if tenant doesn't have the feature."""
        if not self.check_tenant_feature(feature_name):
            raise PermissionDenied(
                f"Your plan doesn't include the '{feature_name}' feature. "
                "Please upgrade to access this functionality."
            )

    def check_tenant_limit(self, limit_name: str, current_count: int) -> bool:
        """Check if tenant is within a specific limit."""
        tenant = self.get_tenant()
        if not tenant or not tenant.plan:
            return False

        limit_attr = f'max_{limit_name}'
        max_allowed = getattr(tenant.plan, limit_attr, 0)
        return current_count < max_allowed

    def get_audit_context(self) -> Dict:
        """Get context for audit logging."""
        return {
            'tenant': self.get_tenant(),
            'user': self.request.user if self.request.user.is_authenticated else None,
            'ip_address': self.get_client_ip(),
            'user_agent': self.request.META.get('HTTP_USER_AGENT', '')[:500],
        }

    def get_client_ip(self) -> Optional[str]:
        """Extract client IP from request."""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return self.request.META.get('REMOTE_ADDR')

    def add_tenant_to_serializer_context(self, context: Dict) -> Dict:
        """Add tenant to serializer context."""
        context['tenant'] = self.get_tenant()
        context['user'] = self.request.user
        return context


class TenantAwareAPIView(TenantContextMixin, APIView):
    """
    Base APIView with tenant awareness.

    Provides:
    - Automatic tenant context from request
    - Feature flag checking
    - Limit enforcement
    - Standardized response helpers
    - Audit logging context

    Usage:
        class MyView(TenantAwareAPIView):
            permission_classes = [IsAuthenticated, IsTenantMember]

            def get(self, request):
                self.require_tenant_feature('analytics')
                data = self.get_analytics_data()
                return self.success_response(data)
    """

    permission_classes = [IsAuthenticated]

    def success_response(self, data=None, message=None, **kwargs) -> Response:
        """Helper to return a standardized success response."""
        return APIResponse.success(data=data, message=message, **kwargs)

    def error_response(self, message, **kwargs) -> Response:
        """Helper to return a standardized error response."""
        return APIResponse.error(message=message, **kwargs)

    def get_serializer_context(self) -> Dict:
        """Get context for serializers with tenant info."""
        context = {
            'request': self.request,
            'view': self,
        }
        return self.add_tenant_to_serializer_context(context)


class TenantAwareViewSet(TenantContextMixin, ModelViewSet):
    """
    Base ModelViewSet with tenant awareness and automatic scoping.

    Provides:
    - Automatic queryset filtering by tenant
    - Tenant context in serializers
    - Standardized response format
    - Audit logging hooks
    - Feature/limit checking

    Subclasses should define:
    - tenant_field: Field name for tenant FK (default: 'tenant')
    - Or override get_queryset() for custom filtering

    Usage:
        class EmployeeViewSet(TenantAwareViewSet):
            queryset = Employee.objects.all()
            serializer_class = EmployeeSerializer
            tenant_field = 'tenant'  # or 'organization__tenant'
    """

    permission_classes = [IsAuthenticated]
    pagination_class = StandardPagination
    tenant_field = 'tenant'  # Override in subclass if different

    def get_queryset(self) -> QuerySet:
        """
        Filter queryset to current tenant.
        Override this method for custom tenant filtering logic.
        """
        queryset = super().get_queryset()
        tenant = self.get_tenant()

        if tenant and self.tenant_field:
            filter_kwargs = {self.tenant_field: tenant}
            queryset = queryset.filter(**filter_kwargs)

        return queryset

    def get_serializer_context(self) -> Dict:
        """Add tenant to serializer context."""
        context = super().get_serializer_context()
        return self.add_tenant_to_serializer_context(context)

    def perform_create(self, serializer):
        """
        Create with tenant context.
        Override to add tenant automatically to new objects.
        """
        tenant = self.get_tenant()
        if tenant and self.tenant_field and self.tenant_field == 'tenant':
            serializer.save(tenant=tenant)
        else:
            serializer.save()

    def create(self, request, *args, **kwargs):
        """Override to return standardized response."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return APIResponse.created(
            data=serializer.data,
            message=f"{self.get_model_name()} created successfully"
        )

    def update(self, request, *args, **kwargs):
        """Override to return standardized response."""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return APIResponse.updated(
            data=serializer.data,
            message=f"{self.get_model_name()} updated successfully"
        )

    def destroy(self, request, *args, **kwargs):
        """Override to return standardized response."""
        instance = self.get_object()
        self.perform_destroy(instance)
        return APIResponse.deleted()

    def list(self, request, *args, **kwargs):
        """Override to return standardized paginated response."""
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return APIResponse.success(data=serializer.data)

    def retrieve(self, request, *args, **kwargs):
        """Override to return standardized response."""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return APIResponse.success(data=serializer.data)

    def get_model_name(self) -> str:
        """Get human-readable model name for messages."""
        if hasattr(self, 'queryset') and self.queryset is not None:
            return self.queryset.model._meta.verbose_name.title()
        return "Resource"


class TenantAwareReadOnlyViewSet(TenantContextMixin, ReadOnlyModelViewSet):
    """
    Read-only ViewSet with tenant awareness.
    Use for resources that shouldn't be modified via API.
    """

    permission_classes = [IsAuthenticated]
    pagination_class = StandardPagination
    tenant_field = 'tenant'

    def get_queryset(self) -> QuerySet:
        """Filter queryset to current tenant."""
        queryset = super().get_queryset()
        tenant = self.get_tenant()

        if tenant and self.tenant_field:
            filter_kwargs = {self.tenant_field: tenant}
            queryset = queryset.filter(**filter_kwargs)

        return queryset

    def get_serializer_context(self) -> Dict:
        """Add tenant to serializer context."""
        context = super().get_serializer_context()
        return self.add_tenant_to_serializer_context(context)

    def list(self, request, *args, **kwargs):
        """Override to return standardized response."""
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return APIResponse.success(data=serializer.data)

    def retrieve(self, request, *args, **kwargs):
        """Override to return standardized response."""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return APIResponse.success(data=serializer.data)


# =============================================================================
# QUERY OPTIMIZATION MIXINS
# =============================================================================

class SelectRelatedMixin:
    """
    Mixin providing automatic select_related optimization for API views.

    Prevents N+1 queries for ForeignKey relationships by eagerly loading
    related objects in the same query.

    Usage:
        class EmployeeViewSet(SelectRelatedMixin, TenantAwareViewSet):
            queryset = Employee.objects.all()
            select_related_fields = ['user', 'department', 'manager']
    """

    # List of FK/O2O fields to include in select_related
    select_related_fields: List[str] = []

    def get_queryset(self) -> QuerySet:
        """Apply select_related optimization."""
        queryset = super().get_queryset()

        if self.select_related_fields:
            queryset = queryset.select_related(*self.select_related_fields)
            logger.debug(
                f"Applied select_related({self.select_related_fields}) "
                f"to {self.__class__.__name__}"
            )

        return queryset


class PrefetchRelatedMixin:
    """
    Mixin providing automatic prefetch_related optimization for API views.

    Prevents N+1 queries for ManyToMany and reverse ForeignKey relationships
    by fetching related objects in separate optimized queries.

    Supports both simple field names and custom Prefetch objects for
    advanced filtering/ordering of related data.

    Usage:
        class JobPostingViewSet(PrefetchRelatedMixin, TenantAwareViewSet):
            queryset = JobPosting.objects.all()
            prefetch_related_fields = ['applications', 'required_skills']

            # For advanced prefetching with filtering
            prefetch_related_objects = {
                'recent_applications': Prefetch(
                    'applications',
                    queryset=Application.objects.filter(
                        status='new'
                    ).select_related('candidate')[:10]
                )
            }
    """

    # Simple list of fields for prefetch_related
    prefetch_related_fields: List[str] = []

    # Dict of name -> Prefetch objects for advanced prefetching
    prefetch_related_objects: Dict[str, Prefetch] = {}

    def get_queryset(self) -> QuerySet:
        """Apply prefetch_related optimization."""
        queryset = super().get_queryset()

        # Apply custom Prefetch objects first
        for name, prefetch in getattr(self, 'prefetch_related_objects', {}).items():
            queryset = queryset.prefetch_related(prefetch)

        # Apply simple prefetch_related fields
        fields_to_prefetch = [
            f for f in self.prefetch_related_fields
            if f not in getattr(self, 'prefetch_related_objects', {})
        ]

        if fields_to_prefetch:
            queryset = queryset.prefetch_related(*fields_to_prefetch)
            logger.debug(
                f"Applied prefetch_related({fields_to_prefetch}) "
                f"to {self.__class__.__name__}"
            )

        return queryset


class DeferFieldsMixin:
    """
    Mixin for deferring heavy fields to reduce memory usage in list views.

    Useful when models have large text/binary fields that aren't needed
    in list displays but are required in detail views.

    Usage:
        class DocumentViewSet(DeferFieldsMixin, TenantAwareViewSet):
            queryset = Document.objects.all()
            defer_fields = ['content', 'binary_data']

            # Or only load specific fields
            only_fields = ['id', 'title', 'status', 'created_at']
    """

    # Fields to defer (exclude from query)
    defer_fields: List[str] = []

    # Only load these fields (overrides defer_fields)
    only_fields: List[str] = []

    # Apply defer/only only in list action
    defer_only_in_list: bool = True

    def get_queryset(self) -> QuerySet:
        """Apply defer/only optimization."""
        queryset = super().get_queryset()

        # Only apply in list action by default
        if self.defer_only_in_list and getattr(self, 'action', None) != 'list':
            return queryset

        # Apply only() if specified (takes precedence)
        if self.only_fields:
            queryset = queryset.only(*self.only_fields)

        # Otherwise apply defer()
        elif self.defer_fields:
            queryset = queryset.defer(*self.defer_fields)

        return queryset


class OptimizedQuerySetMixin(SelectRelatedMixin, PrefetchRelatedMixin, DeferFieldsMixin):
    """
    Combined mixin providing all query optimization features.

    Use this as a single mixin when you need select_related, prefetch_related,
    and defer/only optimizations together.

    Usage:
        class EmployeeViewSet(OptimizedQuerySetMixin, TenantAwareViewSet):
            queryset = Employee.objects.all()
            select_related_fields = ['user', 'department']
            prefetch_related_fields = ['skills', 'certifications']
            defer_fields = ['biography', 'notes']
    """
    pass


# =============================================================================
# ETAG CACHING MIXIN
# =============================================================================

class ETagCacheMixin:
    """
    Mixin providing ETag-based HTTP caching for bandwidth optimization.

    Implements conditional GET requests using ETags. When a client sends
    If-None-Match header with a matching ETag, returns 304 Not Modified
    instead of the full response body.

    Reduces bandwidth usage by up to 95% for unchanged resources.

    Usage:
        class EmployeeViewSet(ETagCacheMixin, TenantAwareViewSet):
            queryset = Employee.objects.all()

            # Optionally customize ETag generation
            def get_etag_value(self, request, obj):
                return f'{obj.pk}:{obj.version}'
    """

    # Enable ETag for list views (may be expensive for large lists)
    etag_enable_list: bool = True

    # Enable ETag for detail views
    etag_enable_detail: bool = True

    def get_etag_value(self, request: Request, obj: Any) -> Optional[str]:
        """
        Generate ETag value for a single object.

        Override this method to customize ETag generation based on your
        model's update tracking fields.

        Args:
            request: The HTTP request
            obj: Model instance

        Returns:
            ETag string or None to skip ETag
        """
        if obj is None:
            return None

        # Try common timestamp/version fields
        if hasattr(obj, 'updated_at') and obj.updated_at:
            return f'{obj.pk}:{obj.updated_at.isoformat()}'

        if hasattr(obj, 'version'):
            return f'{obj.pk}:v{obj.version}'

        if hasattr(obj, 'modified_at') and obj.modified_at:
            return f'{obj.pk}:{obj.modified_at.isoformat()}'

        return str(obj.pk)

    def get_list_etag_value(self, request: Request, queryset: QuerySet) -> Optional[str]:
        """
        Generate ETag value for a list view.

        Uses count and max updated_at to detect changes efficiently.

        Args:
            request: The HTTP request
            queryset: Filtered queryset

        Returns:
            ETag string or None to skip ETag
        """
        count = queryset.count()
        if count == 0:
            return 'empty'

        # Try to get max updated_at for change detection
        model = queryset.model
        if hasattr(model, 'updated_at'):
            max_updated = queryset.aggregate(max_updated=Max('updated_at'))
            if max_updated.get('max_updated'):
                return f'{count}:{max_updated["max_updated"].isoformat()}'

        return str(count)

    def check_etag_match(self, request: Request, etag: str) -> bool:
        """Check if client's If-None-Match header matches current ETag."""
        client_etag = request.META.get('HTTP_IF_NONE_MATCH', '')
        # Handle both quoted and unquoted ETags
        return client_etag in (f'"{etag}"', etag, f'W/"{etag}"')

    def add_etag_header(self, response: Response, etag: str) -> Response:
        """Add ETag header to response."""
        response['ETag'] = f'"{etag}"'
        response['Cache-Control'] = 'private, must-revalidate'
        return response

    def retrieve(self, request, *args, **kwargs):
        """Override retrieve to add ETag support."""
        if not self.etag_enable_detail:
            return super().retrieve(request, *args, **kwargs)

        instance = self.get_object()
        etag = self.get_etag_value(request, instance)

        if etag and self.check_etag_match(request, etag):
            return HttpResponse(status=304)

        response = super().retrieve(request, *args, **kwargs)

        if etag:
            self.add_etag_header(response, etag)

        return response

    def list(self, request, *args, **kwargs):
        """Override list to add ETag support."""
        if not self.etag_enable_list:
            return super().list(request, *args, **kwargs)

        queryset = self.filter_queryset(self.get_queryset())
        etag = self.get_list_etag_value(request, queryset)

        if etag and self.check_etag_match(request, etag):
            return HttpResponse(status=304)

        response = super().list(request, *args, **kwargs)

        if etag:
            self.add_etag_header(response, etag)

        return response


# =============================================================================
# RESPONSE COMPRESSION MIXIN
# =============================================================================

class CompressedResponseMixin:
    """
    Mixin providing response compression for large payloads.

    Automatically compresses JSON responses above a threshold size
    when client accepts gzip encoding.

    Note: For best performance, enable GZipMiddleware in Django settings
    instead of using this mixin. This mixin is for selective compression.

    Usage:
        class LargeDataViewSet(CompressedResponseMixin, TenantAwareViewSet):
            compression_threshold = 1024  # Compress responses > 1KB
    """

    # Minimum response size (bytes) to compress
    compression_threshold: int = 1024

    # Compression level (1-9, higher = more compression but slower)
    compression_level: int = 6

    def finalize_response(self, request, response, *args, **kwargs):
        """Apply compression to large responses."""
        response = super().finalize_response(request, response, *args, **kwargs)

        # Check if client accepts gzip
        accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', '')
        if 'gzip' not in accept_encoding.lower():
            return response

        # Render response to get content length
        if hasattr(response, 'render'):
            response.render()

        # Check if response is large enough to compress
        content = response.content if hasattr(response, 'content') else b''
        if len(content) < self.compression_threshold:
            return response

        # Compress content
        compressed = gzip.compress(content, compresslevel=self.compression_level)

        # Only use compression if it actually reduces size
        if len(compressed) < len(content):
            response.content = compressed
            response['Content-Encoding'] = 'gzip'
            response['Content-Length'] = len(compressed)
            response['Vary'] = 'Accept-Encoding'

        return response


# =============================================================================
# OPTIMIZED TENANT-AWARE VIEWSET
# =============================================================================

class OptimizedTenantViewSet(
    OptimizedQuerySetMixin,
    ETagCacheMixin,
    TenantAwareViewSet
):
    """
    Full-featured ViewSet combining all optimizations with tenant awareness.

    Includes:
    - Automatic tenant filtering
    - select_related for FK optimization
    - prefetch_related for N+1 prevention
    - defer/only for selective field loading
    - ETag caching for bandwidth optimization
    - Standardized response format

    Usage:
        class EmployeeViewSet(OptimizedTenantViewSet):
            queryset = Employee.objects.all()
            serializer_class = EmployeeSerializer

            # Query optimization
            select_related_fields = ['user', 'department', 'manager']
            prefetch_related_fields = ['skills', 'certifications']
            defer_fields = ['biography', 'notes']

            # Caching
            etag_enable_list = True
            etag_enable_detail = True
    """
    pass


class ScalableTenantViewSet(
    OptimizedQuerySetMixin,
    ETagCacheMixin,
    CompressedResponseMixin,
    TenantAwareViewSet
):
    """
    ViewSet optimized for 1M+ user scale with all optimizations.

    Use cursor pagination and all optimizations for high-traffic endpoints.

    Usage:
        class ActivityFeedViewSet(ScalableTenantViewSet):
            queryset = Activity.objects.all()
            serializer_class = ActivitySerializer
            pagination_class = ScalableCursorPagination
    """
    pagination_class = ScalableCursorPagination


class PublicAPIView(APIView):
    """
    Base APIView for public endpoints that don't require authentication.
    Still provides tenant context if available (e.g., career pages).
    """

    permission_classes = []
    authentication_classes = []

    def get_tenant(self) -> Optional[Any]:
        """Get tenant from request if available."""
        return getattr(self.request, 'tenant', None)

    def success_response(self, data=None, message=None, **kwargs) -> Response:
        """Helper to return a standardized success response."""
        return APIResponse.success(data=data, message=message, **kwargs)

    def error_response(self, message, **kwargs) -> Response:
        """Helper to return a standardized error response."""
        return APIResponse.error(message=message, **kwargs)


# =============================================================================
# EXCEPTION HANDLER
# =============================================================================

def custom_exception_handler(exc, context):
    """
    Custom exception handler for standardized error responses.

    Converts all exceptions to the standard response format:
    {
        "success": false,
        "data": null,
        "message": "Error description",
        "errors": [...],
        "error_code": "ERROR_CODE",
        "meta": {...}
    }
    """
    from rest_framework.views import exception_handler

    # Get the standard DRF response
    response = exception_handler(exc, context)

    # Extract request for context
    request = context.get('request')
    request_id = getattr(request, 'request_id', None) if request else None

    if response is None:
        # Unhandled exception
        logger.exception(f"Unhandled exception: {exc}")
        return APIResponse.error(
            message="An unexpected error occurred",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="INTERNAL_ERROR",
            request=request
        )

    # Format the response
    error_data = {
        "success": False,
        "data": None,
        "message": str(exc.detail) if hasattr(exc, 'detail') else str(exc),
        "errors": [],
        "error_code": getattr(exc, 'default_code', 'ERROR'),
        "meta": {
            "timestamp": timezone.now().isoformat(),
        }
    }

    # Include request ID if available
    if request_id:
        error_data["meta"]["request_id"] = request_id

    # Handle validation errors specially
    if isinstance(exc, DRFValidationError):
        error_data["error_code"] = "VALIDATION_ERROR"
        if isinstance(exc.detail, dict):
            error_data["errors"] = [
                {"field": field, "messages": msgs if isinstance(msgs, list) else [str(msgs)]}
                for field, msgs in exc.detail.items()
            ]
            error_data["message"] = "Validation failed"
        elif isinstance(exc.detail, list):
            error_data["errors"] = [{"field": "non_field_errors", "messages": exc.detail}]
            error_data["message"] = exc.detail[0] if exc.detail else "Validation failed"

    # Add tenant context if available
    if request:
        tenant = getattr(request, 'tenant', None)
        if tenant:
            error_data["meta"]["tenant"] = tenant.slug

    response.data = error_data
    return response


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_object_or_404_tenant(model_class, tenant, **kwargs):
    """
    Get an object filtered by tenant or raise 404.

    Usage:
        employee = get_object_or_404_tenant(Employee, request.tenant, uuid=uuid)
    """
    try:
        return model_class.objects.get(tenant=tenant, **kwargs)
    except model_class.DoesNotExist:
        raise NotFound(f"{model_class._meta.verbose_name.title()} not found")


def get_object_or_none_tenant(model_class, tenant, **kwargs):
    """
    Get an object filtered by tenant or return None.

    Usage:
        employee = get_object_or_none_tenant(Employee, request.tenant, uuid=uuid)
    """
    try:
        return model_class.objects.get(tenant=tenant, **kwargs)
    except model_class.DoesNotExist:
        return None
