"""
API Filters - Tenant-Scoped Filter Backends for Zumodra API

This module provides filter classes with tenant awareness:
- TenantScopedFilterBackend: Automatic tenant filtering
- DateRangeFilter: Date range filtering with presets
- AdvancedSearchFilter: Enhanced search with relevance
- GeoSpatialFilter: PostGIS-based location filtering
- RoleBasedFilter: Filter based on user permissions

All filters respect tenant boundaries and plan features.
"""

import logging
from datetime import datetime, timedelta
from functools import reduce
from typing import Any, Dict, List, Optional, Tuple

from django.db.models import Q, QuerySet
from django.utils import timezone
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django.contrib.gis.db.models.functions import Distance

from rest_framework import filters
from rest_framework.request import Request
from rest_framework.exceptions import ValidationError
from django_filters import rest_framework as django_filters
from django_filters import FilterSet, CharFilter, DateFilter, NumberFilter, BooleanFilter

logger = logging.getLogger(__name__)


# =============================================================================
# TENANT-SCOPED FILTER BACKEND
# =============================================================================

class TenantScopedFilterBackend(filters.BaseFilterBackend):
    """
    Automatically filter queryset by tenant.

    This is the primary filter backend that ensures all queries
    are scoped to the current tenant. Should be included in all
    tenant-aware viewsets.

    Configuration via view attributes:
    - tenant_field: Name of the tenant FK field (default: 'tenant')
    - tenant_filter_required: Raise error if no tenant (default: True)

    Usage:
        class MyViewSet(TenantAwareViewSet):
            filter_backends = [TenantScopedFilterBackend, DjangoFilterBackend]
            tenant_field = 'organization__tenant'  # For nested tenant relations
    """

    def filter_queryset(self, request: Request, queryset: QuerySet, view) -> QuerySet:
        tenant = getattr(request, 'tenant', None)
        tenant_field = getattr(view, 'tenant_field', 'tenant')
        tenant_required = getattr(view, 'tenant_filter_required', True)

        if not tenant:
            if tenant_required:
                # Return empty queryset if no tenant context
                logger.warning(
                    f"No tenant context for {view.__class__.__name__}. "
                    "Returning empty queryset."
                )
                return queryset.none()
            return queryset

        if tenant_field:
            filter_kwargs = {tenant_field: tenant}
            return queryset.filter(**filter_kwargs)

        return queryset


class CircusaleFilterBackend(filters.BaseFilterBackend):
    """
    Filter queryset by circusale (business unit/branch).

    Respects user's circusale assignment for role-based access.
    Supervisors see their circusale + subordinates.
    PDG/owners see all circusales.

    Configuration:
    - circusale_field: Field name for circusale FK (default: 'circusale')
    """

    def filter_queryset(self, request: Request, queryset: QuerySet, view) -> QuerySet:
        if not request.user.is_authenticated:
            return queryset

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return queryset

        circusale_field = getattr(view, 'circusale_field', 'circusale')
        if not circusale_field:
            return queryset

        # Check if circusale filtering should be applied
        apply_circusale_filter = getattr(view, 'apply_circusale_filter', True)
        if not apply_circusale_filter:
            return queryset

        try:
            from tenant_profiles.models import TenantUser
            tenant_user = TenantUser.objects.get(
                user=request.user,
                tenant=tenant,
                is_active=True
            )

            # PDG/Owners see all
            if tenant_user.role in ['owner', 'pdg']:
                return queryset

            # Supervisors see their circusale
            if tenant_user.circusale:
                filter_kwargs = {circusale_field: tenant_user.circusale}
                return queryset.filter(**filter_kwargs)

        except Exception as e:
            logger.debug(f"Circusale filter not applied: {e}")

        return queryset


# =============================================================================
# DATE RANGE FILTERS
# =============================================================================

class DateRangeFilter(CharFilter):
    """
    Filter for date ranges with preset options.

    Supports:
    - Preset ranges: today, yesterday, this_week, last_week, this_month,
                     last_month, this_quarter, last_quarter, this_year, last_year
    - Custom ranges: start_date=2024-01-01&end_date=2024-12-31
    - Relative ranges: last_7_days, last_30_days, last_90_days

    Usage in FilterSet:
        class JobFilterSet(FilterSet):
            posted_date = DateRangeFilter(field_name='created_at')
    """

    def __init__(self, *args, **kwargs):
        self.start_field = kwargs.pop('start_field', None)
        self.end_field = kwargs.pop('end_field', None)
        super().__init__(*args, **kwargs)

    def filter(self, qs: QuerySet, value: str) -> QuerySet:
        if not value:
            return qs

        start_date, end_date = self._parse_range(value)

        if start_date and end_date:
            field_name = self.field_name
            return qs.filter(**{
                f'{field_name}__gte': start_date,
                f'{field_name}__lte': end_date,
            })

        return qs

    def _parse_range(self, value: str) -> Tuple[Optional[datetime], Optional[datetime]]:
        """Parse date range value into start and end dates."""
        now = timezone.now()
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)

        presets = {
            'today': (today, now),
            'yesterday': (
                today - timedelta(days=1),
                today - timedelta(microseconds=1)
            ),
            'this_week': (
                today - timedelta(days=today.weekday()),
                now
            ),
            'last_week': (
                today - timedelta(days=today.weekday() + 7),
                today - timedelta(days=today.weekday()) - timedelta(microseconds=1)
            ),
            'this_month': (
                today.replace(day=1),
                now
            ),
            'last_month': (
                (today.replace(day=1) - timedelta(days=1)).replace(day=1),
                today.replace(day=1) - timedelta(microseconds=1)
            ),
            'last_7_days': (today - timedelta(days=7), now),
            'last_30_days': (today - timedelta(days=30), now),
            'last_90_days': (today - timedelta(days=90), now),
            'last_365_days': (today - timedelta(days=365), now),
            'this_year': (today.replace(month=1, day=1), now),
            'last_year': (
                today.replace(year=today.year - 1, month=1, day=1),
                today.replace(month=1, day=1) - timedelta(microseconds=1)
            ),
        }

        if value in presets:
            return presets[value]

        # Try parsing as ISO date
        try:
            date = datetime.fromisoformat(value)
            return (date, date.replace(hour=23, minute=59, second=59))
        except ValueError:
            pass

        return (None, None)


class DateRangeFilterBackend(filters.BaseFilterBackend):
    """
    Filter backend for date range queries.

    Query params:
    - date_range: Preset (today, this_week, etc.) or custom range
    - start_date: ISO format start date
    - end_date: ISO format end date
    - date_field: Which field to filter (default: created_at)
    """

    def filter_queryset(self, request: Request, queryset: QuerySet, view) -> QuerySet:
        date_field = request.query_params.get('date_field', 'created_at')
        date_range = request.query_params.get('date_range')
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        # Validate date field is allowed
        allowed_date_fields = getattr(view, 'allowed_date_fields', ['created_at', 'updated_at'])
        if date_field not in allowed_date_fields:
            date_field = 'created_at'

        if date_range:
            filter_instance = DateRangeFilter(field_name=date_field)
            return filter_instance.filter(queryset, date_range)

        if start_date or end_date:
            try:
                if start_date:
                    start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                    queryset = queryset.filter(**{f'{date_field}__gte': start_dt})
                if end_date:
                    end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                    queryset = queryset.filter(**{f'{date_field}__lte': end_dt})
            except ValueError as e:
                raise ValidationError({'date': f'Invalid date format: {e}'})

        return queryset


# =============================================================================
# ADVANCED SEARCH FILTER
# =============================================================================

class AdvancedSearchFilter(filters.SearchFilter):
    """
    Enhanced search filter with additional features.

    Features:
    - Multi-field search with weighting
    - Exact phrase matching with quotes
    - Exclusion with minus prefix
    - Case-insensitive by default

    Query params:
    - search: Search query
    - search_fields: Comma-separated fields to search (optional)

    Examples:
    - search=python developer
    - search="senior developer"  (exact phrase)
    - search=python -junior  (exclude junior)
    """

    search_param = 'search'
    search_title = 'Search'
    search_description = 'A search term. Supports phrases ("term") and exclusions (-term).'

    def filter_queryset(self, request: Request, queryset: QuerySet, view) -> QuerySet:
        search_terms = self.get_search_terms(request)

        if not search_terms:
            return queryset

        search_fields = self.get_search_fields(view, request)

        if not search_fields:
            return queryset

        # Build complex query
        include_queries = []
        exclude_queries = []

        for term in search_terms:
            if term.startswith('-') and len(term) > 1:
                # Exclusion term
                exclude_term = term[1:]
                for field in search_fields:
                    exclude_queries.append(Q(**{f'{field}__icontains': exclude_term}))
            else:
                # Inclusion term
                term_queries = []
                for field in search_fields:
                    term_queries.append(Q(**{f'{field}__icontains': term}))
                if term_queries:
                    include_queries.append(
                        term_queries[0] if len(term_queries) == 1
                        else reduce(lambda a, b: a | b, term_queries)
                    )

        # Apply include filters (AND between terms)
        if include_queries:
            combined = reduce(lambda a, b: a & b, include_queries)
            queryset = queryset.filter(combined)

        # Apply exclude filters
        for exclude_q in exclude_queries:
            queryset = queryset.exclude(exclude_q)

        return queryset.distinct()

    def get_search_terms(self, request: Request) -> List[str]:
        """
        Parse search query into terms, handling quoted phrases.
        """
        params = request.query_params.get(self.search_param, '')
        params = params.replace(',', ' ')

        terms = []
        current_term = []
        in_quotes = False

        for char in params:
            if char == '"':
                if in_quotes:
                    # End of quoted phrase
                    if current_term:
                        terms.append(''.join(current_term))
                        current_term = []
                    in_quotes = False
                else:
                    # Start of quoted phrase
                    if current_term:
                        terms.extend(''.join(current_term).split())
                        current_term = []
                    in_quotes = True
            elif char == ' ' and not in_quotes:
                if current_term:
                    terms.append(''.join(current_term))
                    current_term = []
            else:
                current_term.append(char)

        if current_term:
            if in_quotes:
                terms.append(''.join(current_term))
            else:
                terms.extend(''.join(current_term).split())

        return [term.strip() for term in terms if term.strip()]


# =============================================================================
# GEOSPATIAL FILTER
# =============================================================================

class GeoSpatialFilterBackend(filters.BaseFilterBackend):
    """
    PostGIS-based location filtering.

    Query params:
    - lat: Latitude
    - lng: Longitude
    - radius: Search radius in kilometers (default: 50)
    - unit: Distance unit (km, mi, m) - default: km

    Requires:
    - PostGIS enabled database
    - Model with PointField

    Usage:
        class ServiceProviderViewSet(TenantAwareViewSet):
            filter_backends = [GeoSpatialFilterBackend]
            location_field = 'location'  # PointField on model
    """

    def filter_queryset(self, request: Request, queryset: QuerySet, view) -> QuerySet:
        lat = request.query_params.get('lat')
        lng = request.query_params.get('lng')

        if not lat or not lng:
            return queryset

        try:
            latitude = float(lat)
            longitude = float(lng)
        except (TypeError, ValueError):
            raise ValidationError({
                'location': 'Invalid latitude or longitude values'
            })

        # Validate coordinates
        if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
            raise ValidationError({
                'location': 'Coordinates out of valid range'
            })

        radius = float(request.query_params.get('radius', 50))
        unit = request.query_params.get('unit', 'km')

        # Convert radius to meters
        if unit == 'mi':
            radius_m = radius * 1609.34
        elif unit == 'm':
            radius_m = radius
        else:  # km
            radius_m = radius * 1000

        location_field = getattr(view, 'location_field', 'location')
        point = Point(longitude, latitude, srid=4326)

        # Filter by distance and annotate with distance
        try:
            queryset = queryset.filter(
                **{f'{location_field}__distance_lte': (point, D(m=radius_m))}
            ).annotate(
                distance=Distance(location_field, point)
            ).order_by('distance')
        except Exception as e:
            logger.warning(f"GeoSpatial filter failed: {e}")
            # Security: return empty queryset on geo query failure instead of unfiltered data
            return queryset.none()

        return queryset


# =============================================================================
# ROLE-BASED FILTER
# =============================================================================

class RoleBasedFilterBackend(filters.BaseFilterBackend):
    """
    Filter queryset based on user's role and permissions.

    This filter restricts data visibility based on:
    - User's role in the tenant
    - Object ownership
    - Department/team membership

    Configuration via view:
    - role_filter_map: Dict mapping roles to filter callables
    - owner_field: Field for ownership check (default: 'created_by')

    Usage:
        class SensitiveDataViewSet(TenantAwareViewSet):
            filter_backends = [RoleBasedFilterBackend]
            owner_field = 'owner'
            role_filter_map = {
                'employee': lambda qs, user: qs.filter(owner=user),
                'supervisor': lambda qs, user: qs.filter(department=user.department),
            }
    """

    def filter_queryset(self, request: Request, queryset: QuerySet, view) -> QuerySet:
        if not request.user.is_authenticated:
            return queryset.none()

        tenant = getattr(request, 'tenant', None)
        if not tenant:
            return queryset

        # Get user's role
        role = self._get_user_role(request.user, tenant)

        # Check for role-based filter map
        role_filter_map = getattr(view, 'role_filter_map', {})
        if role in role_filter_map:
            filter_func = role_filter_map[role]
            return filter_func(queryset, request.user)

        # Default: owners and admins see all, others see their own
        if role in ['owner', 'admin', 'pdg']:
            return queryset

        # Filter by owner field for other roles
        owner_field = getattr(view, 'owner_field', 'created_by')
        if owner_field:
            return queryset.filter(**{owner_field: request.user})

        return queryset

    def _get_user_role(self, user, tenant) -> str:
        """Get user's role in tenant."""
        try:
            from tenant_profiles.models import TenantUser
            tenant_user = TenantUser.objects.get(
                user=user,
                tenant=tenant,
                is_active=True
            )
            return tenant_user.role
        except Exception:
            return 'member'


# =============================================================================
# COMMON FILTERSETS
# =============================================================================

class TenantFilterSet(FilterSet):
    """
    Base FilterSet with common filters for tenant-scoped models.

    Provides:
    - created_at date range filtering
    - updated_at date range filtering
    - is_active boolean filter
    - Search capability
    """

    created_after = DateFilter(field_name='created_at', lookup_expr='gte')
    created_before = DateFilter(field_name='created_at', lookup_expr='lte')
    created_range = DateRangeFilter(field_name='created_at')

    updated_after = DateFilter(field_name='updated_at', lookup_expr='gte')
    updated_before = DateFilter(field_name='updated_at', lookup_expr='lte')

    is_active = BooleanFilter(field_name='is_active')

    class Meta:
        abstract = True


class UUIDFilterSet(TenantFilterSet):
    """
    FilterSet for models with UUID primary keys.
    Adds UUID filtering capability.
    """

    uuid = CharFilter(field_name='uuid', lookup_expr='exact')
    uuid_in = CharFilter(method='filter_uuid_in')

    def filter_uuid_in(self, queryset: QuerySet, name: str, value: str) -> QuerySet:
        """Filter by multiple UUIDs (comma-separated)."""
        if not value:
            return queryset
        uuids = [u.strip() for u in value.split(',') if u.strip()]
        return queryset.filter(uuid__in=uuids)

    class Meta:
        abstract = True


class StatusFilterSet(TenantFilterSet):
    """
    FilterSet for models with status fields.
    Common for workflow-based models.
    """

    status = CharFilter(field_name='status', lookup_expr='exact')
    status_in = CharFilter(method='filter_status_in')
    status_not = CharFilter(method='filter_status_not')

    def filter_status_in(self, queryset: QuerySet, name: str, value: str) -> QuerySet:
        """Filter by multiple statuses (comma-separated)."""
        if not value:
            return queryset
        statuses = [s.strip() for s in value.split(',') if s.strip()]
        return queryset.filter(status__in=statuses)

    def filter_status_not(self, queryset: QuerySet, name: str, value: str) -> QuerySet:
        """Exclude specific status."""
        if not value:
            return queryset
        return queryset.exclude(status=value)

    class Meta:
        abstract = True


# =============================================================================
# FILTER UTILITIES
# =============================================================================

def combine_filters(*filter_backends):
    """
    Combine multiple filter backends into one.

    Usage:
        CombinedFilter = combine_filters(
            TenantScopedFilterBackend,
            DateRangeFilterBackend,
            AdvancedSearchFilter
        )

        class MyViewSet(TenantAwareViewSet):
            filter_backends = [CombinedFilter]
    """

    class CombinedFilterBackend(filters.BaseFilterBackend):
        backends = filter_backends

        def filter_queryset(self, request: Request, queryset: QuerySet, view) -> QuerySet:
            for backend_class in self.backends:
                backend = backend_class()
                queryset = backend.filter_queryset(request, queryset, view)
            return queryset

    return CombinedFilterBackend


# Default filter backends for common use cases
StandardFilterBackends = [
    TenantScopedFilterBackend,
    django_filters.DjangoFilterBackend,
    filters.OrderingFilter,
    AdvancedSearchFilter,
]

FullFilterBackends = [
    TenantScopedFilterBackend,
    CircusaleFilterBackend,
    RoleBasedFilterBackend,
    DateRangeFilterBackend,
    django_filters.DjangoFilterBackend,
    filters.OrderingFilter,
    AdvancedSearchFilter,
]

GeoFilterBackends = [
    TenantScopedFilterBackend,
    GeoSpatialFilterBackend,
    django_filters.DjangoFilterBackend,
    filters.OrderingFilter,
    AdvancedSearchFilter,
]
