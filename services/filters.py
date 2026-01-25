"""
Services API Filters

Django REST Framework filters for the services app API.
Provides comprehensive filtering for services, providers, contracts, etc.
"""

import django_filters
from decimal import Decimal
from django.db.models import Q

from .models import (
    ServiceProvider,
    Service,
    ServiceContract,
    ServiceReview,
    ClientRequest,
    CrossTenantServiceRequest,
)


# ==================== PROVIDER FILTERS ====================


class ServiceProviderFilter(django_filters.FilterSet):
    """
    FilterSet for ServiceProvider API endpoints.

    Provides filtering by provider type, location, availability, ratings, etc.
    """

    # Text search
    q = django_filters.CharFilter(method='filter_search', label='Search query')

    # Location filters
    city = django_filters.CharFilter(field_name='city', lookup_expr='iexact')
    state = django_filters.CharFilter(field_name='state', lookup_expr='iexact')
    country = django_filters.CharFilter(field_name='country', lookup_expr='iexact')

    # Hourly rate range
    min_rate = django_filters.NumberFilter(field_name='hourly_rate', lookup_expr='gte')
    max_rate = django_filters.NumberFilter(field_name='hourly_rate', lookup_expr='lte')
    rate_range = django_filters.RangeFilter(field_name='hourly_rate')

    # Minimum budget range
    min_budget = django_filters.NumberFilter(field_name='minimum_budget', lookup_expr='gte')
    max_budget = django_filters.NumberFilter(field_name='minimum_budget', lookup_expr='lte')

    # Rating filters
    min_rating = django_filters.NumberFilter(field_name='rating_avg', lookup_expr='gte')
    rating__gte = django_filters.NumberFilter(field_name='rating_avg', lookup_expr='gte')

    # Provider type
    provider_type = django_filters.CharFilter(lookup_expr='iexact')
    provider_type__in = django_filters.BaseInFilter(field_name='provider_type')

    # Availability status
    availability_status = django_filters.CharFilter(lookup_expr='iexact')
    availability_status__in = django_filters.BaseInFilter(field_name='availability_status')

    # Boolean filters
    is_verified = django_filters.BooleanFilter()
    is_featured = django_filters.BooleanFilter()
    is_accepting_work = django_filters.BooleanFilter()
    can_work_remotely = django_filters.BooleanFilter()
    can_work_onsite = django_filters.BooleanFilter()
    marketplace_enabled = django_filters.BooleanFilter()

    # Experience filters
    min_completed_jobs = django_filters.NumberFilter(
        field_name='completed_jobs_count',
        lookup_expr='gte'
    )
    min_reviews = django_filters.NumberFilter(
        field_name='total_reviews',
        lookup_expr='gte'
    )

    # Categories
    category = django_filters.NumberFilter(field_name='categories__id')
    category__in = django_filters.BaseInFilter(field_name='categories__id')

    # Skills
    skill = django_filters.NumberFilter(field_name='provider_skills__skill__id')
    skill__in = django_filters.BaseInFilter(field_name='provider_skills__skill__id')
    skill_level = django_filters.CharFilter(field_name='provider_skills__level', lookup_expr='iexact')

    # Ordering
    ordering = django_filters.OrderingFilter(
        fields=(
            ('rating_avg', 'rating'),
            ('hourly_rate', 'rate'),
            ('completed_jobs_count', 'experience'),
            ('total_reviews', 'reviews'),
            ('created_at', 'joined'),
            ('last_active_at', 'active'),
        ),
        field_labels={
            'rating_avg': 'Rating',
            'hourly_rate': 'Hourly Rate',
            'completed_jobs_count': 'Experience',
            'total_reviews': 'Number of Reviews',
            'created_at': 'Join Date',
            'last_active_at': 'Last Active',
        }
    )

    class Meta:
        model = ServiceProvider
        fields = []  # All fields defined explicitly above

    def filter_search(self, queryset, name, value):
        """
        Full-text search across multiple provider fields.

        Searches in:
        - display_name
        - bio
        - tagline
        - city
        - state
        - country
        """
        if not value:
            return queryset

        return queryset.filter(
            Q(display_name__icontains=value) |
            Q(bio__icontains=value) |
            Q(tagline__icontains=value) |
            Q(city__icontains=value) |
            Q(state__icontains=value) |
            Q(country__icontains=value)
        ).distinct()


# ==================== SERVICE FILTERS ====================


class ServiceFilter(django_filters.FilterSet):
    """
    FilterSet for Service API endpoints.

    Provides comprehensive filtering for the service catalog.
    """

    # Text search
    q = django_filters.CharFilter(method='filter_search', label='Search query')

    # Category filters
    category = django_filters.NumberFilter(field_name='category__id')
    category_slug = django_filters.CharFilter(field_name='category__slug', lookup_expr='iexact')
    category__in = django_filters.BaseInFilter(field_name='category__id')

    # Provider filters
    provider = django_filters.UUIDFilter(field_name='provider__uuid')
    provider__in = django_filters.BaseInFilter(field_name='provider__uuid')

    # Price range filters
    min_price = django_filters.NumberFilter(field_name='price', lookup_expr='gte')
    max_price = django_filters.NumberFilter(field_name='price', lookup_expr='lte')
    price_range = django_filters.RangeFilter(field_name='price')

    # Service type filters
    service_type = django_filters.CharFilter(lookup_expr='iexact')
    service_type__in = django_filters.BaseInFilter(field_name='service_type')

    # Delivery type filters
    delivery_type = django_filters.CharFilter(lookup_expr='iexact')
    delivery_type__in = django_filters.BaseInFilter(field_name='delivery_type')

    # Duration filters
    max_duration_days = django_filters.NumberFilter(
        field_name='duration_days',
        lookup_expr='lte'
    )

    # Tags
    tag = django_filters.NumberFilter(field_name='tags__id')
    tag_slug = django_filters.CharFilter(field_name='tags__slug', lookup_expr='iexact')
    tag__in = django_filters.BaseInFilter(field_name='tags__id')

    # Boolean filters
    is_active = django_filters.BooleanFilter()
    is_featured = django_filters.BooleanFilter()
    is_public = django_filters.BooleanFilter()
    published_to_catalog = django_filters.BooleanFilter()

    # Provider filters (nested)
    provider_verified = django_filters.BooleanFilter(
        field_name='provider__is_verified'
    )
    provider_accepting_work = django_filters.BooleanFilter(
        field_name='provider__is_accepting_work'
    )
    provider_can_work_remotely = django_filters.BooleanFilter(
        field_name='provider__can_work_remotely'
    )

    # Location filters (via provider)
    city = django_filters.CharFilter(field_name='provider__city', lookup_expr='iexact')
    state = django_filters.CharFilter(field_name='provider__state', lookup_expr='iexact')
    country = django_filters.CharFilter(field_name='provider__country', lookup_expr='iexact')

    # Date filters
    published_after = django_filters.DateTimeFilter(
        field_name='catalog_synced_at',
        lookup_expr='gte'
    )
    published_before = django_filters.DateTimeFilter(
        field_name='catalog_synced_at',
        lookup_expr='lte'
    )

    # Ordering
    ordering = django_filters.OrderingFilter(
        fields=(
            ('created_at', 'created'),
            ('price', 'price'),
            ('view_count', 'popular'),
            ('order_count', 'orders'),
            ('duration_days', 'duration'),
            ('provider__rating_avg', 'provider_rating'),
        ),
        field_labels={
            'created_at': 'Date Created',
            'price': 'Price',
            'view_count': 'Popularity',
            'order_count': 'Number of Orders',
            'duration_days': 'Delivery Time',
            'provider__rating_avg': 'Provider Rating',
        }
    )

    class Meta:
        model = Service
        fields = []  # All fields defined explicitly above

    def filter_search(self, queryset, name, value):
        """
        Full-text search across multiple service fields.

        Searches in:
        - name
        - description
        - short_description
        - provider display_name
        - category name
        - tags
        """
        if not value:
            return queryset

        return queryset.filter(
            Q(name__icontains=value) |
            Q(description__icontains=value) |
            Q(short_description__icontains=value) |
            Q(provider__display_name__icontains=value) |
            Q(category__name__icontains=value) |
            Q(tags__name__icontains=value)
        ).distinct()


# ==================== CONTRACT FILTERS ====================


class ServiceContractFilter(django_filters.FilterSet):
    """
    FilterSet for ServiceContract API endpoints.

    Provides filtering for contract management dashboards.
    """

    # Status filters
    status = django_filters.CharFilter(lookup_expr='iexact')
    status__in = django_filters.BaseInFilter(field_name='status')

    # Rate type
    rate_type = django_filters.CharFilter(lookup_expr='iexact')

    # Rate range
    min_rate = django_filters.NumberFilter(field_name='agreed_rate', lookup_expr='gte')
    max_rate = django_filters.NumberFilter(field_name='agreed_rate', lookup_expr='lte')

    # Client/Provider filters
    client = django_filters.NumberFilter(field_name='client__id')
    provider = django_filters.UUIDFilter(field_name='provider__uuid')

    # Service filter
    service = django_filters.UUIDFilter(field_name='service__uuid')

    # Date filters
    deadline_after = django_filters.DateFilter(field_name='agreed_deadline', lookup_expr='gte')
    deadline_before = django_filters.DateFilter(field_name='agreed_deadline', lookup_expr='lte')

    started_after = django_filters.DateTimeFilter(field_name='started_at', lookup_expr='gte')
    started_before = django_filters.DateTimeFilter(field_name='started_at', lookup_expr='lte')

    completed_after = django_filters.DateTimeFilter(field_name='completed_at', lookup_expr='gte')
    completed_before = django_filters.DateTimeFilter(field_name='completed_at', lookup_expr='lte')

    # Boolean filters
    has_escrow = django_filters.BooleanFilter(
        method='filter_has_escrow',
        label='Has escrow transaction'
    )

    # Ordering
    ordering = django_filters.OrderingFilter(
        fields=(
            ('created_at', 'created'),
            ('agreed_deadline', 'deadline'),
            ('agreed_rate', 'rate'),
            ('started_at', 'started'),
            ('completed_at', 'completed'),
        ),
        field_labels={
            'created_at': 'Date Created',
            'agreed_deadline': 'Deadline',
            'agreed_rate': 'Contract Rate',
            'started_at': 'Start Date',
            'completed_at': 'Completion Date',
        }
    )

    class Meta:
        model = ServiceContract
        fields = []  # All fields defined explicitly above

    def filter_has_escrow(self, queryset, name, value):
        """Filter contracts with/without escrow transactions."""
        if value:
            return queryset.exclude(escrow_transaction__isnull=True)
        else:
            return queryset.filter(escrow_transaction__isnull=True)


# ==================== REVIEW FILTERS ====================


class ServiceReviewFilter(django_filters.FilterSet):
    """
    FilterSet for ServiceReview API endpoints.

    Provides filtering for review management.
    """

    # Provider filter
    provider = django_filters.UUIDFilter(field_name='provider__uuid')

    # Rating filters
    rating = django_filters.NumberFilter()
    rating__gte = django_filters.NumberFilter(field_name='rating', lookup_expr='gte')
    rating__lte = django_filters.NumberFilter(field_name='rating', lookup_expr='lte')

    # Sub-rating filters
    min_communication = django_filters.NumberFilter(
        field_name='rating_communication',
        lookup_expr='gte'
    )
    min_quality = django_filters.NumberFilter(
        field_name='rating_quality',
        lookup_expr='gte'
    )
    min_timeliness = django_filters.NumberFilter(
        field_name='rating_timeliness',
        lookup_expr='gte'
    )

    # Response filter
    has_response = django_filters.BooleanFilter(
        method='filter_has_response',
        label='Has provider response'
    )

    # Date filters
    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')

    # Ordering
    ordering = django_filters.OrderingFilter(
        fields=(
            ('created_at', 'created'),
            ('rating', 'rating'),
            ('rating_communication', 'communication'),
            ('rating_quality', 'quality'),
            ('rating_timeliness', 'timeliness'),
        ),
        field_labels={
            'created_at': 'Date',
            'rating': 'Overall Rating',
            'rating_communication': 'Communication Rating',
            'rating_quality': 'Quality Rating',
            'rating_timeliness': 'Timeliness Rating',
        }
    )

    class Meta:
        model = ServiceReview
        fields = []  # All fields defined explicitly above

    def filter_has_response(self, queryset, name, value):
        """Filter reviews with/without provider responses."""
        if value:
            return queryset.exclude(provider_response='')
        else:
            return queryset.filter(provider_response='')


# ==================== CLIENT REQUEST FILTERS ====================


class ClientRequestFilter(django_filters.FilterSet):
    """
    FilterSet for ClientRequest API endpoints.

    Provides filtering for client service requests.
    """

    # Status filters
    status = django_filters.CharFilter(lookup_expr='iexact')
    status__in = django_filters.BaseInFilter(field_name='status')

    # Category filter
    category = django_filters.NumberFilter(field_name='category__id')
    category_slug = django_filters.CharFilter(field_name='category__slug', lookup_expr='iexact')

    # Budget filters
    min_budget = django_filters.NumberFilter(field_name='budget_max', lookup_expr='gte')
    max_budget = django_filters.NumberFilter(field_name='budget_max', lookup_expr='lte')

    # Skills
    skill = django_filters.NumberFilter(field_name='required_skills__id')
    skill__in = django_filters.BaseInFilter(field_name='required_skills__id')

    # Location filters
    remote_allowed = django_filters.BooleanFilter()

    # Date filters
    deadline_after = django_filters.DateFilter(field_name='deadline', lookup_expr='gte')
    deadline_before = django_filters.DateFilter(field_name='deadline', lookup_expr='lte')

    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')

    # Ordering
    ordering = django_filters.OrderingFilter(
        fields=(
            ('created_at', 'created'),
            ('deadline', 'deadline'),
            ('budget_max', 'budget'),
        ),
        field_labels={
            'created_at': 'Date Created',
            'deadline': 'Deadline',
            'budget_max': 'Budget',
        }
    )

    class Meta:
        model = ClientRequest
        fields = []  # All fields defined explicitly above


# ==================== CROSS-TENANT REQUEST FILTERS ====================


class CrossTenantServiceRequestFilter(django_filters.FilterSet):
    """
    FilterSet for CrossTenantServiceRequest API endpoints.

    Provides filtering for cross-tenant hiring requests.
    """

    # Status filters
    status = django_filters.CharFilter(lookup_expr='iexact')
    status__in = django_filters.BaseInFilter(field_name='status')

    # Hiring context
    hiring_context = django_filters.CharFilter(lookup_expr='iexact')

    # Target filters
    target_tenant_schema = django_filters.CharFilter(lookup_expr='iexact')
    target_service_uuid = django_filters.UUIDFilter()
    target_provider_uuid = django_filters.UUIDFilter()

    # Budget filters
    min_budget = django_filters.NumberFilter(field_name='budget', lookup_expr='gte')
    max_budget = django_filters.NumberFilter(field_name='budget', lookup_expr='lte')

    # Date filters
    deadline_after = django_filters.DateFilter(field_name='deadline', lookup_expr='gte')
    deadline_before = django_filters.DateFilter(field_name='deadline', lookup_expr='lte')

    created_after = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = django_filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')

    # Response filters
    has_response = django_filters.BooleanFilter(
        method='filter_has_response',
        label='Has provider response'
    )

    # Ordering
    ordering = django_filters.OrderingFilter(
        fields=(
            ('created_at', 'created'),
            ('responded_at', 'responded'),
            ('deadline', 'deadline'),
            ('budget', 'budget'),
        ),
        field_labels={
            'created_at': 'Date Created',
            'responded_at': 'Response Date',
            'deadline': 'Deadline',
            'budget': 'Budget',
        }
    )

    class Meta:
        model = CrossTenantServiceRequest
        fields = []  # All fields defined explicitly above

    def filter_has_response(self, queryset, name, value):
        """Filter requests with/without provider responses."""
        if value:
            return queryset.exclude(provider_response='')
        else:
            return queryset.filter(provider_response='')
