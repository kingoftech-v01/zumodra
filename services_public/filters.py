"""
Services Public API Filters

Django REST Framework filters for the public service catalog API.
"""

import django_filters
from decimal import Decimal
from .models import PublicService


class PublicServiceFilter(django_filters.FilterSet):
    """
    FilterSet for PublicService API endpoints.

    Provides comprehensive filtering options for the public service catalog.
    """

    # Text search
    q = django_filters.CharFilter(method='filter_search', label='Search query')

    # Category filters
    category = django_filters.CharFilter(field_name='category_slug', lookup_expr='iexact')
    category__in = django_filters.BaseInFilter(field_name='category_slug')

    # Location filters
    city = django_filters.CharFilter(field_name='location_city', lookup_expr='iexact')
    state = django_filters.CharFilter(field_name='location_state', lookup_expr='iexact')
    country = django_filters.CharFilter(field_name='location_country', lookup_expr='iexact')

    # Price range filters
    min_price = django_filters.NumberFilter(field_name='price', lookup_expr='gte')
    max_price = django_filters.NumberFilter(field_name='price', lookup_expr='lte')
    price_range = django_filters.RangeFilter(field_name='price')

    # Rating filters
    min_rating = django_filters.NumberFilter(field_name='rating_avg', lookup_expr='gte')
    rating__gte = django_filters.NumberFilter(field_name='rating_avg', lookup_expr='gte')

    # Service type filters
    service_type = django_filters.CharFilter(lookup_expr='iexact')
    service_type__in = django_filters.BaseInFilter(field_name='service_type')

    # Delivery type filters
    delivery_type = django_filters.CharFilter(lookup_expr='iexact')
    delivery_type__in = django_filters.BaseInFilter(field_name='delivery_type')

    # Boolean filters
    is_featured = django_filters.BooleanFilter()
    is_accepting_work = django_filters.BooleanFilter()
    provider_is_verified = django_filters.BooleanFilter()
    can_work_remotely = django_filters.BooleanFilter()

    # Date filters
    published_after = django_filters.DateTimeFilter(field_name='published_at', lookup_expr='gte')
    published_before = django_filters.DateTimeFilter(field_name='published_at', lookup_expr='lte')

    # Ordering
    ordering = django_filters.OrderingFilter(
        fields=(
            ('rating_avg', 'rating'),
            ('price', 'price'),
            ('published_at', 'newest'),
            ('view_count', 'popular'),
            ('total_reviews', 'reviews'),
        ),
        field_labels={
            'rating_avg': 'Rating',
            'price': 'Price',
            'published_at': 'Publication Date',
            'view_count': 'Popularity',
            'total_reviews': 'Number of Reviews',
        }
    )

    class Meta:
        model = PublicService
        fields = []  # All fields defined explicitly above

    def filter_search(self, queryset, name, value):
        """
        Full-text search across multiple fields.

        Searches in:
        - name
        - description
        - short_description
        - provider_name
        - tags_list
        """
        if not value:
            return queryset

        from django.db.models import Q

        return queryset.filter(
            Q(name__icontains=value) |
            Q(description__icontains=value) |
            Q(short_description__icontains=value) |
            Q(provider_name__icontains=value) |
            Q(tags_list__icontains=value)
        ).distinct()
