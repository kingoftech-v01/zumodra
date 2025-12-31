"""
Careers Filters - Django Filter classes for public job filtering.

This module provides filters for:
- Public job listings (department, location, type, experience)
- Admin filtering with additional options
- Talent pool filtering
"""

import django_filters
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .models import JobListing, PublicApplication, TalentPool, TalentPoolMember
from ats.models import JobPosting, JobCategory


class PublicJobListingFilter(django_filters.FilterSet):
    """
    Public job listing filters for job seekers.
    Allows filtering by department, location, job type, etc.
    """

    # Category/Department filters
    category = django_filters.ModelChoiceFilter(
        field_name='job__category',
        queryset=JobCategory.objects.filter(is_active=True),
        label=_('Department/Category')
    )
    category_slug = django_filters.CharFilter(
        field_name='job__category__slug',
        label=_('Department Slug')
    )

    # Location filters
    location = django_filters.CharFilter(
        method='filter_location',
        label=_('Location (city, state, or country)')
    )
    city = django_filters.CharFilter(
        field_name='job__location_city',
        lookup_expr='icontains',
        label=_('City')
    )
    state = django_filters.CharFilter(
        field_name='job__location_state',
        lookup_expr='icontains',
        label=_('State/Province')
    )
    country = django_filters.CharFilter(
        field_name='job__location_country',
        lookup_expr='icontains',
        label=_('Country')
    )
    remote = django_filters.BooleanFilter(
        method='filter_remote',
        label=_('Remote positions only')
    )

    # Job type filters
    job_type = django_filters.ChoiceFilter(
        field_name='job__job_type',
        choices=JobPosting.JobType.choices,
        label=_('Job Type')
    )
    experience_level = django_filters.ChoiceFilter(
        field_name='job__experience_level',
        choices=JobPosting.ExperienceLevel.choices,
        label=_('Experience Level')
    )
    remote_policy = django_filters.ChoiceFilter(
        field_name='job__remote_policy',
        choices=JobPosting.RemotePolicy.choices,
        label=_('Remote Policy')
    )

    # Skills filter
    skills = django_filters.CharFilter(
        method='filter_skills',
        label=_('Required Skills (comma-separated)')
    )

    # Text search
    search = django_filters.CharFilter(
        method='filter_search',
        label=_('Search jobs')
    )

    # Featured jobs
    featured = django_filters.BooleanFilter(
        field_name='is_featured',
        label=_('Featured jobs only')
    )

    # Date filters
    posted_after = django_filters.DateFilter(
        field_name='published_at',
        lookup_expr='gte',
        label=_('Posted after date')
    )
    posted_within_days = django_filters.NumberFilter(
        method='filter_posted_within_days',
        label=_('Posted within X days')
    )

    # Salary filter (only works when salary is visible)
    min_salary = django_filters.NumberFilter(
        method='filter_min_salary',
        label=_('Minimum salary')
    )

    class Meta:
        model = JobListing
        fields = [
            'category', 'category_slug', 'location', 'city', 'state', 'country',
            'remote', 'job_type', 'experience_level', 'remote_policy',
            'skills', 'search', 'featured', 'posted_after', 'posted_within_days',
            'min_salary',
        ]

    def filter_location(self, queryset, name, value):
        """Filter by any location field (city, state, or country)."""
        if not value:
            return queryset
        return queryset.filter(
            Q(job__location_city__icontains=value) |
            Q(job__location_state__icontains=value) |
            Q(job__location_country__icontains=value)
        )

    def filter_remote(self, queryset, name, value):
        """Filter for remote-friendly positions."""
        if value:
            return queryset.filter(
                job__remote_policy__in=['remote', 'hybrid', 'flexible']
            )
        return queryset

    def filter_skills(self, queryset, name, value):
        """Filter by required skills (comma-separated)."""
        if not value:
            return queryset
        skills = [s.strip().lower() for s in value.split(',') if s.strip()]
        if not skills:
            return queryset

        # Filter jobs that have any of the specified skills
        for skill in skills:
            queryset = queryset.filter(
                Q(job__required_skills__icontains=skill) |
                Q(job__preferred_skills__icontains=skill)
            )
        return queryset

    def filter_search(self, queryset, name, value):
        """Full-text search across job title, description, and company."""
        if not value:
            return queryset
        return queryset.filter(
            Q(job__title__icontains=value) |
            Q(job__description__icontains=value) |
            Q(job__responsibilities__icontains=value) |
            Q(job__requirements__icontains=value) |
            Q(job__category__name__icontains=value)
        )

    def filter_posted_within_days(self, queryset, name, value):
        """Filter jobs posted within the last X days."""
        if not value or value <= 0:
            return queryset
        cutoff_date = timezone.now() - timezone.timedelta(days=int(value))
        return queryset.filter(published_at__gte=cutoff_date)

    def filter_min_salary(self, queryset, name, value):
        """Filter by minimum salary (only for jobs showing salary)."""
        if not value:
            return queryset
        return queryset.filter(
            job__show_salary=True,
            job__salary_max__gte=value
        )


class AdminJobListingFilter(PublicJobListingFilter):
    """
    Extended filters for admin job listing management.
    Includes status and analytics-based filters.
    """

    # Status filters
    status = django_filters.ChoiceFilter(
        field_name='job__status',
        choices=JobPosting.JobStatus.choices,
        label=_('Job Status')
    )
    is_expired = django_filters.BooleanFilter(
        method='filter_is_expired',
        label=_('Expired listings')
    )
    has_applications = django_filters.BooleanFilter(
        method='filter_has_applications',
        label=_('Has applications')
    )

    # Analytics-based filters
    min_views = django_filters.NumberFilter(
        field_name='view_count',
        lookup_expr='gte',
        label=_('Minimum views')
    )
    min_applications = django_filters.NumberFilter(
        method='filter_min_applications',
        label=_('Minimum applications')
    )

    # Date range filters
    published_after = django_filters.DateTimeFilter(
        field_name='published_at',
        lookup_expr='gte',
        label=_('Published after')
    )
    published_before = django_filters.DateTimeFilter(
        field_name='published_at',
        lookup_expr='lte',
        label=_('Published before')
    )
    expires_before = django_filters.DateTimeFilter(
        field_name='expires_at',
        lookup_expr='lte',
        label=_('Expires before')
    )

    class Meta(PublicJobListingFilter.Meta):
        fields = PublicJobListingFilter.Meta.fields + [
            'status', 'is_expired', 'has_applications',
            'min_views', 'min_applications',
            'published_after', 'published_before', 'expires_before',
        ]

    def filter_is_expired(self, queryset, name, value):
        """Filter expired or active listings."""
        now = timezone.now()
        if value:
            return queryset.filter(expires_at__lt=now)
        return queryset.filter(
            Q(expires_at__isnull=True) | Q(expires_at__gte=now)
        )

    def filter_has_applications(self, queryset, name, value):
        """Filter listings with/without applications."""
        if value:
            return queryset.filter(public_applications__isnull=False).distinct()
        return queryset.filter(public_applications__isnull=True)

    def filter_min_applications(self, queryset, name, value):
        """Filter by minimum application count."""
        if not value:
            return queryset
        from django.db.models import Count
        return queryset.annotate(
            app_count=Count('public_applications')
        ).filter(app_count__gte=value)


class PublicApplicationFilter(django_filters.FilterSet):
    """
    Filters for admin viewing public applications.
    """

    # Status filters
    status = django_filters.ChoiceFilter(
        choices=PublicApplication.ApplicationStatus.choices,
        label=_('Application Status')
    )

    # Job filter
    job_listing = django_filters.ModelChoiceFilter(
        queryset=JobListing.objects.all(),
        label=_('Job Listing')
    )
    job_title = django_filters.CharFilter(
        field_name='job_listing__job__title',
        lookup_expr='icontains',
        label=_('Job Title')
    )

    # Applicant search
    search = django_filters.CharFilter(
        method='filter_search',
        label=_('Search applicant')
    )
    email = django_filters.CharFilter(
        lookup_expr='icontains',
        label=_('Email')
    )

    # Date filters
    submitted_after = django_filters.DateTimeFilter(
        field_name='submitted_at',
        lookup_expr='gte',
        label=_('Submitted after')
    )
    submitted_before = django_filters.DateTimeFilter(
        field_name='submitted_at',
        lookup_expr='lte',
        label=_('Submitted before')
    )

    # Source tracking filters
    utm_source = django_filters.CharFilter(
        lookup_expr='icontains',
        label=_('UTM Source')
    )
    utm_campaign = django_filters.CharFilter(
        lookup_expr='icontains',
        label=_('UTM Campaign')
    )

    # Consent filters
    has_marketing_consent = django_filters.BooleanFilter(
        field_name='marketing_consent',
        label=_('Has marketing consent')
    )

    class Meta:
        model = PublicApplication
        fields = [
            'status', 'job_listing', 'job_title', 'search', 'email',
            'submitted_after', 'submitted_before',
            'utm_source', 'utm_campaign', 'has_marketing_consent',
        ]

    def filter_search(self, queryset, name, value):
        """Search by name or email."""
        if not value:
            return queryset
        return queryset.filter(
            Q(first_name__icontains=value) |
            Q(last_name__icontains=value) |
            Q(email__icontains=value)
        )


class TalentPoolFilter(django_filters.FilterSet):
    """Filters for talent pool management."""

    search = django_filters.CharFilter(
        method='filter_search',
        label=_('Search pools')
    )
    is_public = django_filters.BooleanFilter(
        label=_('Public pools')
    )
    has_members = django_filters.BooleanFilter(
        method='filter_has_members',
        label=_('Has members')
    )
    created_by = django_filters.NumberFilter(
        field_name='created_by__id',
        label=_('Created by user ID')
    )

    class Meta:
        model = TalentPool
        fields = ['search', 'is_public', 'has_members', 'created_by']

    def filter_search(self, queryset, name, value):
        """Search by pool name or description."""
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value) |
            Q(description__icontains=value)
        )

    def filter_has_members(self, queryset, name, value):
        """Filter pools with/without members."""
        if value:
            return queryset.filter(members__isnull=False).distinct()
        return queryset.filter(members__isnull=True)


class TalentPoolMemberFilter(django_filters.FilterSet):
    """Filters for talent pool members."""

    pool = django_filters.ModelChoiceFilter(
        queryset=TalentPool.objects.all(),
        label=_('Talent Pool')
    )
    search = django_filters.CharFilter(
        method='filter_search',
        label=_('Search candidates')
    )
    skills = django_filters.CharFilter(
        method='filter_skills',
        label=_('Skills (comma-separated)')
    )
    added_after = django_filters.DateTimeFilter(
        field_name='added_at',
        lookup_expr='gte',
        label=_('Added after')
    )

    class Meta:
        model = TalentPoolMember
        fields = ['pool', 'search', 'skills', 'added_after']

    def filter_search(self, queryset, name, value):
        """Search by candidate name or email."""
        if not value:
            return queryset
        return queryset.filter(
            Q(candidate__first_name__icontains=value) |
            Q(candidate__last_name__icontains=value) |
            Q(candidate__email__icontains=value)
        )

    def filter_skills(self, queryset, name, value):
        """Filter by candidate skills."""
        if not value:
            return queryset
        skills = [s.strip().lower() for s in value.split(',') if s.strip()]
        for skill in skills:
            queryset = queryset.filter(candidate__skills__icontains=skill)
        return queryset
