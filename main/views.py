"""
Main App Views - Public landing pages and utility views.

This module provides views that work on the public schema (no tenant context):
- Public careers landing page (for when careers tables don't exist)
"""

from django.shortcuts import render
from django.utils.translation import gettext_lazy as _


def public_careers_landing(request):
    """
    Public job listings aggregated from all companies.

    Shows all open jobs from all companies/tenants with search and filtering.
    Users can browse and apply to jobs directly.

    NOTE: This view queries PublicJobCatalog (public schema) instead of JobPosting
    (tenant schema) to avoid cross-schema access issues. Data is synced via signals.
    """
    from tenants.models import PublicJobCatalog
    from django.core.paginator import Paginator
    from django.db.models import Q
    from django.utils import timezone

    # Get filter parameters
    search = request.GET.get('search', '').strip()
    category = request.GET.get('category')
    location = request.GET.get('location')
    job_type = request.GET.get('job_type')
    remote = request.GET.get('remote')
    page = request.GET.get('page', 1)

    # Base queryset - all published jobs from public catalog
    jobs = PublicJobCatalog.objects.filter(
        published_at__lte=timezone.now()
    ).select_related('tenant').order_by('-is_featured', '-published_at')

    # Apply filters
    if search:
        # Search in title, description, and skills (JSONField contains)
        jobs = jobs.filter(
            Q(title__icontains=search) |
            Q(description__icontains=search) |
            Q(required_skills__icontains=search) |
            Q(preferred_skills__icontains=search) |
            Q(company_name__icontains=search)
        )

    if category:
        # Category slug is denormalized in catalog
        jobs = jobs.filter(category_slug=category)

    if location:
        jobs = jobs.filter(
            Q(location_city__icontains=location) |
            Q(location_country__icontains=location) |
            Q(location_state__icontains=location)
        )

    if job_type:
        jobs = jobs.filter(job_type=job_type)

    if remote == 'true':
        jobs = jobs.filter(remote_policy__in=['remote', 'hybrid', 'flexible'])

    # Pagination
    paginator = Paginator(jobs, 12)  # 12 jobs per page
    try:
        jobs_page = paginator.page(page)
    except:
        jobs_page = paginator.page(1)

    # Get filter options from catalog (denormalized data)
    # Categories: get distinct category_slug and category_name pairs
    categories_raw = PublicJobCatalog.objects.filter(
        published_at__lte=timezone.now()
    ).exclude(
        category_slug=''
    ).values_list('category_slug', 'category_name').distinct().order_by('category_name')

    # Convert to objects with slug and name attributes for template compatibility
    categories = [
        type('Category', (), {'slug': slug, 'name': name})()
        for slug, name in categories_raw if slug and name
    ]

    # Locations: get distinct city/country pairs
    locations_raw = PublicJobCatalog.objects.filter(
        published_at__lte=timezone.now()
    ).exclude(
        location_city=''
    ).values_list('location_city', 'location_country').distinct()

    locations = list(set([
        f"{city}, {country}" for city, country in locations_raw
        if city and country
    ]))

    context = {
        'jobs': jobs_page,
        'total_jobs': paginator.count,
        'categories': categories,
        'locations': sorted(locations),
        'job_types': [
            ('full_time', _('Full-time')),
            ('part_time', _('Part-time')),
            ('contract', _('Contract')),
            ('internship', _('Internship')),
            ('temporary', _('Temporary')),
            ('freelance', _('Freelance')),
        ],
        'search': search,
        'selected_category': category,
        'selected_location': location,
        'selected_job_type': job_type,
        'selected_remote': remote,
        'page_title': _('Browse Jobs'),
        'meta_description': _('Browse all open job positions. Find your next career opportunity and apply online.'),
    }

    return render(request, 'careers/browse_jobs.html', context)
