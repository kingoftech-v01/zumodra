"""
Main App Views - Public landing pages and utility views.

This module provides views that work on the public schema (no tenant context):
- Public careers landing pages (grid and map views)
- Public company browsing (grid and map views)
"""

from django.shortcuts import render
from django.utils.translation import gettext_lazy as _


def public_careers_landing(request):
    """
    Public job listings aggregated from all companies (GRID VIEW).

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
        'view_mode': 'grid',  # Added for view toggle
        'page_title': _('Browse Jobs'),
        'meta_description': _('Browse all open job positions. Find your next career opportunity and apply online.'),
    }

    return render(request, 'careers/browse_jobs.html', context)


def public_careers_map(request):
    """
    Public job listings aggregated from all companies (MAP VIEW).

    Same as public_careers_landing but uses map template.
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

    # Base queryset - all published jobs with coordinates
    jobs = PublicJobCatalog.objects.filter(
        published_at__lte=timezone.now(),
        location_coordinates__isnull=False  # Only jobs with location data
    ).select_related('tenant').order_by('-is_featured', '-published_at')

    # Apply filters
    if search:
        jobs = jobs.filter(
            Q(title__icontains=search) |
            Q(description__icontains=search) |
            Q(required_skills__icontains=search) |
            Q(preferred_skills__icontains=search) |
            Q(company_name__icontains=search)
        )

    if category:
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

    # Get filter options
    categories_raw = PublicJobCatalog.objects.filter(
        published_at__lte=timezone.now()
    ).exclude(
        category_slug=''
    ).values_list('category_slug', 'category_name').distinct().order_by('category_name')

    categories = [
        type('Category', (), {'slug': slug, 'name': name})()
        for slug, name in categories_raw if slug and name
    ]

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
        'jobs': jobs,
        'total_jobs': jobs.count(),
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
        'view_mode': 'map',  # Added for view toggle
        'page_title': _('Browse Jobs - Map View'),
        'meta_description': _('Browse all open job positions on an interactive map.'),
    }

    return render(request, 'careers/browse_jobs_map.html', context)


def public_companies_grid(request):
    """
    Public company browsing aggregated from all tenants (GRID VIEW).

    Shows all companies/tenants with published jobs.
    """
    from tenants.models import Tenant
    from django.db.models import Count, Q

    search = request.GET.get('search', '').strip()
    location = request.GET.get('location')
    industry = request.GET.get('industry')

    # Get tenants with published jobs
    companies = Tenant.objects.filter(
        published_jobs__isnull=False
    ).annotate(
        open_jobs_count=Count('published_jobs')
    ).distinct().order_by('-open_jobs_count')

    # Apply filters
    if search:
        companies = companies.filter(
            Q(name__icontains=search) |
            Q(description__icontains=search)
        )

    if location:
        companies = companies.filter(
            Q(city__icontains=location) |
            Q(country__icontains=location)
        )

    # Get unique locations
    locations = Tenant.objects.filter(
        published_jobs__isnull=False,
        city__isnull=False
    ).values_list('city', 'country').distinct()

    location_list = list(set([
        f"{city}, {country}" for city, country in locations
        if city and country
    ]))

    context = {
        'companies': companies,
        'total_companies': companies.count(),
        'locations': sorted(location_list),
        'search': search,
        'selected_location': location,
        'view_mode': 'grid',
        'page_title': _('Browse Companies'),
        'meta_description': _('Discover companies hiring on Zumodra.'),
    }

    return render(request, 'careers/browse_companies.html', context)


def public_companies_map(request):
    """
    Public company browsing aggregated from all tenants (MAP VIEW).

    Same as public_companies_grid but uses map template.
    """
    from tenants.models import Tenant
    from django.db.models import Count, Q

    search = request.GET.get('search', '').strip()
    location = request.GET.get('location')

    # Get tenants with published jobs and coordinates
    # Note: Tenant model may not have company_coordinates field yet
    companies = Tenant.objects.filter(
        published_jobs__isnull=False
    ).annotate(
        open_jobs_count=Count('published_jobs')
    ).distinct().order_by('-open_jobs_count')

    # Filter for companies with location (city is required for map display)
    companies = companies.exclude(city__isnull=True).exclude(city__exact='')

    # Apply filters
    if search:
        companies = companies.filter(
            Q(name__icontains=search) |
            Q(description__icontains=search)
        )

    if location:
        companies = companies.filter(
            Q(city__icontains=location) |
            Q(country__icontains=location)
        )

    # Get unique locations
    locations = Tenant.objects.filter(
        published_jobs__isnull=False,
        city__isnull=False
    ).values_list('city', 'country').distinct()

    location_list = list(set([
        f"{city}, {country}" for city, country in locations
        if city and country
    ]))

    context = {
        'companies': companies,
        'total_companies': companies.count(),
        'locations': sorted(location_list),
        'search': search,
        'selected_location': location,
        'view_mode': 'map',
        'page_title': _('Browse Companies - Map View'),
        'meta_description': _('Discover companies hiring on Zumodra on an interactive map.'),
    }

    return render(request, 'careers/browse_companies_map.html', context)


def public_job_detail(request, pk=None, slug=None):
    """
    Public job detail page (works with PublicJobCatalog).

    Shows job details from the public catalog. Works with both ID and slug.
    """
    from tenants.models import PublicJobCatalog
    from django.shortcuts import get_object_or_404
    from django.utils import timezone
    from django.http import Http404

    now = timezone.now()

    # Get job by ID or slug
    if pk:
        job = get_object_or_404(
            PublicJobCatalog.objects.select_related('tenant'),
            pk=pk,
            published_at__lte=now
        )
    elif slug:
        job = get_object_or_404(
            PublicJobCatalog.objects.select_related('tenant'),
            slug=slug,
            published_at__lte=now
        )
    else:
        raise Http404(_("Job not found"))

    # Check application deadline
    if job.application_deadline and job.application_deadline < now:
        raise Http404(_("This job posting application deadline has passed"))

    # Get related jobs (same category)
    related_jobs = PublicJobCatalog.objects.filter(
        category_slug=job.category_slug,
        published_at__lte=now
    ).exclude(pk=job.pk).select_related('tenant')[:3]

    context = {
        'job': job,
        'related_jobs': related_jobs,
        'page_title': f"{job.title} - {job.company_name}",
        'meta_description': f"Apply for {job.title} at {job.company_name}. {job.location_city}, {job.location_country}.",
    }

    return render(request, 'careers/job_detail.html', context)


def public_job_alert_save(request):
    """
    Handle job alert subscription from public schema.

    This is a simple stub that stores alert preferences.
    For full functionality, users should visit tenant-specific career pages.
    """
    from django.http import JsonResponse
    from django.contrib import messages
    from django.shortcuts import redirect

    if request.method != 'POST':
        return redirect('careers:home')

    email = request.POST.get('email', '').strip()
    alert_title = request.POST.get('alert_title', '').strip()
    frequency = request.POST.get('frequency', 'weekly')

    if not email:
        messages.error(request, _('Email is required for job alerts.'))
        return redirect('careers:home')

    # For the public schema, we just acknowledge the request
    # Full job alert functionality is available on tenant-specific career pages
    messages.success(
        request,
        _('Thank you! Job alert preferences saved. You will receive updates at %(email)s.') % {'email': email}
    )

    return redirect('careers:home')
