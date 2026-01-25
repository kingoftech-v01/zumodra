"""
Accounts Freelancer Profile Template Views - Frontend HTML views.

This module provides template-based views for freelancer profiles:
- Public freelancer browsing (grid and map views)
- Freelancer profile detail page
- Own profile management (create/edit)
- Portfolio showcase

All views render HTML templates using Django's render().
Uses HTMX for dynamic interactions and Alpine.js for client-side reactivity.

URL Namespace: frontend:accounts:freelancer_*
"""

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from .models import FreelancerProfile


# ============================================================================
# PUBLIC BROWSING VIEWS
# ============================================================================

def freelancer_browse(request):
    """
    Browse all verified freelancer profiles (public access).

    Features:
    - Search by name, title, skills
    - Filter by availability, location, skills
    - Sort by rating, hourly rate, experience
    - Pagination (12 profiles per page)
    - Grid view with profile cards

    Template: accounts/freelancer_browse.html
    Context:
        - freelancers: Paginated queryset
        - search: Search query
        - filters: Applied filter values
        - total_count: Total freelancers matching filters
    """
    # Get query parameters
    search = request.GET.get('search', '').strip()
    availability = request.GET.get('availability')
    min_rate = request.GET.get('min_rate')
    max_rate = request.GET.get('max_rate')
    currency = request.GET.get('currency', 'CAD')
    remote_only = request.GET.get('remote_only')
    country = request.GET.get('country')
    skills = request.GET.get('skills', '').strip()
    sort_by = request.GET.get('sort', '-average_rating')
    page = request.GET.get('page', 1)

    # Base queryset - only verified freelancers
    freelancers = FreelancerProfile.objects.filter(
        is_verified=True
    ).select_related('user').prefetch_related('categories')

    # Apply search (name, title, bio, skills)
    if search:
        freelancers = freelancers.filter(
            Q(user__first_name__icontains=search) |
            Q(user__last_name__icontains=search) |
            Q(professional_title__icontains=search) |
            Q(bio__icontains=search) |
            Q(skills__icontains=search)
        )

    # Apply availability filter
    if availability:
        freelancers = freelancers.filter(availability_status=availability)

    # Apply hourly rate filters
    if min_rate:
        freelancers = freelancers.filter(
            hourly_rate__gte=min_rate,
            hourly_rate_currency=currency
        )

    if max_rate:
        freelancers = freelancers.filter(
            hourly_rate__lte=max_rate,
            hourly_rate_currency=currency
        )

    # Apply remote-only filter
    if remote_only == 'true':
        freelancers = freelancers.filter(remote_only=True)

    # Apply country filter
    if country:
        freelancers = freelancers.filter(country__iexact=country)

    # Apply skills filter (contains any of comma-separated skills)
    if skills:
        skill_list = [s.strip() for s in skills.split(',')]
        for skill in skill_list:
            freelancers = freelancers.filter(skills__icontains=skill)

    # Apply sorting
    valid_sorts = [
        'hourly_rate', '-hourly_rate',
        'average_rating', '-average_rating',
        'years_of_experience', '-years_of_experience',
        'created_at', '-created_at'
    ]
    if sort_by in valid_sorts:
        freelancers = freelancers.order_by(sort_by)
    else:
        freelancers = freelancers.order_by('-average_rating', '-created_at')

    # Pagination
    paginator = Paginator(freelancers, 12)
    freelancers_page = paginator.get_page(page)

    # Get unique countries for filter dropdown
    countries = FreelancerProfile.objects.filter(
        is_verified=True,
        country__isnull=False
    ).exclude(country='').values_list('country', flat=True).distinct().order_by('country')

    # Get common skills for filter suggestions
    # (This could be optimized with aggregation)
    common_skills = ['Python', 'JavaScript', 'React', 'Django', 'Node.js', 'TypeScript', 'AWS', 'Docker']

    context = {
        'freelancers': freelancers_page,
        'total_count': paginator.count,
        'search': search,
        'availability': availability,
        'min_rate': min_rate,
        'max_rate': max_rate,
        'currency': currency,
        'remote_only': remote_only,
        'country': country,
        'skills': skills,
        'sort_by': sort_by,
        'countries': countries,
        'common_skills': common_skills,
        'currencies': ['CAD', 'USD', 'EUR', 'GBP'],
        'page_title': _('Browse Freelancers'),
        'meta_description': _('Find verified freelancers for your next project'),
    }

    return render(request, 'accounts/freelancer_browse.html', context)


def freelancer_available(request):
    """
    Browse only available freelancers (shortcut view).

    Same as freelancer_browse but pre-filtered to available status.

    Template: accounts/freelancer_browse.html
    """
    # Clone request.GET and add availability filter
    from django.http import QueryDict
    query_dict = request.GET.copy()
    query_dict['availability'] = 'available'
    request.GET = query_dict

    return freelancer_browse(request)


# ============================================================================
# DETAIL VIEWS
# ============================================================================

def freelancer_detail(request, uuid):
    """
    Display detailed public profile for a freelancer.

    Shows:
    - Professional info and bio
    - Skills and categories
    - Portfolio links
    - Stats (ratings, completed projects)
    - Reviews (if implemented)
    - Contact button (for authenticated users)

    Template: accounts/freelancer_detail.html
    Context:
        - freelancer: FreelancerProfile instance
        - can_contact: Whether current user can contact this freelancer
        - similar_freelancers: Suggestions based on skills/category
    """
    freelancer = get_object_or_404(
        FreelancerProfile.objects.select_related('user').prefetch_related('categories'),
        uuid=uuid,
        is_verified=True  # Only show verified profiles publicly
    )

    # Permission check for contact button
    can_contact = request.user.is_authenticated and request.user != freelancer.user

    # Get similar freelancers (same category or similar skills)
    similar_freelancers = FreelancerProfile.objects.filter(
        is_verified=True,
        availability_status='available'
    ).exclude(uuid=uuid)

    # Filter by shared categories
    if freelancer.categories.exists():
        similar_freelancers = similar_freelancers.filter(
            categories__in=freelancer.categories.all()
        )

    similar_freelancers = similar_freelancers.distinct()[:6]

    context = {
        'freelancer': freelancer,
        'can_contact': can_contact,
        'similar_freelancers': similar_freelancers,
        'page_title': f"{freelancer.professional_title} - {freelancer.user.get_full_name() or freelancer.user.email}",
        'meta_description': freelancer.bio[:160] if freelancer.bio else '',
    }

    return render(request, 'accounts/freelancer_detail.html', context)


# ============================================================================
# PROFILE MANAGEMENT VIEWS (Authenticated)
# ============================================================================

@login_required
def freelancer_profile_me(request):
    """
    View/Edit current user's freelancer profile.

    GET: Display profile or creation form if no profile exists
    Redirects to creation or edit view as appropriate

    This is a router view that determines whether to show
    create or edit based on profile existence.
    """
    try:
        profile = FreelancerProfile.objects.get(user=request.user)
        # Redirect to edit view
        return redirect('accounts:frontend:freelancer_profile_edit', uuid=profile.uuid)
    except FreelancerProfile.DoesNotExist:
        # Redirect to create view
        return redirect('accounts:frontend:freelancer_profile_create')


@login_required
def freelancer_profile_create(request):
    """
    Create a new freelancer profile for current user.

    GET: Display empty form
    POST: Validate and save new profile

    Template: accounts/freelancer_profile_form.html
    Context:
        - form: FreelancerProfileForm instance (if using forms)
        - form_title: "Create Freelancer Profile"
        - is_create: True
    """
    # Check if user already has a profile
    if hasattr(request.user, 'freelancer_profile'):
        messages.warning(request, _('You already have a freelancer profile'))
        return redirect('accounts:frontend:freelancer_profile_edit',
                       uuid=request.user.freelancer_profile.uuid)

    if request.method == 'POST':
        # For now, just show a message (form implementation can be added later)
        messages.info(
            request,
            _('Freelancer profile creation via HTML forms coming soon. Please use the API endpoint.')
        )
        return redirect('accounts:frontend:freelancer_profile_me')

    context = {
        'form_title': _('Create Your Freelancer Profile'),
        'is_create': True,
        'cancel_url': 'dashboard:index',
        'api_endpoint': '/api/v1/accounts/freelancer-profiles/me/',
        'page_title': _('Create Freelancer Profile'),
    }

    return render(request, 'accounts/freelancer_profile_form.html', context)


@login_required
def freelancer_profile_edit(request, uuid):
    """
    Edit existing freelancer profile.

    GET: Display pre-filled form
    POST: Validate and save changes

    Only owner can edit their own profile.

    Template: accounts/freelancer_profile_form.html
    Context:
        - freelancer: FreelancerProfile instance
        - form: FreelancerProfileForm with current data
        - form_title: "Edit Freelancer Profile"
        - is_create: False
    """
    freelancer = get_object_or_404(FreelancerProfile, uuid=uuid)

    # Permission check - only owner can edit
    if freelancer.user != request.user:
        messages.error(request, _('You can only edit your own freelancer profile'))
        return redirect('accounts:frontend:freelancer_detail', uuid=uuid)

    if request.method == 'POST':
        # For now, just show a message (form implementation can be added later)
        messages.info(
            request,
            _('Freelancer profile editing via HTML forms coming soon. Please use the API endpoint.')
        )
        return redirect('accounts:frontend:freelancer_detail', uuid=uuid)

    context = {
        'freelancer': freelancer,
        'form_title': _('Edit Your Freelancer Profile'),
        'is_create': False,
        'cancel_url': 'accounts:frontend:freelancer_detail',
        'api_endpoint': f'/api/v1/accounts/freelancer-profiles/{uuid}/',
        'page_title': _('Edit Freelancer Profile'),
    }

    return render(request, 'accounts/freelancer_profile_form.html', context)


@login_required
def freelancer_profile_dashboard(request):
    """
    Freelancer dashboard showing stats and activity.

    Displays:
    - Profile completion status
    - Recent activity
    - Earnings summary
    - Pending proposals/contracts
    - Reviews received

    Template: accounts/freelancer_dashboard.html
    Context:
        - freelancer: FreelancerProfile instance
        - completion_percentage: Profile completion %
        - recent_activity: Recent projects/services
        - stats: Aggregated statistics
    """
    try:
        freelancer = FreelancerProfile.objects.select_related('user').prefetch_related(
            'categories'
        ).get(user=request.user)
    except FreelancerProfile.DoesNotExist:
        messages.info(request, _('Create your freelancer profile to access the dashboard'))
        return redirect('accounts:frontend:freelancer_profile_create')

    # Calculate profile completion
    completion_fields = [
        bool(freelancer.professional_title),
        bool(freelancer.bio),
        bool(freelancer.skills),
        bool(freelancer.hourly_rate),
        freelancer.has_portfolio,
        bool(freelancer.city and freelancer.country),
        freelancer.categories.exists(),
    ]
    completion_percentage = int((sum(completion_fields) / len(completion_fields)) * 100)

    # Aggregate stats
    stats = {
        'total_earnings': freelancer.total_earnings,
        'completed_projects': freelancer.completed_projects,
        'completed_services': freelancer.completed_services,
        'average_rating': freelancer.average_rating,
        'total_reviews': freelancer.total_reviews,
        'availability_status': freelancer.get_availability_status_display(),
    }

    context = {
        'freelancer': freelancer,
        'completion_percentage': completion_percentage,
        'stats': stats,
        'page_title': _('Freelancer Dashboard'),
    }

    return render(request, 'accounts/freelancer_dashboard.html', context)


# ============================================================================
# CUSTOM ACTION VIEWS
# ============================================================================

@login_required
def freelancer_toggle_availability(request, uuid):
    """
    Toggle freelancer availability status.

    POST only: Cycle through available → busy → unavailable → available

    Redirects to: freelancer_dashboard or freelancer_detail
    """
    freelancer = get_object_or_404(FreelancerProfile, uuid=uuid)

    # Permission check
    if freelancer.user != request.user:
        messages.error(request, _('You can only update your own availability'))
        return redirect('accounts:frontend:freelancer_detail', uuid=uuid)

    if request.method == 'POST':
        # Cycle availability status
        status_cycle = {
            'available': 'busy',
            'busy': 'unavailable',
            'unavailable': 'available',
        }

        new_status = status_cycle.get(freelancer.availability_status, 'available')
        freelancer.availability_status = new_status
        freelancer.save(update_fields=['availability_status'])

        messages.success(
            request,
            _('Availability updated to %(status)s') % {
                'status': freelancer.get_availability_status_display()
            }
        )

    return redirect('accounts:frontend:freelancer_profile_dashboard')
