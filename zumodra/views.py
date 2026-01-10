from django.shortcuts import render
from django.http import HttpResponse, FileResponse, Http404
from django.conf import settings
from django.db.models import Count, Avg
import os


# =============================================================================
# PUBLIC PAGE VIEWS
# =============================================================================
# All public pages extend base.html and use i18n for translation support.
# =============================================================================

def home_view(request):
    """
    Public homepage with marketplace preview.

    Runs in PUBLIC schema and queries PublicServiceCatalog for marketplace data.
    Shows platform stats, featured services, and service categories from all companies.

    Architecture:
    - User identity: PUBLIC schema (CustomUser)
    - Tenant info: PUBLIC schema (Tenant)
    - Marketplace catalog: PUBLIC schema (PublicServiceCatalog - denormalized)
    - Services: TENANT schemas (not accessible from here)
    """
    from django.contrib.auth import get_user_model
    from tenants.models import Tenant, PublicServiceCatalog
    import logging

    User = get_user_model()
    logger = logging.getLogger(__name__)

    context = {}

    try:
        # Platform-wide stats (public schema only)
        context['stats'] = {
            'total_users': User.objects.filter(is_active=True).count(),
            'total_organizations': Tenant.objects.exclude(schema_name='public').count(),
            'total_services': PublicServiceCatalog.objects.filter(is_active=True).count(),
            'total_freelancers': User.objects.filter(is_available_for_hire=True, is_active=True).count(),
        }

        # Featured services from marketplace catalog
        context['featured_services'] = PublicServiceCatalog.objects.filter(
            is_active=True,
            is_featured=True
        ).select_related('tenant').order_by('-rating_avg', '-published_at')[:6]

        # Service categories (aggregated from catalog)
        context['service_categories'] = (
            PublicServiceCatalog.objects
            .filter(is_active=True)
            .values('category_name', 'category_slug')
            .annotate(service_count=Count('id'))
            .order_by('-service_count')[:8]
        )

        # Top-rated providers (aggregated from catalog)
        from django.db.models import Avg
        context['top_providers'] = (
            PublicServiceCatalog.objects
            .filter(is_active=True)
            .values('provider_name', 'provider_uuid', 'tenant__name', 'tenant__slug')
            .annotate(
                avg_rating=Avg('rating_avg'),
                total_services=Count('id')
            )
            .order_by('-avg_rating', '-total_services')[:4]
        )

    except Exception as e:
        # Handle case where tables don't exist yet (fresh install)
        logger.warning(f"Error loading homepage data: {e}")
        context['stats'] = {
            'total_users': 0,
            'total_organizations': 0,
            'total_services': 0,
            'total_freelancers': 0,
        }
        context['featured_services'] = []
        context['service_categories'] = []
        context['top_providers'] = []

    return render(request, 'index.html', context)


def about_us_view(request):
    """About us page with company story and team."""
    return render(request, 'about-us.html')


def services_view(request):
    """
    Public marketplace browsing (no tenant context required).

    Shows services from PublicServiceCatalog with search, filtering, and sorting.
    Accessible to all users (authenticated or not) for browsing the marketplace.

    Query Parameters:
    - search: Text search in service name/description/category
    - category: Filter by category slug
    - min_price: Minimum price filter
    - max_price: Maximum price filter
    - sort: Sort order (-rating_avg, price, -price, -published_at, name)
    - page: Pagination page number
    """
    from tenants.models import PublicServiceCatalog
    from django.core.paginator import Paginator
    from django.db.models import Q, Count

    services_query = PublicServiceCatalog.objects.filter(is_active=True)

    # Search
    search = request.GET.get('search', '').strip()
    if search:
        services_query = services_query.filter(
            Q(name__icontains=search) |
            Q(description__icontains=search) |
            Q(category_name__icontains=search) |
            Q(provider_name__icontains=search)
        )

    # Filter by category
    category_slug = request.GET.get('category')
    if category_slug:
        services_query = services_query.filter(category_slug=category_slug)

    # Filter by price range
    min_price = request.GET.get('min_price')
    max_price = request.GET.get('max_price')
    if min_price:
        try:
            services_query = services_query.filter(price__gte=float(min_price))
        except (ValueError, TypeError):
            pass
    if max_price:
        try:
            services_query = services_query.filter(price__lte=float(max_price))
        except (ValueError, TypeError):
            pass

    # Sorting
    sort_by = request.GET.get('sort', '-rating_avg')
    allowed_sorts = ['-rating_avg', 'price', '-price', '-published_at', 'name']
    if sort_by in allowed_sorts:
        services_query = services_query.order_by(sort_by)
    else:
        services_query = services_query.order_by('-rating_avg')

    # Pagination
    paginator = Paginator(services_query, 24)  # 24 services per page
    page_number = request.GET.get('page', 1)
    services = paginator.get_page(page_number)

    # Get available categories for filter dropdown
    categories = (
        PublicServiceCatalog.objects
        .filter(is_active=True)
        .values('category_name', 'category_slug')
        .annotate(count=Count('id'))
        .order_by('category_name')
    )

    context = {
        'services': services,
        'categories': categories,
        'search': search,
        'selected_category': category_slug,
        'sort_by': sort_by,
        'min_price': min_price,
        'max_price': max_price,
        'total_count': paginator.count,
    }

    return render(request, 'marketplace/public_services.html', context)


def pricing_view(request):
    """Pricing plans page (Starter, Pro, Business, Enterprise)."""
    return render(request, 'pricing.html')


def faq_view(request):
    """Frequently asked questions page with accordion."""
    return render(request, 'faqs.html')


def contact_us_view(request):
    """Contact page with form and information."""
    return render(request, 'contact.html')


def become_seller_view(request):
    """Freelancer onboarding page."""
    return render(request, 'become-seller.html')


def become_buyer_view(request):
    """Employer/client onboarding page."""
    return render(request, 'become-buyer.html')


def term_of_use_view(request):
    """Terms of use legal page."""
    return render(request, 'term-of-use.html')


def privacy_policy_view(request):
    """Privacy policy legal page."""
    return render(request, 'privacy-policy.html')


def auth_test_view(request):
    """Test view to verify authentication status."""
    if request.user.is_authenticated:
        return HttpResponse(f"Authenticated as: {request.user.email}")
    return HttpResponse("Not authenticated", status=401)


def js_dir_view(request, file_name):
    """Serve JavaScript files from the static/js directory."""
    file_path = os.path.join(settings.STATIC_ROOT, 'js', file_name)
    if os.path.exists(file_path):
        return FileResponse(open(file_path, 'rb'), content_type='application/javascript')
    raise Http404(f"JavaScript file '{file_name}' not found")