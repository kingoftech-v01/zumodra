from django.shortcuts import render
from django.http import HttpResponse, FileResponse, Http404
from django.conf import settings
import os


# =============================================================================
# PUBLIC PAGE VIEWS
# =============================================================================
# All public pages extend base.html and use i18n for translation support.
# =============================================================================

def home_view(request):
    """Homepage with hero, features, and testimonials."""
    return render(request, 'index.html')


def about_us_view(request):
    """About us page with company story and team."""
    return render(request, 'about-us.html')


def services_view(request):
    """Services overview page."""
    return render(request, 'services.html')


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