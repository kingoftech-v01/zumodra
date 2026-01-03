from django.shortcuts import render
from django.http import HttpResponse, FileResponse, Http404
from django.conf import settings
import os


def term_of_use_view(request):
    return render(request, 'term-of-use.html')

def privacy_policy_view(request):
    return render(request, 'privacy/privacy_policy.html')



def home_view(request):
    return render(request, 'index.html')

def about_us_view(request):
    return render(request, 'about-us.html')

def contact_us_view(request):
    return render(request, 'contact1.html')

def faq_view(request):
    return render(request, 'faqs.html')

def services_view(request):
    return render(request, 'services.html')

def pricing_view(request):
    return render(request, 'pricing.html')


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