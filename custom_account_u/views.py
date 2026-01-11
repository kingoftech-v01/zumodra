from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
import requests
from django.http import HttpResponse, HttpResponseServerError
import hmac
import hashlib
import json
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt

# Get API keys from settings (never hardcode secrets)
MY_API_KEY = getattr(settings, 'IDENFY_API_KEY', '')
MY_API_SECRET = getattr(settings, 'IDENFY_API_SECRET', '')
IDENFY_GENERATE_TOKEN_URL = 'https://ivs.idenfy.com/api/v2/token'
IDENFY_REDIRECT_URL = 'https://ivs.idenfy.com/api/v2/redirect'
IDENFY_KYB_URL = 'https://ivs.idenfy.com/api/v2/kyb'
SECRET_WEBHOOK_KEY = getattr(settings, 'IDENFY_WEBHOOK_SECRET', '')


@login_required
def launch_kyc_view(request):
    """Launch KYC verification page - requires authentication."""
    return render(request, 'accounts/launch_kyc.html')

def create_identification_token():
    try:
        payload = {"clientId": "votre_client_id_depuis_idenfy"}
        response = requests.post(
            url=IDENFY_GENERATE_TOKEN_URL,
            json=payload,
            auth=(MY_API_KEY, MY_API_SECRET),
            timeout=10
        )
        response.raise_for_status()
        return response.json().get('authToken')
    except Exception as e:
        print(f"Erreur création token iDenfy : {e}")
        return None

@login_required
def start_kyc(request):
    """Start KYC process - requires authentication."""
    token = create_identification_token()
    if token:
        url = f"{IDENFY_REDIRECT_URL}?authToken={token}"
        return redirect(url)
    else:
        return HttpResponseServerError("Erreur lors de la génération du jeton iDenfy.")

# utils/face_verification.py
def check_face_auth_status(scanRef):
    url = f"https://ivs.idenfy.com/identification/facial-auth/{scanRef}/check-status/?method=FACE_MATCHING"
    response = requests.get(url, auth=(MY_API_KEY, MY_API_SECRET))
    data = response.json()
    print("Statut vérification visage :", data)
    return data

def generate_face_auth_token(scanRef):
    payload = {
        "scanRef": scanRef,
        "type": "AUTHENTICATION",
        "method": "FACE_MATCHING",
        "generateDigitString": True
    }
    url = "https://ivs.idenfy.com/partner/authentication-info"
    response = requests.post(url, json=payload, auth=(MY_API_KEY, MY_API_SECRET))
    print("Jeton d’authentification faciale :", response.json())
    return response.json()

@login_required
def start_face_auth(request, scanRef):
    """Start face authentication - requires authentication."""
    token = generate_face_auth_token(scanRef)
    if token:
        url = f"https://ivs.idenfy.com/identification/facial-auth/{scanRef}/start/?authToken={token['authToken']}"
        return redirect(url)
    else:
        return HttpResponseServerError("Erreur lors de la génération du jeton d'authentification faciale.")
    
# utils/kyb_verification.py
def verify_business(legal_name, registration_number, country_code):
    payload = {
        "companyName": legal_name,
        "registrationNumber": registration_number,
        "countryCode": country_code
    }
    try:
        response = requests.post(
            url=IDENFY_KYB_URL,
            json=payload,
            auth=(MY_API_KEY, MY_API_SECRET)
        )
        response.raise_for_status()
        data = response.json()
        print("Résultat KYB :", data)
        return data
    except Exception as e:
        print(f"Erreur KYB iDenfy : {e}")
        return None

@login_required
def start_kyb(request):
    """Start KYB (Know Your Business) verification - requires authentication."""
    legal_name = request.POST.get('legal_name')
    registration_number = request.POST.get('registration_number')
    country_code = request.POST.get('country_code')
    result = verify_business(legal_name, registration_number, country_code)
    return render(request, 'accounts/kyb.html', {'result': result})

@csrf_exempt
def idenfy_webhook(request):
    try:
        body = request.body.decode('utf-8')
        signature = request.headers.get('X-Signature', '')
        computed = hmac.new(
            SECRET_WEBHOOK_KEY.encode(),
            body.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, computed):
            return HttpResponseForbidden("Invalid signature")

        data = json.loads(body)
        event_type = data.get("eventType")
        scan_ref = data.get("scanRef")
        status = data.get("status")

        print(f"Webhook reçu : {event_type} ({status}) pour scanRef={scan_ref}")

        if event_type == "IDENTIFICATION_COMPLETED" and status == "APPROVED":
            # Vérification réussie
            # → Créez/validez votre utilisateur ici
            pass

        elif event_type == "IDENTIFICATION_EXPIRED":
            print("Session expirée ou annulée")

        return JsonResponse({"message": "ok"})
    except Exception as e:
        print(f"Erreur webhook: {e}")
        return JsonResponse({"error": str(e)}, status=400)


# =============================================================================
# PublicProfile Views
# =============================================================================

from django.shortcuts import get_object_or_404
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.db.models import Q

from .models import PublicProfile, ProfileFieldSync


@login_required
def public_profile_view(request):
    """
    View and edit own public marketplace profile.
    GET: Display profile form
    POST: Update profile
    """
    profile, created = PublicProfile.objects.get_or_create(
        user=request.user,
        defaults={'display_name': f"{request.user.first_name} {request.user.last_name}".strip() or request.user.email}
    )

    if request.method == 'POST':
        # Basic fields
        profile.display_name = request.POST.get('display_name', profile.display_name)
        profile.professional_title = request.POST.get('professional_title', '')
        profile.bio = request.POST.get('bio', '')
        profile.public_email = request.POST.get('public_email', '')
        profile.phone = request.POST.get('phone', '')

        # Location
        profile.city = request.POST.get('city', '')
        profile.state = request.POST.get('state', '')
        profile.country = request.POST.get('country', 'CA')
        profile.timezone = request.POST.get('timezone', 'America/Toronto')

        # Links
        profile.linkedin_url = request.POST.get('linkedin_url', '')
        profile.github_url = request.POST.get('github_url', '')
        profile.portfolio_url = request.POST.get('portfolio_url', '')
        profile.personal_website = request.POST.get('personal_website', '')

        # Marketplace
        profile.available_for_work = request.POST.get('available_for_work') == 'on'
        profile.profile_visibility = request.POST.get('profile_visibility', profile.profile_visibility)

        # Hourly rates
        hourly_min = request.POST.get('hourly_rate_min', '')
        hourly_max = request.POST.get('hourly_rate_max', '')
        profile.hourly_rate_min = float(hourly_min) if hourly_min else None
        profile.hourly_rate_max = float(hourly_max) if hourly_max else None
        profile.currency = request.POST.get('currency', 'CAD')

        # Handle file uploads
        if 'avatar' in request.FILES:
            profile.avatar = request.FILES['avatar']
        if 'cv_file' in request.FILES:
            profile.cv_file = request.FILES['cv_file']
            from django.utils import timezone
            profile.cv_last_updated = timezone.now()

        profile.save()
        messages.success(request, 'Your public profile has been updated successfully!')
        return redirect('custom_account_u:public_profile')

    context = {
        'profile': profile,
        'completion_percentage': profile.completion_percentage,
        'verification_badges': profile.verification_badges,
        'visibility_choices': PublicProfile.VISIBILITY_CHOICES,
    }

    return render(request, 'custom_account_u/public_profile.html', context)


@login_required
def profile_sync_settings_list(request):
    """
    View all profile sync settings across all tenants user has joined.
    """
    sync_settings = ProfileFieldSync.objects.filter(user=request.user).order_by('-created_at')

    # Get tenant information (we'll need to query Tenant model)
    from tenants.models import Tenant
    tenant_map = {}
    for setting in sync_settings:
        if setting.tenant_uuid not in tenant_map:
            try:
                tenant = Tenant.objects.get(uuid=setting.tenant_uuid)
                tenant_map[setting.tenant_uuid] = tenant
            except Tenant.DoesNotExist:
                tenant_map[setting.tenant_uuid] = None

    context = {
        'sync_settings': sync_settings,
        'tenant_map': tenant_map,
    }

    return render(request, 'custom_account_u/sync_settings_list.html', context)


@login_required
def profile_sync_settings_edit(request, tenant_uuid):
    """
    Edit profile sync settings for a specific tenant.
    Controls which fields sync from PublicProfile to TenantProfile.
    """
    # Verify user is member of this tenant
    from tenants.models import Tenant
    from accounts.models import TenantUser

    try:
        tenant = Tenant.objects.get(uuid=tenant_uuid)
    except Tenant.DoesNotExist:
        messages.error(request, 'Tenant not found.')
        return redirect('custom_account_u:sync_settings_list')

    # Verify user membership (check in tenant schema)
    from django_tenants.utils import tenant_context
    with tenant_context(tenant):
        if not TenantUser.objects.filter(user=request.user, tenant=tenant).exists():
            messages.error(request, 'You are not a member of this organization.')
            return redirect('custom_account_u:sync_settings_list')

    # Get or create sync settings
    sync_settings, created = ProfileFieldSync.get_or_create_defaults(
        user=request.user,
        tenant_uuid=tenant_uuid
    )

    if request.method == 'POST':
        # Update field sync toggles
        sync_settings.sync_display_name = request.POST.get('sync_display_name') == 'on'
        sync_settings.sync_avatar = request.POST.get('sync_avatar') == 'on'
        sync_settings.sync_bio = request.POST.get('sync_bio') == 'on'
        sync_settings.sync_public_email = request.POST.get('sync_public_email') == 'on'
        sync_settings.sync_phone = request.POST.get('sync_phone') == 'on'
        sync_settings.sync_city = request.POST.get('sync_city') == 'on'
        sync_settings.sync_state = request.POST.get('sync_state') == 'on'
        sync_settings.sync_country = request.POST.get('sync_country') == 'on'
        sync_settings.sync_linkedin = request.POST.get('sync_linkedin') == 'on'
        sync_settings.sync_github = request.POST.get('sync_github') == 'on'
        sync_settings.sync_portfolio = request.POST.get('sync_portfolio') == 'on'
        sync_settings.sync_skills = request.POST.get('sync_skills') == 'on'
        sync_settings.sync_languages = request.POST.get('sync_languages') == 'on'
        sync_settings.auto_sync = request.POST.get('auto_sync') == 'on'

        sync_settings.save()

        messages.success(request, f'Sync settings for {tenant.name} have been updated!')
        return redirect('custom_account_u:sync_settings_list')

    context = {
        'sync_settings': sync_settings,
        'tenant': tenant,
        'enabled_fields': sync_settings.get_enabled_fields(),
    }

    return render(request, 'custom_account_u/sync_settings_edit.html', context)


@login_required
def trigger_manual_sync(request, tenant_uuid):
    """
    Trigger manual profile sync for a specific tenant.
    POST only.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    from tenants.models import Tenant
    from accounts.services import ProfileSyncService

    try:
        tenant = Tenant.objects.get(uuid=tenant_uuid)
    except Tenant.DoesNotExist:
        return JsonResponse({'error': 'Tenant not found'}, status=404)

    # Trigger sync
    try:
        result = ProfileSyncService.sync_manual_trigger(
            user=request.user,
            tenant=tenant
        )

        if result['success']:
            messages.success(
                request,
                f"Successfully synced {len(result['synced_fields'])} fields to {tenant.name}!"
            )
            return JsonResponse({
                'success': True,
                'synced_fields': result['synced_fields'],
                'sync_timestamp': result['sync_timestamp'],
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Unknown error')
            }, status=400)

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
def view_other_public_profile(request, profile_uuid):
    """
    View another user's public marketplace profile.
    Respects visibility settings.
    """
    profile = get_object_or_404(PublicProfile, uuid=profile_uuid)

    # Check visibility
    if profile.profile_visibility == PublicProfile.VISIBILITY_PRIVATE:
        if profile.user != request.user:
            messages.error(request, 'This profile is private.')
            return redirect('dashboard')

    elif profile.profile_visibility == PublicProfile.VISIBILITY_TENANTS_ONLY:
        # Check if viewer shares a tenant with profile owner
        from accounts.models import TenantUser

        viewer_tenants = set(TenantUser.objects.filter(user=request.user).values_list('tenant_id', flat=True))
        profile_tenants = set(TenantUser.objects.filter(user=profile.user).values_list('tenant_id', flat=True))

        if not viewer_tenants.intersection(profile_tenants) and profile.user != request.user:
            messages.error(request, 'This profile is only visible to shared organizations.')
            return redirect('dashboard')

    context = {
        'profile': profile,
        'is_own_profile': profile.user == request.user,
        'completion_percentage': profile.completion_percentage,
        'verification_badges': profile.verification_badges,
    }

    return render(request, 'custom_account_u/public_profile_view.html', context)


@login_required
def public_profile_search(request):
    """
    Search public marketplace profiles.
    For marketplace/freelance discovery.
    """
    query = request.GET.get('q', '')
    skills = request.GET.getlist('skills')
    location = request.GET.get('location', '')
    available_only = request.GET.get('available_only') == 'on'

    profiles = PublicProfile.objects.filter(
        profile_visibility=PublicProfile.VISIBILITY_PUBLIC
    )

    if query:
        profiles = profiles.filter(
            Q(display_name__icontains=query) |
            Q(professional_title__icontains=query) |
            Q(bio__icontains=query)
        )

    if skills:
        # Filter by skills (JSON field contains any of the selected skills)
        for skill in skills:
            profiles = profiles.filter(skills__contains=[skill])

    if location:
        profiles = profiles.filter(
            Q(city__icontains=location) |
            Q(state__icontains=location) |
            Q(country__icontains=location)
        )

    if available_only:
        profiles = profiles.filter(available_for_work=True)

    profiles = profiles.order_by('-updated_at')

    # Pagination
    paginator = Paginator(profiles, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'profiles': page_obj,
        'query': query,
        'skills': skills,
        'location': location,
        'available_only': available_only,
    }

    return render(request, 'custom_account_u/profile_search.html', context)


