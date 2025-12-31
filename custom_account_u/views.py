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



