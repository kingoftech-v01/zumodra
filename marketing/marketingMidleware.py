import time
import json
from django.utils.deprecation import MiddlewareMixin
from django.utils.crypto import get_random_string
import geoip2.database
from user_agents import parse as parse_user_agent

# Path to GeoLite2 database (update as needed)
GEOIP_DB = '/usr/share/GeoIP/GeoLite2-Country.mmdb'

class AdvancedMarketingMiddleware(MiddlewareMixin):

    def process_request(self, request):
        # Marketing ID, one per user for analytics/tracking
        if 'marketing_id' not in request.COOKIES:
            request.marketing_id = get_random_string(24)
        else:
            request.marketing_id = request.COOKIES['marketing_id']

        # Referral and UTM params for marketing attribution
        ref_params = {}
        for key in ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'ref']:
            if key in request.GET:
                ref_params[key] = request.GET[key]
        request.ref_params = ref_params

        # Device & Browser Detection
        user_agent = parse_user_agent(request.META.get('HTTP_USER_AGENT', ''))
        request.device_type = (
            'mobile' if user_agent.is_mobile else
            'tablet' if user_agent.is_tablet else
            'pc'
        )
        request.browser = user_agent.browser.family
        request.os = user_agent.os.family

        # GeoIP: Country Detection
        ip = self.extract_ip(request)
        try:
            with geoip2.database.Reader(GEOIP_DB) as reader:
                response = reader.country(ip)
                request.country = response.country.iso_code
        except Exception:
            request.country = 'UNKNOWN'

        # Track initial visit timestamp
        if "first_marketing_visit" not in request.session:
            request.session["first_marketing_visit"] = time.time()

    def process_response(self, request, response):
        # Set persistent marketing ID cookie
        if hasattr(request, "marketing_id"):
            response.set_cookie('marketing_id', request.marketing_id, max_age=60 * 60 * 24 * 365)

        # Store referral and UTM params in session
        if hasattr(request, "ref_params") and request.ref_params:
            request.session['ref_params'] = request.ref_params

        # Log extended marketing event
        self.log_event(request)

        return response

    def log_event(self, request):
        event = {
            "timestamp": time.time(),
            "path": getattr(request, "path", ""),
            "method": getattr(request, "method", ""),
            "marketing_id": getattr(request, "marketing_id", None),
            "country": getattr(request, "country", None),
            "device_type": getattr(request, "device_type", None),
            "browser": getattr(request, "browser", None),
            "os": getattr(request, "os", None),
            "ref_params": getattr(request, "ref_params", None),
            "ip": self.extract_ip(request),
        }
        # Push event to your logging, analytics or BI system
        # Example: marketing_logger.log(event)
        print('MARKETING EVENT:', json.dumps(event))

    def extract_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


# In yourapp/middleware/marketing_middleware.py

import time
from django.utils.deprecation import MiddlewareMixin
from django.utils.crypto import get_random_string

class MarketingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Example: Add Marketing ID cookie for tracking
        if "marketing_id" not in request.COOKIES:
            marketing_id = get_random_string(24)
            request.marketing_id = marketing_id
        else:
            request.marketing_id = request.COOKIES["marketing_id"]

        # Example: Capture referral/UTM params for attribution
        ref_params = {}
        for key in ["utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term", "ref"]:
            if key in request.GET:
                ref_params[key] = request.GET[key]
        request.ref_params = ref_params

        # Example: Capture initial visit time for lead scoring
        if "first_marketing_visit" not in request.session:
            request.session["first_marketing_visit"] = time.time()

    def process_response(self, request, response):
        # Set marketing ID in cookie if missing
        if hasattr(request, "marketing_id"):
            response.set_cookie("marketing_id", request.marketing_id, max_age=60 * 60 * 24 * 365)

        # Store referral params in session for later use
        if hasattr(request, "ref_params") and request.ref_params:
            request.session["ref_params"] = request.ref_params

        # Example: Log request for analytics (expand for event-based logging)
        self.log_marketing_event(request)

        return response

    def log_marketing_event(self, request):
        # Placeholder for integrating with a real logging system, database, or 3rd party analytics
        event = {
            "path": request.path,
            "method": request.method,
            "marketing_id": getattr(request, "marketing_id", None),
            "ref_params": getattr(request, "ref_params", None),
        }
        # This could push to an external system:
        # marketing_logger.log(event)
        print(f"Marketing Event Logged: {event}")

