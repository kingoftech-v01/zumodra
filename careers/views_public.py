"""
Careers Public API Views - Public endpoints for career portal.

This module provides PUBLIC (no authentication) endpoints for:
- Career site configuration
- Job listings
- Job applications
- Job alerts

All endpoints are rate-limited and support CORS for embedded career pages.
"""

import logging
from uuid import UUID

from django.utils import timezone

from rest_framework import status, permissions, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import AnonRateThrottle
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

logger = logging.getLogger(__name__)


# =============================================================================
# THROTTLING
# =============================================================================

class ApplicationSubmitThrottle(AnonRateThrottle):
    """Rate limit for application submissions: 5 per hour per IP."""
    rate = '5/hour'
    scope = 'application_submit'


class PublicViewThrottle(AnonRateThrottle):
    """Rate limit for public views: 100 per hour per IP."""
    rate = '100/hour'
    scope = 'public_view'


# =============================================================================
# CORS MIXIN
# =============================================================================

class CORSMixin:
    """Mixin to add CORS headers for embedded career pages."""

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)

        if hasattr(self, 'allow_cors') and self.allow_cors:
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
            response['Access-Control-Max-Age'] = '86400'

        return response


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


# =============================================================================
# PUBLIC CAREER SITE VIEWS
# =============================================================================

class PublicCareerSiteView(CORSMixin, APIView):
    """
    Get career site configuration by domain.

    Public endpoint - no authentication required.
    Fetches site by subdomain or custom domain.

    GET /api/public/careers/sites/<domain>/
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get(self, request, domain):
        from careers.services import CareerSiteService
        from careers.serializers import CareerSitePublicSerializer

        site = CareerSiteService.get_site_by_domain(domain)

        if not site:
            return Response(
                {'error': 'Career site not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = CareerSitePublicSerializer(site, context={'request': request})
        return Response(serializer.data)


class PublicCareerSiteJobsView(CORSMixin, generics.ListAPIView):
    """
    List active jobs for a career site.

    Public endpoint - no authentication required.
    Supports filtering by department, location, type, search.

    GET /api/public/careers/sites/<domain>/jobs/
    GET /api/public/careers/sites/<domain>/jobs/?department=engineering&location=Montreal
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get(self, request, domain):
        from careers.services import CareerSiteService
        from careers.serializers import JobListingPublicSerializer

        site = CareerSiteService.get_site_by_domain(domain)

        if not site:
            return Response(
                {'error': 'Career site not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Build filters from query params
        filters = {
            'department': request.query_params.get('department'),
            'location': request.query_params.get('location'),
            'job_type': request.query_params.get('job_type'),
            'remote': request.query_params.get('remote') == 'true',
            'search': request.query_params.get('search'),
            'featured_only': request.query_params.get('featured') == 'true',
        }

        jobs = CareerSiteService.get_active_jobs(site, filters)

        # Pagination
        page = self.paginate_queryset(jobs)
        if page is not None:
            serializer = JobListingPublicSerializer(page, many=True, context={'request': request})
            return self.get_paginated_response(serializer.data)

        serializer = JobListingPublicSerializer(jobs, many=True, context={'request': request})
        return Response(serializer.data)


class PublicCareerSiteJobDetailView(CORSMixin, APIView):
    """
    Get job details from a career site.

    Public endpoint - no authentication required.
    Increments view count on access.

    GET /api/public/careers/sites/<domain>/jobs/<slug>/
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get(self, request, domain, slug):
        from careers.services import CareerSiteService
        from careers.serializers import JobListingDetailPublicSerializer
        from careers.models import JobView

        site = CareerSiteService.get_site_by_domain(domain)

        if not site:
            return Response(
                {'error': 'Career site not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        listing = CareerSiteService.get_job_detail(site, slug)

        if not listing:
            return Response(
                {'error': 'Job not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Increment view count
        listing.increment_view()

        # Track detailed view analytics
        try:
            JobView.objects.create(
                job_listing=listing,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                referrer=request.META.get('HTTP_REFERER', ''),
                session_key=request.session.session_key if hasattr(request, 'session') and request.session else '',
                utm_source=request.query_params.get('utm_source', ''),
                utm_medium=request.query_params.get('utm_medium', ''),
                utm_campaign=request.query_params.get('utm_campaign', ''),
            )
        except Exception as e:
            logger.warning(f"Failed to track job view: {e}")

        serializer = JobListingDetailPublicSerializer(listing, context={'request': request})
        return Response(serializer.data)


class PublicApplicationSubmitView(CORSMixin, APIView):
    """
    Submit job application from public career site.

    Public endpoint - no authentication required.
    Rate limited to prevent spam.

    POST /api/public/careers/sites/<domain>/apply/
    POST /api/public/careers/sites/<domain>/apply/<job_slug>/
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ApplicationSubmitThrottle]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    allow_cors = True

    def post(self, request, domain, job_slug=None):
        from careers.services import CareerSiteService, PublicApplicationService

        site = CareerSiteService.get_site_by_domain(domain)

        if not site:
            return Response(
                {'error': 'Career site not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Get job if specified
        job = None
        if job_slug:
            job = CareerSiteService.get_job_detail(site, job_slug)
            if not job:
                return Response(
                    {'error': 'Job not found or no longer accepting applications.'},
                    status=status.HTTP_404_NOT_FOUND
                )

        # Check if general applications are allowed
        if not job and not site.allow_general_applications:
            return Response(
                {'error': 'This career site does not accept general applications.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate application data
        validation = CareerSiteService.validate_application(
            site, job, request.data
        )

        if not validation.is_valid:
            return Response(
                {'errors': validation.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check for duplicate
        if job and PublicApplicationService.check_duplicate(
            request.data.get('email'), job
        ):
            return Response(
                {'error': 'You have already applied for this position.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Build request metadata
        request_meta = {
            'ip_address': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'referrer': request.META.get('HTTP_REFERER', ''),
        }

        # Submit application
        result = PublicApplicationService.submit_application(
            site=site,
            job=job,
            data=request.data,
            files=request.FILES,
            request_meta=request_meta
        )

        if result.success:
            return Response(
                {
                    'message': 'Your application has been submitted successfully.',
                    'application_id': result.data['application_id'],
                },
                status=status.HTTP_201_CREATED
            )
        else:
            return Response(
                {'error': result.error},
                status=status.HTTP_400_BAD_REQUEST
            )


# =============================================================================
# JOB ALERT VIEWS
# =============================================================================

class JobAlertSubscribeView(CORSMixin, APIView):
    """
    Subscribe to job alerts.

    Public endpoint - no authentication required.

    POST /api/public/careers/alerts/subscribe/
    Body: {
        "domain": "acme",
        "email": "user@example.com",
        "departments": ["engineering"],
        "job_types": ["full_time"],
        "locations": ["Montreal"],
        "keywords": ["python", "django"],
        "remote_only": false,
        "frequency": "daily"
    }
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def post(self, request):
        from careers.services import CareerSiteService, JobAlertService

        domain = request.data.get('domain')
        email = request.data.get('email')

        if not domain or not email:
            return Response(
                {'error': 'Domain and email are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        site = CareerSiteService.get_site_by_domain(domain)

        if not site:
            return Response(
                {'error': 'Career site not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        preferences = {
            'name': request.data.get('name', ''),
            'departments': request.data.get('departments', []),
            'job_types': request.data.get('job_types', []),
            'locations': request.data.get('locations', []),
            'keywords': request.data.get('keywords', []),
            'remote_only': request.data.get('remote_only', False),
            'frequency': request.data.get('frequency', 'daily'),
        }

        request_meta = {
            'ip_address': get_client_ip(request),
        }

        result = JobAlertService.subscribe(
            email=email,
            site=site,
            preferences=preferences,
            request_meta=request_meta
        )

        if result.success:
            return Response(result.data, status=status.HTTP_201_CREATED)
        else:
            return Response(
                {'error': result.error},
                status=status.HTTP_400_BAD_REQUEST
            )


class JobAlertConfirmView(CORSMixin, APIView):
    """
    Confirm job alert subscription.

    Public endpoint - no authentication required.

    GET /api/public/careers/alerts/confirm/<token>/
    """
    permission_classes = [permissions.AllowAny]
    allow_cors = True

    def get(self, request, token):
        from careers.services import JobAlertService

        try:
            token_uuid = UUID(str(token))
        except ValueError:
            return Response(
                {'error': 'Invalid token format.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        result = JobAlertService.confirm_subscription(token_uuid)

        if result.success:
            return Response(result.data)
        else:
            return Response(
                {'error': result.error},
                status=status.HTTP_400_BAD_REQUEST
            )


class JobAlertUnsubscribeView(CORSMixin, APIView):
    """
    Unsubscribe from job alerts.

    Public endpoint - no authentication required.

    GET /api/public/careers/alerts/unsubscribe/<token>/
    """
    permission_classes = [permissions.AllowAny]
    allow_cors = True

    def get(self, request, token):
        from careers.services import JobAlertService

        try:
            token_uuid = UUID(str(token))
        except ValueError:
            return Response(
                {'error': 'Invalid token format.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        result = JobAlertService.unsubscribe(token_uuid)

        if result.success:
            return Response(result.data)
        else:
            return Response(
                {'error': result.error},
                status=status.HTTP_400_BAD_REQUEST
            )


# =============================================================================
# PUBLIC UTILITY VIEWS
# =============================================================================

class PublicCareerSiteDepartmentsView(CORSMixin, APIView):
    """
    Get departments with active jobs for a career site.

    GET /api/public/careers/sites/<domain>/departments/
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get(self, request, domain):
        from careers.services import CareerSiteService

        site = CareerSiteService.get_site_by_domain(domain)

        if not site:
            return Response(
                {'error': 'Career site not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        departments = CareerSiteService.get_departments(site)
        return Response(departments)


class PublicCareerSiteLocationsView(CORSMixin, APIView):
    """
    Get locations with active jobs for a career site.

    GET /api/public/careers/sites/<domain>/locations/
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get(self, request, domain):
        from careers.services import CareerSiteService

        site = CareerSiteService.get_site_by_domain(domain)

        if not site:
            return Response(
                {'error': 'Career site not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        locations = CareerSiteService.get_locations(site)
        return Response({'locations': locations})
