"""
Careers Views - REST API views for public career pages.

This module provides:
- Public endpoints (no auth) for job seekers
- Admin endpoints for tenant management
- Rate limiting for application submissions
- CORS headers for embedded career pages
- UTM/analytics tracking
"""

from django.utils import timezone
from django.db.models import F
from django.shortcuts import get_object_or_404
from django.http import Http404

from rest_framework import viewsets, generics, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import AnonRateThrottle
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from .models import (
    CareerPage, CareerPageSection, JobListing,
    PublicApplication, TalentPool, TalentPoolMember
)
from .serializers import (
    CareerPagePublicSerializer, CareerPageAdminSerializer,
    CareerPageSectionSerializer,
    JobListingPublicSerializer, JobListingDetailPublicSerializer,
    JobListingAdminSerializer,
    PublicApplicationSerializer, PublicApplicationStatusSerializer,
    TalentPoolSerializer, TalentPoolDetailSerializer,
    TalentPoolMemberSerializer,
)
from .filters import (
    PublicJobListingFilter, AdminJobListingFilter,
    PublicApplicationFilter, TalentPoolFilter, TalentPoolMemberFilter
)


# ==================== CUSTOM PERMISSIONS ====================

class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Allow read access to anyone, write access to admin users.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user and request.user.is_staff


class IsAdminUser(permissions.BasePermission):
    """
    Allow access only to admin users.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_staff


# ==================== CUSTOM THROTTLING ====================

class ApplicationSubmitThrottle(AnonRateThrottle):
    """
    Rate limiting for application submissions.
    Prevents spam/abuse of application endpoint.
    """
    rate = '5/hour'  # 5 applications per hour per IP
    scope = 'application_submit'


class PublicViewThrottle(AnonRateThrottle):
    """
    Rate limiting for public views.
    """
    rate = '100/hour'
    scope = 'public_view'


# ==================== CORS MIXIN ====================

class CORSMixin:
    """
    Mixin to add CORS headers for embedded career pages.
    """
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)

        # Add CORS headers for embedded career pages
        origin = request.META.get('HTTP_ORIGIN', '')

        # Allow all origins for public endpoints (or configure specific domains)
        if hasattr(self, 'allow_cors') and self.allow_cors:
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
            response['Access-Control-Max-Age'] = '86400'

        return response


# ==================== PUBLIC CAREER PAGE VIEWS ====================

class CareerPagePublicView(CORSMixin, generics.RetrieveAPIView):
    """
    Public career page view.
    Returns the career page configuration for public display.

    GET /api/careers/page/
    GET /api/careers/page/?domain=example.com
    """
    serializer_class = CareerPagePublicSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get_object(self):
        """
        Get the career page.
        Can filter by domain query param for multi-tenant setups.

        Returns None when accessed from public schema (for public job browsing).
        """
        from django.db import connection

        # Check if we're in the public schema
        if connection.schema_name == 'public':
            # Return None - the serializer will handle creating a default response
            return None

        domain = self.request.query_params.get('domain')

        # For multi-tenant, filter by domain
        # For single-tenant, just get the first active career page
        queryset = CareerPage.objects.filter(is_active=True)

        if not queryset.exists():
            raise Http404("No active career page found.")

        return queryset.first()

    def get(self, request, *args, **kwargs):
        """Handle GET request, returning default config for public schema."""
        from django.db import connection

        if connection.schema_name == 'public':
            # Return default career page config for public job browsing
            return Response({
                'title': 'Career Opportunities',
                'description': 'Browse open positions from companies using our platform',
                'company_name': 'Zumodra',
                'show_company_info': False,
                'show_culture_section': False,
                'show_benefits_section': False,
                'show_testimonials': False,
                'is_active': True,
            })

        return super().get(request, *args, **kwargs)


class PublicJobListingListView(CORSMixin, generics.ListAPIView):
    """
    Public job listing list view.
    Lists all active, published jobs from PublicJobCatalog.

    GET /api/careers/jobs/
    GET /api/careers/jobs/?category=engineering&location=Remote&job_type=full_time
    """
    from tenants.models import PublicJobCatalog
    from careers.serializers import PublicJobCatalogListSerializer

    serializer_class = PublicJobCatalogListSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['title', 'description', 'company_name']
    ordering_fields = ['published_at', 'is_featured', 'view_count']
    ordering = ['-is_featured', '-published_at']
    allow_cors = True

    def get_queryset(self):
        """Return only active, published jobs from public catalog."""
        from tenants.models import PublicJobCatalog
        from django.db.models import Q
        now = timezone.now()

        # Base queryset: jobs that have been published, excluding those past deadline
        queryset = PublicJobCatalog.objects.filter(
            published_at__lte=now
        ).filter(
            Q(application_deadline__isnull=True) | Q(application_deadline__gte=now)
        ).select_related('tenant')

        # Apply filters from query params
        job_type = self.request.query_params.get('job_type')
        if job_type:
            queryset = queryset.filter(job_type=job_type)

        location = self.request.query_params.get('location')
        if location:
            # Search across city, state, and country
            queryset = queryset.filter(
                Q(location_city__icontains=location) |
                Q(location_state__icontains=location) |
                Q(location_country__icontains=location)
            )

        category = self.request.query_params.get('category')
        if category:
            queryset = queryset.filter(category_slug=category)

        is_remote = self.request.query_params.get('remote')
        if is_remote and is_remote.lower() in ['true', '1', 'yes']:
            # Filter for remote or hybrid positions
            queryset = queryset.filter(remote_policy__in=['remote', 'hybrid', 'flexible'])

        return queryset


class PublicJobListingDetailView(CORSMixin, generics.RetrieveAPIView):
    """
    Public job listing detail view.
    Returns detailed job information from PublicJobCatalog.
    Increments view count on access.

    GET /api/careers/jobs/<job_id>/
    """
    from tenants.models import PublicJobCatalog
    from careers.serializers import PublicJobCatalogDetailSerializer

    serializer_class = PublicJobCatalogDetailSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    lookup_field = 'uuid'
    allow_cors = True

    def get_queryset(self):
        """Return only active, published jobs from public catalog."""
        from tenants.models import PublicJobCatalog
        from django.db.models import Q
        now = timezone.now()
        return PublicJobCatalog.objects.filter(
            published_at__lte=now
        ).filter(
            Q(application_deadline__isnull=True) | Q(application_deadline__gte=now)
        ).select_related('tenant')

    def retrieve(self, request, *args, **kwargs):
        """Increment view count on job detail access."""
        instance = self.get_object()

        # Increment view count atomically
        instance.increment_view_count()
        instance.refresh_from_db()

        # Track UTM parameters if provided
        self._track_view(request, instance)

        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def _track_view(self, request, job_listing):
        """Track view analytics (UTM, referrer, etc.)."""
        # This could be expanded to log views in a separate analytics table
        # For now, just log to console in debug mode
        import logging
        logger = logging.getLogger(__name__)

        utm_source = request.query_params.get('utm_source', '')
        utm_medium = request.query_params.get('utm_medium', '')
        utm_campaign = request.query_params.get('utm_campaign', '')

        if any([utm_source, utm_medium, utm_campaign]):
            logger.info(
                f"Job view: {job_listing.job.title} | "
                f"UTM: {utm_source}/{utm_medium}/{utm_campaign}"
            )


class PublicJobListingBySlugView(PublicJobListingDetailView):
    """
    Public job listing detail by custom slug.

    GET /api/careers/jobs/slug/<custom_slug>/
    """
    lookup_field = 'custom_slug'


class PublicApplicationCreateView(CORSMixin, generics.CreateAPIView):
    """
    Public application submission view.
    Allows job seekers to submit applications without authentication.
    Includes rate limiting to prevent spam.

    POST /api/careers/apply/
    """
    serializer_class = PublicApplicationSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ApplicationSubmitThrottle]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    allow_cors = True

    def create(self, request, *args, **kwargs):
        """Create application with UTM tracking."""
        # Capture UTM parameters from request
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)

        # Get UTM params from query string if not in body
        if 'utm_source' not in data:
            data['utm_source'] = request.query_params.get('utm_source', '')
        if 'utm_medium' not in data:
            data['utm_medium'] = request.query_params.get('utm_medium', '')
        if 'utm_campaign' not in data:
            data['utm_campaign'] = request.query_params.get('utm_campaign', '')
        if 'referrer' not in data:
            data['referrer'] = request.META.get('HTTP_REFERER', '')

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        # Return success response with application UUID
        return Response(
            {
                'status': 'success',
                'message': 'Your application has been submitted successfully.',
                'application_id': str(serializer.instance.uuid),
            },
            status=status.HTTP_201_CREATED
        )


class ApplicationStatusView(CORSMixin, generics.RetrieveAPIView):
    """
    Check application status by UUID.
    Allows candidates to track their application.

    GET /api/careers/application/<uuid>/status/
    """
    serializer_class = PublicApplicationStatusSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    lookup_field = 'uuid'
    allow_cors = True

    def get_queryset(self):
        return PublicApplication.objects.all()


# ==================== ADMIN CAREER PAGE VIEWS ====================

class CareerPageViewSet(viewsets.ModelViewSet):
    """
    Admin career page management.
    Full CRUD for career page configuration.

    GET /api/careers/admin/pages/
    POST /api/careers/admin/pages/
    GET /api/careers/admin/pages/<id>/
    PUT /api/careers/admin/pages/<id>/
    PATCH /api/careers/admin/pages/<id>/
    DELETE /api/careers/admin/pages/<id>/
    """
    queryset = CareerPage.objects.all()
    serializer_class = CareerPageAdminSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ['title', 'tagline', 'description']
    ordering = ['-updated_at']

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Toggle career page active status."""
        career_page = self.get_object()
        career_page.is_active = not career_page.is_active
        career_page.save(update_fields=['is_active'])
        return Response({
            'status': 'success',
            'is_active': career_page.is_active
        })

    @action(detail=True, methods=['get'])
    def preview(self, request, pk=None):
        """Get career page preview data."""
        career_page = self.get_object()
        serializer = CareerPagePublicSerializer(
            career_page, context={'request': request}
        )
        return Response(serializer.data)


class CareerPageSectionViewSet(viewsets.ModelViewSet):
    """
    Admin career page section management.

    GET /api/careers/admin/sections/
    POST /api/careers/admin/sections/
    PUT /api/careers/admin/sections/<id>/
    DELETE /api/careers/admin/sections/<id>/
    """
    queryset = CareerPageSection.objects.all()
    serializer_class = CareerPageSectionSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['career_page', 'section_type', 'is_visible']
    ordering = ['order']

    @action(detail=False, methods=['post'])
    def reorder(self, request):
        """
        Reorder sections.
        Expects: {'section_ids': [1, 3, 2, 4]}
        """
        section_ids = request.data.get('section_ids', [])
        for order, section_id in enumerate(section_ids):
            CareerPageSection.objects.filter(id=section_id).update(order=order)
        return Response({'status': 'success'})


class CareerPagePreviewView(generics.RetrieveAPIView):
    """
    Career page preview for admins.
    Shows how the public career page will appear.

    GET /api/careers/admin/preview/<id>/
    """
    queryset = CareerPage.objects.all()
    serializer_class = CareerPagePublicSerializer
    permission_classes = [IsAdminUser]


# ==================== ADMIN JOB LISTING VIEWS ====================

class JobListingViewSet(viewsets.ModelViewSet):
    """
    Admin job listing management.

    GET /api/careers/admin/listings/
    POST /api/careers/admin/listings/
    GET /api/careers/admin/listings/<id>/
    PUT /api/careers/admin/listings/<id>/
    DELETE /api/careers/admin/listings/<id>/
    """
    queryset = JobListing.objects.select_related('job', 'job__category').all()
    serializer_class = JobListingAdminSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = AdminJobListingFilter
    search_fields = ['job__title', 'job__reference_code', 'custom_slug']
    ordering_fields = ['published_at', 'view_count', 'apply_click_count']
    ordering = ['-published_at']

    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        """Publish a job listing."""
        listing = self.get_object()
        if listing.job.status != 'open':
            return Response(
                {'error': 'Job must be in "open" status to publish.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        listing.published_at = timezone.now()
        listing.save(update_fields=['published_at'])
        return Response({
            'status': 'success',
            'published_at': listing.published_at
        })

    @action(detail=True, methods=['post'])
    def unpublish(self, request, pk=None):
        """Unpublish a job listing."""
        listing = self.get_object()
        listing.published_at = None
        listing.save(update_fields=['published_at'])
        return Response({'status': 'success'})

    @action(detail=True, methods=['post'])
    def toggle_featured(self, request, pk=None):
        """Toggle featured status."""
        listing = self.get_object()
        listing.is_featured = not listing.is_featured
        listing.save(update_fields=['is_featured'])
        return Response({
            'status': 'success',
            'is_featured': listing.is_featured
        })

    @action(detail=True, methods=['get'])
    def analytics(self, request, pk=None):
        """Get detailed analytics for a job listing."""
        listing = self.get_object()
        serializer = self.get_serializer(listing)
        return Response({
            'analytics': serializer.data.get('analytics', {}),
            'funnel_metrics': serializer.data.get('funnel_metrics', {}),
        })

    @action(detail=True, methods=['get'])
    def applications(self, request, pk=None):
        """Get applications for a specific job listing."""
        listing = self.get_object()
        applications = listing.public_applications.all()

        # Apply filters
        filterset = PublicApplicationFilter(
            request.query_params,
            queryset=applications
        )

        page = self.paginate_queryset(filterset.qs)
        if page is not None:
            serializer = PublicApplicationStatusSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PublicApplicationStatusSerializer(filterset.qs, many=True)
        return Response(serializer.data)


# ==================== ADMIN APPLICATION VIEWS ====================

class PublicApplicationViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Admin view of public applications.
    Read-only with processing actions.

    GET /api/careers/admin/applications/
    GET /api/careers/admin/applications/<id>/
    """
    queryset = PublicApplication.objects.select_related(
        'job_listing', 'job_listing__job'
    ).all()
    permission_classes = [IsAdminUser]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = PublicApplicationFilter
    search_fields = ['first_name', 'last_name', 'email']
    ordering_fields = ['submitted_at', 'status']
    ordering = ['-submitted_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return PublicApplicationStatusSerializer
        return PublicApplicationSerializer

    @action(detail=True, methods=['post'])
    def process(self, request, pk=None):
        """Process application into ATS."""
        application = self.get_object()

        if application.status != 'pending':
            return Response(
                {'error': f'Application already processed. Status: {application.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        success = application.process_to_ats()

        if success:
            return Response({
                'status': 'success',
                'message': 'Application processed successfully.',
                'ats_candidate_id': application.ats_candidate.uuid if application.ats_candidate else None,
                'ats_application_id': application.ats_application.uuid if application.ats_application else None,
            })
        else:
            return Response(
                {
                    'status': 'error',
                    'error': application.processing_error
                },
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'])
    def mark_spam(self, request, pk=None):
        """Mark application as spam."""
        application = self.get_object()
        application.status = 'spam'
        application.save(update_fields=['status'])
        return Response({'status': 'success'})

    @action(detail=False, methods=['post'])
    def bulk_process(self, request):
        """Bulk process multiple applications."""
        application_ids = request.data.get('application_ids', [])
        results = {'success': [], 'failed': []}

        for app_id in application_ids:
            try:
                application = PublicApplication.objects.get(pk=app_id)
                if application.status == 'pending':
                    if application.process_to_ats():
                        results['success'].append(app_id)
                    else:
                        results['failed'].append({
                            'id': app_id,
                            'error': application.processing_error
                        })
                else:
                    results['failed'].append({
                        'id': app_id,
                        'error': f'Already processed: {application.status}'
                    })
            except PublicApplication.DoesNotExist:
                results['failed'].append({
                    'id': app_id,
                    'error': 'Application not found'
                })

        return Response(results)


# ==================== ADMIN TALENT POOL VIEWS ====================

class TalentPoolViewSet(viewsets.ModelViewSet):
    """
    Admin talent pool management.

    GET /api/careers/admin/talent-pools/
    POST /api/careers/admin/talent-pools/
    GET /api/careers/admin/talent-pools/<id>/
    PUT /api/careers/admin/talent-pools/<id>/
    DELETE /api/careers/admin/talent-pools/<id>/
    """
    queryset = TalentPool.objects.all()
    permission_classes = [IsAdminUser]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = TalentPoolFilter
    search_fields = ['name', 'description']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return TalentPoolDetailSerializer
        return TalentPoolSerializer

    @action(detail=True, methods=['get'])
    def members(self, request, pk=None):
        """Get members of a talent pool."""
        pool = self.get_object()
        members = pool.members.select_related('candidate', 'added_by').all()

        # Apply filters
        filterset = TalentPoolMemberFilter(
            request.query_params,
            queryset=members
        )

        page = self.paginate_queryset(filterset.qs)
        if page is not None:
            serializer = TalentPoolMemberSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = TalentPoolMemberSerializer(filterset.qs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def add_candidate(self, request, pk=None):
        """Add a candidate to the talent pool."""
        pool = self.get_object()
        candidate_id = request.data.get('candidate_id')

        if not candidate_id:
            return Response(
                {'error': 'candidate_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        from ats.models import Candidate
        try:
            candidate = Candidate.objects.get(pk=candidate_id)
        except Candidate.DoesNotExist:
            return Response(
                {'error': 'Candidate not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check if already in pool
        if pool.members.filter(candidate=candidate).exists():
            return Response(
                {'error': 'Candidate already in this pool'},
                status=status.HTTP_400_BAD_REQUEST
            )

        member = TalentPoolMember.objects.create(
            pool=pool,
            candidate=candidate,
            added_by=request.user,
            notes=request.data.get('notes', '')
        )

        serializer = TalentPoolMemberSerializer(member)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'])
    def remove_candidate(self, request, pk=None):
        """Remove a candidate from the talent pool."""
        pool = self.get_object()
        candidate_id = request.data.get('candidate_id')

        deleted, _ = pool.members.filter(candidate_id=candidate_id).delete()

        if deleted:
            return Response({'status': 'success'})
        return Response(
            {'error': 'Candidate not found in this pool'},
            status=status.HTTP_404_NOT_FOUND
        )


class TalentPoolMemberViewSet(viewsets.ModelViewSet):
    """
    Admin talent pool member management.

    GET /api/careers/admin/talent-pool-members/
    POST /api/careers/admin/talent-pool-members/
    PUT /api/careers/admin/talent-pool-members/<id>/
    DELETE /api/careers/admin/talent-pool-members/<id>/
    """
    queryset = TalentPoolMember.objects.select_related(
        'pool', 'candidate', 'added_by'
    ).all()
    serializer_class = TalentPoolMemberSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = TalentPoolMemberFilter
    ordering = ['-added_at']


# ==================== UTILITY VIEWS ====================

class JobCategoriesListView(CORSMixin, generics.ListAPIView):
    """
    List all active job categories for filter dropdowns.

    GET /api/careers/categories/
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get(self, request):
        from django.db import connection

        # If in public schema, get categories from PublicJobCatalog
        if connection.schema_name == 'public':
            from tenants.models import PublicJobCatalog
            categories = PublicJobCatalog.objects.filter(
                category_name__isnull=False
            ).exclude(
                category_name=''
            ).values(
                'category_name', 'category_slug'
            ).distinct().order_by('category_name')

            return Response([
                {
                    'name': cat['category_name'],
                    'slug': cat['category_slug'],
                }
                for cat in categories
            ])

        # Otherwise, query from tenant schema
        from ats.models import JobCategory
        categories = JobCategory.objects.filter(is_active=True).values(
            'id', 'name', 'slug', 'icon', 'color'
        )
        return Response(list(categories))


class JobLocationsListView(CORSMixin, generics.ListAPIView):
    """
    List all unique job locations for filter dropdowns.

    GET /api/careers/locations/
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get(self, request):
        from django.db import connection

        # If in public schema, get locations from PublicJobCatalog
        if connection.schema_name == 'public':
            from tenants.models import PublicJobCatalog

            cities = PublicJobCatalog.objects.exclude(
                location_city=''
            ).values_list(
                'location_city', flat=True
            ).distinct().order_by('location_city')

            countries = PublicJobCatalog.objects.exclude(
                location_country=''
            ).values_list(
                'location_country', flat=True
            ).distinct().order_by('location_country')

            return Response({
                'cities': list(cities),
                'countries': list(countries),
            })

        # Otherwise, query from tenant schema
        from ats.models import JobPosting

        # Get unique locations from open jobs
        cities = JobPosting.objects.filter(
            status='open'
        ).exclude(
            location_city=''
        ).values_list(
            'location_city', flat=True
        ).distinct()

        countries = JobPosting.objects.filter(
            status='open'
        ).exclude(
            location_country=''
        ).values_list(
            'location_country', flat=True
        ).distinct()

        return Response({
            'cities': list(set(cities)),
            'countries': list(set(countries)),
        })


class CareerPageStatsView(CORSMixin, APIView):
    """
    Public career page statistics.
    Used for displaying "Join our team of X employees" type content.

    GET /api/careers/stats/
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get(self, request):
        from django.db import connection
        from django.db.models import Count, Q
        now = timezone.now()

        # If in public schema, get stats from PublicJobCatalog
        if connection.schema_name == 'public':
            from tenants.models import PublicJobCatalog

            # Count active jobs
            active_jobs = PublicJobCatalog.objects.filter(
                published_at__lte=now
            ).filter(
                Q(application_deadline__isnull=True) | Q(application_deadline__gte=now)
            ).count()

            # Get category breakdown
            categories = PublicJobCatalog.objects.filter(
                published_at__lte=now,
                category_name__isnull=False
            ).filter(
                Q(application_deadline__isnull=True) | Q(application_deadline__gte=now)
            ).exclude(
                category_name=''
            ).values(
                'category_name'
            ).annotate(
                count=Count('id')
            ).order_by('-count')[:5]

            # Get location breakdown
            locations = PublicJobCatalog.objects.filter(
                published_at__lte=now,
                location_city__isnull=False
            ).filter(
                Q(application_deadline__isnull=True) | Q(application_deadline__gte=now)
            ).exclude(
                location_city=''
            ).values(
                'location_city'
            ).annotate(
                count=Count('id')
            ).order_by('-count')[:5]

            return Response({
                'total_open_positions': active_jobs,
                'top_categories': [
                    {'job__category__name': cat['category_name'], 'count': cat['count']}
                    for cat in categories
                ],
                'top_locations': [
                    {'job__location_city': loc['location_city'], 'count': loc['count']}
                    for loc in locations
                ],
            })

        # Otherwise, query from tenant schema
        active_jobs = JobListing.objects.filter(
            job__status='open',
            job__published_on_career_page=True,
            published_at__isnull=False,
        ).exclude(expires_at__lt=now).count()

        # Get category breakdown
        categories = JobListing.objects.filter(
            job__status='open',
            job__published_on_career_page=True,
            published_at__isnull=False,
        ).exclude(
            expires_at__lt=now
        ).values(
            'job__category__name'
        ).annotate(
            count=Count('id')
        ).order_by('-count')[:5]

        # Get location breakdown
        locations = JobListing.objects.filter(
            job__status='open',
            job__published_on_career_page=True,
            published_at__isnull=False,
        ).exclude(
            expires_at__lt=now
        ).exclude(
            job__location_city=''
        ).values(
            'job__location_city'
        ).annotate(
            count=Count('id')
        ).order_by('-count')[:5]

        return Response({
            'total_open_positions': active_jobs,
            'top_categories': list(categories),
            'top_locations': list(locations),
        })
