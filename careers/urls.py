"""
Careers URLs - URL routing for public career pages and admin API.

This module provides:
- Public API endpoints (no auth) for job seekers at /api/careers/
- Admin API endpoints for tenant management at /api/careers/admin/
- Server-rendered template views for SEO at /careers/

URL Structure:
    Template Views (server-rendered for SEO):
        /careers/                             - Career home (job list)
        /careers/jobs/<id>/                   - Job detail page
        /careers/jobs/<slug>/                 - Job detail by slug
        /careers/apply/<id>/                  - Application form
        /careers/apply/<slug>/                - Application form by slug
        /careers/application/<uuid>/success/  - Application success
        /careers/alerts/                      - Job alert subscription
        /careers/alerts/confirmed/            - Subscription confirmed
        /careers/alerts/unsubscribed/         - Unsubscribed
        /careers/sitemap.xml                  - SEO sitemap
        /careers/robots.txt                   - Robots.txt

    Public API (no authentication required):
        /api/careers/page/                    - Career page configuration
        /api/careers/jobs/                    - List all public jobs
        /api/careers/jobs/<id>/               - Job detail (increments view)
        /api/careers/jobs/slug/<slug>/        - Job detail by custom slug
        /api/careers/apply/                   - Submit application
        /api/careers/application/<uuid>/status/  - Check application status
        /api/careers/categories/              - List job categories
        /api/careers/locations/               - List job locations
        /api/careers/stats/                   - Career page statistics

    Admin API (authentication required):
        /api/careers/admin/pages/             - Career page CRUD
        /api/careers/admin/sections/          - Career page sections CRUD
        /api/careers/admin/preview/<id>/      - Career page preview
        /api/careers/admin/listings/          - Job listings CRUD
        /api/careers/admin/applications/      - Applications management
        /api/careers/admin/talent-pools/      - Talent pools CRUD
        /api/careers/admin/talent-pool-members/  - Pool members CRUD
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    # Public API views
    CareerPagePublicView,
    PublicJobListingListView,
    PublicJobListingDetailView,
    PublicJobListingBySlugView,
    PublicApplicationCreateView,
    ApplicationStatusView,
    JobCategoriesListView,
    JobLocationsListView,
    CareerPageStatsView,
    # Admin API views
    CareerPageViewSet,
    CareerPageSectionViewSet,
    CareerPagePreviewView,
    JobListingViewSet,
    PublicApplicationViewSet,
    TalentPoolViewSet,
    TalentPoolMemberViewSet,
)

from .template_views import (
    # Server-rendered template views
    CareerSiteHomeView,
    BrowseJobsMapView,
    BrowseCompaniesView,
    BrowseCompaniesMapView,
    BrowseProjectsView,
    BrowseProjectsMapView,
    JobDetailPageView,
    ApplicationPageView,
    ApplicationSuccessView,
    JobAlertSubscribeView,
    JobAlertConfirmTokenView,
    JobAlertConfirmedView,
    JobAlertUnsubscribeTokenView,
    JobAlertUnsubscribedView,
    CareersSitemapView,
    RobotsTxtView,
)


# ==================== ADMIN ROUTER ====================

admin_router = DefaultRouter()
admin_router.register(r'pages', CareerPageViewSet, basename='admin-career-page')
admin_router.register(r'sections', CareerPageSectionViewSet, basename='admin-career-section')
admin_router.register(r'listings', JobListingViewSet, basename='admin-job-listing')
admin_router.register(r'applications', PublicApplicationViewSet, basename='admin-application')
admin_router.register(r'talent-pools', TalentPoolViewSet, basename='admin-talent-pool')
admin_router.register(r'talent-pool-members', TalentPoolMemberViewSet, basename='admin-pool-member')


# ==================== URL PATTERNS ====================

app_name = 'careers'

# Public URL patterns (no authentication required)
public_patterns = [
    # Career page
    path('page/', CareerPagePublicView.as_view(), name='public-career-page'),

    # Job listings
    path('jobs/', PublicJobListingListView.as_view(), name='public-job-list'),
    path('jobs/<int:pk>/', PublicJobListingDetailView.as_view(), name='public-job-detail'),
    path('jobs/slug/<slug:custom_slug>/', PublicJobListingBySlugView.as_view(), name='public-job-by-slug'),

    # Applications
    path('apply/', PublicApplicationCreateView.as_view(), name='public-apply'),
    path('application/<uuid:uuid>/status/', ApplicationStatusView.as_view(), name='application-status'),

    # Filter dropdowns
    path('categories/', JobCategoriesListView.as_view(), name='job-categories'),
    path('locations/', JobLocationsListView.as_view(), name='job-locations'),

    # Statistics
    path('stats/', CareerPageStatsView.as_view(), name='career-stats'),
]

# Admin URL patterns (authentication required)
admin_patterns = [
    # Preview
    path('preview/<int:pk>/', CareerPagePreviewView.as_view(), name='admin-preview'),

    # Router URLs
    path('', include(admin_router.urls)),
]

# ==================== TEMPLATE VIEW PATTERNS ====================

# Server-rendered template views for SEO (at /careers/)
template_patterns = [
    # Career home (job list)
    path('', CareerSiteHomeView.as_view(), name='home'),

    # Job detail pages
    path('jobs/<int:pk>/', JobDetailPageView.as_view(), name='job-detail'),
    path('jobs/<slug:slug>/', JobDetailPageView.as_view(), name='job-detail-slug'),

    # Application pages
    path('apply/<int:pk>/', ApplicationPageView.as_view(), name='apply'),
    path('apply/<slug:slug>/', ApplicationPageView.as_view(), name='apply-slug'),
    path('application/<uuid:uuid>/success/', ApplicationSuccessView.as_view(), name='application-success'),

    # Job alerts
    path('alerts/', JobAlertSubscribeView.as_view(), name='subscribe'),
    path('alerts/confirm/<uuid:token>/', JobAlertConfirmTokenView.as_view(), name='alert-confirm'),
    path('alerts/confirmed/', JobAlertConfirmedView.as_view(), name='alert-confirmed'),
    path('alerts/unsubscribe/<uuid:token>/', JobAlertUnsubscribeTokenView.as_view(), name='alert-unsubscribe'),
    path('alerts/unsubscribed/', JobAlertUnsubscribedView.as_view(), name='alert-unsubscribed'),

    # SEO
    path('sitemap.xml', CareersSitemapView.as_view(), name='sitemap'),
    path('robots.txt', RobotsTxtView.as_view(), name='robots'),
]


# Combined URL patterns
urlpatterns = [
    # Public API endpoints (no auth) - for /api/careers/
    path('', include((public_patterns, 'public'))),

    # Admin API endpoints (auth required) - for /api/careers/admin/
    path('admin/', include((admin_patterns, 'admin'))),

    # Template views (server-rendered) - for /careers/
    # Note: These should be mounted at /careers/ in the main urls.py
    path('pages/', include((template_patterns, 'template'))),

    # Direct URL aliases for navigation
    # These allow templates to use {% url 'careers:job_list' %}, {% url 'careers:browse_jobs' %}, etc.
    path('jobs/', CareerSiteHomeView.as_view(), name='job_list'),
    path('browse/', CareerSiteHomeView.as_view(), name='browse_jobs'),
    path('browse/map/', BrowseJobsMapView.as_view(), name='browse_jobs_map'),
    path('companies/', BrowseCompaniesView.as_view(), name='browse_companies'),
    path('companies/map/', BrowseCompaniesMapView.as_view(), name='browse_companies_map'),
    path('projects/', BrowseProjectsView.as_view(), name='browse_projects'),
    path('projects/map/', BrowseProjectsMapView.as_view(), name='browse_projects_map'),

    # Job detail aliases (template uses underscore)
    path('job/<int:pk>/', JobDetailPageView.as_view(), name='job_detail'),
    path('job/<slug:slug>/', JobDetailPageView.as_view(), name='job_detail'),
]


"""
API Endpoints Reference:

PUBLIC ENDPOINTS (No Authentication Required):
==============================================

Career Page:
    GET  /api/careers/page/
         Returns the active career page configuration with branding, content, and settings.
         Query params: ?domain=example.com (for multi-tenant filtering)

Job Listings:
    GET  /api/careers/jobs/
         List all active, published job listings.
         Query params (filters):
             - category=<id>         Filter by category ID
             - category_slug=<slug>  Filter by category slug
             - location=<text>       Search in city, state, or country
             - city=<text>           Filter by city (icontains)
             - country=<text>        Filter by country (icontains)
             - remote=true           Show remote-friendly positions
             - job_type=full_time|part_time|contract|internship|temporary|freelance
             - experience_level=entry|junior|mid|senior|lead|executive
             - remote_policy=on_site|remote|hybrid|flexible
             - skills=python,django  Filter by skills (comma-separated)
             - search=<text>         Full-text search
             - featured=true         Featured jobs only
             - posted_within_days=7  Jobs posted in last X days
             - min_salary=50000      Minimum salary filter

    GET  /api/careers/jobs/<id>/
         Get job detail. Automatically increments view count.
         Query params: ?utm_source=x&utm_medium=y&utm_campaign=z (tracked)

    GET  /api/careers/jobs/slug/<custom_slug>/
         Get job detail by custom slug.

Applications:
    POST /api/careers/apply/
         Submit a job application. Rate limited to 5/hour per IP.
         Content-Type: multipart/form-data (for resume upload)
         Body fields:
             - job_listing (optional, for general applications)
             - first_name (required)
             - last_name (required)
             - email (required)
             - phone
             - resume (required file upload)
             - cover_letter
             - custom_answers (JSON object)
             - linkedin_url
             - portfolio_url
             - privacy_consent (required, must be true)
             - marketing_consent
         Query params: ?utm_source=x&utm_medium=y&utm_campaign=z

    GET  /api/careers/application/<uuid>/status/
         Check application status by UUID.
         Returns: job title, status, submission date

Utility:
    GET  /api/careers/categories/
         List active job categories for filter dropdowns.

    GET  /api/careers/locations/
         List unique job locations for filter dropdowns.

    GET  /api/careers/stats/
         Get career page statistics (open positions, top categories, locations).


ADMIN ENDPOINTS (Authentication Required):
==========================================

Career Pages:
    GET    /api/careers/admin/pages/           List all career pages
    POST   /api/careers/admin/pages/           Create career page
    GET    /api/careers/admin/pages/<id>/      Get career page detail
    PUT    /api/careers/admin/pages/<id>/      Update career page
    PATCH  /api/careers/admin/pages/<id>/      Partial update
    DELETE /api/careers/admin/pages/<id>/      Delete career page
    POST   /api/careers/admin/pages/<id>/toggle_active/  Toggle active status
    GET    /api/careers/admin/pages/<id>/preview/        Preview as public

Career Page Sections:
    GET    /api/careers/admin/sections/        List all sections
    POST   /api/careers/admin/sections/        Create section
    PUT    /api/careers/admin/sections/<id>/   Update section
    DELETE /api/careers/admin/sections/<id>/   Delete section
    POST   /api/careers/admin/sections/reorder/  Reorder sections
           Body: {"section_ids": [1, 3, 2, 4]}

Preview:
    GET    /api/careers/admin/preview/<id>/    Preview career page as public

Job Listings:
    GET    /api/careers/admin/listings/        List all job listings with analytics
    POST   /api/careers/admin/listings/        Create job listing
    GET    /api/careers/admin/listings/<id>/   Get listing with analytics
    PUT    /api/careers/admin/listings/<id>/   Update listing
    DELETE /api/careers/admin/listings/<id>/   Delete listing
    POST   /api/careers/admin/listings/<id>/publish/         Publish listing
    POST   /api/careers/admin/listings/<id>/unpublish/       Unpublish listing
    POST   /api/careers/admin/listings/<id>/toggle_featured/ Toggle featured
    GET    /api/careers/admin/listings/<id>/analytics/       Get detailed analytics
    GET    /api/careers/admin/listings/<id>/applications/    Get applications

Applications:
    GET    /api/careers/admin/applications/            List all applications
    GET    /api/careers/admin/applications/<id>/       Get application detail
    POST   /api/careers/admin/applications/<id>/process/    Process to ATS
    POST   /api/careers/admin/applications/<id>/mark_spam/  Mark as spam
    POST   /api/careers/admin/applications/bulk_process/    Bulk process
           Body: {"application_ids": [1, 2, 3]}

Talent Pools:
    GET    /api/careers/admin/talent-pools/            List talent pools
    POST   /api/careers/admin/talent-pools/            Create pool
    GET    /api/careers/admin/talent-pools/<id>/       Get pool with members
    PUT    /api/careers/admin/talent-pools/<id>/       Update pool
    DELETE /api/careers/admin/talent-pools/<id>/       Delete pool
    GET    /api/careers/admin/talent-pools/<id>/members/     List pool members
    POST   /api/careers/admin/talent-pools/<id>/add_candidate/
           Body: {"candidate_id": 123, "notes": "optional"}
    POST   /api/careers/admin/talent-pools/<id>/remove_candidate/
           Body: {"candidate_id": 123}

Talent Pool Members:
    GET    /api/careers/admin/talent-pool-members/     List all members
    POST   /api/careers/admin/talent-pool-members/     Add member
    PUT    /api/careers/admin/talent-pool-members/<id>/  Update member notes
    DELETE /api/careers/admin/talent-pool-members/<id>/  Remove member


RATE LIMITING:
==============
- Public views: 100 requests/hour per IP
- Application submission: 5 applications/hour per IP

CORS:
=====
Public endpoints include CORS headers for embedded career pages:
- Access-Control-Allow-Origin: *
- Access-Control-Allow-Methods: GET, POST, OPTIONS
- Access-Control-Allow-Headers: Content-Type, X-Requested-With
"""
