"""
Blog URLs Configuration
========================

Unified URL configuration for blog application following URL_AND_VIEW_CONVENTIONS.md.

IMPORTANT: Wagtail CMS Routing
------------------------------
Most blog routing is handled AUTOMATICALLY by Wagtail via the main urls.py catch-all:
- /<lang>/blog/ → BlogIndexPage.serve() (with get_context() for pagination)
- /<lang>/blog/<slug>/ → BlogPostPage.serve() (with get_context() for comments, sidebar)
- /<lang>/blog/category/<slug>/ → CategoryPage.serve()

These URLs are NOT defined here - Wagtail's catch-all pattern in zumodra/urls.py handles them.

This file defines AUXILIARY features:
1. Frontend: Search and comment submission
2. API: RESTful endpoints for blog resources

URL Namespaces:
- Frontend: frontend:blog:view_name
- API: api:v1:blog:resource-action

Integration:
- Frontend URLs included in zumodra/urls.py via i18n_patterns
- API URLs included in api/urls_v1.py
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views_frontend
from . import views_api

# ============================================================================
# API ROUTER
# ============================================================================

api_router = DefaultRouter()

# Blog posts - basename='post' generates: post-list, post-detail, etc.
api_router.register(r'posts', views_api.BlogPostViewSet, basename='post')

# Categories - basename='category'
api_router.register(r'categories', views_api.CategoryViewSet, basename='category')

# Comments - basename='comment'
api_router.register(r'comments', views_api.CommentViewSet, basename='comment')

# Tags - basename='tag'
api_router.register(r'tags', views_api.TagViewSet, basename='tag')

# ============================================================================
# API URLPATTERNS
# ============================================================================

api_urlpatterns = [
    # Router URLs (posts/, categories/, comments/, tags/)
    path('', include(api_router.urls)),

    # Stats endpoint
    path('stats/', views_api.BlogStatsView.as_view(), name='stats'),
]

# ============================================================================
# FRONTEND URLPATTERNS
# ============================================================================

frontend_urlpatterns = [
    # Multi-criteria search
    # GET /<lang>/blog/search/?q=text&category=id&tag=slug&page=num
    path('search/', views_frontend.blog_search_view, name='search'),

    # Comment submission (POST only)
    # POST /<lang>/blog/comment/<post_id>/ with form data
    path('comment/<int:post_id>/', views_frontend.submit_comment, name='submit_comment'),
]

# ============================================================================
# MAIN URL CONFIGURATION
# ============================================================================
# This file exports TWO separate URL configurations:
# 1. frontend_urlpatterns - included in zumodra/urls.py via i18n_patterns
# 2. api_urlpatterns - included in api/urls_v1.py
#
# DO NOT define app_name here - namespaces are defined at inclusion point
# ============================================================================

# Default urlpatterns for backward compatibility
# When included directly via include('blog.urls'), use frontend URLs
urlpatterns = frontend_urlpatterns
