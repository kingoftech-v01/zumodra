"""
Blog API URLs.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    BlogPostViewSet,
    CategoryViewSet,
    CommentViewSet,
    TagViewSet,
    BlogStatsView,
)

app_name = 'blog'

router = DefaultRouter()

# Blog posts
router.register(r'posts', BlogPostViewSet, basename='post')

# Categories
router.register(r'categories', CategoryViewSet, basename='category')

# Comments
router.register(r'comments', CommentViewSet, basename='comment')

# Tags
router.register(r'tags', TagViewSet, basename='tag')

urlpatterns = [
    path('', include(router.urls)),
    path('stats/', BlogStatsView.as_view(), name='stats'),
]
