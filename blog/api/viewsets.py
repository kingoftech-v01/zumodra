"""
Blog API ViewSets - DEPRECATED
================================

This module is deprecated. All ViewSets moved to blog/views_api.py per
URL_AND_VIEW_CONVENTIONS.md.

Migration:
    OLD: from blog.api.viewsets import BlogPostViewSet
    NEW: from blog.views_api import BlogPostViewSet

This shim will be removed in a future version.
"""

import warnings

warnings.warn(
    "blog.api.viewsets is deprecated. Use blog.views_api instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export from new location for backwards compatibility
from blog.views_api import (
    BlogPostFilter,
    BlogPostViewSet,
    CategoryViewSet,
    CommentViewSet,
    TagViewSet,
    BlogStatsView,
)

__all__ = [
    'BlogPostFilter',
    'BlogPostViewSet',
    'CategoryViewSet',
    'CommentViewSet',
    'TagViewSet',
    'BlogStatsView',
]
