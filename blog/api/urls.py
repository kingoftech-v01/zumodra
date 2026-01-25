"""
Blog API URLs - DEPRECATED
===========================

This module is deprecated. All URL patterns moved to blog/urls.py per
URL_AND_VIEW_CONVENTIONS.md.

Migration:
    OLD: path('blog/', include('blog.api.urls'))
    NEW: path('blog/', include('blog.urls'))  # Import api_urlpatterns

This shim will be removed in a future version.
"""

import warnings

warnings.warn(
    "blog.api.urls is deprecated. Use blog.urls (api_urlpatterns) instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export from new location for backwards compatibility
from blog.urls import api_urlpatterns

urlpatterns = api_urlpatterns
