"""
Dashboard Service Admin - DEPRECATED

This module is deprecated. Admin configuration has been consolidated into the `services` app.

MIGRATION NOTE:
- Admin classes are now in `services.admin`
- This file is kept for backwards compatibility only
- No models are registered here to avoid duplicate registration
"""

import warnings

warnings.warn(
    "dashboard_service.admin is deprecated. "
    "Admin is now configured in services.admin.",
    DeprecationWarning,
    stacklevel=2
)

from django.contrib import admin

# Models are registered in services.admin
# This file intentionally does not register any models to avoid duplicates
