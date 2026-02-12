"""
DEPRECATED: Django-Tenants Configuration for Zumodra
=====================================================
This file is DEPRECATED as of 2026-02-12.

Multi-tenancy has been removed from the Zumodra platform.
All apps now run in a single database schema.

This file is retained for reference only and will be removed in a future release.
Do NOT import this file in any new code.

See DEPRECATION.md for migration details.
"""

import warnings

warnings.warn(
    "settings_tenants.py is deprecated. Multi-tenancy has been removed. "
    "Use zumodra.settings instead.",
    DeprecationWarning,
    stacklevel=2,
)
