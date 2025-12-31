"""
Dashboard Service WebSocket Consumers - DEPRECATED

This module is deprecated. All WebSocket consumers have been consolidated into the `services` app.

MIGRATION NOTE:
- Import consumers from `services.consumers` instead
- This file re-exports consumers for backwards compatibility only
"""

import warnings

warnings.warn(
    "dashboard_service.consumers is deprecated. "
    "Import consumers from services.consumers instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export consumers from services for backwards compatibility
from services.consumers import (
    LocationConsumer,
    ProviderStatusConsumer,
)

__all__ = [
    'LocationConsumer',
    'ProviderStatusConsumer',
]
