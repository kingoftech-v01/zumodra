"""
dashboard_service Models - DEPRECATED

This module is deprecated. All models have been consolidated into the `services` app.

MIGRATION NOTE:
- All models from this app now live in `services.models`
- Import from `services.models` instead of `dashboard_service.models`
- This file re-exports models for backwards compatibility only

The following models have been renamed:
- ServiceCategory -> services.ServiceCategory
- ServicesTag -> services.ServiceTag
- ServicesPicture -> services.ServiceImage
- ProviderSkill -> services.ProviderSkill
- ServiceProviderProfile -> services.ServiceProvider
- Service -> services.Service
- ServiceLike -> services.ServiceLike
- ClientRequest -> services.ClientRequest
- Match -> services.ProviderMatch
- ServiceRequest -> services.ClientRequest
- ServiceProposal -> services.ServiceProposal
- ServiceContract -> services.ServiceContract
- ServiceComment -> services.ServiceReview
- ServiceMessage -> services.ContractMessage
"""

import warnings

# Emit deprecation warning on import
warnings.warn(
    "dashboard_service.models is deprecated. "
    "Import from services.models instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export all models from services for backwards compatibility
from services.models import (
    # Canonical names
    ServiceCategory,
    ServiceTag,
    ServiceImage,
    ProviderSkill,
    ServiceProvider,
    Service,
    ServiceLike,
    ClientRequest,
    ProviderMatch,
    ServiceProposal,
    ServiceContract,
    ServiceReview,
    ContractMessage,

    # Backwards compatibility aliases
    ServicesTag,
    ServicesPicture,
    ServiceProviderProfile,
    Match,
    ServiceRequest,
    ServiceComment,
    ServiceMessage,
)

__all__ = [
    'ServiceCategory',
    'ServiceTag',
    'ServiceImage',
    'ProviderSkill',
    'ServiceProvider',
    'Service',
    'ServiceLike',
    'ClientRequest',
    'ProviderMatch',
    'ServiceProposal',
    'ServiceContract',
    'ServiceReview',
    'ContractMessage',
    # Old aliases
    'ServicesTag',
    'ServicesPicture',
    'ServiceProviderProfile',
    'Match',
    'ServiceRequest',
    'ServiceComment',
    'ServiceMessage',
]
