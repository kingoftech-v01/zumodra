"""
Dashboard Service Views - DEPRECATED

This module is deprecated. All views have been consolidated into the `services` app.

MIGRATION NOTE:
- Import views from `services.views` instead
- This file maintains backwards compatibility only
"""

import warnings

warnings.warn(
    "dashboard_service.views is deprecated. "
    "Import views from services.views instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export views from services for backwards compatibility
from services.views import (
    browse_services,
    service_detail,
    like_service,
    browse_nearby_services,
    provider_dashboard,
    create_provider_profile,
    edit_provider_profile,
    provider_profile_view,
    create_service,
    edit_service,
    delete_service,
    create_service_request,
    my_requests,
    view_request,
    submit_proposal,
    accept_proposal,
    view_contract,
    my_contracts,
    update_contract_status,
    add_review,
    address_to_coords,
    coords_to_address,
    search_services_ajax,
)

# Backwards compatibility aliases
service_view = provider_dashboard
add_service_view = create_service
service_detail_view = service_detail
update_service_view = edit_service
delete_service_view = delete_service
browse_service = browse_services
browse_service_detail = service_detail
