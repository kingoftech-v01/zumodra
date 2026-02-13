"""
Tenant Validators

Business rule validators for tenant operations.
"""

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def validate_company_can_receive_invitations(tenant):
    """Validate that a tenant can receive invitations (must be a company)."""
    if hasattr(tenant, 'tenant_type') and tenant.tenant_type == 'freelancer':
        raise ValidationError(
            _('Freelancer tenants cannot send invitations.')
        )


def validate_company_can_create_jobs(tenant):
    """Validate that a tenant can create job postings."""
    if hasattr(tenant, 'tenant_type') and tenant.tenant_type == 'freelancer':
        raise ValidationError(
            _('Freelancer tenants cannot create job postings.')
        )
