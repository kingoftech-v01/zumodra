"""
Tenant Type Validation Functions

Validation logic for enforcing tenant type rules:
- COMPANY tenants can create jobs and have employees
- FREELANCER tenants cannot create jobs and must remain single-user
"""

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def validate_freelancer_members(tenant):
    """
    Validate that freelancer tenants have exactly 1 member.

    Args:
        tenant: Tenant instance

    Raises:
        ValidationError: If freelancer tenant has more than 1 active member
    """
    if tenant.tenant_type == 'freelancer':
        active_members = tenant.members.filter(is_active=True).count()
        if active_members > 1:
            raise ValidationError(
                _('Freelancer tenants cannot have more than one member.')
            )


def validate_company_can_create_jobs(tenant):
    """
    Validate that only companies can create jobs.

    Args:
        tenant: Tenant instance

    Raises:
        ValidationError: If freelancer tenant attempts to create job
    """
    if tenant.tenant_type == 'freelancer':
        raise ValidationError(
            _('Freelancer tenants cannot create job postings. Switch to Company type first.')
        )


def validate_company_can_receive_invitations(tenant):
    """
    Validate that only companies can receive employee invitations.

    Args:
        tenant: Tenant instance

    Raises:
        ValidationError: If freelancer tenant attempts to send invitation
    """
    if tenant.tenant_type == 'freelancer':
        raise ValidationError(
            _('Freelancer tenants cannot receive employee invitations. Only companies can have employees.')
        )
