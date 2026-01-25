"""
Tenant Type Validation Functions

Validation logic for enforcing tenant type rules.

Note: Individual freelancers are now FreelancerProfile user profiles (not tenants).
All tenants are COMPANY type only.
"""

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


# REMOVED: validate_freelancer_members
# REMOVED: validate_company_can_create_jobs
# REMOVED: validate_company_can_receive_invitations
# All validators removed as FREELANCER tenant type was deprecated.
# Individual freelancers are now FreelancerProfile user profiles (accounts app).
