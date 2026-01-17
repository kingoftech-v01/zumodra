"""
Custom Allauth Adapter for Zumodra

Handles post-signup logic including:
- Creating UserProfile
- Assigning users to default tenant
- Setting up initial permissions

Author: Rhematek Solutions
"""

from django.conf import settings
from allauth.account.adapter import DefaultAccountAdapter


class ZumodraAccountAdapter(DefaultAccountAdapter):
    """
    Custom adapter for Zumodra-specific account logic.
    Note: MFA/2FA support is now built into django-allauth 65.3.0+
    and doesn't require a separate adapter.
    """

    def save_user(self, request, user, form, commit=True):
        """
        Save user and perform post-signup setup.
        """
        user = super().save_user(request, user, form, commit=False)

        # Save first_name and last_name from form if available
        if hasattr(form, 'cleaned_data'):
            user.first_name = form.cleaned_data.get('first_name', '')
            user.last_name = form.cleaned_data.get('last_name', '')

        if commit:
            user.save()
            # Post-save setup
            self._setup_user_profile(user)
            self._assign_to_default_tenant(request, user)

        return user

    def _setup_user_profile(self, user):
        """
        Ensure UserProfile exists for the user.
        This is also handled by signals, but we ensure it here.

        Note: UserProfile is a tenant-specific model and only exists
        in tenant schemas, not in the public schema.
        """
        from accounts.models import UserProfile
        from django.db import connection
        from django.db.utils import ProgrammingError

        # Skip if on public schema (UserProfile table only exists in tenant schemas)
        if connection.schema_name == 'public':
            return

        try:
            UserProfile.objects.get_or_create(user=user)
        except ProgrammingError:
            # UserProfile table doesn't exist in public schema, that's okay
            pass

    def _assign_to_default_tenant(self, request, user):
        """
        Assign user to a tenant based on the current request context.

        Logic:
        1. If signing up on a tenant subdomain, assign to that tenant
        2. If signing up on public domain, users are NOT auto-assigned
        3. Multi-tier signup wizards will handle tenant creation

        Note: This method is now deprecated for multi-tier signup.
        The signup wizards (CompanySetupWizard, FreelancerOnboardingWizard)
        handle tenant creation and user assignment.
        """
        from tenants.models import Tenant
        from accounts.models import TenantUser
        from django.db import connection
        from django.db.utils import ProgrammingError

        # Skip auto-assignment if on public schema
        # Let the multi-tier signup wizard handle it
        if connection.schema_name == 'public':
            return

        tenant = None

        # Check if request has tenant context (from django-tenants middleware)
        if hasattr(request, 'tenant') and request.tenant:
            # Don't assign to public schema
            if request.tenant.schema_name != 'public':
                tenant = request.tenant

        # If no tenant from request, try to get default/demo tenant
        if not tenant:
            # Look for an active tenant to assign new users to
            # Priority: 'beta' > 'demo' > first active tenant
            for schema_name in ['beta', 'demo']:
                tenant = Tenant.objects.filter(
                    schema_name=schema_name,
                    status='active'
                ).first()
                if tenant:
                    break

            # Fallback to first active tenant
            if not tenant:
                tenant = Tenant.objects.filter(status='active').exclude(
                    schema_name='public'
                ).first()

        # Create TenantUser if we have a tenant
        if tenant:
            try:
                TenantUser.objects.get_or_create(
                    user=user,
                    tenant=tenant,
                    defaults={
                        'role': 'employee',  # Default role for new signups
                        'is_active': True,
                    }
                )
            except ProgrammingError:
                # TenantUser table doesn't exist in public schema
                pass

    def get_login_redirect_url(self, request):
        """
        Return the URL to redirect to after login.
        """
        from django.urls import reverse
        from accounts.models import TenantUser
        from django.db import connection
        from django.db.utils import ProgrammingError

        if request.user.is_authenticated:
            try:
                # Only query TenantUser if we're not in public schema
                # TenantUser table only exists in tenant schemas
                if connection.schema_name != 'public':
                    tenant_user = TenantUser.objects.filter(
                        user=request.user,
                        is_active=True
                    ).first()

                    if tenant_user:
                        # Redirect to tenant dashboard
                        return reverse('frontend:dashboard:index')
            except ProgrammingError:
                # Table doesn't exist in public schema, that's okay
                pass

        # Default redirect (dashboard will handle public users)
        return reverse('frontend:dashboard:index')

    def get_signup_redirect_url(self, request):
        """
        Return the URL to redirect to after signup.
        Routes to appropriate setup flow based on user type.
        """
        from django.urls import reverse

        # Check if user selected a specific type during signup
        user_type = request.session.get('post_signup_user_type', 'public')

        if user_type == 'company':
            # Company needs tenant workspace setup
            return reverse('custom_account_u:company_setup_wizard')
        elif user_type == 'freelancer':
            # Freelancer needs marketplace profile + Stripe Connect
            return reverse('custom_account_u:freelancer_onboarding_wizard')
        elif user_type == 'public':
            # Public user - optional profile setup
            return reverse('custom_account_u:public_profile_setup')

        # Default fallback
        return reverse('frontend:dashboard:index')
