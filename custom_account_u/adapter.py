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
        """
        from accounts.models import UserProfile
        UserProfile.objects.get_or_create(user=user)

    def _assign_to_default_tenant(self, request, user):
        """
        Assign user to a tenant based on the current request context.

        Logic:
        1. If signing up on a tenant subdomain, assign to that tenant
        2. If signing up on public domain, check for default tenant
        3. If no tenant context, user remains unassigned (admin must assign)
        """
        from tenants.models import Tenant
        from accounts.models import TenantUser

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
            TenantUser.objects.get_or_create(
                user=user,
                tenant=tenant,
                defaults={
                    'role': 'employee',  # Default role for new signups
                    'is_active': True,
                }
            )

    def get_login_redirect_url(self, request):
        """
        Return the URL to redirect to after login.
        """
        # Check if user has any tenant assignments
        from accounts.models import TenantUser

        if request.user.is_authenticated:
            tenant_user = TenantUser.objects.filter(
                user=request.user,
                is_active=True
            ).first()

            if tenant_user:
                # Redirect to tenant dashboard
                return f'/dashboard/'

        # Default redirect
        return super().get_login_redirect_url(request)

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
        return '/dashboard/'
