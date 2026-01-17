"""
Freelancer Onboarding Wizard

Multi-step wizard for freelancer signup:
1. Professional profile
2. Marketplace plan selection (optional)
3. Stripe Connect setup for payments
"""

import logging
from django.shortcuts import redirect
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from formtools.wizard.views import SessionWizardView

logger = logging.getLogger(__name__)


class FreelancerOnboardingWizard(LoginRequiredMixin, SessionWizardView):
    """
    Multi-step wizard for freelancer onboarding.

    Steps:
    1. profile - Professional title, bio, skills, rates
    2. plan - Marketplace plan (FREE or PRO)
    3. stripe_connect - Stripe Connect account setup
    """
    template_name = 'custom_account_u/freelancer_onboarding.html'

    # Define form list as class attribute (required by SessionWizardView)
    from custom_account_u.forms import (
        FreelancerProfileForm,
        FreelancerPlanForm,
        StripeConnectForm
    )
    form_list = [
        ('profile', FreelancerProfileForm),
        ('plan', FreelancerPlanForm),
        ('stripe_connect', StripeConnectForm),
    ]

    def done(self, form_list, **kwargs):
        """
        Process complete onboarding and create freelancer resources.
        """
        from tenants.services import TenantService
        from tenants.models import Plan
        from accounts.models import TenantUser
        from custom_account_u.models import PublicProfile
        from finance.stripe_service import StripeConnectService, StripeNotConfiguredError

        # Get cleaned data from all steps
        profile_data = self.get_cleaned_data_for_step('profile')
        plan_data = self.get_cleaned_data_for_step('plan')
        stripe_data = self.get_cleaned_data_for_step('stripe_connect')

        # 1. Create or update PublicProfile
        try:
            # Convert skills string to list
            skills_list = [
                skill.strip()
                for skill in profile_data['skills'].split(',')
                if skill.strip()
            ]

            public_profile, created = PublicProfile.objects.update_or_create(
                user=self.request.user,
                defaults={
                    'professional_title': profile_data['professional_title'],
                    'bio': profile_data['bio'],
                    'skills': skills_list,
                    'hourly_rate_min': profile_data['hourly_rate_min'],
                    'hourly_rate_max': profile_data['hourly_rate_max'],
                    'available_for_work': profile_data['available_for_work'],
                    'profile_visibility': 'PUBLIC',
                }
            )

            logger.info(f"Created PublicProfile for freelancer {self.request.user.email}")

        except Exception as e:
            logger.error(f"PublicProfile creation failed: {e}", exc_info=True)

        # 2. Create freelancer tenant workspace
        try:
            # Get FREE plan for freelancer workspace
            free_plan = Plan.objects.filter(slug='free').first()
            if not free_plan:
                free_plan = Plan.objects.filter(price_monthly=0).first()

            tenant = TenantService.create_tenant(
                name=f"{self.request.user.get_full_name()}'s Workspace",
                owner_email=self.request.user.email,
                plan=free_plan,
                tenant_type='freelancer'
            )

            logger.info(f"Created freelancer tenant {tenant.schema_name}")

            # Provision tenant
            TenantService.provision_tenant(tenant)

            # Add user as OWNER
            TenantUser.objects.create(
                tenant=tenant,
                user=self.request.user,
                role='owner'
            )

        except Exception as e:
            logger.error(f"Freelancer tenant creation failed: {e}", exc_info=True)

        # 3. Setup Stripe Connect if requested
        if stripe_data and stripe_data.get('setup_payments'):
            try:
                # Create Stripe Connect account link
                connect_url = StripeConnectService.create_account_link(
                    user=self.request.user,
                    refresh_url=self.request.build_absolute_uri(
                        reverse_lazy('custom_account_u:stripe_connect_refresh')
                    ),
                    return_url=self.request.build_absolute_uri(
                        reverse_lazy('frontend:dashboard:index')
                    )
                )

                logger.info(f"Created Stripe Connect link for {self.request.user.email}")

                # Mark post-signup complete
                self.request.session['post_signup_complete'] = True

                # Redirect to Stripe Connect onboarding
                return redirect(connect_url)

            except StripeNotConfiguredError as e:
                logger.warning(f"Stripe Connect not configured: {e}")
                # Continue to dashboard without payment setup
            except Exception as e:
                logger.error(f"Stripe Connect setup failed: {e}", exc_info=True)

        # Mark post-signup complete
        self.request.session['post_signup_complete'] = True

        # Redirect to dashboard
        return redirect('frontend:dashboard:index')

    def get_context_data(self, form, **kwargs):
        """
        Add context for template.
        """
        context = super().get_context_data(form=form, **kwargs)

        # Add step information
        context['step_title'] = {
            'profile': 'Professional Profile',
            'plan': 'Choose Your Plan',
            'stripe_connect': 'Payment Setup',
        }.get(self.steps.current, 'Onboarding')

        context['step_number'] = self.steps.step1 + 1
        context['total_steps'] = len(self.get_form_list())

        return context
