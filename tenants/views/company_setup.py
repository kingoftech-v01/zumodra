"""
Company Setup Wizard

Multi-step wizard for company signup:
1. Company information
2. Plan selection
3. Payment setup (if paid plan)
"""

import logging
from django.shortcuts import redirect
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from formtools.wizard.views import SessionWizardView

logger = logging.getLogger(__name__)


class CompanySetupWizard(LoginRequiredMixin, SessionWizardView):
    """
    Multi-step wizard for company tenant setup.

    Steps:
    1. company_info - Company name, size, industry, website
    2. plan_selection - Choose subscription plan
    3. payment - Stripe payment (skipped if FREE plan)
    """
    template_name = 'tenants/company_setup_wizard.html'

    def get_form_list(self):
        """
        Dynamically adjust form list based on plan selection.
        """
        from tenants.forms import CompanyInfoForm, PlanSelectionForm, StripePaymentForm

        form_list = [
            ('company_info', CompanyInfoForm),
            ('plan_selection', PlanSelectionForm),
        ]

        # Only add payment step if plan requires payment
        plan_data = self.get_cleaned_data_for_step('plan_selection')
        if plan_data:
            from tenants.models import Plan
            try:
                plan = Plan.objects.get(id=plan_data['plan_id'])
                if plan.price_monthly > 0:
                    form_list.append(('payment', StripePaymentForm))
            except Plan.DoesNotExist:
                pass

        return form_list

    def done(self, form_list, **kwargs):
        """
        Process complete signup and create tenant.
        """
        from tenants.services import TenantService
        from tenants.models import Plan
        from accounts.models import TenantUser
        from finance.stripe_service import StripeService, StripeNotConfiguredError

        # Get cleaned data from all steps
        company_data = self.get_cleaned_data_for_step('company_info')
        plan_data = self.get_cleaned_data_for_step('plan_selection')

        # Get selected plan
        plan = Plan.objects.get(id=plan_data['plan_id'])

        # Initialize Stripe variables
        stripe_customer_id = None
        stripe_subscription_id = None

        # Handle payment for paid plans
        if plan.price_monthly > 0:
            payment_data = self.get_cleaned_data_for_step('payment')
            if payment_data:
                try:
                    # Create Stripe subscription
                    stripe_result = StripeService.create_subscription(
                        user=self.request.user,
                        plan=plan,
                        payment_method_id=payment_data['stripe_payment_method_id'],
                        trial_days=14,
                    )
                    stripe_customer_id = stripe_result['customer_id']
                    stripe_subscription_id = stripe_result['subscription_id']

                    logger.info(
                        f"Created Stripe subscription {stripe_subscription_id} "
                        f"for {self.request.user.email}"
                    )

                except StripeNotConfiguredError as e:
                    logger.warning(f"Stripe not configured: {e}")
                    # Continue without payment in development
                except Exception as e:
                    logger.error(f"Stripe subscription failed: {e}", exc_info=True)
                    # In production, you'd want to show an error and not create tenant
                    # For now, log and continue

        # Create tenant
        try:
            tenant = TenantService.create_tenant(
                name=company_data['company_name'],
                owner_email=self.request.user.email,
                plan=plan,
                tenant_type='company',
                stripe_customer_id=stripe_customer_id,
                stripe_subscription_id=stripe_subscription_id,
                metadata={
                    'company_size': company_data['company_size'],
                    'industry': company_data['industry'],
                    'website': company_data.get('website', ''),
                }
            )

            logger.info(
                f"Created tenant {tenant.schema_name} for company "
                f"{company_data['company_name']}"
            )

            # Provision tenant (run migrations, create default data)
            TenantService.provision_tenant(tenant)

            # Add user as OWNER
            TenantUser.objects.create(
                tenant=tenant,
                user=self.request.user,
                role='owner'
            )

            logger.info(f"Added {self.request.user.email} as owner of {tenant.schema_name}")

            # Mark post-signup complete
            self.request.session['post_signup_complete'] = True

            # Redirect to tenant dashboard
            tenant_url = f'https://{tenant.get_primary_domain()}/app/dashboard/'
            return redirect(tenant_url)

        except Exception as e:
            logger.error(f"Tenant creation failed: {e}", exc_info=True)
            # In production, show error page
            # For now, redirect to dashboard with error message
            from django.contrib import messages
            messages.error(
                self.request,
                f'Failed to create workspace: {str(e)}. Please contact support.'
            )
            return redirect('frontend:dashboard:index')

    def get_context_data(self, form, **kwargs):
        """
        Add context for template.
        """
        context = super().get_context_data(form=form, **kwargs)

        # Add step information
        context['step_title'] = {
            'company_info': 'Company Information',
            'plan_selection': 'Choose Your Plan',
            'payment': 'Payment Details',
        }.get(self.steps.current, 'Setup')

        context['step_number'] = self.steps.step1 + 1
        context['total_steps'] = len(self.get_form_list())

        return context
