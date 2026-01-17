"""
Stripe Integration Service

Provides unified interface for:
1. Subscription Management (for company plans)
2. Stripe Connect (for freelancer marketplace payments)

Gracefully handles missing Stripe credentials for development.
"""

import logging
from typing import Optional, Dict, Any
from django.conf import settings
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)
User = get_user_model()

# Try to import stripe, but don't fail if not installed
try:
    import stripe
    STRIPE_AVAILABLE = True
    stripe.api_key = getattr(settings, 'STRIPE_SECRET_KEY', None)
except ImportError:
    STRIPE_AVAILABLE = False
    logger.warning("Stripe library not installed. Payment features will be disabled.")


class StripeNotConfiguredError(Exception):
    """Raised when Stripe operations are attempted without proper configuration."""
    pass


class StripeService:
    """
    Subscription management for company plans.

    Handles:
    - Creating Stripe customers
    - Creating subscriptions with free trials
    - Updating subscription plans
    - Canceling subscriptions
    """

    @staticmethod
    def _check_configured():
        """Verify Stripe is configured."""
        if not STRIPE_AVAILABLE:
            raise StripeNotConfiguredError(
                "Stripe library not installed. Run: pip install stripe"
            )
        if not getattr(settings, 'STRIPE_SECRET_KEY', None):
            raise StripeNotConfiguredError(
                "STRIPE_SECRET_KEY not configured in settings"
            )

    @classmethod
    def create_customer(cls, user: User, email: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a Stripe customer for a user.

        Args:
            user: Django user instance
            email: Email (defaults to user.email)

        Returns:
            dict with customer_id and customer object
        """
        cls._check_configured()

        try:
            customer = stripe.Customer.create(
                email=email or user.email,
                name=user.get_full_name() or user.email,
                metadata={
                    'user_id': str(user.id),
                    'user_email': user.email,
                }
            )

            logger.info(f"Created Stripe customer {customer.id} for user {user.email}")

            return {
                'customer_id': customer.id,
                'customer': customer,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe customer creation failed: {e}")
            raise

    @classmethod
    def create_subscription(
        cls,
        user: User,
        plan,  # tenants.models.Plan
        payment_method_id: str,
        trial_days: int = 14
    ) -> Dict[str, Any]:
        """
        Create a subscription for a company plan.

        Args:
            user: User who owns the subscription
            plan: Plan model instance
            payment_method_id: Stripe payment method ID from frontend
            trial_days: Trial period in days (default 14)

        Returns:
            dict with subscription details
        """
        cls._check_configured()

        try:
            # Create or retrieve customer
            customer_result = cls.create_customer(user)
            customer_id = customer_result['customer_id']

            # Attach payment method to customer
            stripe.PaymentMethod.attach(
                payment_method_id,
                customer=customer_id,
            )

            # Set as default payment method
            stripe.Customer.modify(
                customer_id,
                invoice_settings={
                    'default_payment_method': payment_method_id,
                },
            )

            # Create subscription with trial
            subscription = stripe.Subscription.create(
                customer=customer_id,
                items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': plan.name,
                            'description': f'{plan.name} Plan - {plan.max_users} users',
                        },
                        'unit_amount': int(plan.price_monthly * 100),  # Convert to cents
                        'recurring': {
                            'interval': 'month',
                        },
                    },
                    'quantity': 1,
                }],
                trial_period_days=trial_days if plan.price_monthly > 0 else 0,
                metadata={
                    'user_id': str(user.id),
                    'plan_id': str(plan.id),
                    'plan_name': plan.name,
                },
            )

            logger.info(
                f"Created subscription {subscription.id} for user {user.email} "
                f"on plan {plan.name}"
            )

            return {
                'customer_id': customer_id,
                'subscription_id': subscription.id,
                'subscription': subscription,
                'trial_end': subscription.trial_end,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe subscription creation failed: {e}")
            raise

    @classmethod
    def cancel_subscription(cls, subscription_id: str) -> Dict[str, Any]:
        """
        Cancel a subscription immediately.

        Args:
            subscription_id: Stripe subscription ID

        Returns:
            dict with cancellation details
        """
        cls._check_configured()

        try:
            subscription = stripe.Subscription.delete(subscription_id)

            logger.info(f"Canceled subscription {subscription_id}")

            return {
                'subscription_id': subscription.id,
                'status': subscription.status,
                'canceled_at': subscription.canceled_at,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe subscription cancellation failed: {e}")
            raise

    @classmethod
    def update_subscription_plan(
        cls,
        subscription_id: str,
        new_plan  # tenants.models.Plan
    ) -> Dict[str, Any]:
        """
        Update subscription to a different plan.

        Args:
            subscription_id: Existing subscription ID
            new_plan: New Plan model instance

        Returns:
            dict with updated subscription
        """
        cls._check_configured()

        try:
            # Retrieve current subscription
            subscription = stripe.Subscription.retrieve(subscription_id)

            # Update subscription
            updated_subscription = stripe.Subscription.modify(
                subscription_id,
                items=[{
                    'id': subscription['items']['data'][0].id,
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': new_plan.name,
                            'description': f'{new_plan.name} Plan - {new_plan.max_users} users',
                        },
                        'unit_amount': int(new_plan.price_monthly * 100),
                        'recurring': {
                            'interval': 'month',
                        },
                    },
                }],
                metadata={
                    'plan_id': str(new_plan.id),
                    'plan_name': new_plan.name,
                },
            )

            logger.info(f"Updated subscription {subscription_id} to plan {new_plan.name}")

            return {
                'subscription_id': updated_subscription.id,
                'subscription': updated_subscription,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe subscription update failed: {e}")
            raise


class StripeConnectService:
    """
    Stripe Connect for freelancer marketplace payments.

    Handles:
    - Creating connected accounts
    - Account onboarding links
    - Transfers and payouts
    """

    @staticmethod
    def _check_configured():
        """Verify Stripe is configured."""
        if not STRIPE_AVAILABLE:
            raise StripeNotConfiguredError(
                "Stripe library not installed. Run: pip install stripe"
            )
        if not getattr(settings, 'STRIPE_SECRET_KEY', None):
            raise StripeNotConfiguredError(
                "STRIPE_SECRET_KEY not configured in settings"
            )

    @classmethod
    def create_connected_account(cls, user: User) -> Dict[str, Any]:
        """
        Create a Stripe Connect account for a freelancer.

        Args:
            user: Freelancer user

        Returns:
            dict with account_id and account object
        """
        cls._check_configured()

        try:
            account = stripe.Account.create(
                type='express',  # Express accounts for marketplace
                country='US',  # Default to US, can be updated later
                email=user.email,
                capabilities={
                    'card_payments': {'requested': True},
                    'transfers': {'requested': True},
                },
                metadata={
                    'user_id': str(user.id),
                    'user_email': user.email,
                },
            )

            logger.info(f"Created Stripe Connect account {account.id} for {user.email}")

            return {
                'account_id': account.id,
                'account': account,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe Connect account creation failed: {e}")
            raise

    @classmethod
    def create_account_link(
        cls,
        user: User,
        account_id: Optional[str] = None,
        refresh_url: str = None,
        return_url: str = None
    ) -> str:
        """
        Create onboarding link for Stripe Connect account.

        Args:
            user: Freelancer user
            account_id: Existing account ID (creates new if None)
            refresh_url: URL to redirect if link expires
            return_url: URL to redirect after completion

        Returns:
            Onboarding URL
        """
        cls._check_configured()

        try:
            # Create account if not exists
            if not account_id:
                result = cls.create_connected_account(user)
                account_id = result['account_id']

            # Create account link
            account_link = stripe.AccountLink.create(
                account=account_id,
                refresh_url=refresh_url or 'https://example.com/connect/refresh',
                return_url=return_url or 'https://example.com/connect/return',
                type='account_onboarding',
            )

            logger.info(f"Created onboarding link for account {account_id}")

            return account_link.url

        except stripe.error.StripeError as e:
            logger.error(f"Stripe account link creation failed: {e}")
            raise

    @classmethod
    def create_transfer(
        cls,
        amount: int,  # in cents
        currency: str,
        destination_account_id: str,
        description: str = None
    ) -> Dict[str, Any]:
        """
        Create a transfer to a connected account.

        Args:
            amount: Amount in cents
            currency: Currency code (e.g., 'usd')
            destination_account_id: Connected account ID
            description: Transfer description

        Returns:
            dict with transfer details
        """
        cls._check_configured()

        try:
            transfer = stripe.Transfer.create(
                amount=amount,
                currency=currency,
                destination=destination_account_id,
                description=description,
            )

            logger.info(
                f"Created transfer {transfer.id} of {amount} {currency} "
                f"to {destination_account_id}"
            )

            return {
                'transfer_id': transfer.id,
                'transfer': transfer,
            }

        except stripe.error.StripeError as e:
            logger.error(f"Stripe transfer creation failed: {e}")
            raise
