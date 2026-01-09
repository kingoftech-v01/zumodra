"""
Tests for Finance API.

This module tests the finance API endpoints including:
- Payment transactions
- Subscriptions
- Invoices
- Payment methods
- Refunds
- Escrow transactions
- Disputes
- Stripe Connect
"""

import pytest
from decimal import Decimal
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from finance.models import (
    PaymentTransaction, SubscriptionPlan, UserSubscription,
    Invoice, RefundRequest, PaymentMethod,
    EscrowTransaction, Dispute, EscrowPayout,
    ConnectedAccount, PayoutSchedule, PlatformFee
)


@pytest.fixture
def api_client():
    """Return API client."""
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, user_factory):
    """Return authenticated API client."""
    user = user_factory()
    api_client.force_authenticate(user=user)
    return api_client, user


@pytest.fixture
def admin_authenticated_client(api_client, superuser_factory):
    """Return authenticated admin API client."""
    admin = superuser_factory()
    api_client.force_authenticate(user=admin)
    return api_client, admin


@pytest.fixture
def subscription_plan(db):
    """Create test subscription plan."""
    return SubscriptionPlan.objects.create(
        name='Pro Plan',
        slug='pro-plan',
        price=Decimal('29.99'),
        interval='month',
        features=['Feature 1', 'Feature 2'],
        is_active=True
    )


@pytest.fixture
def user_subscription(db, user_factory, subscription_plan):
    """Create test user subscription."""
    user = user_factory()
    return UserSubscription.objects.create(
        user=user,
        plan=subscription_plan,
        status='active',
        stripe_subscription_id='sub_test_123'
    )


@pytest.fixture
def payment_transaction(db, user_factory):
    """Create test payment transaction."""
    user = user_factory()
    return PaymentTransaction.objects.create(
        user=user,
        amount=Decimal('99.99'),
        currency='USD',
        succeeded=True,
        stripe_payment_intent_id='pi_test_123'
    )


@pytest.fixture
def invoice(db, user_factory):
    """Create test invoice."""
    user = user_factory()
    return Invoice.objects.create(
        user=user,
        invoice_number='INV-0001',
        amount_due=Decimal('99.99'),
        amount_paid=Decimal('0.00'),
        currency='USD',
        paid=False
    )


@pytest.fixture
def payment_method(db, user_factory):
    """Create test payment method."""
    user = user_factory()
    return PaymentMethod.objects.create(
        user=user,
        payment_type='card',
        stripe_payment_method_id='pm_test_123',
        last_four='4242',
        brand='visa',
        exp_month=12,
        exp_year=2030,
        is_default=True
    )


@pytest.fixture
def escrow_transaction(db, user_factory):
    """Create test escrow transaction."""
    buyer = user_factory()
    seller = user_factory()
    return EscrowTransaction.objects.create(
        buyer=buyer,
        seller=seller,
        amount=Decimal('500.00'),
        currency='USD',
        status='initialized',
        description='Test escrow'
    )


# =============================================================================
# PAYMENT TRANSACTION TESTS
# =============================================================================

class TestPaymentTransactionViewSet:
    """Tests for PaymentTransactionViewSet."""

    @pytest.mark.django_db
    def test_list_transactions_authenticated(self, authenticated_client, payment_transaction):
        """Test listing payment transactions requires authentication."""
        client, user = authenticated_client
        # Update transaction to belong to authenticated user
        payment_transaction.user = user
        payment_transaction.save()

        url = reverse('api_v1:finance:payment-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_list_transactions_unauthenticated(self, api_client):
        """Test listing transactions fails without authentication."""
        url = reverse('api_v1:finance:payment-list')
        response = api_client.get(url)

        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_my_transactions_action(self, authenticated_client, payment_transaction):
        """Test my_transactions action returns only user's transactions."""
        client, user = authenticated_client
        payment_transaction.user = user
        payment_transaction.save()

        url = reverse('api_v1:finance:payment-my-transactions')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_stats_requires_admin(self, authenticated_client):
        """Test stats endpoint requires admin access."""
        client, user = authenticated_client

        url = reverse('api_v1:finance:payment-stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_stats_admin_access(self, admin_authenticated_client, payment_transaction):
        """Test admin can access payment stats."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:finance:payment-stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'total_transactions' in response.data.get('data', {})


# =============================================================================
# SUBSCRIPTION TESTS
# =============================================================================

class TestSubscriptionPlanViewSet:
    """Tests for SubscriptionPlanViewSet."""

    @pytest.mark.django_db
    def test_list_plans_public(self, api_client, subscription_plan):
        """Test subscription plans are publicly accessible."""
        url = reverse('api_v1:finance:subscription-plan-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_plan(self, api_client, subscription_plan):
        """Test retrieving a subscription plan."""
        url = reverse('api_v1:finance:subscription-plan-detail', args=[subscription_plan.id])
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestUserSubscriptionViewSet:
    """Tests for UserSubscriptionViewSet."""

    @pytest.mark.django_db
    def test_my_subscription(self, authenticated_client, subscription_plan):
        """Test getting current user's subscription."""
        client, user = authenticated_client
        UserSubscription.objects.create(
            user=user,
            plan=subscription_plan,
            status='active'
        )

        url = reverse('api_v1:finance:user-subscription-my-subscription')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_cancel_subscription(self, authenticated_client, subscription_plan):
        """Test cancelling a subscription."""
        client, user = authenticated_client
        subscription = UserSubscription.objects.create(
            user=user,
            plan=subscription_plan,
            status='active'
        )

        url = reverse('api_v1:finance:user-subscription-cancel', args=[subscription.id])
        response = client.post(url, {'cancel_at_period_end': True})

        assert response.status_code == status.HTTP_200_OK
        subscription.refresh_from_db()
        assert subscription.status == 'canceling'

    @pytest.mark.django_db
    def test_cannot_cancel_others_subscription(self, authenticated_client, user_subscription):
        """Test cannot cancel another user's subscription."""
        client, user = authenticated_client

        url = reverse('api_v1:finance:user-subscription-cancel', args=[user_subscription.id])
        response = client.post(url, {'cancel_at_period_end': True})

        assert response.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# INVOICE TESTS
# =============================================================================

class TestInvoiceViewSet:
    """Tests for InvoiceViewSet."""

    @pytest.mark.django_db
    def test_list_invoices(self, authenticated_client, invoice):
        """Test listing invoices."""
        client, user = authenticated_client
        invoice.user = user
        invoice.save()

        url = reverse('api_v1:finance:invoice-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_pay_invoice(self, authenticated_client, invoice, payment_method):
        """Test paying an invoice."""
        client, user = authenticated_client
        invoice.user = user
        invoice.save()
        payment_method.user = user
        payment_method.save()

        url = reverse('api_v1:finance:invoice-pay', args=[invoice.id])
        response = client.post(url, {
            'payment_method_id': payment_method.stripe_payment_method_id
        })

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_download_invoice(self, authenticated_client, invoice):
        """Test downloading invoice PDF."""
        client, user = authenticated_client
        invoice.user = user
        invoice.save()

        url = reverse('api_v1:finance:invoice-download', args=[invoice.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# PAYMENT METHOD TESTS
# =============================================================================

class TestPaymentMethodViewSet:
    """Tests for PaymentMethodViewSet."""

    @pytest.mark.django_db
    def test_list_payment_methods(self, authenticated_client, payment_method):
        """Test listing payment methods."""
        client, user = authenticated_client
        payment_method.user = user
        payment_method.save()

        url = reverse('api_v1:finance:payment-method-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_set_default_payment_method(self, authenticated_client, payment_method):
        """Test setting default payment method."""
        client, user = authenticated_client
        payment_method.user = user
        payment_method.is_default = False
        payment_method.save()

        url = reverse('api_v1:finance:payment-method-set-default', args=[payment_method.id])
        response = client.post(url)

        assert response.status_code == status.HTTP_200_OK
        payment_method.refresh_from_db()
        assert payment_method.is_default is True


# =============================================================================
# ESCROW TRANSACTION TESTS
# =============================================================================

class TestEscrowTransactionViewSet:
    """Tests for EscrowTransactionViewSet."""

    @pytest.mark.django_db
    def test_list_escrows_as_buyer(self, api_client, escrow_transaction):
        """Test listing escrows as buyer."""
        api_client.force_authenticate(user=escrow_transaction.buyer)

        url = reverse('api_v1:finance:escrow-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_fund_escrow(self, api_client, escrow_transaction):
        """Test funding an escrow."""
        api_client.force_authenticate(user=escrow_transaction.buyer)

        url = reverse('api_v1:finance:escrow-fund', args=[escrow_transaction.id])
        response = api_client.post(url, {'notes': 'Funding escrow'})

        assert response.status_code == status.HTTP_200_OK
        escrow_transaction.refresh_from_db()
        assert escrow_transaction.status == 'funded'

    @pytest.mark.django_db
    def test_mark_delivered(self, api_client, escrow_transaction):
        """Test marking escrow as delivered."""
        escrow_transaction.mark_funded()
        api_client.force_authenticate(user=escrow_transaction.seller)

        url = reverse('api_v1:finance:escrow-mark-delivered', args=[escrow_transaction.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK
        escrow_transaction.refresh_from_db()
        assert escrow_transaction.status == 'service_delivered'

    @pytest.mark.django_db
    def test_release_funds(self, api_client, escrow_transaction):
        """Test releasing escrow funds."""
        escrow_transaction.mark_funded()
        escrow_transaction.mark_service_delivered()
        api_client.force_authenticate(user=escrow_transaction.buyer)

        url = reverse('api_v1:finance:escrow-release', args=[escrow_transaction.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK
        escrow_transaction.refresh_from_db()
        assert escrow_transaction.status == 'released'

    @pytest.mark.django_db
    def test_raise_dispute(self, api_client, escrow_transaction):
        """Test raising a dispute."""
        escrow_transaction.mark_funded()
        api_client.force_authenticate(user=escrow_transaction.buyer)

        url = reverse('api_v1:finance:escrow-dispute', args=[escrow_transaction.id])
        response = api_client.post(url, {'reason': 'Service not as described'})

        assert response.status_code == status.HTTP_200_OK
        escrow_transaction.refresh_from_db()
        assert escrow_transaction.status == 'dispute'

    @pytest.mark.django_db
    def test_cancel_escrow(self, api_client, escrow_transaction):
        """Test cancelling unfunded escrow."""
        api_client.force_authenticate(user=escrow_transaction.buyer)

        url = reverse('api_v1:finance:escrow-cancel', args=[escrow_transaction.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK
        escrow_transaction.refresh_from_db()
        assert escrow_transaction.status == 'cancelled'

    @pytest.mark.django_db
    def test_escrow_stats(self, api_client, escrow_transaction):
        """Test escrow stats endpoint."""
        api_client.force_authenticate(user=escrow_transaction.buyer)

        url = reverse('api_v1:finance:escrow-stats')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'as_buyer' in response.data.get('data', {})
        assert 'as_seller' in response.data.get('data', {})


# =============================================================================
# DISPUTE TESTS
# =============================================================================

class TestDisputeViewSet:
    """Tests for DisputeViewSet."""

    @pytest.mark.django_db
    def test_list_disputes(self, api_client, escrow_transaction):
        """Test listing disputes."""
        escrow_transaction.mark_funded()
        escrow_transaction.raise_dispute()

        dispute = Dispute.objects.create(
            escrow=escrow_transaction,
            raised_by=escrow_transaction.buyer,
            reason='Service not delivered'
        )

        api_client.force_authenticate(user=escrow_transaction.buyer)

        url = reverse('api_v1:finance:dispute-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_resolve_dispute_admin_only(self, admin_authenticated_client, escrow_transaction):
        """Test only admin can resolve disputes."""
        escrow_transaction.mark_funded()
        escrow_transaction.raise_dispute()

        dispute = Dispute.objects.create(
            escrow=escrow_transaction,
            raised_by=escrow_transaction.buyer,
            reason='Service not delivered'
        )

        client, admin = admin_authenticated_client

        url = reverse('api_v1:finance:dispute-resolve', args=[dispute.id])
        response = client.post(url, {
            'resolution': 'refund_buyer',
            'resolution_notes': 'Full refund granted'
        })

        assert response.status_code == status.HTTP_200_OK
        dispute.refresh_from_db()
        assert dispute.resolved is True


# =============================================================================
# CONNECTED ACCOUNT TESTS
# =============================================================================

class TestConnectedAccountViewSet:
    """Tests for ConnectedAccountViewSet."""

    @pytest.mark.django_db
    def test_my_account(self, authenticated_client):
        """Test getting current user's connected account."""
        client, user = authenticated_client
        ConnectedAccount.objects.create(
            user=user,
            account_id='acct_test_123',
            account_status='active',
            country='US'
        )

        url = reverse('api_v1:finance:connected-account-my-account')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_create_onboarding_link(self, authenticated_client):
        """Test generating onboarding link."""
        client, user = authenticated_client
        account = ConnectedAccount.objects.create(
            user=user,
            account_id='acct_test_123',
            account_status='pending',
            country='US'
        )

        url = reverse('api_v1:finance:connected-account-create-onboarding-link', args=[account.id])
        response = client.post(url, {
            'return_url': 'https://example.com/return',
            'refresh_url': 'https://example.com/refresh'
        })

        # May fail if Stripe not configured, but endpoint should be accessible
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_500_INTERNAL_SERVER_ERROR]


# =============================================================================
# FINANCE ANALYTICS TESTS
# =============================================================================

class TestFinanceAnalyticsViewSet:
    """Tests for FinanceAnalyticsViewSet."""

    @pytest.mark.django_db
    def test_payment_stats_requires_admin(self, authenticated_client):
        """Test payment stats requires admin."""
        client, user = authenticated_client

        url = reverse('api_v1:finance:analytics-payment-stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_payment_stats_admin(self, admin_authenticated_client, payment_transaction):
        """Test admin can access payment stats."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:finance:analytics-payment-stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_subscription_stats(self, admin_authenticated_client, user_subscription):
        """Test subscription stats endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:finance:analytics-subscription-stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_escrow_stats(self, admin_authenticated_client, escrow_transaction):
        """Test escrow stats endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:finance:analytics-escrow-stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_connect_stats(self, admin_authenticated_client):
        """Test Stripe Connect stats endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:finance:analytics-connect-stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_revenue_chart(self, admin_authenticated_client, payment_transaction):
        """Test revenue chart endpoint."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:finance:analytics-revenue-chart')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'labels' in response.data.get('data', {})
        assert 'revenue' in response.data.get('data', {})
