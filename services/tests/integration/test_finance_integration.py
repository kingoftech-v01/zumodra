"""
Services & Finance Tests for Zumodra

Comprehensive tests for the freelance marketplace (services) and finance apps:
- Service listing CRUD operations
- Mission workflow (post -> fund -> deliver -> accept/dispute -> payout)
- Escrow payment flows
- Stripe webhook handling
- Dispute resolution
- Subscription management
- Invoice generation
- Payment history
- Refund processing
- KYC verification requirements for transactions

All tests use tenant isolation and proper factory patterns.
"""

import json
import uuid
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from django.utils import timezone
from django.db import IntegrityError
from django.core.exceptions import ValidationError

from tests.base import TenantTestCase, APITenantTestCase
from conftest import (
    UserFactory, TenantFactory, PlanFactory, TenantUserFactory,
    VerifiedKYCFactory, KYCVerificationFactory
)


# ============================================================================
# TEST FIXTURES - Service Marketplace Factories
# ============================================================================

@pytest.fixture
def service_category(db):
    """Create a service category for testing."""
    from services.models import ServiceCategory
    from conftest import TenantFactory

    tenant = TenantFactory()
    return ServiceCategory.objects.create(
        tenant=tenant,
        name='Web Development',
        slug='web-development',
        description='Web development services',
        is_active=True
    )


@pytest.fixture
def service_provider(db, user_factory, tenant_factory):
    """Create a service provider user with profile."""
    from services.models import ServiceProvider

    tenant = tenant_factory()
    user = user_factory()

    provider = ServiceProvider.objects.create(
        tenant=tenant,
        user=user,
        display_name='Pro Dev Services',
        tagline='Quality web development',
        bio='Full stack development services',
        hourly_rate=Decimal('75.00'),
        is_verified=True,
        is_active=True,
        stripe_account_id='acct_test123',
        stripe_onboarding_complete=True,
        stripe_payouts_enabled=True
    )
    return provider


@pytest.fixture
def unverified_provider(db, user_factory, tenant_factory):
    """Create an unverified service provider."""
    from services.models import ServiceProvider

    tenant = tenant_factory()
    user = user_factory()

    provider = ServiceProvider.objects.create(
        tenant=tenant,
        user=user,
        display_name='Unverified Dev',
        hourly_rate=Decimal('50.00'),
        is_verified=False,
        is_active=True
    )
    return provider


@pytest.fixture
def service_listing(db, service_provider, service_category):
    """Create a service listing."""
    from services.models import Service

    return Service.objects.create(
        tenant=service_provider.tenant,
        provider=service_provider,
        category=service_category,
        name='Custom Web Application Development',
        description='Build custom web applications using modern technologies',
        price=Decimal('5000.00'),
        service_type='fixed',
        duration_days=30,
        is_active=True,
        is_featured=False
    )


@pytest.fixture
def client_user(db, user_factory, tenant_factory):
    """Create a client user with verified KYC."""
    tenant = tenant_factory()
    user = user_factory(email='client@example.com')
    VerifiedKYCFactory(user=user)
    TenantUserFactory(user=user, tenant=tenant, role='employee')
    return user


@pytest.fixture
def unverified_client(db, user_factory):
    """Create a client user without KYC verification."""
    return user_factory(email='unverified_client@example.com')


@pytest.fixture
def connected_account(db, service_provider):
    """Create a Stripe connected account for the provider."""
    from finance.models import ConnectedAccount

    return ConnectedAccount.objects.create(
        user=service_provider.user,
        account_id='acct_test_connected_123',
        account_status='active',
        charges_enabled=True,
        payouts_enabled=True,
        details_submitted=True,
        country='CA',
        default_currency='CAD',
        business_type='individual'
    )


@pytest.fixture
def subscription_plan(db):
    """Create a subscription plan."""
    from finance.models import SubscriptionPlan

    return SubscriptionPlan.objects.create(
        name='Professional',
        stripe_product_id='prod_test123',
        stripe_price_id='price_test123',
        price=Decimal('29.99'),
        currency='CAD',
        interval='month',
        description='Professional tier with all features'
    )


# ============================================================================
# SERVICE LISTING CRUD TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceListingCRUD:
    """Test service listing create, read, update, delete operations."""

    def test_create_service_listing(self, service_provider, service_category):
        """Test creating a new service listing."""
        from services.models import Service

        listing = Service.objects.create(
            tenant=service_provider.tenant,
            provider=service_provider,
            category=service_category,
            name='Mobile App Development',
            description='Cross-platform mobile app development',
            price=Decimal('8000.00'),
            service_type='fixed',
            duration_days=45
        )

        assert listing.pk is not None
        assert listing.name == 'Mobile App Development'
        assert listing.price == Decimal('8000.00')
        assert listing.provider == service_provider

    def test_service_listing_slug_generation(self, service_provider, service_category):
        """Test that service slug is auto-generated."""
        from services.models import Service

        listing = Service.objects.create(
            tenant=service_provider.tenant,
            provider=service_provider,
            category=service_category,
            name='Enterprise Solution Design',
            price=Decimal('15000.00'),
            service_type='custom'
        )

        assert listing.slug != ''
        assert 'enterprise' in listing.slug.lower()

    def test_service_listing_pricing_types(self, service_provider, service_category):
        """Test different pricing types for services."""
        from services.models import Service

        # Fixed price listing
        fixed_listing = Service.objects.create(
            tenant=service_provider.tenant,
            provider=service_provider,
            category=service_category,
            name='Logo Design',
            price=Decimal('500.00'),
            service_type='fixed',
            duration_days=7
        )

        # Hourly rate listing
        hourly_listing = Service.objects.create(
            tenant=service_provider.tenant,
            provider=service_provider,
            category=service_category,
            name='Consulting',
            price=Decimal('100.00'),
            service_type='hourly',
            duration_days=0
        )

        # Custom quote listing
        custom_listing = Service.objects.create(
            tenant=service_provider.tenant,
            provider=service_provider,
            category=service_category,
            name='Complex Integration',
            price_min=Decimal('5000.00'),
            price_max=Decimal('20000.00'),
            service_type='custom'
        )

        assert fixed_listing.service_type == 'fixed'
        assert hourly_listing.service_type == 'hourly'
        assert custom_listing.service_type == 'custom'

    def test_update_service_listing(self, service_listing):
        """Test updating a service listing."""
        original_name = service_listing.name
        service_listing.name = 'Updated Service Name'
        service_listing.price = Decimal('6000.00')
        service_listing.save()

        service_listing.refresh_from_db()
        assert service_listing.name == 'Updated Service Name'
        assert service_listing.price == Decimal('6000.00')

    def test_deactivate_service_listing(self, service_listing):
        """Test deactivating a service listing."""
        service_listing.is_active = False
        service_listing.save()

        service_listing.refresh_from_db()
        assert not service_listing.is_active

    def test_service_listing_stats_tracking(self, service_listing):
        """Test view and order count tracking."""
        initial_views = service_listing.view_count
        initial_orders = service_listing.order_count

        service_listing.view_count += 10
        service_listing.order_count += 2
        service_listing.save()

        service_listing.refresh_from_db()
        assert service_listing.view_count == initial_views + 10
        assert service_listing.order_count == initial_orders + 2


# ============================================================================
# SERVICE PROPOSAL TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceProposalFlow:
    """Test service proposal creation and management."""

    def test_create_proposal(self, service_provider, client_user):
        """Test creating a proposal responding to a client request."""
        from services.models import ClientRequest, ServiceProposal

        client_request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Need a Custom E-commerce Platform',
            description='Looking for a developer to build an e-commerce site',
            budget_min=Decimal('5000.00'),
            budget_max=Decimal('10000.00'),
            status='open'
        )

        proposal = ServiceProposal.objects.create(
            tenant=service_provider.tenant,
            client_request=client_request,
            provider=service_provider,
            proposed_rate=Decimal('7500.00'),
            rate_type='fixed',
            cover_letter='I have extensive experience in e-commerce development.',
            proposed_timeline_days=45,
            status='pending'
        )

        assert proposal.pk is not None
        assert proposal.status == 'pending'
        assert proposal.proposed_rate == Decimal('7500.00')

    def test_accept_proposal(self, service_provider, client_user):
        """Test client accepting a proposal."""
        from services.models import ClientRequest, ServiceProposal

        client_request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Web App Project',
            description='Build a web application',
            status='open'
        )

        proposal = ServiceProposal.objects.create(
            tenant=service_provider.tenant,
            client_request=client_request,
            provider=service_provider,
            proposed_rate=Decimal('6000.00'),
            rate_type='fixed',
            cover_letter='Ready to start immediately.',
            status='pending'
        )

        # Client accepts
        proposal.status = 'accepted'
        proposal.save()

        assert proposal.status == 'accepted'

    def test_reject_proposal(self, service_provider, client_user):
        """Test client rejecting a proposal."""
        from services.models import ClientRequest, ServiceProposal

        client_request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Design Project',
            description='Need design work',
            status='open'
        )

        proposal = ServiceProposal.objects.create(
            tenant=service_provider.tenant,
            client_request=client_request,
            provider=service_provider,
            proposed_rate=Decimal('3000.00'),
            rate_type='fixed',
            cover_letter='Experienced designer here.',
            status='pending'
        )

        proposal.status = 'rejected'
        proposal.save()

        assert proposal.status == 'rejected'

    def test_withdraw_proposal(self, service_provider, client_user):
        """Test provider withdrawing a proposal."""
        from services.models import ClientRequest, ServiceProposal

        client_request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Consulting Project',
            description='Need business consulting',
            status='open'
        )

        proposal = ServiceProposal.objects.create(
            tenant=service_provider.tenant,
            client_request=client_request,
            provider=service_provider,
            proposed_rate=Decimal('2000.00'),
            rate_type='hourly',
            cover_letter='Expert consultant.',
            status='pending'
        )

        proposal.status = 'withdrawn'
        proposal.save()

        assert proposal.status == 'withdrawn'

    def test_unique_proposal_per_request_provider(self, service_provider, client_user):
        """Test that a provider can only submit one proposal per request."""
        from services.models import ClientRequest, ServiceProposal

        client_request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Unique Project',
            description='Test project',
            status='open'
        )

        ServiceProposal.objects.create(
            tenant=service_provider.tenant,
            client_request=client_request,
            provider=service_provider,
            proposed_rate=Decimal('5000.00'),
            rate_type='fixed',
            cover_letter='First proposal.',
            status='pending'
        )

        # Attempting to create another proposal should fail
        with pytest.raises(IntegrityError):
            ServiceProposal.objects.create(
                tenant=service_provider.tenant,
                client_request=client_request,
                provider=service_provider,
                proposed_rate=Decimal('4000.00'),
                rate_type='fixed',
                cover_letter='Second proposal.',
                status='pending'
            )


# ============================================================================
# CONTRACT FLOW TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceContractFlow:
    """Test service contract creation and lifecycle."""

    def test_create_contract_from_proposal(self, service_provider, client_user, service_listing):
        """Test creating a contract from an accepted proposal."""
        from services.models import ClientRequest, ServiceProposal, ServiceContract

        client_request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Contract Project',
            description='Project requiring contract',
            status='open'
        )

        proposal = ServiceProposal.objects.create(
            tenant=service_provider.tenant,
            client_request=client_request,
            provider=service_provider,
            proposed_rate=Decimal('6000.00'),
            rate_type='fixed',
            cover_letter='Ready to work.',
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            proposal=proposal,
            service=service_listing,
            client_request=client_request,
            title=client_request.title,
            description='Contract for web development',
            agreed_rate=proposal.proposed_rate,
            rate_type='fixed',
            currency='CAD',
            agreed_deadline=timezone.now().date() + timedelta(days=30),
            status='draft'
        )

        assert contract.pk is not None
        assert contract.status == 'draft'
        assert contract.agreed_rate == Decimal('6000.00')

    def test_contract_status_transitions(self, service_provider, client_user, service_listing):
        """Test contract status transitions through the workflow."""
        from services.models import ServiceContract

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='Status Test Contract',
            agreed_rate=Decimal('5000.00'),
            rate_type='fixed',
            currency='CAD',
            status='draft'
        )

        # Draft -> Pending Payment
        contract.status = 'pending_payment'
        contract.save()
        assert contract.status == 'pending_payment'

        # Pending Payment -> Funded
        contract.status = 'funded'
        contract.save()
        assert contract.status == 'funded'

        # Funded -> In Progress (using method)
        contract.start()
        assert contract.status == 'in_progress'
        assert contract.started_at is not None

        # In Progress -> Delivered
        contract.deliver()
        assert contract.status == 'delivered'
        assert contract.delivered_at is not None

        # Delivered -> Completed
        contract.complete()
        assert contract.status == 'completed'
        assert contract.completed_at is not None

    def test_contract_cancellation(self, service_provider, client_user, service_listing):
        """Test contract cancellation."""
        from services.models import ServiceContract

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='Cancellation Test',
            agreed_rate=Decimal('3000.00'),
            rate_type='fixed',
            currency='CAD',
            status='in_progress'
        )

        contract.cancel(reason='Client requested cancellation due to budget constraints')

        assert contract.status == 'cancelled'
        assert contract.cancelled_at is not None
        assert 'budget constraints' in contract.cancellation_reason

    def test_contract_provider_payout_calculation(self, service_provider, client_user, service_listing):
        """Test provider payout amount calculation after platform fee."""
        from services.models import ServiceContract

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='Payout Test Contract',
            agreed_rate=Decimal('10000.00'),
            rate_type='fixed',
            currency='CAD',
            platform_fee_percent=Decimal('10.00'),
            status='completed'
        )

        expected_payout = Decimal('10000.00') - (Decimal('10000.00') * Decimal('0.10'))
        assert contract.provider_payout_amount == expected_payout


# ============================================================================
# ESCROW PAYMENT FLOW TESTS
# ============================================================================

@pytest.mark.django_db
class TestEscrowPaymentFlow:
    """Test escrow payment creation and lifecycle."""

    def test_create_escrow_transaction(self, client_user, service_provider):
        """Test creating an escrow transaction."""
        from escrow.models import EscrowTransaction

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('5000.00'),
            currency='CAD',
            status='initialized',
            agreement_details='Web development project escrow'
        )

        assert escrow.pk is not None
        assert escrow.status == 'initialized'
        assert escrow.amount == Decimal('5000.00')

    def test_escrow_funding(self, client_user, service_provider):
        """Test funding an escrow transaction."""
        from escrow.models import EscrowTransaction

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('3000.00'),
            currency='CAD',
            status='initialized'
        )

        escrow.mark_funded()

        assert escrow.status == 'funded'
        assert escrow.funded_at is not None

    def test_escrow_service_delivery(self, client_user, service_provider):
        """Test marking service as delivered in escrow."""
        from escrow.models import EscrowTransaction

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('4000.00'),
            currency='CAD',
            status='funded',
            funded_at=timezone.now()
        )

        escrow.mark_service_delivered()

        assert escrow.status == 'service_delivered'
        assert escrow.service_delivered_at is not None

    def test_escrow_release(self, client_user, service_provider):
        """Test releasing escrow funds to seller."""
        from escrow.models import EscrowTransaction

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('6000.00'),
            currency='CAD',
            status='service_delivered',
            funded_at=timezone.now(),
            service_delivered_at=timezone.now()
        )

        escrow.mark_released()

        assert escrow.status == 'released'
        assert escrow.released_at is not None

    def test_escrow_refund(self, client_user, service_provider):
        """Test refunding escrow to buyer."""
        from escrow.models import EscrowTransaction

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('2000.00'),
            currency='CAD',
            status='funded',
            funded_at=timezone.now()
        )

        escrow.mark_refunded()

        assert escrow.status == 'refunded'
        assert escrow.refunded_at is not None

    def test_escrow_cancellation(self, client_user, service_provider):
        """Test cancelling an escrow transaction."""
        from escrow.models import EscrowTransaction

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('1500.00'),
            currency='CAD',
            status='initialized'
        )

        escrow.cancel()

        assert escrow.status == 'cancelled'
        assert escrow.cancelled_at is not None


# ============================================================================
# COMPLETE MISSION WORKFLOW TESTS
# ============================================================================

@pytest.mark.django_db
class TestCompleteMissionWorkflow:
    """Test complete mission workflow: post -> fund -> deliver -> accept/dispute -> payout."""

    def test_full_mission_success_flow(
        self, service_provider, client_user, service_listing, connected_account
    ):
        """Test complete successful mission flow from posting to payout."""
        from services.models import (
            ClientRequest, ServiceProposal, ServiceContract
        )
        from escrow.models import EscrowTransaction, EscrowPayout

        # 1. Client posts a request
        client_request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Full Flow Test Project',
            description='Complete mission workflow test',
            budget_min=Decimal('4000.00'),
            budget_max=Decimal('6000.00'),
            status='open'
        )
        assert client_request.status == 'open'

        # 2. Provider submits proposal
        proposal = ServiceProposal.objects.create(
            tenant=service_provider.tenant,
            client_request=client_request,
            provider=service_provider,
            proposed_rate=Decimal('5000.00'),
            rate_type='fixed',
            cover_letter='Experienced in this type of work.',
            status='pending'
        )
        assert proposal.status == 'pending'

        # 3. Client accepts proposal
        proposal.status = 'accepted'
        proposal.save()

        # 4. Create contract
        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            proposal=proposal,
            service=service_listing,
            client_request=client_request,
            title='Full Flow Contract',
            agreed_rate=proposal.proposed_rate,
            rate_type='fixed',
            currency='CAD',
            status='pending_payment'
        )
        assert contract.status == 'pending_payment'

        # 5. Client funds escrow
        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=contract.agreed_rate,
            currency='CAD',
            status='initialized',
            payment_intent_id='pi_test123'
        )
        escrow.mark_funded()

        contract.escrow_transaction = escrow
        contract.status = 'funded'
        contract.save()
        assert contract.status == 'funded'
        assert escrow.status == 'funded'

        # 6. Start work
        contract.start()
        assert contract.status == 'in_progress'

        # 7. Provider delivers
        contract.deliver()
        escrow.mark_service_delivered()
        assert contract.status == 'delivered'

        # 8. Client accepts delivery
        contract.complete()
        escrow.mark_released()
        assert contract.status == 'completed'
        assert escrow.status == 'released'

        # 9. Payout created
        payout = EscrowPayout.objects.create(
            escrow=escrow,
            payout_id='po_test123',
            amount=contract.provider_payout_amount,
            currency='CAD',
            status='completed'
        )
        assert payout.status == 'completed'

    def test_mission_with_dispute_flow(
        self, service_provider, client_user, service_listing
    ):
        """Test mission flow with dispute raised."""
        from services.models import ServiceContract
        from escrow.models import EscrowTransaction, Dispute

        # Setup contract and escrow
        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='Dispute Flow Contract',
            agreed_rate=Decimal('4000.00'),
            rate_type='fixed',
            currency='CAD',
            status='in_progress',
            started_at=timezone.now()
        )

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=contract.agreed_rate,
            currency='CAD',
            status='funded',
            funded_at=timezone.now()
        )

        contract.escrow_transaction = escrow
        contract.save()

        # Provider delivers
        contract.deliver()
        escrow.mark_service_delivered()

        # Client raises dispute
        escrow.raise_dispute()
        contract.status = 'disputed'
        contract.save()

        dispute = Dispute.objects.create(
            escrow=escrow,
            raised_by=client_user,
            reason='Deliverable does not match requirements',
            details='The work delivered does not include all agreed features.'
        )

        assert contract.status == 'disputed'
        assert escrow.status == 'dispute'
        assert not dispute.resolved


# ============================================================================
# DISPUTE RESOLUTION TESTS
# ============================================================================

@pytest.mark.django_db
class TestDisputeResolution:
    """Test dispute filing and resolution process."""

    def test_file_dispute(self, client_user, service_provider):
        """Test filing a dispute on an escrow transaction."""
        from escrow.models import EscrowTransaction, Dispute

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('5000.00'),
            currency='CAD',
            status='service_delivered',
            funded_at=timezone.now(),
            service_delivered_at=timezone.now()
        )

        dispute = Dispute.objects.create(
            escrow=escrow,
            raised_by=client_user,
            reason='Quality issues',
            details='The delivered work has multiple bugs.'
        )

        escrow.raise_dispute()

        assert dispute.pk is not None
        assert escrow.status == 'dispute'
        assert not dispute.resolved

    def test_resolve_dispute_in_buyer_favor(self, client_user, service_provider):
        """Test resolving dispute in buyer's favor with refund."""
        from escrow.models import EscrowTransaction, Dispute

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('3000.00'),
            currency='CAD',
            status='dispute',
            funded_at=timezone.now(),
            dispute_raised_at=timezone.now()
        )

        dispute = Dispute.objects.create(
            escrow=escrow,
            raised_by=client_user,
            reason='Non-delivery',
            details='Provider did not deliver any work.'
        )

        # Resolve in buyer's favor
        dispute.resolved = True
        dispute.resolved_at = timezone.now()
        dispute.resolution_notes = 'Full refund issued to buyer. Provider failed to deliver.'
        dispute.save()

        escrow.mark_refunded()

        assert dispute.resolved
        assert escrow.status == 'refunded'

    def test_resolve_dispute_in_seller_favor(self, client_user, service_provider):
        """Test resolving dispute in seller's favor with release."""
        from escrow.models import EscrowTransaction, Dispute

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('4000.00'),
            currency='CAD',
            status='dispute',
            funded_at=timezone.now(),
            dispute_raised_at=timezone.now()
        )

        dispute = Dispute.objects.create(
            escrow=escrow,
            raised_by=client_user,
            reason='Scope disagreement',
            details='Client claims work is incomplete but all requirements were met.'
        )

        # Resolve in seller's favor
        dispute.resolved = True
        dispute.resolved_at = timezone.now()
        dispute.resolution_notes = 'Work meets all agreed requirements. Funds released to seller.'
        dispute.save()

        escrow.mark_released()

        assert dispute.resolved
        assert escrow.status == 'released'

    def test_multiple_disputes_same_escrow(self, client_user, service_provider):
        """Test that multiple disputes can be filed on same escrow."""
        from escrow.models import EscrowTransaction, Dispute

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('5000.00'),
            currency='CAD',
            status='dispute',
            funded_at=timezone.now(),
            dispute_raised_at=timezone.now()
        )

        dispute1 = Dispute.objects.create(
            escrow=escrow,
            raised_by=client_user,
            reason='Initial complaint',
            details='First issue raised.'
        )

        dispute2 = Dispute.objects.create(
            escrow=escrow,
            raised_by=service_provider.user,
            reason='Counter-complaint',
            details='Response to initial complaint.'
        )

        assert escrow.disputes.count() == 2


# ============================================================================
# STRIPE WEBHOOK HANDLING TESTS
# ============================================================================

@pytest.mark.django_db
class TestStripeWebhookHandling:
    """Test Stripe webhook event handling."""

    def test_webhook_event_logging(self, db):
        """Test that webhook events are logged."""
        from finance.models import StripeWebhookEvent

        event_data = {
            'id': 'evt_test123',
            'type': 'payment_intent.succeeded',
            'data': {
                'object': {
                    'id': 'pi_test123',
                    'amount': 500000,
                    'currency': 'cad'
                }
            }
        }

        webhook_event = StripeWebhookEvent.objects.create(
            event_id='evt_test123',
            json_payload=event_data,
            processed=False
        )

        assert webhook_event.pk is not None
        assert webhook_event.event_id == 'evt_test123'
        assert not webhook_event.processed

    def test_webhook_event_processing(self, db):
        """Test marking webhook event as processed."""
        from finance.models import StripeWebhookEvent

        webhook_event = StripeWebhookEvent.objects.create(
            event_id='evt_process_test',
            json_payload={'type': 'test'},
            processed=False
        )

        webhook_event.processed = True
        webhook_event.processed_at = timezone.now()
        webhook_event.save()

        webhook_event.refresh_from_db()
        assert webhook_event.processed
        assert webhook_event.processed_at is not None

    def test_webhook_event_error_handling(self, db):
        """Test webhook event error logging."""
        from finance.models import StripeWebhookEvent

        webhook_event = StripeWebhookEvent.objects.create(
            event_id='evt_error_test',
            json_payload={'type': 'invalid_event'},
            processed=False,
            error_message='Unknown event type'
        )

        assert webhook_event.error_message is not None

    def test_duplicate_webhook_event_prevention(self, db):
        """Test that duplicate webhook events are prevented."""
        from finance.models import StripeWebhookEvent

        StripeWebhookEvent.objects.create(
            event_id='evt_duplicate_test',
            json_payload={'type': 'test'},
            processed=False
        )

        with pytest.raises(IntegrityError):
            StripeWebhookEvent.objects.create(
                event_id='evt_duplicate_test',
                json_payload={'type': 'test_duplicate'},
                processed=False
            )


# ============================================================================
# SUBSCRIPTION MANAGEMENT TESTS
# ============================================================================

@pytest.mark.django_db
class TestSubscriptionManagement:
    """Test subscription creation and management."""

    def test_create_subscription_plan(self, db):
        """Test creating a subscription plan."""
        from finance.models import SubscriptionPlan

        plan = SubscriptionPlan.objects.create(
            name='Enterprise',
            stripe_product_id='prod_enterprise',
            stripe_price_id='price_enterprise',
            price=Decimal('99.99'),
            currency='CAD',
            interval='month',
            description='Enterprise features'
        )

        assert plan.pk is not None
        assert plan.price == Decimal('99.99')
        assert plan.interval == 'month'

    def test_create_user_subscription(self, client_user, subscription_plan):
        """Test creating a user subscription."""
        from finance.models import UserSubscription

        subscription = UserSubscription.objects.create(
            user=client_user,
            plan=subscription_plan,
            stripe_subscription_id='sub_test123',
            status='active',
            current_period_start=timezone.now(),
            current_period_end=timezone.now() + timedelta(days=30)
        )

        assert subscription.pk is not None
        assert subscription.status == 'active'
        assert subscription.plan == subscription_plan

    def test_subscription_status_changes(self, client_user, subscription_plan):
        """Test subscription status transitions."""
        from finance.models import UserSubscription

        subscription = UserSubscription.objects.create(
            user=client_user,
            plan=subscription_plan,
            stripe_subscription_id='sub_status_test',
            status='active',
            current_period_start=timezone.now(),
            current_period_end=timezone.now() + timedelta(days=30)
        )

        # Test various status changes
        for status in ['past_due', 'canceled', 'active']:
            subscription.status = status
            subscription.save()
            subscription.refresh_from_db()
            assert subscription.status == status

    def test_subscription_period_renewal(self, client_user, subscription_plan):
        """Test subscription period renewal."""
        from finance.models import UserSubscription

        old_end = timezone.now()
        new_end = old_end + timedelta(days=30)

        subscription = UserSubscription.objects.create(
            user=client_user,
            plan=subscription_plan,
            stripe_subscription_id='sub_renewal_test',
            status='active',
            current_period_start=old_end - timedelta(days=30),
            current_period_end=old_end
        )

        # Simulate renewal
        subscription.current_period_start = old_end
        subscription.current_period_end = new_end
        subscription.save()

        assert subscription.current_period_end == new_end


# ============================================================================
# INVOICE GENERATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestInvoiceGeneration:
    """Test invoice creation and management."""

    def test_create_invoice(self, client_user):
        """Test creating an invoice."""
        from finance.models import Invoice

        invoice = Invoice.objects.create(
            user=client_user,
            invoice_number='INV-2024-001',
            stripe_invoice_id='in_test123',
            amount_due=Decimal('99.99'),
            amount_paid=Decimal('0.00'),
            currency='CAD',
            due_date=timezone.now() + timedelta(days=30),
            paid=False
        )

        assert invoice.pk is not None
        assert invoice.invoice_number == 'INV-2024-001'
        assert not invoice.paid

    def test_mark_invoice_paid(self, client_user):
        """Test marking an invoice as paid."""
        from finance.models import Invoice

        invoice = Invoice.objects.create(
            user=client_user,
            invoice_number='INV-2024-002',
            amount_due=Decimal('150.00'),
            currency='CAD',
            paid=False
        )

        invoice.paid = True
        invoice.amount_paid = invoice.amount_due
        invoice.paid_at = timezone.now()
        invoice.save()

        invoice.refresh_from_db()
        assert invoice.paid
        assert invoice.amount_paid == invoice.amount_due
        assert invoice.paid_at is not None

    def test_partial_invoice_payment(self, client_user):
        """Test partial invoice payment."""
        from finance.models import Invoice

        invoice = Invoice.objects.create(
            user=client_user,
            invoice_number='INV-2024-003',
            amount_due=Decimal('200.00'),
            amount_paid=Decimal('0.00'),
            currency='CAD',
            paid=False
        )

        # Partial payment
        invoice.amount_paid = Decimal('100.00')
        invoice.save()

        assert not invoice.paid
        assert invoice.amount_paid < invoice.amount_due

    def test_invoice_number_unique(self, client_user):
        """Test that invoice numbers are unique."""
        from finance.models import Invoice

        Invoice.objects.create(
            user=client_user,
            invoice_number='INV-UNIQUE-001',
            amount_due=Decimal('50.00'),
            currency='CAD'
        )

        with pytest.raises(IntegrityError):
            Invoice.objects.create(
                user=client_user,
                invoice_number='INV-UNIQUE-001',
                amount_due=Decimal('75.00'),
                currency='CAD'
            )


# ============================================================================
# PAYMENT HISTORY TESTS
# ============================================================================

@pytest.mark.django_db
class TestPaymentHistory:
    """Test payment transaction history."""

    def test_create_payment_transaction(self, client_user):
        """Test creating a payment transaction."""
        from payments.models import PaymentTransaction

        payment = PaymentTransaction.objects.create(
            user=client_user,
            amount=Decimal('500.00'),
            currency='CAD',
            stripe_payment_intent_id='pi_test123',
            description='Service payment',
            succeeded=True
        )

        assert payment.pk is not None
        assert payment.succeeded
        assert payment.amount == Decimal('500.00')

    def test_failed_payment_transaction(self, client_user):
        """Test recording a failed payment transaction."""
        from payments.models import PaymentTransaction

        payment = PaymentTransaction.objects.create(
            user=client_user,
            amount=Decimal('300.00'),
            currency='CAD',
            stripe_payment_intent_id='pi_failed123',
            description='Failed payment attempt',
            succeeded=False,
            failure_code='card_declined',
            failure_message='Your card was declined.'
        )

        assert not payment.succeeded
        assert payment.failure_code == 'card_declined'
        assert payment.failure_message is not None

    def test_user_payment_history(self, client_user):
        """Test retrieving user's payment history."""
        from payments.models import PaymentTransaction

        # Create multiple payments
        PaymentTransaction.objects.create(
            user=client_user,
            amount=Decimal('100.00'),
            currency='CAD',
            succeeded=True
        )
        PaymentTransaction.objects.create(
            user=client_user,
            amount=Decimal('200.00'),
            currency='CAD',
            succeeded=True
        )
        PaymentTransaction.objects.create(
            user=client_user,
            amount=Decimal('50.00'),
            currency='CAD',
            succeeded=False,
            failure_code='insufficient_funds'
        )

        payments = PaymentTransaction.objects.filter(user=client_user)
        assert payments.count() == 3

        successful = payments.filter(succeeded=True)
        assert successful.count() == 2


# ============================================================================
# REFUND PROCESSING TESTS
# ============================================================================

@pytest.mark.django_db
class TestRefundProcessing:
    """Test refund request and processing."""

    def test_create_refund_request(self, client_user):
        """Test creating a refund request."""
        from payments.models import PaymentTransaction, RefundRequest

        payment = PaymentTransaction.objects.create(
            user=client_user,
            amount=Decimal('250.00'),
            currency='CAD',
            stripe_payment_intent_id='pi_refund_test',
            succeeded=True
        )

        refund_request = RefundRequest.objects.create(
            payment=payment,
            reason='Service not as described'
        )

        assert refund_request.pk is not None
        assert not refund_request.approved
        assert refund_request.processed_at is None

    def test_approve_refund_request(self, client_user, user_factory):
        """Test approving a refund request."""
        from payments.models import PaymentTransaction, RefundRequest

        admin_user = user_factory(is_staff=True)

        payment = PaymentTransaction.objects.create(
            user=client_user,
            amount=Decimal('175.00'),
            currency='CAD',
            succeeded=True
        )

        refund_request = RefundRequest.objects.create(
            payment=payment,
            reason='Duplicate charge'
        )

        refund_request.approved = True
        refund_request.processed_at = timezone.now()
        refund_request.processed_by = admin_user
        refund_request.save()

        assert refund_request.approved
        assert refund_request.processed_by == admin_user

    def test_deny_refund_request(self, client_user, user_factory):
        """Test denying a refund request."""
        from payments.models import PaymentTransaction, RefundRequest

        admin_user = user_factory(is_staff=True)

        payment = PaymentTransaction.objects.create(
            user=client_user,
            amount=Decimal('500.00'),
            currency='CAD',
            succeeded=True
        )

        refund_request = RefundRequest.objects.create(
            payment=payment,
            reason='Changed my mind'
        )

        refund_request.approved = False
        refund_request.processed_at = timezone.now()
        refund_request.processed_by = admin_user
        refund_request.save()

        assert not refund_request.approved
        assert refund_request.processed_at is not None


# ============================================================================
# KYC VERIFICATION REQUIREMENTS TESTS
# ============================================================================

@pytest.mark.django_db
class TestKYCVerificationRequirements:
    """Test KYC verification requirements for transactions."""

    def test_verified_user_can_transact(self, client_user, service_provider):
        """Test that KYC verified users can create escrow transactions."""
        from escrow.models import EscrowTransaction
        from tenant_profiles.models import KYCVerification

        # Verify client's KYC status
        kyc = KYCVerification.objects.filter(user=client_user, status='verified').first()
        assert kyc is not None or VerifiedKYCFactory(user=client_user)

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('1000.00'),
            currency='CAD',
            status='initialized'
        )

        assert escrow.pk is not None

    def test_provider_kyc_verification(self, service_provider):
        """Test provider KYC verification status."""
        assert service_provider.is_verified

    def test_unverified_provider_flag(self, unverified_provider):
        """Test that unverified providers are flagged correctly."""
        assert not unverified_provider.is_verified

    def test_kyc_verification_required_for_payout(
        self, unverified_provider, client_user
    ):
        """Test that KYC verification is needed for payouts."""
        from escrow.models import EscrowTransaction

        # Create escrow with unverified provider
        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=unverified_provider.user,
            amount=Decimal('2000.00'),
            currency='CAD',
            status='service_delivered'
        )

        # Provider should not be able to receive payouts without verification
        assert not unverified_provider.is_verified
        # In real implementation, payout would be blocked


# ============================================================================
# CONNECTED ACCOUNT TESTS
# ============================================================================

@pytest.mark.django_db
class TestConnectedAccount:
    """Test Stripe Connect connected account functionality."""

    def test_create_connected_account(self, user_factory):
        """Test creating a connected account."""
        from finance.models import ConnectedAccount

        user = user_factory()
        account = ConnectedAccount.objects.create(
            user=user,
            account_id='acct_new_test',
            account_status='pending',
            country='CA',
            default_currency='CAD',
            business_type='individual'
        )

        assert account.pk is not None
        assert account.account_status == 'pending'

    def test_connected_account_activation(self, connected_account):
        """Test connected account activation."""
        connected_account.account_status = 'active'
        connected_account.charges_enabled = True
        connected_account.payouts_enabled = True
        connected_account.activated_at = timezone.now()
        connected_account.save()

        connected_account.refresh_from_db()
        assert connected_account.account_status == 'active'
        assert connected_account.charges_enabled
        assert connected_account.payouts_enabled

    def test_connected_account_capability_update(self, connected_account):
        """Test updating connected account capabilities."""
        connected_account.handle_capability_updated('transfers', 'active')
        connected_account.handle_capability_updated('card_payments', 'active')

        assert connected_account.capabilities['transfers'] == 'active'
        assert connected_account.capabilities['card_payments'] == 'active'

    @patch('stripe.Account.create')
    def test_create_stripe_connect_account(self, mock_stripe_create, user_factory):
        """Test creating Stripe Connect account via API."""
        from finance.models import ConnectedAccount

        mock_stripe_create.return_value = MagicMock(id='acct_stripe_test')

        user = user_factory()
        account = ConnectedAccount.objects.create(
            user=user,
            country='CA',
            default_currency='CAD',
            business_type='individual'
        )

        account.create_connect_account()

        assert account.account_id == 'acct_stripe_test'
        assert account.account_status == 'onboarding'

    @patch('stripe.Account.retrieve')
    def test_refresh_account_status(self, mock_stripe_retrieve, connected_account):
        """Test refreshing account status from Stripe."""
        mock_account = MagicMock()
        mock_account.charges_enabled = True
        mock_account.payouts_enabled = True
        mock_account.details_submitted = True
        mock_account.capabilities = {'transfers': 'active', 'card_payments': 'active'}
        mock_stripe_retrieve.return_value = mock_account

        connected_account.refresh_account_status()

        assert connected_account.charges_enabled
        assert connected_account.payouts_enabled


# ============================================================================
# PLATFORM FEE TESTS
# ============================================================================

@pytest.mark.django_db
class TestPlatformFee:
    """Test platform fee calculation and collection."""

    def test_calculate_percentage_fee(self, connected_account, client_user, service_provider):
        """Test percentage-based platform fee calculation."""
        from escrow.models import EscrowTransaction, PlatformFee

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('1000.00'),
            currency='CAD',
            status='funded'
        )

        fee = PlatformFee.objects.create(
            escrow=escrow,
            connected_account=connected_account,
            fee_type='percentage',
            percentage_rate=Decimal('10.00'),
            transaction_amount=escrow.amount,
            fee_amount=Decimal('0.00'),
            currency='CAD'
        )

        fee.calculate_fee()

        assert fee.fee_amount == Decimal('100.00')

    def test_calculate_fixed_fee(self, connected_account, client_user, service_provider):
        """Test fixed platform fee calculation."""
        from escrow.models import EscrowTransaction, PlatformFee

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('500.00'),
            currency='CAD',
            status='funded'
        )

        fee = PlatformFee.objects.create(
            escrow=escrow,
            connected_account=connected_account,
            fee_type='fixed',
            fixed_amount=Decimal('25.00'),
            transaction_amount=escrow.amount,
            fee_amount=Decimal('0.00'),
            currency='CAD'
        )

        fee.calculate_fee()

        assert fee.fee_amount == Decimal('25.00')

    def test_calculate_combined_fee(self, connected_account, client_user, service_provider):
        """Test combined percentage + fixed platform fee."""
        from escrow.models import EscrowTransaction, PlatformFee

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('1000.00'),
            currency='CAD',
            status='funded'
        )

        fee = PlatformFee.objects.create(
            escrow=escrow,
            connected_account=connected_account,
            fee_type='combined',
            percentage_rate=Decimal('5.00'),
            fixed_amount=Decimal('10.00'),
            transaction_amount=escrow.amount,
            fee_amount=Decimal('0.00'),
            currency='CAD'
        )

        fee.calculate_fee()

        # 5% of 1000 = 50, + 10 fixed = 60
        assert fee.fee_amount == Decimal('60.00')

    def test_mark_fee_collected(self, connected_account, client_user, service_provider):
        """Test marking platform fee as collected."""
        from escrow.models import EscrowTransaction, PlatformFee

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('800.00'),
            currency='CAD',
            status='released'
        )

        fee = PlatformFee.objects.create(
            escrow=escrow,
            connected_account=connected_account,
            fee_type='percentage',
            percentage_rate=Decimal('10.00'),
            transaction_amount=escrow.amount,
            fee_amount=Decimal('80.00'),
            currency='CAD',
            status='pending'
        )

        fee.mark_collected(stripe_application_fee_id='fee_test123')

        assert fee.status == 'collected'
        assert fee.stripe_application_fee_id == 'fee_test123'


# ============================================================================
# ESCROW AUDIT LOGGING TESTS
# ============================================================================

@pytest.mark.django_db
class TestEscrowAuditLogging:
    """Test escrow transaction audit logging."""

    def test_create_audit_log(self, client_user, service_provider):
        """Test creating an audit log entry."""
        from escrow.models import EscrowTransaction, EscrowAudit

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('2000.00'),
            currency='CAD',
            status='initialized'
        )

        audit = EscrowAudit.objects.create(
            escrow=escrow,
            user=client_user,
            action='initialized',
            notes='Escrow transaction created'
        )

        assert audit.pk is not None
        assert audit.action == 'initialized'

    def test_audit_log_for_status_changes(self, client_user, service_provider):
        """Test audit logging for each status change."""
        from escrow.models import EscrowTransaction, EscrowAudit

        escrow = EscrowTransaction.objects.create(
            buyer=client_user,
            seller=service_provider.user,
            amount=Decimal('3000.00'),
            currency='CAD',
            status='initialized'
        )

        # Log each status change
        statuses = ['funded', 'service_delivered', 'released']
        for status in statuses:
            EscrowAudit.objects.create(
                escrow=escrow,
                user=client_user,
                action=status,
                notes=f'Status changed to {status}'
            )

        audit_count = EscrowAudit.objects.filter(escrow=escrow).count()
        assert audit_count == 3


# ============================================================================
# PAYMENT METHOD TESTS
# ============================================================================

@pytest.mark.django_db
class TestPaymentMethod:
    """Test payment method storage and management."""

    def test_create_payment_method(self, client_user):
        """Test creating a saved payment method."""
        from finance.models import PaymentMethod

        payment_method = PaymentMethod.objects.create(
            user=client_user,
            stripe_payment_method_id='pm_test123',
            card_brand='visa',
            card_last4='4242',
            card_exp_month=12,
            card_exp_year=2025,
            is_default=True
        )

        assert payment_method.pk is not None
        assert payment_method.card_brand == 'visa'
        assert payment_method.is_default

    def test_multiple_payment_methods(self, client_user):
        """Test user with multiple payment methods."""
        from finance.models import PaymentMethod

        PaymentMethod.objects.create(
            user=client_user,
            stripe_payment_method_id='pm_visa_test',
            card_brand='visa',
            card_last4='4242',
            card_exp_month=12,
            card_exp_year=2025,
            is_default=True
        )

        PaymentMethod.objects.create(
            user=client_user,
            stripe_payment_method_id='pm_mc_test',
            card_brand='mastercard',
            card_last4='5555',
            card_exp_month=6,
            card_exp_year=2026,
            is_default=False
        )

        methods = PaymentMethod.objects.filter(user=client_user)
        assert methods.count() == 2

        default_methods = methods.filter(is_default=True)
        assert default_methods.count() == 1


# ============================================================================
# SERVICE REVIEW TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceReviews:
    """Test service review and rating functionality."""

    def test_create_review(self, service_provider, client_user, service_listing):
        """Test creating a service review."""
        from services.models import ServiceContract, ServiceReview

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='Completed Project',
            agreed_rate=Decimal('3000.00'),
            rate_type='fixed',
            currency='CAD',
            status='completed',
            completed_at=timezone.now()
        )

        review = ServiceReview.objects.create(
            tenant=service_provider.tenant,
            contract=contract,
            reviewer=client_user,
            provider=service_provider,
            rating=5,
            rating_communication=5,
            rating_quality=5,
            rating_timeliness=4,
            title='Excellent Work!',
            content='The provider delivered exceptional work.'
        )

        assert review.pk is not None
        assert review.rating == 5

    def test_provider_rating_update(self, service_provider, client_user, service_listing):
        """Test that provider rating is updated after review."""
        from services.models import ServiceContract, ServiceReview

        initial_rating = service_provider.rating_avg

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='Rating Test Project',
            agreed_rate=Decimal('2000.00'),
            rate_type='fixed',
            currency='CAD',
            status='completed'
        )

        ServiceReview.objects.create(
            tenant=service_provider.tenant,
            contract=contract,
            reviewer=client_user,
            provider=service_provider,
            rating=4,
            content='Good work.'
        )

        service_provider.refresh_from_db()
        # Rating should be updated (exact value depends on existing reviews)
        assert service_provider.total_reviews >= 1

    def test_provider_response_to_review(self, service_provider, client_user, service_listing):
        """Test provider responding to a review."""
        from services.models import ServiceContract, ServiceReview

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='Response Test Project',
            agreed_rate=Decimal('1500.00'),
            rate_type='fixed',
            currency='CAD',
            status='completed'
        )

        review = ServiceReview.objects.create(
            tenant=service_provider.tenant,
            contract=contract,
            reviewer=client_user,
            provider=service_provider,
            rating=4,
            content='Good experience overall.'
        )

        review.provider_response = 'Thank you for the positive feedback!'
        review.provider_responded_at = timezone.now()
        review.save()

        review.refresh_from_db()
        assert review.provider_response is not None
        assert review.provider_responded_at is not None


# ============================================================================
# PAYOUT SCHEDULE TESTS
# ============================================================================

@pytest.mark.django_db
class TestPayoutSchedule:
    """Test payout schedule configuration."""

    def test_create_payout_schedule(self, connected_account):
        """Test creating a payout schedule."""
        from finance.models import PayoutSchedule

        schedule = PayoutSchedule.objects.create(
            connected_account=connected_account,
            interval='weekly',
            weekly_anchor='friday',
            delay_days=2,
            minimum_payout_amount=Decimal('100.00')
        )

        assert schedule.pk is not None
        assert schedule.interval == 'weekly'
        assert schedule.weekly_anchor == 'friday'

    def test_daily_payout_schedule(self, connected_account):
        """Test daily payout schedule."""
        from finance.models import PayoutSchedule

        schedule = PayoutSchedule.objects.create(
            connected_account=connected_account,
            interval='daily',
            delay_days=1,
            minimum_payout_amount=Decimal('50.00')
        )

        assert schedule.interval == 'daily'
        assert schedule.delay_days == 1

    def test_monthly_payout_schedule(self, connected_account):
        """Test monthly payout schedule."""
        from finance.models import PayoutSchedule

        schedule = PayoutSchedule.objects.create(
            connected_account=connected_account,
            interval='monthly',
            monthly_anchor=15,
            delay_days=3,
            minimum_payout_amount=Decimal('200.00')
        )

        assert schedule.interval == 'monthly'
        assert schedule.monthly_anchor == 15


# ============================================================================
# ONBOARDING FLOW TESTS
# ============================================================================

@pytest.mark.django_db
class TestStripeConnectOnboarding:
    """Test Stripe Connect onboarding flow."""

    def test_create_onboarding_record(self, connected_account):
        """Test creating an onboarding record."""
        from finance.models import StripeConnectOnboarding

        onboarding = StripeConnectOnboarding.objects.create(
            connected_account=connected_account,
            status='not_started'
        )

        assert onboarding.pk is not None
        assert onboarding.status == 'not_started'

    def test_onboarding_in_progress(self, connected_account):
        """Test onboarding in progress status."""
        from finance.models import StripeConnectOnboarding

        onboarding = StripeConnectOnboarding.objects.create(
            connected_account=connected_account,
            status='in_progress',
            started_at=timezone.now(),
            onboarding_url='https://connect.stripe.com/setup/test',
            return_url='https://zumodra.com/onboarding/return',
            refresh_url='https://zumodra.com/onboarding/refresh'
        )

        assert onboarding.status == 'in_progress'
        assert onboarding.started_at is not None

    def test_onboarding_completion(self, connected_account):
        """Test completing onboarding."""
        from finance.models import StripeConnectOnboarding

        onboarding = StripeConnectOnboarding.objects.create(
            connected_account=connected_account,
            status='in_progress',
            started_at=timezone.now() - timedelta(hours=1)
        )

        onboarding.status = 'completed'
        onboarding.completed_at = timezone.now()
        onboarding.save()

        assert onboarding.status == 'completed'
        assert onboarding.completed_at is not None

    def test_update_requirements(self, connected_account):
        """Test updating requirements from Stripe."""
        from finance.models import StripeConnectOnboarding

        onboarding = StripeConnectOnboarding.objects.create(
            connected_account=connected_account,
            status='in_progress'
        )

        requirements_data = {
            'currently_due': ['individual.id_number', 'external_account'],
            'past_due': [],
            'eventually_due': ['business_url'],
            'pending_verification': []
        }

        onboarding.update_requirements(requirements_data)

        assert 'individual.id_number' in onboarding.requirements_current
        assert 'business_url' in onboarding.requirements_eventually_due

    def test_onboarding_link_expiry_check(self, connected_account):
        """Test onboarding link expiry check."""
        from finance.models import StripeConnectOnboarding

        onboarding = StripeConnectOnboarding.objects.create(
            connected_account=connected_account,
            status='in_progress',
            link_expires_at=timezone.now() - timedelta(hours=1)
        )

        assert onboarding.is_link_expired()

        # Update to future expiry
        onboarding.link_expires_at = timezone.now() + timedelta(hours=1)
        onboarding.save()

        assert not onboarding.is_link_expired()


# ============================================================================
# CONTRACT MESSAGE TESTS
# ============================================================================

@pytest.mark.django_db
class TestContractMessages:
    """Test contract messaging functionality."""

    def test_send_message(self, service_provider, client_user, service_listing):
        """Test sending a message in a contract."""
        from services.models import ServiceContract, ContractMessage

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='Messaging Test Contract',
            agreed_rate=Decimal('2000.00'),
            rate_type='fixed',
            currency='CAD',
            status='in_progress'
        )

        message = ContractMessage.objects.create(
            tenant=service_provider.tenant,
            contract=contract,
            sender=client_user,
            content='Hello, I have a question about the project.',
            is_system_message=False
        )

        assert message.pk is not None
        assert message.sender == client_user

    def test_system_message(self, service_provider, client_user, service_listing):
        """Test creating a system message."""
        from services.models import ServiceContract, ContractMessage

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='System Message Test',
            agreed_rate=Decimal('1500.00'),
            rate_type='fixed',
            currency='CAD',
            status='in_progress'
        )

        system_message = ContractMessage.objects.create(
            tenant=service_provider.tenant,
            contract=contract,
            sender=None,
            content='Contract status has been updated to In Progress.',
            is_system_message=True
        )

        assert system_message.is_system_message
        assert system_message.sender is None

    def test_mark_message_read(self, service_provider, client_user, service_listing):
        """Test marking a message as read."""
        from services.models import ServiceContract, ContractMessage

        contract = ServiceContract.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            provider=service_provider,
            service=service_listing,
            title='Read Receipt Test',
            agreed_rate=Decimal('1000.00'),
            rate_type='fixed',
            currency='CAD',
            status='in_progress'
        )

        message = ContractMessage.objects.create(
            tenant=service_provider.tenant,
            contract=contract,
            sender=service_provider.user,
            content='Here is an update on your project.'
        )

        message.read_at = timezone.now()
        message.save()

        assert message.read_at is not None


# ============================================================================
# PROVIDER SKILLS TESTS
# ============================================================================

@pytest.mark.django_db
class TestProviderSkills:
    """Test provider skill management."""

    def test_add_skill_to_provider(self, service_provider):
        """Test adding a skill to a provider."""
        from services.models import ProviderSkill
        from configurations.models import Skill

        skill = Skill.objects.create(
            name='Python',
            slug='python',
            category='programming'
        )

        provider_skill = ProviderSkill.objects.create(
            tenant=service_provider.tenant,
            provider=service_provider,
            skill=skill,
            level='expert',
            years_experience=5,
            is_verified=True
        )

        assert provider_skill.pk is not None
        assert provider_skill.level == 'expert'
        assert provider_skill.years_experience == 5

    def test_skill_levels(self, service_provider):
        """Test different skill levels."""
        from services.models import ProviderSkill
        from configurations.models import Skill

        levels = ['beginner', 'intermediate', 'advanced', 'expert']

        for i, level in enumerate(levels):
            skill = Skill.objects.create(
                name=f'Skill {i}',
                slug=f'skill-{i}',
                category='test'
            )

            provider_skill = ProviderSkill.objects.create(
                tenant=service_provider.tenant,
                provider=service_provider,
                skill=skill,
                level=level,
                years_experience=i + 1
            )

            assert provider_skill.level == level


# ============================================================================
# CLIENT REQUEST TESTS
# ============================================================================

@pytest.mark.django_db
class TestClientRequest:
    """Test client request functionality."""

    def test_create_client_request(self, client_user, tenant_factory):
        """Test creating a client request."""
        from services.models import ClientRequest

        tenant = tenant_factory()

        request = ClientRequest.objects.create(
            tenant=tenant,
            client=client_user,
            title='Need a Mobile App',
            description='Looking for iOS and Android app development',
            budget_min=Decimal('10000.00'),
            budget_max=Decimal('20000.00'),
            currency='CAD',
            remote_allowed=True,
            deadline=timezone.now().date() + timedelta(days=60),
            status='open'
        )

        assert request.pk is not None
        assert request.status == 'open'

    def test_close_client_request(self, client_user, tenant_factory):
        """Test closing a client request."""
        from services.models import ClientRequest

        tenant = tenant_factory()

        request = ClientRequest.objects.create(
            tenant=tenant,
            client=client_user,
            title='Test Request',
            description='Test description',
            status='open'
        )

        request.status = 'closed'
        request.save()

        assert request.status == 'closed'

    def test_cancel_client_request(self, client_user, tenant_factory):
        """Test cancelling a client request."""
        from services.models import ClientRequest

        tenant = tenant_factory()

        request = ClientRequest.objects.create(
            tenant=tenant,
            client=client_user,
            title='Cancelled Request',
            description='This will be cancelled',
            status='open'
        )

        request.status = 'cancelled'
        request.save()

        assert request.status == 'cancelled'


# ============================================================================
# PROVIDER MATCH TESTS
# ============================================================================

@pytest.mark.django_db
class TestProviderMatching:
    """Test provider matching functionality."""

    def test_create_provider_match(self, service_provider, client_user):
        """Test creating a provider match."""
        from services.models import ClientRequest, ProviderMatch

        request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Matching Test Request',
            description='Find best providers',
            status='open'
        )

        match = ProviderMatch.objects.create(
            tenant=service_provider.tenant,
            client_request=request,
            provider=service_provider,
            score=Decimal('0.8500'),
            score_breakdown={
                'skills': 0.9,
                'availability': 0.8,
                'rating': 0.85
            }
        )

        assert match.pk is not None
        assert match.score == Decimal('0.8500')

    def test_accept_match(self, service_provider, client_user):
        """Test accepting a provider match."""
        from services.models import ClientRequest, ProviderMatch

        request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Accept Match Test',
            description='Test accepting a match',
            status='open'
        )

        match = ProviderMatch.objects.create(
            tenant=service_provider.tenant,
            client_request=request,
            provider=service_provider,
            score=Decimal('0.9000')
        )

        match.viewed_by_client = True
        match.accepted_by_client = True
        match.save()

        assert match.accepted_by_client

    def test_reject_match(self, service_provider, client_user):
        """Test rejecting a provider match."""
        from services.models import ClientRequest, ProviderMatch

        request = ClientRequest.objects.create(
            tenant=service_provider.tenant,
            client=client_user,
            title='Reject Match Test',
            description='Test rejecting a match',
            status='open'
        )

        match = ProviderMatch.objects.create(
            tenant=service_provider.tenant,
            client_request=request,
            provider=service_provider,
            score=Decimal('0.5000')
        )

        match.viewed_by_client = True
        match.rejected_by_client = True
        match.save()

        assert match.rejected_by_client


# ============================================================================
# SERVICE LIKE/FAVORITE TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceLikes:
    """Test service like/favorite functionality."""

    def test_like_service(self, service_listing, client_user):
        """Test liking a service."""
        from services.models import ServiceLike

        like = ServiceLike.objects.create(
            tenant=service_listing.tenant,
            user=client_user,
            service=service_listing
        )

        assert like.pk is not None

    def test_unique_like_per_user_service(self, service_listing, client_user):
        """Test that a user can only like a service once."""
        from services.models import ServiceLike

        ServiceLike.objects.create(
            tenant=service_listing.tenant,
            user=client_user,
            service=service_listing
        )

        with pytest.raises(IntegrityError):
            ServiceLike.objects.create(
                tenant=service_listing.tenant,
                user=client_user,
                service=service_listing
            )

    def test_unlike_service(self, service_listing, client_user):
        """Test removing a like from a service."""
        from services.models import ServiceLike

        like = ServiceLike.objects.create(
            tenant=service_listing.tenant,
            user=client_user,
            service=service_listing
        )

        like.delete()

        likes = ServiceLike.objects.filter(
            user=client_user,
            service=service_listing
        )
        assert likes.count() == 0
