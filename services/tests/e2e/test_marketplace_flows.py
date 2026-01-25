"""
Marketplace & Escrow Flow Tests for Zumodra

Tests the complete service marketplace workflow including:
- Service listings and proposals
- Contract creation and management
- Escrow funding, milestones, and payouts
- Disputes and resolutions
"""

import pytest
from datetime import timedelta
from decimal import Decimal
from django.utils import timezone
from unittest.mock import patch, MagicMock

from conftest import (
    UserFactory, TenantFactory, PlanFactory, TenantUserFactory
)


# ============================================================================
# TEST FIXTURES - Service Marketplace Factories
# ============================================================================

@pytest.fixture
def service_category(db):
    """Create a service category."""
    from services.models import ServiceCategory

    return ServiceCategory.objects.create(
        name='Web Development',
        slug='web-development',
        description='Web development services',
        is_active=True
    )


@pytest.fixture
def service_provider(db, user_factory):
    """Create a service provider user with profile."""
    user = user_factory()
    from services.models import ServiceProvider

    provider = ServiceProvider.objects.create(
        user=user,
        business_name='Pro Dev Services',
        tagline='Quality web development',
        description='Full stack development services',
        hourly_rate=Decimal('75.00'),
        is_verified=True,
        is_active=True
    )
    return provider


@pytest.fixture
def service_listing(db, service_provider, service_category):
    """Create a service listing."""
    from services.models import ServiceListing

    return ServiceListing.objects.create(
        provider=service_provider,
        category=service_category,
        title='Custom Web Application Development',
        description='Build custom web applications',
        price=Decimal('5000.00'),
        price_type='fixed',
        delivery_time_days=30,
        is_active=True,
        is_featured=False
    )


@pytest.fixture
def client_user(db, user_factory):
    """Create a client user."""
    return user_factory(email='client@example.com')


# ============================================================================
# SERVICE LISTING TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceListings:
    """Test service listing creation and management."""

    def test_create_service_listing(self, service_provider, service_category):
        """Test creating a new service listing."""
        from services.models import ServiceListing

        listing = ServiceListing.objects.create(
            provider=service_provider,
            category=service_category,
            title='Mobile App Development',
            description='Cross-platform mobile app development',
            price=Decimal('8000.00'),
            price_type='fixed',
            delivery_time_days=45
        )

        assert listing.pk is not None
        assert listing.title == 'Mobile App Development'
        assert listing.price == Decimal('8000.00')

    def test_service_listing_pricing_types(self, service_provider, service_category):
        """Test different pricing types for services."""
        from services.models import ServiceListing

        # Fixed price listing
        fixed_listing = ServiceListing.objects.create(
            provider=service_provider,
            category=service_category,
            title='Logo Design',
            price=Decimal('500.00'),
            price_type='fixed',
            delivery_time_days=7
        )

        # Hourly rate listing
        hourly_listing = ServiceListing.objects.create(
            provider=service_provider,
            category=service_category,
            title='Consulting',
            price=Decimal('100.00'),
            price_type='hourly',
            delivery_time_days=0
        )

        assert fixed_listing.price_type == 'fixed'
        assert hourly_listing.price_type == 'hourly'


# ============================================================================
# PROPOSAL FLOW TESTS
# ============================================================================

@pytest.mark.django_db
class TestProposalFlow:
    """Test service proposal creation and management."""

    def test_create_proposal(self, service_listing, client_user):
        """Test creating a proposal from provider to client."""
        from services.models import ServiceProposal

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Custom E-commerce Platform',
            description='Build a custom e-commerce platform',
            price=Decimal('7500.00'),
            estimated_delivery_days=45,
            status='pending'
        )

        assert proposal.pk is not None
        assert proposal.status == 'pending'
        assert proposal.price == Decimal('7500.00')

    def test_accept_proposal(self, service_listing, client_user):
        """Test client accepting a proposal."""
        from services.models import ServiceProposal

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Web App Development',
            price=Decimal('6000.00'),
            estimated_delivery_days=30,
            status='pending'
        )

        # Client accepts
        proposal.status = 'accepted'
        proposal.accepted_at = timezone.now()
        proposal.save()

        assert proposal.status == 'accepted'
        assert proposal.accepted_at is not None

    def test_decline_proposal(self, service_listing, client_user):
        """Test client declining a proposal."""
        from services.models import ServiceProposal

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Web App Development',
            price=Decimal('6000.00'),
            estimated_delivery_days=30,
            status='pending'
        )

        proposal.status = 'declined'
        proposal.declined_at = timezone.now()
        proposal.save()

        assert proposal.status == 'declined'

    def test_proposal_revision(self, service_listing, client_user):
        """Test revising a proposal after client feedback."""
        from services.models import ServiceProposal

        # Initial proposal
        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Web App Development',
            price=Decimal('8000.00'),
            estimated_delivery_days=30,
            status='pending'
        )

        # Client requests revision
        proposal.status = 'revision_requested'
        proposal.save()

        # Provider revises
        proposal.price = Decimal('7000.00')
        proposal.status = 'pending'
        proposal.revision_count = 1
        proposal.save()

        assert proposal.price == Decimal('7000.00')
        assert proposal.revision_count == 1


# ============================================================================
# CONTRACT AND ESCROW TESTS
# ============================================================================

@pytest.mark.django_db
class TestContractFlow:
    """Test service contract creation and lifecycle."""

    def test_create_contract_from_proposal(self, service_listing, client_user):
        """Test creating a contract from an accepted proposal."""
        from services.models import ServiceProposal, ServiceContract

        # Create and accept proposal
        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Web App Development',
            price=Decimal('6000.00'),
            estimated_delivery_days=30,
            status='accepted'
        )

        # Create contract
        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title=proposal.title,
            description=proposal.description or 'Custom web development project',
            total_amount=proposal.price,
            currency='CAD',
            start_date=timezone.now().date(),
            expected_end_date=timezone.now().date() + timedelta(days=30),
            status='pending_funding'
        )

        assert contract.pk is not None
        assert contract.status == 'pending_funding'
        assert contract.total_amount == Decimal('6000.00')

    def test_fund_contract_escrow(self, service_listing, client_user):
        """Test funding a contract through escrow."""
        from services.models import ServiceProposal, ServiceContract, EscrowTransaction

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            price=Decimal('5000.00'),
            estimated_delivery_days=30,
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            total_amount=proposal.price,
            currency='CAD',
            status='pending_funding'
        )

        # Fund escrow
        escrow = EscrowTransaction.objects.create(
            contract=contract,
            amount=contract.total_amount,
            currency='CAD',
            transaction_type='deposit',
            status='completed',
            funded_by=client_user,
            funded_at=timezone.now()
        )

        contract.status = 'active'
        contract.funded_at = timezone.now()
        contract.save()

        assert escrow.status == 'completed'
        assert contract.status == 'active'

    def test_contract_milestone_completion(self, service_listing, client_user):
        """Test milestone-based contract completion."""
        from services.models import ServiceProposal, ServiceContract, ContractMilestone

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Milestone Project',
            price=Decimal('9000.00'),
            estimated_delivery_days=60,
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title='Milestone Project',
            total_amount=proposal.price,
            currency='CAD',
            status='active'
        )

        # Create milestones
        milestone1 = ContractMilestone.objects.create(
            contract=contract,
            title='Design Phase',
            description='Complete UI/UX design',
            amount=Decimal('3000.00'),
            due_date=timezone.now().date() + timedelta(days=20),
            order=1,
            status='pending'
        )

        milestone2 = ContractMilestone.objects.create(
            contract=contract,
            title='Development Phase',
            description='Complete development',
            amount=Decimal('6000.00'),
            due_date=timezone.now().date() + timedelta(days=50),
            order=2,
            status='pending'
        )

        # Complete first milestone
        milestone1.status = 'completed'
        milestone1.completed_at = timezone.now()
        milestone1.save()

        assert milestone1.status == 'completed'
        assert milestone2.status == 'pending'


# ============================================================================
# ESCROW PAYOUT TESTS
# ============================================================================

@pytest.mark.django_db
class TestEscrowPayout:
    """Test escrow release and payout functionality."""

    def test_release_escrow_on_completion(self, service_listing, client_user):
        """Test releasing escrow funds when contract completes."""
        from services.models import (
            ServiceProposal, ServiceContract, EscrowTransaction
        )

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            price=Decimal('5000.00'),
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            total_amount=proposal.price,
            currency='CAD',
            status='active'
        )

        # Initial funding
        deposit = EscrowTransaction.objects.create(
            contract=contract,
            amount=contract.total_amount,
            currency='CAD',
            transaction_type='deposit',
            status='completed',
            funded_by=client_user
        )

        # Complete contract
        contract.status = 'completed'
        contract.completed_at = timezone.now()
        contract.save()

        # Release escrow
        release = EscrowTransaction.objects.create(
            contract=contract,
            amount=contract.total_amount,
            currency='CAD',
            transaction_type='release',
            status='completed',
            released_to=service_listing.provider.user,
            released_at=timezone.now()
        )

        assert release.status == 'completed'
        assert release.transaction_type == 'release'

    def test_partial_release_for_milestone(self, service_listing, client_user):
        """Test partial escrow release for milestone completion."""
        from services.models import (
            ServiceProposal, ServiceContract, ContractMilestone, EscrowTransaction
        )

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Milestone Project',
            price=Decimal('9000.00'),
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title='Milestone Project',
            total_amount=proposal.price,
            currency='CAD',
            status='active'
        )

        milestone = ContractMilestone.objects.create(
            contract=contract,
            title='Phase 1',
            amount=Decimal('3000.00'),
            order=1,
            status='pending'
        )

        # Complete milestone
        milestone.status = 'completed'
        milestone.completed_at = timezone.now()
        milestone.save()

        # Partial release
        partial_release = EscrowTransaction.objects.create(
            contract=contract,
            milestone=milestone,
            amount=milestone.amount,
            currency='CAD',
            transaction_type='partial_release',
            status='completed',
            released_at=timezone.now()
        )

        assert partial_release.amount == Decimal('3000.00')
        assert partial_release.transaction_type == 'partial_release'


# ============================================================================
# DISPUTE RESOLUTION TESTS
# ============================================================================

@pytest.mark.django_db
class TestDisputeFlow:
    """Test dispute filing and resolution process."""

    def test_file_dispute(self, service_listing, client_user):
        """Test filing a dispute on a contract."""
        from services.models import (
            ServiceProposal, ServiceContract, ServiceDispute
        )

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            price=Decimal('5000.00'),
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            total_amount=proposal.price,
            currency='CAD',
            status='active'
        )

        # File dispute
        dispute = ServiceDispute.objects.create(
            contract=contract,
            filed_by=client_user,
            reason='Work not delivered as specified',
            description='The delivered work does not match the agreed specifications',
            status='open',
            disputed_amount=Decimal('2000.00')
        )

        contract.status = 'disputed'
        contract.save()

        assert dispute.pk is not None
        assert dispute.status == 'open'
        assert contract.status == 'disputed'

    def test_resolve_dispute_in_client_favor(self, service_listing, client_user):
        """Test resolving dispute in client's favor with refund."""
        from services.models import (
            ServiceProposal, ServiceContract, ServiceDispute, EscrowTransaction
        )

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            price=Decimal('5000.00'),
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            total_amount=proposal.price,
            currency='CAD',
            status='disputed'
        )

        dispute = ServiceDispute.objects.create(
            contract=contract,
            filed_by=client_user,
            reason='Non-delivery',
            status='open',
            disputed_amount=contract.total_amount
        )

        # Resolve in client favor
        dispute.status = 'resolved'
        dispute.resolution = 'full_refund'
        dispute.resolution_notes = 'Provider failed to deliver. Full refund issued.'
        dispute.resolved_at = timezone.now()
        dispute.save()

        # Issue refund
        refund = EscrowTransaction.objects.create(
            contract=contract,
            amount=contract.total_amount,
            currency='CAD',
            transaction_type='refund',
            status='completed',
            released_to=client_user,
            released_at=timezone.now()
        )

        contract.status = 'cancelled'
        contract.save()

        assert dispute.status == 'resolved'
        assert dispute.resolution == 'full_refund'
        assert refund.transaction_type == 'refund'

    def test_resolve_dispute_with_partial_payment(self, service_listing, client_user):
        """Test resolving dispute with partial payment to both parties."""
        from services.models import (
            ServiceProposal, ServiceContract, ServiceDispute, EscrowTransaction
        )

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            price=Decimal('4000.00'),
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            total_amount=proposal.price,
            currency='CAD',
            status='disputed'
        )

        dispute = ServiceDispute.objects.create(
            contract=contract,
            filed_by=client_user,
            reason='Partial delivery',
            status='open',
            disputed_amount=Decimal('2000.00')
        )

        # Resolve with split
        dispute.status = 'resolved'
        dispute.resolution = 'partial_split'
        dispute.resolution_notes = '50% to provider for work done, 50% refund to client'
        dispute.resolved_at = timezone.now()
        dispute.save()

        # Partial payment to provider
        provider_payment = EscrowTransaction.objects.create(
            contract=contract,
            amount=Decimal('2000.00'),
            currency='CAD',
            transaction_type='partial_release',
            status='completed'
        )

        # Partial refund to client
        client_refund = EscrowTransaction.objects.create(
            contract=contract,
            amount=Decimal('2000.00'),
            currency='CAD',
            transaction_type='refund',
            status='completed'
        )

        assert provider_payment.amount == Decimal('2000.00')
        assert client_refund.amount == Decimal('2000.00')


# ============================================================================
# COMPLETE MARKETPLACE FLOW INTEGRATION TEST
# ============================================================================

@pytest.mark.django_db
class TestCompleteMarketplaceFlow:
    """Integration test for complete marketplace workflow."""

    def test_full_service_to_payout_flow(
        self,
        user_factory,
        service_category,
        service_provider
    ):
        """Test complete flow: listing → proposal → contract → escrow → payout."""
        from services.models import (
            ServiceListing, ServiceProposal, ServiceContract,
            EscrowTransaction
        )

        # 1. Create service listing
        listing = ServiceListing.objects.create(
            provider=service_provider,
            category=service_category,
            title='Website Development',
            description='Professional website development',
            price=Decimal('3000.00'),
            price_type='fixed',
            delivery_time_days=21,
            is_active=True
        )
        assert listing.pk is not None

        # 2. Client views and requests proposal
        client = user_factory(email='client@test.com')

        proposal = ServiceProposal.objects.create(
            service=listing,
            client=client,
            provider=service_provider,
            title='Website for Client',
            description='Custom business website',
            price=Decimal('3500.00'),
            estimated_delivery_days=21,
            status='pending'
        )
        assert proposal.status == 'pending'

        # 3. Client accepts proposal
        proposal.status = 'accepted'
        proposal.accepted_at = timezone.now()
        proposal.save()

        # 4. Create contract
        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client,
            provider=service_provider,
            title=proposal.title,
            description=proposal.description,
            total_amount=proposal.price,
            currency='CAD',
            start_date=timezone.now().date(),
            expected_end_date=timezone.now().date() + timedelta(days=21),
            status='pending_funding'
        )
        assert contract.status == 'pending_funding'

        # 5. Client funds escrow
        escrow_deposit = EscrowTransaction.objects.create(
            contract=contract,
            amount=contract.total_amount,
            currency='CAD',
            transaction_type='deposit',
            status='completed',
            funded_by=client,
            funded_at=timezone.now()
        )

        contract.status = 'active'
        contract.funded_at = timezone.now()
        contract.save()
        assert contract.status == 'active'

        # 6. Provider completes work
        contract.status = 'pending_approval'
        contract.save()

        # 7. Client approves delivery
        contract.status = 'completed'
        contract.completed_at = timezone.now()
        contract.save()

        # 8. Escrow released to provider
        escrow_release = EscrowTransaction.objects.create(
            contract=contract,
            amount=contract.total_amount,
            currency='CAD',
            transaction_type='release',
            status='completed',
            released_to=service_provider.user,
            released_at=timezone.now()
        )

        assert escrow_release.status == 'completed'
        assert escrow_release.transaction_type == 'release'
        assert contract.status == 'completed'


# ============================================================================
# REVIEW AND RATING TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceReviews:
    """Test service review and rating functionality."""

    def test_client_leaves_review(self, service_listing, client_user):
        """Test client leaving a review after service completion."""
        from services.models import (
            ServiceProposal, ServiceContract, ServiceReview
        )

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            price=Decimal('3000.00'),
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            total_amount=proposal.price,
            currency='CAD',
            status='completed'
        )

        review = ServiceReview.objects.create(
            contract=contract,
            reviewer=client_user,
            reviewed_user=service_listing.provider.user,
            rating=5,
            title='Excellent work!',
            content='The provider delivered exactly what was promised.',
            would_recommend=True
        )

        assert review.rating == 5
        assert review.would_recommend

    def test_provider_responds_to_review(self, service_listing, client_user):
        """Test provider responding to a client review."""
        from services.models import (
            ServiceProposal, ServiceContract, ServiceReview
        )

        proposal = ServiceProposal.objects.create(
            service=service_listing,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            price=Decimal('3000.00'),
            status='accepted'
        )

        contract = ServiceContract.objects.create(
            proposal=proposal,
            client=client_user,
            provider=service_listing.provider,
            title='Project',
            total_amount=proposal.price,
            currency='CAD',
            status='completed'
        )

        review = ServiceReview.objects.create(
            contract=contract,
            reviewer=client_user,
            reviewed_user=service_listing.provider.user,
            rating=4,
            content='Good work overall.'
        )

        # Provider responds
        review.response = 'Thank you for your feedback!'
        review.response_at = timezone.now()
        review.save()

        assert review.response is not None
