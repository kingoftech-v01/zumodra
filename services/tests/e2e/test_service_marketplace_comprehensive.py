#!/usr/bin/env python3
"""
Comprehensive Service Marketplace Workflow Test
Integrated with pytest and Django test infrastructure

Tests the complete end-to-end flow:
1. Creating service listings
2. Editing service details
3. Publishing/unpublishing services
4. Service search and filtering
5. Proposal submission
6. Contract creation
7. Escrow payment handling
8. Reviews and ratings
"""

import pytest
import json
from pathlib import Path
from datetime import datetime, timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase, TransactionTestCase, Client
from django.urls import reverse
from rest_framework.test import APIClient, APITestCase
from rest_framework import status

from tenants.models import Tenant
from tenant_profiles.models import UserProfile
from services.models import (
    ServiceCategory, ServiceTag, Service, ServiceProvider,
    ClientRequest, ServiceProposal, ServiceContract, ServiceReview
)
from finance.models import Transaction, Escrow

User = get_user_model()


class ServiceMarketplaceSetupMixin:
    """Mixin for common setup across marketplace tests"""

    def setUp_marketplace(self):
        """Setup common test data for marketplace tests"""
        # Create tenant
        self.tenant = Tenant.objects.create(
            slug='marketplace-test-comprehensive',
            name='Marketplace Comprehensive Test',
            domain_url='marketplace-test.localhost'
        )

        # Create users
        self.seller_user = User.objects.create_user(
            username='marketplace_seller_comprehensive',
            email='seller@marketplace-comprehensive.com',
            password='TestPass123!',
            first_name='Test',
            last_name='Seller',
            tenant=self.tenant
        )

        self.buyer_user = User.objects.create_user(
            username='marketplace_buyer_comprehensive',
            email='buyer@marketplace-comprehensive.com',
            password='TestPass123!',
            first_name='Test',
            last_name='Buyer',
            tenant=self.tenant
        )

        # Create service provider
        self.provider = ServiceProvider.objects.create(
            tenant=self.tenant,
            user=self.seller_user,
            display_name=f'{self.seller_user.first_name} {self.seller_user.last_name}',
            hourly_rate=Decimal('50.00'),
            availability_status='available',
            provider_type='individual'
        )

        # Create service category
        self.category = ServiceCategory.objects.create(
            tenant=self.tenant,
            name='Web Development',
            slug='web-development-comprehensive',
            description='Web development services'
        )

        # Create test service
        self.service = Service.objects.create(
            tenant=self.tenant,
            provider=self.provider,
            category=self.category,
            title='Professional Web Development',
            description='High-quality web development services',
            price=Decimal('500.00'),
            service_type='fixed',
            delivery_type='remote',
            is_active=True
        )


class ServiceListingTestCase(ServiceMarketplaceSetupMixin, TestCase):
    """Test service listing creation, editing, and publication"""

    def setUp(self):
        """Setup test data"""
        self.setUp_marketplace()
        self.client = Client()
        self.api_client = APIClient()

    def test_create_service_listing(self):
        """Test creating a new service listing"""
        assert Service.objects.filter(id=self.service.id).exists()
        assert self.service.title == 'Professional Web Development'
        assert self.service.price == Decimal('500.00')

    def test_edit_service_details(self):
        """Test editing service details"""
        self.service.description = "Updated description"
        self.service.price = Decimal('750.00')
        self.service.save()

        updated_service = Service.objects.get(id=self.service.id)
        assert updated_service.description == "Updated description"
        assert updated_service.price == Decimal('750.00')

    def test_publish_unpublish_service(self):
        """Test toggling service publication status"""
        # Unpublish
        self.service.is_active = False
        self.service.save()
        assert Service.objects.get(id=self.service.id).is_active == False

        # Republish
        self.service.is_active = True
        self.service.save()
        assert Service.objects.get(id=self.service.id).is_active == True

    def test_service_provider_relationship(self):
        """Test service is linked to provider"""
        assert self.service.provider == self.provider
        assert self.service.provider.user == self.seller_user

    def test_service_category_relationship(self):
        """Test service is linked to category"""
        assert self.service.category == self.category

    def test_multiple_services_per_provider(self):
        """Test provider can have multiple services"""
        service2 = Service.objects.create(
            tenant=self.tenant,
            provider=self.provider,
            category=self.category,
            title='Second Service',
            description='Another service',
            price=Decimal('300.00'),
            service_type='hourly',
            delivery_type='onsite',
            is_active=True
        )

        provider_services = Service.objects.filter(provider=self.provider)
        assert provider_services.count() >= 2


class ServiceSearchFilterTestCase(ServiceMarketplaceSetupMixin, TestCase):
    """Test service search and filtering"""

    def setUp(self):
        """Setup test data"""
        self.setUp_marketplace()

        # Create multiple services
        self.services = []
        for i in range(5):
            service = Service.objects.create(
                tenant=self.tenant,
                provider=self.provider,
                category=self.category,
                title=f'Service {i+1}',
                description=f'Description for service {i+1}',
                price=Decimal('100.00') * (i + 1),
                service_type='fixed' if i % 2 == 0 else 'hourly',
                delivery_type='remote',
                is_active=True
            )
            self.services.append(service)

    def test_filter_by_category(self):
        """Test filtering services by category"""
        services = Service.objects.filter(
            tenant=self.tenant,
            category=self.category,
            is_active=True
        )
        assert services.count() >= 5

    def test_filter_by_price_range(self):
        """Test filtering services by price range"""
        services_expensive = Service.objects.filter(
            tenant=self.tenant,
            price__gte=Decimal('300.00')
        )
        assert services_expensive.count() >= 1

        services_cheap = Service.objects.filter(
            tenant=self.tenant,
            price__lt=Decimal('300.00')
        )
        assert services_cheap.count() >= 1

    def test_filter_by_service_type(self):
        """Test filtering services by type (fixed/hourly)"""
        fixed_services = Service.objects.filter(
            tenant=self.tenant,
            service_type='fixed'
        )
        assert fixed_services.count() >= 1

        hourly_services = Service.objects.filter(
            tenant=self.tenant,
            service_type='hourly'
        )
        assert hourly_services.count() >= 1

    def test_search_by_title(self):
        """Test searching services by title"""
        services = Service.objects.filter(
            tenant=self.tenant,
            title__icontains='Service 1'
        )
        assert services.count() >= 1

    def test_filter_active_services_only(self):
        """Test filtering only active services"""
        # Create inactive service
        inactive_service = Service.objects.create(
            tenant=self.tenant,
            provider=self.provider,
            category=self.category,
            title='Inactive Service',
            description='This service is inactive',
            price=Decimal('999.00'),
            service_type='fixed',
            delivery_type='remote',
            is_active=False
        )

        active_services = Service.objects.filter(
            tenant=self.tenant,
            is_active=True
        )
        assert inactive_service not in active_services


class ProposalTestCase(ServiceMarketplaceSetupMixin, TestCase):
    """Test proposal submission and management"""

    def setUp(self):
        """Setup test data"""
        self.setUp_marketplace()

        # Create client request
        self.client_request = ClientRequest.objects.create(
            tenant=self.tenant,
            client=self.buyer_user,
            category=self.category,
            title='Looking for web development help',
            description='Need help building a new website',
            budget_min=Decimal('1000.00'),
            budget_max=Decimal('2000.00'),
            status='open'
        )

    def test_submit_proposal(self):
        """Test submitting a proposal"""
        proposal = ServiceProposal.objects.create(
            tenant=self.tenant,
            service=self.service,
            client_request=self.client_request,
            provider=self.provider,
            proposed_price=Decimal('1500.00'),
            delivery_days=14,
            description='I can help with your project',
            status='pending'
        )

        assert ServiceProposal.objects.filter(id=proposal.id).exists()
        assert proposal.provider == self.provider
        assert proposal.client_request == self.client_request

    def test_proposal_status_transitions(self):
        """Test proposal status workflow"""
        proposal = ServiceProposal.objects.create(
            tenant=self.tenant,
            service=self.service,
            client_request=self.client_request,
            provider=self.provider,
            proposed_price=Decimal('1500.00'),
            delivery_days=14,
            description='I can help',
            status='pending'
        )

        # Accept proposal
        proposal.status = 'accepted'
        proposal.save()
        assert ServiceProposal.objects.get(id=proposal.id).status == 'accepted'

        # Reject proposal
        proposal.status = 'rejected'
        proposal.save()
        assert ServiceProposal.objects.get(id=proposal.id).status == 'rejected'

    def test_provider_receives_proposal_list(self):
        """Test provider can view received proposals"""
        proposal1 = ServiceProposal.objects.create(
            tenant=self.tenant,
            service=self.service,
            client_request=self.client_request,
            provider=self.provider,
            proposed_price=Decimal('1500.00'),
            delivery_days=14,
            description='Proposal 1',
            status='pending'
        )

        proposals = ServiceProposal.objects.filter(provider=self.provider)
        assert proposal1 in proposals


class ContractTestCase(ServiceMarketplaceSetupMixin, TestCase):
    """Test contract creation and management"""

    def setUp(self):
        """Setup test data"""
        self.setUp_marketplace()

        # Create proposal
        self.client_request = ClientRequest.objects.create(
            tenant=self.tenant,
            client=self.buyer_user,
            category=self.category,
            title='Web development project',
            description='Need help',
            budget_min=Decimal('1000.00'),
            budget_max=Decimal('2000.00'),
            status='open'
        )

        self.proposal = ServiceProposal.objects.create(
            tenant=self.tenant,
            service=self.service,
            client_request=self.client_request,
            provider=self.provider,
            proposed_price=Decimal('1500.00'),
            delivery_days=14,
            description='I can help',
            status='pending'
        )

    def test_create_contract_from_proposal(self):
        """Test creating contract from proposal"""
        contract = ServiceContract.objects.create(
            tenant=self.tenant,
            client=self.buyer_user,
            provider=self.provider,
            service=self.service,
            proposal=self.proposal,
            title=f"Contract for {self.client_request.title}",
            description="Terms and conditions",
            amount=self.proposal.proposed_price,
            currency='USD',
            status='pending_acceptance',
            delivery_deadline=datetime.now().date() + timedelta(days=14)
        )

        assert ServiceContract.objects.filter(id=contract.id).exists()
        assert contract.amount == Decimal('1500.00')
        assert contract.client == self.buyer_user
        assert contract.provider == self.provider

    def test_contract_status_workflow(self):
        """Test contract status transitions"""
        contract = ServiceContract.objects.create(
            tenant=self.tenant,
            client=self.buyer_user,
            provider=self.provider,
            service=self.service,
            proposal=self.proposal,
            title="Contract",
            description="Terms",
            amount=Decimal('1500.00'),
            currency='USD',
            status='pending_acceptance'
        )

        # Accept contract
        contract.status = 'accepted'
        contract.save()
        assert ServiceContract.objects.get(id=contract.id).status == 'accepted'

        # Mark as active
        contract.status = 'active'
        contract.save()
        assert ServiceContract.objects.get(id=contract.id).status == 'active'

        # Mark as completed
        contract.status = 'completed'
        contract.completed_at = datetime.now()
        contract.save()
        assert ServiceContract.objects.get(id=contract.id).status == 'completed'


class EscrowPaymentTestCase(ServiceMarketplaceSetupMixin, TestCase):
    """Test escrow and payment handling"""

    def setUp(self):
        """Setup test data"""
        self.setUp_marketplace()

        # Create contract
        self.client_request = ClientRequest.objects.create(
            tenant=self.tenant,
            client=self.buyer_user,
            category=self.category,
            title='Project',
            description='Help needed',
            budget_min=Decimal('1000.00'),
            budget_max=Decimal('2000.00'),
            status='open'
        )

        self.proposal = ServiceProposal.objects.create(
            tenant=self.tenant,
            service=self.service,
            client_request=self.client_request,
            provider=self.provider,
            proposed_price=Decimal('1500.00'),
            delivery_days=14,
            description='Help',
            status='pending'
        )

        self.contract = ServiceContract.objects.create(
            tenant=self.tenant,
            client=self.buyer_user,
            provider=self.provider,
            service=self.service,
            proposal=self.proposal,
            title="Contract",
            description="Terms",
            amount=Decimal('1500.00'),
            currency='USD',
            status='active'
        )

    def test_create_escrow(self):
        """Test escrow creation"""
        escrow = Escrow.objects.create(
            tenant=self.tenant,
            contract=self.contract,
            amount=self.contract.amount,
            currency='USD',
            payer=self.buyer_user,
            payee=self.provider.user,
            status='pending'
        )

        assert Escrow.objects.filter(id=escrow.id).exists()
        assert escrow.amount == Decimal('1500.00')

    def test_escrow_status_transitions(self):
        """Test escrow status workflow"""
        escrow = Escrow.objects.create(
            tenant=self.tenant,
            contract=self.contract,
            amount=self.contract.amount,
            currency='USD',
            payer=self.buyer_user,
            payee=self.provider.user,
            status='pending'
        )

        # Hold funds
        escrow.status = 'held'
        escrow.save()
        assert Escrow.objects.get(id=escrow.id).status == 'held'

        # Release funds
        escrow.status = 'released'
        escrow.released_at = datetime.now()
        escrow.save()
        assert Escrow.objects.get(id=escrow.id).status == 'released'

    def test_create_payment_transaction(self):
        """Test payment transaction creation"""
        escrow = Escrow.objects.create(
            tenant=self.tenant,
            contract=self.contract,
            amount=self.contract.amount,
            currency='USD',
            payer=self.buyer_user,
            payee=self.provider.user,
            status='pending'
        )

        transaction = Transaction.objects.create(
            tenant=self.tenant,
            user=self.buyer_user,
            type='payment',
            amount=self.contract.amount,
            currency='USD',
            status='completed',
            description=f'Payment for contract {self.contract.id}',
            reference_id=str(escrow.id)
        )

        assert Transaction.objects.filter(id=transaction.id).exists()
        assert transaction.amount == Decimal('1500.00')


class ReviewRatingTestCase(ServiceMarketplaceSetupMixin, TestCase):
    """Test reviews and ratings"""

    def setUp(self):
        """Setup test data"""
        self.setUp_marketplace()

        # Create and complete contract
        self.client_request = ClientRequest.objects.create(
            tenant=self.tenant,
            client=self.buyer_user,
            category=self.category,
            title='Project',
            description='Help',
            budget_min=Decimal('1000.00'),
            budget_max=Decimal('2000.00'),
            status='open'
        )

        self.proposal = ServiceProposal.objects.create(
            tenant=self.tenant,
            service=self.service,
            client_request=self.client_request,
            provider=self.provider,
            proposed_price=Decimal('1500.00'),
            delivery_days=14,
            description='Help',
            status='pending'
        )

        self.contract = ServiceContract.objects.create(
            tenant=self.tenant,
            client=self.buyer_user,
            provider=self.provider,
            service=self.service,
            proposal=self.proposal,
            title="Contract",
            description="Terms",
            amount=Decimal('1500.00'),
            currency='USD',
            status='completed',
            completed_at=datetime.now()
        )

    def test_create_review(self):
        """Test review creation"""
        review = ServiceReview.objects.create(
            tenant=self.tenant,
            contract=self.contract,
            reviewer=self.buyer_user,
            provider=self.provider,
            rating=5,
            rating_communication=5,
            rating_quality=5,
            rating_timeliness=5,
            title='Excellent service!',
            content='Very satisfied with the work'
        )

        assert ServiceReview.objects.filter(id=review.id).exists()
        assert review.rating == 5

    def test_multiple_reviews_for_provider(self):
        """Test provider can have multiple reviews"""
        # Create another contract and review
        contract2 = ServiceContract.objects.create(
            tenant=self.tenant,
            client=self.buyer_user,
            provider=self.provider,
            service=self.service,
            title="Contract 2",
            description="Terms",
            amount=Decimal('1000.00'),
            currency='USD',
            status='completed',
            completed_at=datetime.now()
        )

        review1 = ServiceReview.objects.create(
            tenant=self.tenant,
            contract=self.contract,
            reviewer=self.buyer_user,
            provider=self.provider,
            rating=5,
            title='Great!',
            content='Excellent work'
        )

        review2 = ServiceReview.objects.create(
            tenant=self.tenant,
            contract=contract2,
            reviewer=self.buyer_user,
            provider=self.provider,
            rating=4,
            title='Good work',
            content='Well done'
        )

        reviews = ServiceReview.objects.filter(provider=self.provider)
        assert reviews.count() >= 2

    def test_provider_response_to_review(self):
        """Test provider response to review"""
        review = ServiceReview.objects.create(
            tenant=self.tenant,
            contract=self.contract,
            reviewer=self.buyer_user,
            provider=self.provider,
            rating=5,
            title='Great!',
            content='Excellent'
        )

        # Provider responds
        review.provider_response = "Thank you for the kind words!"
        review.provider_responded_at = datetime.now()
        review.save()

        updated_review = ServiceReview.objects.get(id=review.id)
        assert updated_review.provider_response is not None


@pytest.mark.integration
class ServiceMarketplaceIntegrationTest:
    """Full integration test of complete workflow"""

    def test_complete_marketplace_workflow(self):
        """Test complete workflow from listing to review"""
        # This would be a real pytest test
        pass


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
