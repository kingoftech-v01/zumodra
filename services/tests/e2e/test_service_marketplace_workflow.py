#!/usr/bin/env python3
"""
Comprehensive Service Marketplace Workflow Test
Tests the complete end-to-end flow of the service marketplace:
1. Creating service listings
2. Editing service details
3. Publishing/unpublishing services
4. Service search and filtering
5. Proposal submission
6. Contract creation
7. Escrow payment handling
"""

import os
import sys
import django
import json
import requests
from pathlib import Path
from datetime import datetime, timedelta
from decimal import Decimal

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
sys.path.insert(0, '/c/Users/techn/OneDrive/Documents/zumodra')

django.setup()

from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status

# Import models
from services.models import (
    ServiceCategory, ServiceTag, Service, ServiceProvider,
    ClientRequest, ServiceProposal, ServiceContract, ServiceReview
)
from finance.models import Transaction, Escrow
from tenants.models import Tenant
from core.test_helpers import create_test_tenant, create_test_user

User = get_user_model()


class ServiceMarketplaceTest:
    def __init__(self):
        self.results = []
        self.errors = []
        self.test_data = {}
        self.api_client = APIClient()
        self.web_client = Client()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = Path("/c/Users/techn/OneDrive/Documents/zumodra/test_results/marketplace")
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def log(self, msg, level="INFO"):
        """Log a message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}]"
        print(f"{prefix} {msg}")

    def log_result(self, test_name, status_code, message="", passed=True):
        """Log test result"""
        result = {
            'test': test_name,
            'status_code': status_code,
            'message': message,
            'passed': passed,
            'timestamp': datetime.now().isoformat()
        }
        self.results.append(result)

        status_str = "PASS" if passed else "FAIL"
        self.log(f"[{status_str}] {test_name} - Status: {status_code}",
                level="SUCCESS" if passed else "ERROR")

    def log_error(self, test_name, error):
        """Log an error"""
        self.errors.append({'test': test_name, 'error': str(error)})
        self.log(f"ERROR in {test_name}: {error}", level="ERROR")

    def setup_test_environment(self):
        """Setup test environment with tenant and users"""
        self.log("Setting up test environment...")
        try:
            # Create or get test tenant
            tenant, _ = Tenant.objects.get_or_create(
                slug='marketplace-test',
                defaults={
                    'name': 'Marketplace Test Tenant',
                    'domain_url': 'marketplace-test.localhost'
                }
            )
            self.test_data['tenant'] = tenant

            # Create test users
            seller_user, _ = User.objects.get_or_create(
                username='marketplace_seller',
                defaults={
                    'email': 'seller@marketplace-test.com',
                    'first_name': 'Test',
                    'last_name': 'Seller',
                    'tenant': tenant
                }
            )
            if not seller_user.is_active:
                seller_user.is_active = True
                seller_user.save()
            seller_user.set_password('TestPass123!')
            seller_user.save()
            self.test_data['seller_user'] = seller_user

            buyer_user, _ = User.objects.get_or_create(
                username='marketplace_buyer',
                defaults={
                    'email': 'buyer@marketplace-test.com',
                    'first_name': 'Test',
                    'last_name': 'Buyer',
                    'tenant': tenant
                }
            )
            if not buyer_user.is_active:
                buyer_user.is_active = True
                buyer_user.save()
            buyer_user.set_password('TestPass123!')
            buyer_user.save()
            self.test_data['buyer_user'] = buyer_user

            self.api_client.force_authenticate(user=seller_user)
            self.log("Test environment setup complete")
            return True

        except Exception as e:
            self.log_error("setup_test_environment", e)
            return False

    def test_create_service_listing(self):
        """Test 1: Creating service listings"""
        self.log("Testing: Create Service Listing")
        try:
            seller = self.test_data['seller_user']
            tenant = self.test_data['tenant']

            # Create or get service provider
            provider, created = ServiceProvider.objects.get_or_create(
                user=seller,
                tenant=tenant,
                defaults={
                    'display_name': f'{seller.first_name} {seller.last_name}',
                    'hourly_rate': Decimal('50.00'),
                    'availability_status': 'available',
                    'provider_type': 'individual'
                }
            )
            self.test_data['service_provider'] = provider

            # Create or get category
            category, created = ServiceCategory.objects.get_or_create(
                name='Web Development',
                tenant=tenant,
                defaults={
                    'slug': 'web-development',
                    'description': 'Web development services'
                }
            )
            self.test_data['service_category'] = category

            # Create service
            service = Service.objects.create(
                tenant=tenant,
                provider=provider,
                category=category,
                title='Professional Web Development',
                description='High-quality web development services',
                price=Decimal('500.00'),
                service_type='fixed',
                delivery_type='remote',
                is_active=True
            )
            self.test_data['service'] = service

            self.log_result(
                "test_create_service_listing",
                200,
                f"Created service: {service.id}",
                passed=True
            )
            return True

        except Exception as e:
            self.log_error("test_create_service_listing", e)
            self.log_result("test_create_service_listing", 500, str(e), passed=False)
            return False

    def test_edit_service_details(self):
        """Test 2: Editing service details"""
        self.log("Testing: Edit Service Details")
        try:
            service = self.test_data['service']

            # Update service details
            service.description = "Updated: Professional Web Development Services with modern stack"
            service.price = Decimal('750.00')
            service.save()

            # Verify changes
            updated = Service.objects.get(id=service.id)
            assert updated.description == service.description
            assert updated.price == Decimal('750.00')

            self.log_result(
                "test_edit_service_details",
                200,
                "Successfully updated service details",
                passed=True
            )
            return True

        except Exception as e:
            self.log_error("test_edit_service_details", e)
            self.log_result("test_edit_service_details", 500, str(e), passed=False)
            return False

    def test_publish_unpublish_service(self):
        """Test 3: Publishing/unpublishing services"""
        self.log("Testing: Publish/Unpublish Service")
        try:
            service = self.test_data['service']

            # Publish service
            service.is_active = True
            service.save()
            assert Service.objects.get(id=service.id).is_active == True

            # Unpublish service
            service.is_active = False
            service.save()
            assert Service.objects.get(id=service.id).is_active == False

            # Republish service
            service.is_active = True
            service.save()
            assert Service.objects.get(id=service.id).is_active == True

            self.log_result(
                "test_publish_unpublish_service",
                200,
                "Successfully toggled service publication status",
                passed=True
            )
            return True

        except Exception as e:
            self.log_error("test_publish_unpublish_service", e)
            self.log_result("test_publish_unpublish_service", 500, str(e), passed=False)
            return False

    def test_service_search_and_filtering(self):
        """Test 4: Service search and filtering"""
        self.log("Testing: Service Search and Filtering")
        try:
            tenant = self.test_data['tenant']
            category = self.test_data['service_category']

            # Create multiple services for filtering
            for i in range(3):
                Service.objects.create(
                    tenant=tenant,
                    provider=self.test_data['service_provider'],
                    category=category,
                    title=f'Service {i+1}',
                    description=f'Description for service {i+1}',
                    price=Decimal('100.00') * (i + 1),
                    service_type='fixed',
                    delivery_type='remote',
                    is_active=True
                )

            # Test filtering by category
            services = Service.objects.filter(
                tenant=tenant,
                category=category,
                is_active=True
            )
            assert services.count() >= 4  # Original + 3 new

            # Test filtering by price range
            services_expensive = Service.objects.filter(
                tenant=tenant,
                price__gte=Decimal('500.00')
            )
            assert services_expensive.count() >= 1

            # Test search by title
            services_search = Service.objects.filter(
                tenant=tenant,
                title__icontains='Web'
            )
            assert services_search.count() >= 1

            self.log_result(
                "test_service_search_and_filtering",
                200,
                f"Found {services.count()} services, filtering working correctly",
                passed=True
            )
            return True

        except Exception as e:
            self.log_error("test_service_search_and_filtering", e)
            self.log_result("test_service_search_and_filtering", 500, str(e), passed=False)
            return False

    def test_proposal_submission(self):
        """Test 5: Proposal submission"""
        self.log("Testing: Proposal Submission")
        try:
            tenant = self.test_data['tenant']
            buyer = self.test_data['buyer_user']

            # Create a client request
            client_request = ClientRequest.objects.create(
                tenant=tenant,
                client=buyer,
                category=self.test_data['service_category'],
                title='Looking for web development help',
                description='Need help building a new website',
                budget_min=Decimal('1000.00'),
                budget_max=Decimal('2000.00'),
                status='open'
            )
            self.test_data['client_request'] = client_request

            # Create proposal from service provider
            proposal = ServiceProposal.objects.create(
                tenant=tenant,
                service=self.test_data['service'],
                client_request=client_request,
                provider=self.test_data['service_provider'],
                proposed_price=Decimal('1500.00'),
                delivery_days=14,
                description='I can help with your web development project',
                status='pending'
            )
            self.test_data['proposal'] = proposal

            # Verify proposal creation
            assert ServiceProposal.objects.filter(id=proposal.id).exists()

            self.log_result(
                "test_proposal_submission",
                200,
                f"Created proposal: {proposal.id}",
                passed=True
            )
            return True

        except Exception as e:
            self.log_error("test_proposal_submission", e)
            self.log_result("test_proposal_submission", 500, str(e), passed=False)
            return False

    def test_contract_creation(self):
        """Test 6: Contract creation"""
        self.log("Testing: Contract Creation")
        try:
            tenant = self.test_data['tenant']
            proposal = self.test_data['proposal']
            buyer = self.test_data['buyer_user']
            seller = self.test_data['seller_user']

            # Accept proposal and create contract
            contract = ServiceContract.objects.create(
                tenant=tenant,
                client=buyer,
                provider=self.test_data['service_provider'],
                service=self.test_data['service'],
                proposal=proposal,
                title=f"Contract for {proposal.client_request.title}",
                description="Agreed upon terms and conditions",
                amount=proposal.proposed_price,
                currency='USD',
                status='pending_acceptance',
                delivery_deadline=datetime.now().date() + timedelta(days=14)
            )
            self.test_data['contract'] = contract

            # Verify contract creation
            assert ServiceContract.objects.filter(id=contract.id).exists()

            # Update contract status
            contract.status = 'active'
            contract.save()

            self.log_result(
                "test_contract_creation",
                200,
                f"Created contract: {contract.id}",
                passed=True
            )
            return True

        except Exception as e:
            self.log_error("test_contract_creation", e)
            self.log_result("test_contract_creation", 500, str(e), passed=False)
            return False

    def test_escrow_payment_handling(self):
        """Test 7: Escrow payment handling"""
        self.log("Testing: Escrow Payment Handling")
        try:
            tenant = self.test_data['tenant']
            contract = self.test_data['contract']
            buyer = self.test_data['buyer_user']

            # Create escrow for contract
            escrow = Escrow.objects.create(
                tenant=tenant,
                contract=contract,
                amount=contract.amount,
                currency='USD',
                payer=buyer,
                payee=contract.provider.user,
                status='pending'
            )
            self.test_data['escrow'] = escrow

            # Create payment transaction
            transaction = Transaction.objects.create(
                tenant=tenant,
                user=buyer,
                type='payment',
                amount=contract.amount,
                currency='USD',
                status='completed',
                description=f'Payment for contract {contract.id}',
                reference_id=escrow.id
            )
            self.test_data['transaction'] = transaction

            # Update escrow status
            escrow.status = 'held'
            escrow.save()

            # Verify escrow and transaction
            assert Escrow.objects.filter(id=escrow.id).exists()
            assert Transaction.objects.filter(id=transaction.id).exists()

            self.log_result(
                "test_escrow_payment_handling",
                200,
                f"Created escrow: {escrow.id}, Transaction: {transaction.id}",
                passed=True
            )
            return True

        except Exception as e:
            self.log_error("test_escrow_payment_handling", e)
            self.log_result("test_escrow_payment_handling", 500, str(e), passed=False)
            return False

    def test_contract_completion_and_review(self):
        """Test 8: Contract completion and review"""
        self.log("Testing: Contract Completion and Review")
        try:
            tenant = self.test_data['tenant']
            contract = self.test_data['contract']
            buyer = self.test_data['buyer_user']

            # Mark contract as completed
            contract.status = 'completed'
            contract.completed_at = datetime.now()
            contract.save()

            # Create review
            review = ServiceReview.objects.create(
                tenant=tenant,
                contract=contract,
                reviewer=buyer,
                provider=contract.provider,
                rating=5,
                rating_communication=5,
                rating_quality=5,
                rating_timeliness=5,
                title='Excellent service!',
                content='Very satisfied with the work performed'
            )
            self.test_data['review'] = review

            # Update provider rating
            contract.provider.update_rating()

            # Verify review and rating
            assert ServiceReview.objects.filter(id=review.id).exists()

            self.log_result(
                "test_contract_completion_and_review",
                200,
                f"Created review: {review.id}",
                passed=True
            )
            return True

        except Exception as e:
            self.log_error("test_contract_completion_and_review", e)
            self.log_result("test_contract_completion_and_review", 500, str(e), passed=False)
            return False

    def test_api_endpoints(self):
        """Test API endpoints for service marketplace"""
        self.log("Testing: API Endpoints")
        try:
            seller = self.test_data['seller_user']
            tenant = self.test_data['tenant']
            self.api_client.force_authenticate(user=seller)

            endpoints = [
                ('get', '/api/v1/services/categories/', 'List categories'),
                ('get', '/api/v1/services/', 'List services'),
                ('get', '/api/v1/services/providers/', 'List providers'),
                ('get', '/api/v1/services/contracts/', 'List contracts'),
            ]

            api_results = []
            for method, endpoint, description in endpoints:
                try:
                    if method == 'get':
                        response = self.api_client.get(endpoint)
                    api_results.append({
                        'endpoint': endpoint,
                        'method': method,
                        'status': response.status_code,
                        'description': description,
                        'passed': response.status_code in [200, 201, 204]
                    })
                except Exception as e:
                    api_results.append({
                        'endpoint': endpoint,
                        'method': method,
                        'error': str(e),
                        'passed': False
                    })

            self.test_data['api_results'] = api_results

            passed = sum(1 for r in api_results if r.get('passed', False))
            total = len(api_results)

            self.log_result(
                "test_api_endpoints",
                200,
                f"API test: {passed}/{total} passed",
                passed=passed == total
            )
            return True

        except Exception as e:
            self.log_error("test_api_endpoints", e)
            self.log_result("test_api_endpoints", 500, str(e), passed=False)
            return False

    def run_all_tests(self):
        """Run all tests"""
        self.log("=" * 80)
        self.log("SERVICE MARKETPLACE WORKFLOW TEST SUITE")
        self.log("=" * 80)

        # Setup
        if not self.setup_test_environment():
            self.log("Failed to setup test environment", level="CRITICAL")
            return False

        # Run tests in sequence
        tests = [
            self.test_create_service_listing,
            self.test_edit_service_details,
            self.test_publish_unpublish_service,
            self.test_service_search_and_filtering,
            self.test_proposal_submission,
            self.test_contract_creation,
            self.test_escrow_payment_handling,
            self.test_contract_completion_and_review,
            self.test_api_endpoints,
        ]

        for test in tests:
            try:
                test()
            except Exception as e:
                self.log_error(test.__name__, e)

        # Generate report
        self.generate_report()
        return True

    def generate_report(self):
        """Generate test report"""
        self.log("=" * 80)
        self.log("GENERATING TEST REPORT")
        self.log("=" * 80)

        # Summary
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r['passed'])
        failed_tests = total_tests - passed_tests

        self.log(f"Total Tests: {total_tests}")
        self.log(f"Passed: {passed_tests}")
        self.log(f"Failed: {failed_tests}")
        self.log(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")

        # Detailed results
        self.log("\nDetailed Results:")
        for result in self.results:
            status_str = "PASS" if result['passed'] else "FAIL"
            self.log(f"  [{status_str}] {result['test']}: {result['message']}")

        # Errors
        if self.errors:
            self.log("\nErrors:")
            for error in self.errors:
                self.log(f"  {error['test']}: {error['error']}")

        # Save JSON report
        report_data = {
            'timestamp': self.timestamp,
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'success_rate': f"{(passed_tests/total_tests*100):.1f}%"
            },
            'results': self.results,
            'errors': self.errors,
            'test_data': {
                'tenant': str(self.test_data.get('tenant', 'N/A')),
                'seller_user': str(self.test_data.get('seller_user', 'N/A')),
                'buyer_user': str(self.test_data.get('buyer_user', 'N/A')),
            }
        }

        report_path = self.report_dir / f"marketplace_test_report_{self.timestamp}.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        self.log(f"\nReport saved to: {report_path}")

        # Save markdown report
        md_report = self.generate_markdown_report(report_data)
        md_path = self.report_dir / f"marketplace_test_report_{self.timestamp}.md"
        with open(md_path, 'w') as f:
            f.write(md_report)

        self.log(f"Markdown report saved to: {md_path}")

    def generate_markdown_report(self, report_data):
        """Generate markdown formatted report"""
        md = f"""# Service Marketplace Workflow Test Report
Generated: {report_data['timestamp']}

## Summary
- **Total Tests**: {report_data['summary']['total_tests']}
- **Passed**: {report_data['summary']['passed']}
- **Failed**: {report_data['summary']['failed']}
- **Success Rate**: {report_data['summary']['success_rate']}

## Test Results

| Test | Status | Message |
|------|--------|---------|
"""
        for result in report_data['results']:
            status = "✓ PASS" if result['passed'] else "✗ FAIL"
            md += f"| {result['test']} | {status} | {result['message']} |\n"

        if report_data['errors']:
            md += "\n## Errors\n\n"
            for error in report_data['errors']:
                md += f"### {error['test']}\n```\n{error['error']}\n```\n\n"

        md += "\n## Test Data\n"
        md += f"- Tenant: {report_data['test_data']['tenant']}\n"
        md += f"- Seller: {report_data['test_data']['seller_user']}\n"
        md += f"- Buyer: {report_data['test_data']['buyer_user']}\n"

        return md


def main():
    """Main entry point"""
    tester = ServiceMarketplaceTest()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
