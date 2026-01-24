#!/usr/bin/env python3
"""
Simple Service Marketplace Workflow Test
Tests the complete end-to-end flow of the service marketplace
"""

import os
import sys
import django
import json
from pathlib import Path
from datetime import datetime, timedelta
from decimal import Decimal

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    django.setup()
    print("[SUCCESS] Django setup complete")
except Exception as e:
    print(f"[ERROR] Django setup failed: {e}")
    sys.exit(1)

from django.contrib.auth import get_user_model
from services.models import (
    ServiceCategory, ServiceTag, Service, ServiceProvider,
    ClientRequest, ServiceProposal, ServiceContract, ServiceReview
)
from finance.models import Transaction, Escrow
from tenants.models import Tenant

User = get_user_model()

def main():
    print("\n" + "=" * 80)
    print("SERVICE MARKETPLACE WORKFLOW TEST")
    print("=" * 80)

    report_dir = Path("test_results/marketplace")
    report_dir.mkdir(parents=True, exist_ok=True)

    results = []

    # Test 1: Get or create tenant
    print("\n[TEST 1] Get/Create Test Tenant")
    try:
        tenant, created = Tenant.objects.get_or_create(
            slug='marketplace-test',
            defaults={
                'name': 'Marketplace Test Tenant',
                'domain_url': 'marketplace-test.localhost'
            }
        )
        print(f"  ✓ Tenant: {tenant.name} (created={created})")
        results.append({'test': 'Create Tenant', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Create Tenant', 'passed': False, 'error': str(e)})

    # Test 2: Create test users
    print("\n[TEST 2] Create Test Users")
    try:
        seller_user, _ = User.objects.get_or_create(
            username='marketplace_seller_test',
            defaults={
                'email': 'seller@marketplace-test.com',
                'first_name': 'Test',
                'last_name': 'Seller',
                'tenant': tenant
            }
        )
        seller_user.set_password('TestPass123!')
        seller_user.is_active = True
        seller_user.save()
        print(f"  ✓ Seller User: {seller_user.email}")

        buyer_user, _ = User.objects.get_or_create(
            username='marketplace_buyer_test',
            defaults={
                'email': 'buyer@marketplace-test.com',
                'first_name': 'Test',
                'last_name': 'Buyer',
                'tenant': tenant
            }
        )
        buyer_user.set_password('TestPass123!')
        buyer_user.is_active = True
        buyer_user.save()
        print(f"  ✓ Buyer User: {buyer_user.email}")

        results.append({'test': 'Create Users', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Create Users', 'passed': False, 'error': str(e)})

    # Test 3: Create service provider
    print("\n[TEST 3] Create Service Provider")
    try:
        provider, created = ServiceProvider.objects.get_or_create(
            user=seller_user,
            tenant=tenant,
            defaults={
                'display_name': f'{seller_user.first_name} {seller_user.last_name}',
                'hourly_rate': Decimal('50.00'),
                'availability_status': 'available',
                'provider_type': 'individual'
            }
        )
        print(f"  ✓ Service Provider: {provider.display_name} (ID={provider.id})")
        results.append({'test': 'Create Service Provider', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Create Service Provider', 'passed': False, 'error': str(e)})

    # Test 4: Create service category
    print("\n[TEST 4] Create Service Category")
    try:
        category, created = ServiceCategory.objects.get_or_create(
            name='Web Development',
            tenant=tenant,
            defaults={
                'slug': 'web-development-test',
                'description': 'Web development services'
            }
        )
        print(f"  ✓ Service Category: {category.name} (ID={category.id})")
        results.append({'test': 'Create Service Category', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Create Service Category', 'passed': False, 'error': str(e)})

    # Test 5: Create service listing
    print("\n[TEST 5] Create Service Listing")
    try:
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
        print(f"  ✓ Service: {service.title} (ID={service.id})")
        results.append({'test': 'Create Service Listing', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Create Service Listing', 'passed': False, 'error': str(e)})

    # Test 6: Edit service details
    print("\n[TEST 6] Edit Service Details")
    try:
        service.description = "Updated: Professional Web Development Services"
        service.price = Decimal('750.00')
        service.save()

        updated = Service.objects.get(id=service.id)
        assert updated.price == Decimal('750.00')
        print(f"  ✓ Updated service price to ${updated.price}")
        results.append({'test': 'Edit Service Details', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Edit Service Details', 'passed': False, 'error': str(e)})

    # Test 7: Publish/Unpublish service
    print("\n[TEST 7] Publish/Unpublish Service")
    try:
        service.is_active = False
        service.save()
        assert Service.objects.get(id=service.id).is_active == False
        print(f"  ✓ Service unpublished")

        service.is_active = True
        service.save()
        assert Service.objects.get(id=service.id).is_active == True
        print(f"  ✓ Service republished")
        results.append({'test': 'Publish/Unpublish Service', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Publish/Unpublish Service', 'passed': False, 'error': str(e)})

    # Test 8: Service search and filtering
    print("\n[TEST 8] Service Search and Filtering")
    try:
        # Create additional services
        for i in range(2):
            Service.objects.create(
                tenant=tenant,
                provider=provider,
                category=category,
                title=f'Service {i+1}',
                description=f'Description for service {i+1}',
                price=Decimal('100.00') * (i + 1),
                service_type='fixed',
                delivery_type='remote',
                is_active=True
            )

        # Filter by category
        services_by_category = Service.objects.filter(
            tenant=tenant,
            category=category,
            is_active=True
        )
        print(f"  ✓ Found {services_by_category.count()} services in category")

        # Filter by price
        services_by_price = Service.objects.filter(
            tenant=tenant,
            price__gte=Decimal('500.00')
        )
        print(f"  ✓ Found {services_by_price.count()} services with price >= $500")

        results.append({'test': 'Service Search and Filtering', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Service Search and Filtering', 'passed': False, 'error': str(e)})

    # Test 9: Create client request
    print("\n[TEST 9] Create Client Request")
    try:
        client_request = ClientRequest.objects.create(
            tenant=tenant,
            client=buyer_user,
            category=category,
            title='Looking for web development help',
            description='Need help building a new website',
            budget_min=Decimal('1000.00'),
            budget_max=Decimal('2000.00'),
            status='open'
        )
        print(f"  ✓ Client Request: {client_request.title} (ID={client_request.id})")
        results.append({'test': 'Create Client Request', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Create Client Request', 'passed': False, 'error': str(e)})

    # Test 10: Submit proposal
    print("\n[TEST 10] Submit Proposal")
    try:
        proposal = ServiceProposal.objects.create(
            tenant=tenant,
            service=service,
            client_request=client_request,
            provider=provider,
            proposed_price=Decimal('1500.00'),
            delivery_days=14,
            description='I can help with your web development project',
            status='pending'
        )
        print(f"  ✓ Proposal: ${proposal.proposed_price} (ID={proposal.id})")
        results.append({'test': 'Submit Proposal', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Submit Proposal', 'passed': False, 'error': str(e)})

    # Test 11: Create contract
    print("\n[TEST 11] Create Contract")
    try:
        contract = ServiceContract.objects.create(
            tenant=tenant,
            client=buyer_user,
            provider=provider,
            service=service,
            proposal=proposal,
            title=f"Contract for {client_request.title}",
            description="Agreed upon terms and conditions",
            amount=proposal.proposed_price,
            currency='USD',
            status='pending_acceptance',
            delivery_deadline=datetime.now().date() + timedelta(days=14)
        )
        print(f"  ✓ Contract: {contract.title} (ID={contract.id})")
        results.append({'test': 'Create Contract', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Create Contract', 'passed': False, 'error': str(e)})

    # Test 12: Create escrow
    print("\n[TEST 12] Create Escrow Payment")
    try:
        escrow = Escrow.objects.create(
            tenant=tenant,
            contract=contract,
            amount=contract.amount,
            currency='USD',
            payer=buyer_user,
            payee=provider.user,
            status='pending'
        )
        print(f"  ✓ Escrow: ${escrow.amount} (ID={escrow.id})")
        results.append({'test': 'Create Escrow Payment', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Create Escrow Payment', 'passed': False, 'error': str(e)})

    # Test 13: Create transaction
    print("\n[TEST 13] Create Payment Transaction")
    try:
        transaction = Transaction.objects.create(
            tenant=tenant,
            user=buyer_user,
            type='payment',
            amount=contract.amount,
            currency='USD',
            status='completed',
            description=f'Payment for contract {contract.id}',
            reference_id=str(escrow.id)
        )
        print(f"  ✓ Transaction: ${transaction.amount} (ID={transaction.id})")
        results.append({'test': 'Create Payment Transaction', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Create Payment Transaction', 'passed': False, 'error': str(e)})

    # Test 14: Complete contract and create review
    print("\n[TEST 14] Complete Contract and Create Review")
    try:
        contract.status = 'completed'
        contract.completed_at = datetime.now()
        contract.save()

        review = ServiceReview.objects.create(
            tenant=tenant,
            contract=contract,
            reviewer=buyer_user,
            provider=provider,
            rating=5,
            rating_communication=5,
            rating_quality=5,
            rating_timeliness=5,
            title='Excellent service!',
            content='Very satisfied with the work performed'
        )
        print(f"  ✓ Review: Rating {review.rating}/5 (ID={review.id})")
        results.append({'test': 'Complete Contract and Review', 'passed': True})
    except Exception as e:
        print(f"  ✗ Error: {e}")
        results.append({'test': 'Complete Contract and Review', 'passed': False, 'error': str(e)})

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    total = len(results)
    passed = sum(1 for r in results if r['passed'])
    failed = total - passed

    print(f"\nTotal Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/total*100):.1f}%")

    print("\nDetailed Results:")
    for result in results:
        status = "✓ PASS" if result['passed'] else "✗ FAIL"
        msg = result.get('error', 'OK')
        print(f"  [{status}] {result['test']}: {msg}")

    # Save JSON report
    report = {
        'timestamp': datetime.now().isoformat(),
        'total_tests': total,
        'passed': passed,
        'failed': failed,
        'success_rate': f"{(passed/total*100):.1f}%",
        'results': results
    }

    report_path = report_dir / f"marketplace_test_simple_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\nReport saved to: {report_path}")

    return passed == total

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
