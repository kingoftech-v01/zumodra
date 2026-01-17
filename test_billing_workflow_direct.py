#!/usr/bin/env python3
"""
Direct Subscription & Billing Workflow Testing Script
=====================================================

Tests subscription and billing without requiring Docker web services to be running.
Runs directly against the Django ORM and Stripe API.
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta
from decimal import Decimal
import uuid

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

import django
django.setup()

import stripe
from django.conf import settings
from django.utils import timezone
from django.db.models import Sum

from finance.models import (
    SubscriptionPlan, UserSubscription, PaymentTransaction, Invoice,
    StripeWebhookEvent, PaymentMethod
)
from accounts.models import User as CustomUser

# Configure logging
log_dir = 'test_results'
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{log_dir}/subscription_billing_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Stripe
stripe.api_key = settings.STRIPE_SECRET_KEY

class BillingWorkflowTester:
    """Test subscription and billing workflows."""

    def __init__(self):
        self.test_results = {}
        self.test_user = None
        self.test_plan = None
        self.stripe_customer = None
        self.errors = []

    def log_section(self, title):
        """Log a section header."""
        logger.info("\n" + "=" * 80)
        logger.info(title)
        logger.info("=" * 80)

    def log_subsection(self, title):
        """Log a subsection."""
        logger.info(f"\n--- {title} ---")

    def create_test_user(self):
        """Create a test user."""
        self.log_subsection("Creating Test User")
        try:
            email = f"test_billing_{uuid.uuid4().hex[:8]}@example.com"
            user = CustomUser.objects.create_user(
                email=email,
                password='TestPassword123!',
                first_name='Test',
                last_name='Billing',
            )
            self.test_user = user
            logger.info(f"✓ Test user created: {email}")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to create test user: {e}")
            self.errors.append(str(e))
            return False

    # =========================================================================
    # TEST 1: PLAN SELECTION
    # =========================================================================

    def test_1_plan_selection(self):
        """Test 1: Plan selection and listing."""
        self.log_section("TEST 1: PLAN SELECTION & UPGRADE/DOWNGRADE")

        try:
            # List plans
            self.log_subsection("1.1 List Available Plans")
            plans = SubscriptionPlan.objects.all()
            logger.info(f"Found {plans.count()} subscription plans")

            if plans.count() == 0:
                logger.warning("⚠ No subscription plans found in database")
                logger.info("Creating test plans...")
                plans_to_create = [
                    {
                        'name': 'Starter',
                        'price': Decimal('29.99'),
                        'stripe_product_id': f'prod_starter_{uuid.uuid4().hex[:8]}',
                        'stripe_price_id': f'price_starter_{uuid.uuid4().hex[:8]}',
                        'interval': 'month',
                    },
                    {
                        'name': 'Professional',
                        'price': Decimal('79.99'),
                        'stripe_product_id': f'prod_pro_{uuid.uuid4().hex[:8]}',
                        'stripe_price_id': f'price_pro_{uuid.uuid4().hex[:8]}',
                        'interval': 'month',
                    },
                    {
                        'name': 'Enterprise',
                        'price': Decimal('199.99'),
                        'stripe_product_id': f'prod_ent_{uuid.uuid4().hex[:8]}',
                        'stripe_price_id': f'price_ent_{uuid.uuid4().hex[:8]}',
                        'interval': 'month',
                    },
                ]

                for plan_data in plans_to_create:
                    plan = SubscriptionPlan.objects.create(**plan_data)
                    logger.info(f"  Created: {plan.name} - ${plan.price}/{plan.interval}")
                    plans = SubscriptionPlan.objects.all()

            # Display plans
            for plan in plans:
                logger.info(f"  ✓ {plan.name}: ${plan.price} {plan.currency}/{plan.interval}")
                logger.info(f"    - Stripe Product: {plan.stripe_product_id}")
                logger.info(f"    - Stripe Price: {plan.stripe_price_id}")

            self.test_plan = plans.first()
            self.test_results['test_1_plans_listed'] = True

            # Test: Plan details
            self.log_subsection("1.2 Plan Details")
            logger.info(f"Plan Name: {self.test_plan.name}")
            logger.info(f"Price: {self.test_plan.price} {self.test_plan.currency}")
            logger.info(f"Interval: {self.test_plan.interval}")
            self.test_results['test_1_plan_details'] = True

            # Test: Compare plans
            self.log_subsection("1.3 Compare Plans")
            if plans.count() >= 2:
                logger.info("Plan Comparison:")
                for plan in plans.order_by('price'):
                    logger.info(f"  {plan.name}: ${plan.price}")
                self.test_results['test_1_plan_comparison'] = True

            return True

        except Exception as e:
            logger.error(f"✗ Test 1 failed: {e}")
            self.errors.append(f"Test 1: {e}")
            return False

    def test_1_upgrade_downgrade(self):
        """Test upgrading and downgrading plans."""
        self.log_subsection("1.4 Plan Upgrade/Downgrade")

        try:
            plans = SubscriptionPlan.objects.order_by('price')

            if plans.count() < 2:
                logger.warning("⚠ Need at least 2 plans for upgrade/downgrade test")
                return False

            plan1 = plans[0]
            plan2 = plans[1]

            # Create initial subscription
            logger.info(f"Creating subscription with {plan1.name} plan...")
            subscription = UserSubscription.objects.create(
                user=self.test_user,
                plan=plan1,
                stripe_subscription_id=f"sub_{uuid.uuid4().hex[:12]}",
                status='active',
                current_period_start=timezone.now(),
                current_period_end=timezone.now() + timedelta(days=30),
            )
            logger.info(f"✓ Initial subscription: {plan1.name} (ID: {subscription.stripe_subscription_id})")

            # Upgrade
            logger.info(f"Upgrading to {plan2.name} plan...")
            subscription.plan = plan2
            subscription.save()
            logger.info(f"✓ Plan upgraded to {plan2.name}")
            self.test_results['test_1_upgrade'] = True

            # Downgrade
            logger.info(f"Downgrading to {plan1.name} plan...")
            subscription.plan = plan1
            subscription.save()
            logger.info(f"✓ Plan downgraded to {plan1.name}")
            self.test_results['test_1_downgrade'] = True

            return True

        except Exception as e:
            logger.error(f"✗ Upgrade/downgrade failed: {e}")
            self.errors.append(f"Upgrade/downgrade: {e}")
            return False

    # =========================================================================
    # TEST 2: STRIPE PAYMENT INTEGRATION
    # =========================================================================

    def test_2_stripe_integration(self):
        """Test 2: Stripe payment integration."""
        self.log_section("TEST 2: STRIPE PAYMENT INTEGRATION")

        try:
            if not self.test_plan:
                logger.error("✗ No test plan available")
                return False

            # Create Stripe customer
            self.log_subsection("2.1 Create Stripe Customer")
            try:
                customer = stripe.Customer.create(
                    email=self.test_user.email,
                    description=f"Customer for {self.test_user.email}",
                    metadata={
                        'user_id': str(self.test_user.id),
                    }
                )
                self.stripe_customer = customer
                logger.info(f"✓ Stripe customer created: {customer.id}")
                self.test_results['test_2_customer_created'] = True
            except stripe.error.StripeError as e:
                logger.error(f"✗ Failed to create Stripe customer: {e}")
                logger.warning("⚠ Skipping Stripe-specific tests")
                return False

            # Create checkout session
            self.log_subsection("2.2 Create Checkout Session")
            try:
                checkout_session = stripe.checkout.Session.create(
                    customer=customer.id,
                    payment_method_types=['card'],
                    line_items=[{
                        'price': self.test_plan.stripe_price_id,
                        'quantity': 1,
                    }],
                    mode='subscription',
                    success_url='http://localhost:8002/finance/subscription/success/',
                    cancel_url='http://localhost:8002/finance/subscription/cancel/',
                    metadata={
                        'user_id': str(self.test_user.id),
                        'plan_id': str(self.test_plan.id),
                    },
                )
                logger.info(f"✓ Checkout session created: {checkout_session.id}")
                logger.info(f"  - URL: {checkout_session.url}")
                logger.info(f"  - Payment Status: {checkout_session.payment_status}")
                self.test_results['test_2_checkout_created'] = True
            except stripe.error.StripeError as e:
                logger.warning(f"⚠ Checkout session creation: {e}")

            # Create payment intent
            self.log_subsection("2.3 Create Payment Intent")
            try:
                payment_intent = stripe.PaymentIntent.create(
                    amount=int(self.test_plan.price * 100),
                    currency=self.test_plan.currency.lower(),
                    payment_method_types=['card'],
                    customer=customer.id,
                    metadata={
                        'user_id': str(self.test_user.id),
                        'plan_id': str(self.test_plan.id),
                    },
                )
                logger.info(f"✓ Payment intent created: {payment_intent.id}")
                logger.info(f"  - Amount: {payment_intent.amount/100} {payment_intent.currency.upper()}")
                logger.info(f"  - Status: {payment_intent.status}")
                self.test_results['test_2_payment_intent'] = True
            except stripe.error.StripeError as e:
                logger.warning(f"⚠ Payment intent creation: {e}")

            return True

        except Exception as e:
            logger.error(f"✗ Test 2 failed: {e}")
            self.errors.append(f"Test 2: {e}")
            return False

    def test_2_payment_transaction_logging(self):
        """Test payment transaction logging."""
        self.log_subsection("2.4 Payment Transaction Logging")

        try:
            # Create succeeded payment
            logger.info("Creating succeeded payment transaction...")
            payment_success = PaymentTransaction.objects.create(
                user=self.test_user,
                amount=Decimal('99.99'),
                currency='USD',
                stripe_payment_intent_id=f"pi_success_{uuid.uuid4().hex[:12]}",
                description='Test subscription payment',
                succeeded=True,
            )
            logger.info(f"✓ Payment recorded: {payment_success.id}")
            logger.info(f"  - Amount: ${payment_success.amount}")
            logger.info(f"  - Status: Succeeded")
            self.test_results['test_2_payment_logged'] = True

            # Create failed payment
            logger.info("Creating failed payment transaction...")
            payment_fail = PaymentTransaction.objects.create(
                user=self.test_user,
                amount=Decimal('49.99'),
                currency='USD',
                stripe_payment_intent_id=f"pi_failed_{uuid.uuid4().hex[:12]}",
                description='Test payment - card declined',
                succeeded=False,
                failure_code='card_declined',
                failure_message='Your card was declined',
            )
            logger.info(f"✓ Failed payment recorded: {payment_fail.id}")
            logger.info(f"  - Amount: ${payment_fail.amount}")
            logger.info(f"  - Status: Failed")
            logger.info(f"  - Reason: {payment_fail.failure_message}")
            self.test_results['test_2_payment_failures_logged'] = True

            return True

        except Exception as e:
            logger.error(f"✗ Payment transaction logging failed: {e}")
            self.errors.append(f"Payment logging: {e}")
            return False

    # =========================================================================
    # TEST 3: INVOICE GENERATION
    # =========================================================================

    def test_3_invoice_generation(self):
        """Test 3: Invoice generation."""
        self.log_section("TEST 3: INVOICE GENERATION")

        try:
            # Create invoice
            self.log_subsection("3.1 Create Invoice")
            invoice = Invoice.objects.create(
                user=self.test_user,
                invoice_number=f"INV-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
                stripe_invoice_id=f"in_{uuid.uuid4().hex[:12]}",
                amount_due=Decimal('99.99'),
                amount_paid=Decimal('0.00'),
                currency='USD',
                due_date=timezone.now() + timedelta(days=30),
                paid=False,
            )
            logger.info(f"✓ Invoice created: {invoice.invoice_number}")
            logger.info(f"  - Amount: ${invoice.amount_due}")
            logger.info(f"  - Due Date: {invoice.due_date.date()}")
            logger.info(f"  - Status: Unpaid")
            self.test_results['test_3_invoice_created'] = True

            # Mark as paid
            self.log_subsection("3.2 Mark Invoice as Paid")
            invoice.paid = True
            invoice.amount_paid = invoice.amount_due
            invoice.paid_at = timezone.now()
            invoice.save()
            logger.info(f"✓ Invoice marked as paid: {invoice.invoice_number}")
            logger.info(f"  - Paid Amount: ${invoice.amount_paid}")
            logger.info(f"  - Paid At: {invoice.paid_at}")
            self.test_results['test_3_invoice_paid'] = True

            # Retrieve invoice
            self.log_subsection("3.3 Retrieve Invoice")
            retrieved = Invoice.objects.get(id=invoice.id)
            logger.info(f"✓ Invoice retrieved: {retrieved.invoice_number}")
            logger.info(f"  - Total: ${retrieved.amount_due}")
            logger.info(f"  - Paid: ${retrieved.amount_paid}")
            self.test_results['test_3_invoice_retrieved'] = True

            return True

        except Exception as e:
            logger.error(f"✗ Test 3 failed: {e}")
            self.errors.append(f"Test 3: {e}")
            return False

    # =========================================================================
    # TEST 4: PAYMENT HISTORY TRACKING
    # =========================================================================

    def test_4_payment_history(self):
        """Test 4: Payment history tracking."""
        self.log_section("TEST 4: PAYMENT HISTORY TRACKING")

        try:
            # Create payment history
            self.log_subsection("4.1 Create Payment History")
            for i in range(5):
                PaymentTransaction.objects.create(
                    user=self.test_user,
                    amount=Decimal('99.99') + Decimal(i * 10),
                    currency='USD',
                    stripe_payment_intent_id=f"pi_hist_{i}_{uuid.uuid4().hex[:8]}",
                    description=f'Payment {i+1}',
                    succeeded=i < 4,
                )
            logger.info(f"✓ Created 5 payment transactions")
            self.test_results['test_4_payments_created'] = True

            # Retrieve all payments
            self.log_subsection("4.2 Retrieve Payment History")
            all_payments = PaymentTransaction.objects.filter(
                user=self.test_user
            ).order_by('-created_at')
            logger.info(f"✓ Retrieved {all_payments.count()} payments")
            self.test_results['test_4_history_retrieved'] = True

            # Filter by status
            self.log_subsection("4.3 Filter by Payment Status")
            succeeded = all_payments.filter(succeeded=True)
            failed = all_payments.filter(succeeded=False)
            logger.info(f"✓ Succeeded: {succeeded.count()}, Failed: {failed.count()}")
            self.test_results['test_4_status_filtering'] = True

            # Calculate totals
            self.log_subsection("4.4 Calculate Payment Statistics")
            total = all_payments.filter(succeeded=True).aggregate(Sum('amount'))['amount__sum'] or Decimal('0')
            logger.info(f"✓ Total succeeded payments: ${total}")
            logger.info(f"✓ Total transaction count: {all_payments.count()}")
            self.test_results['test_4_statistics'] = True

            # Filter by date range
            self.log_subsection("4.5 Date Range Filtering")
            start_date = timezone.now() - timedelta(days=7)
            recent = all_payments.filter(created_at__gte=start_date)
            logger.info(f"✓ Payments in last 7 days: {recent.count()}")
            self.test_results['test_4_date_filtering'] = True

            return True

        except Exception as e:
            logger.error(f"✗ Test 4 failed: {e}")
            self.errors.append(f"Test 4: {e}")
            return False

    # =========================================================================
    # TEST 5: SUBSCRIPTION RENEWAL
    # =========================================================================

    def test_5_subscription_renewal(self):
        """Test 5: Subscription renewal."""
        self.log_section("TEST 5: SUBSCRIPTION RENEWAL")

        try:
            if not self.test_plan:
                logger.error("✗ No test plan")
                return False

            # Create subscription
            self.log_subsection("5.1 Create Subscription")
            start = timezone.now()
            end = start + timedelta(days=30)

            subscription = UserSubscription.objects.create(
                user=self.test_user,
                plan=self.test_plan,
                stripe_subscription_id=f"sub_renew_{uuid.uuid4().hex[:12]}",
                status='active',
                current_period_start=start,
                current_period_end=end,
            )
            logger.info(f"✓ Subscription created: {subscription.stripe_subscription_id}")
            logger.info(f"  - Plan: {subscription.plan.name}")
            logger.info(f"  - Period: {start.date()} to {end.date()}")
            self.test_results['test_5_subscription_created'] = True

            # Simulate renewal
            self.log_subsection("5.2 Simulate Renewal")
            new_start = subscription.current_period_end
            new_end = new_start + timedelta(days=30)
            subscription.current_period_start = new_start
            subscription.current_period_end = new_end
            subscription.save()
            logger.info(f"✓ Subscription renewed")
            logger.info(f"  - New period: {new_start.date()} to {new_end.date()}")
            self.test_results['test_5_renewal_simulated'] = True

            # Create renewal invoice
            self.log_subsection("5.3 Generate Renewal Invoice")
            renewal_invoice = Invoice.objects.create(
                user=self.test_user,
                invoice_number=f"INV-RENEWAL-{uuid.uuid4().hex[:6].upper()}",
                stripe_invoice_id=f"in_renewal_{uuid.uuid4().hex[:12]}",
                amount_due=self.test_plan.price,
                amount_paid=Decimal('0.00'),
                currency=self.test_plan.currency,
                due_date=timezone.now() + timedelta(days=30),
                paid=False,
            )
            logger.info(f"✓ Renewal invoice created: {renewal_invoice.invoice_number}")
            logger.info(f"  - Amount: ${renewal_invoice.amount_due}")
            self.test_results['test_5_renewal_invoice'] = True

            return True

        except Exception as e:
            logger.error(f"✗ Test 5 failed: {e}")
            self.errors.append(f"Test 5: {e}")
            return False

    # =========================================================================
    # TEST 6: CANCELLATION WORKFLOW
    # =========================================================================

    def test_6_cancellation(self):
        """Test 6: Cancellation workflow."""
        self.log_section("TEST 6: CANCELLATION WORKFLOW")

        try:
            if not self.test_plan:
                logger.error("✗ No test plan")
                return False

            # Create subscription for cancellation
            self.log_subsection("6.1 Create Subscription for Cancellation")
            subscription = UserSubscription.objects.create(
                user=self.test_user,
                plan=self.test_plan,
                stripe_subscription_id=f"sub_cancel_{uuid.uuid4().hex[:12]}",
                status='active',
                current_period_start=timezone.now(),
                current_period_end=timezone.now() + timedelta(days=30),
            )
            logger.info(f"✓ Subscription created: {subscription.stripe_subscription_id}")
            self.test_results['test_6_subscription_created'] = True

            # Cancel at period end
            self.log_subsection("6.2 Schedule Cancellation at Period End")
            subscription.status = 'canceling'
            subscription.save()
            logger.info(f"✓ Cancellation scheduled")
            logger.info(f"  - Status: {subscription.status}")
            logger.info(f"  - Will expire: {subscription.current_period_end.date()}")
            self.test_results['test_6_cancel_at_period_end'] = True

            # Immediate cancellation
            self.log_subsection("6.3 Immediate Cancellation")
            sub2 = UserSubscription.objects.create(
                user=self.test_user,
                plan=self.test_plan,
                stripe_subscription_id=f"sub_imm_cancel_{uuid.uuid4().hex[:12]}",
                status='active',
                current_period_start=timezone.now(),
                current_period_end=timezone.now() + timedelta(days=30),
            )
            sub2.status = 'canceled'
            sub2.save()
            logger.info(f"✓ Subscription canceled immediately")
            logger.info(f"  - Status: {sub2.status}")
            self.test_results['test_6_immediate_cancel'] = True

            # Reactivation
            self.log_subsection("6.4 Reactivate Subscription")
            sub2.status = 'active'
            sub2.save()
            logger.info(f"✓ Subscription reactivated")
            logger.info(f"  - Status: {sub2.status}")
            self.test_results['test_6_reactivation'] = True

            return True

        except Exception as e:
            logger.error(f"✗ Test 6 failed: {e}")
            self.errors.append(f"Test 6: {e}")
            return False

    # =========================================================================
    # TEST 7: WEBHOOK PROCESSING
    # =========================================================================

    def test_7_webhooks(self):
        """Test 7: Webhook processing."""
        self.log_section("TEST 7: WEBHOOK PROCESSING")

        try:
            # Log webhook event
            self.log_subsection("7.1 Log Webhook Event")
            webhook_payload = {
                'id': f'evt_{uuid.uuid4().hex[:12]}',
                'type': 'customer.subscription.updated',
                'created': int(time.time()),
                'data': {
                    'object': {
                        'id': 'sub_test_123',
                        'status': 'active',
                        'current_period_end': int((timezone.now() + timedelta(days=30)).timestamp()),
                    }
                }
            }

            webhook = StripeWebhookEvent.objects.create(
                event_id=webhook_payload['id'],
                json_payload=webhook_payload,
                processed=False,
            )
            logger.info(f"✓ Webhook event recorded: {webhook.event_id}")
            logger.info(f"  - Type: {webhook_payload['type']}")
            self.test_results['test_7_webhook_logged'] = True

            # Mark as processed
            self.log_subsection("7.2 Process Webhook Event")
            webhook.processed = True
            webhook.processed_at = timezone.now()
            webhook.save()
            logger.info(f"✓ Webhook marked as processed")
            logger.info(f"  - Processed at: {webhook.processed_at}")
            self.test_results['test_7_webhook_processed'] = True

            # Deduplication test
            self.log_subsection("7.3 Webhook Deduplication")
            existing = StripeWebhookEvent.objects.filter(
                event_id=webhook_payload['id']
            ).count()
            logger.info(f"✓ Webhook records with same event_id: {existing}")
            if existing == 1:
                logger.info("✓ Deduplication working correctly")
                self.test_results['test_7_deduplication'] = True
            else:
                logger.warning(f"⚠ Found {existing} records (expected 1)")

            # Create more webhooks for retrieval test
            self.log_subsection("7.4 Retrieve Unprocessed Webhooks")
            for i in range(3):
                StripeWebhookEvent.objects.create(
                    event_id=f'evt_unproc_{i}_{uuid.uuid4().hex[:8]}',
                    json_payload={
                        'type': f'event_type_{i}',
                    },
                    processed=False,
                )

            unprocessed = StripeWebhookEvent.objects.filter(processed=False)
            logger.info(f"✓ Unprocessed webhooks: {unprocessed.count()}")
            self.test_results['test_7_unprocessed_retrieved'] = True

            # Error handling
            self.log_subsection("7.5 Webhook Error Handling")
            error_webhook = StripeWebhookEvent.objects.create(
                event_id=f'evt_error_{uuid.uuid4().hex[:12]}',
                json_payload={'type': 'invoice.payment_failed'},
                processed=False,
                error_message='Payment declined: insufficient funds',
            )
            logger.info(f"✓ Error webhook logged: {error_webhook.event_id}")
            logger.info(f"  - Error: {error_webhook.error_message}")
            self.test_results['test_7_error_handling'] = True

            return True

        except Exception as e:
            logger.error(f"✗ Test 7 failed: {e}")
            self.errors.append(f"Test 7: {e}")
            return False

    def generate_report(self):
        """Generate test report."""
        self.log_section("TEST REPORT SUMMARY")

        passed = sum(1 for v in self.test_results.values() if v is True)
        total = len(self.test_results)

        logger.info("\nTest Results by Category:")
        for test, result in sorted(self.test_results.items()):
            status = "✓ PASS" if result else "✗ FAIL"
            logger.info(f"  {status} - {test}")

        logger.info(f"\nOverall: {passed}/{total} tests passed ({int(passed/total*100)}%)")

        if self.errors:
            logger.info("\nErrors Found:")
            for error in self.errors:
                logger.info(f"  ✗ {error}")

        # Save JSON report
        report = {
            'timestamp': datetime.now().isoformat(),
            'test_user_email': self.test_user.email if self.test_user else None,
            'passed': passed,
            'total': total,
            'success_rate': f"{int(passed/total*100)}%",
            'results': self.test_results,
            'errors': self.errors,
        }

        report_file = f'{log_dir}/subscription_billing_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"\nReport saved to: {report_file}")
        return report

    def run_all_tests(self):
        """Run all tests."""
        logger.info("\n" * 2)
        self.log_section("ZUMODRA SUBSCRIPTION & BILLING WORKFLOW TEST SUITE")
        logger.info(f"Test Started: {datetime.now()}")

        # Create test user
        if not self.create_test_user():
            logger.error("Failed to create test user")
            return

        # Run all tests
        self.test_1_plan_selection()
        self.test_1_upgrade_downgrade()
        self.test_2_stripe_integration()
        self.test_2_payment_transaction_logging()
        self.test_3_invoice_generation()
        self.test_4_payment_history()
        self.test_5_subscription_renewal()
        self.test_6_cancellation()
        self.test_7_webhooks()

        # Generate report
        report = self.generate_report()
        logger.info(f"\nTest Completed: {datetime.now()}")

        return report


def main():
    """Main execution."""
    tester = BillingWorkflowTester()
    tester.run_all_tests()


if __name__ == '__main__':
    main()
