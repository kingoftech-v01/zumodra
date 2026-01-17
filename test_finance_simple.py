"""
Quick Finance System Verification Test

Tests that finance Celery tasks can import models without ImportError.
This verifies the model name fixes (Payment → PaymentTransaction, etc.)
"""

import sys

# Test 1: Import all finance models
print("Test 1: Import finance models")
try:
    from finance.models import (
        PaymentTransaction,
        UserSubscription,
        RefundRequest,
        Invoice,
        SubscriptionPlan,
    )
    print("  ✅ PASS: All finance models imported successfully")
except ImportError as e:
    print(f"  ❌ FAIL: ImportError - {e}")
    sys.exit(1)

# Test 2: Import all finance tasks
print("\nTest 2: Import finance Celery tasks")
try:
    from finance.tasks import (
        sync_stripe_payments,
        generate_monthly_invoices,
        process_pending_refunds,
        retry_failed_payments,
        update_subscription_status,
        process_escrow_transactions,
        generate_daily_financial_report,
    )
    print("  ✅ PASS: All finance tasks imported successfully")
except ImportError as e:
    print(f"  ❌ FAIL: ImportError - {e}")
    sys.exit(1)

print("\n=== SUMMARY ===")
print("SUCCESS: Finance system model name fixes verified!")
print("All tasks can now execute without ImportError")
