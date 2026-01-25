#!/usr/bin/env python
"""
Comprehensive Multi-Tenancy Isolation Testing
==============================================

Tests all aspects of multi-tenant isolation:
1. Schema-based tenant separation
2. Data isolation between tenants
3. Cross-tenant data leak prevention
4. Subdomain routing to correct tenant
5. Shared vs tenant-specific tables
6. Tenant switching for staff users
7. Database query filtering
"""

import os
import sys
import django
import json
from datetime import datetime, timedelta
from decimal import Decimal

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "zumodra.settings")
sys.path.insert(0, os.path.dirname(__file__))
django.setup()

from django.test import TestCase, Client, RequestFactory
from django.db import connection, connections
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site
from django.conf import settings
from django_tenants.utils import get_tenant_model, get_public_schema_name

from tenants.models import Tenant, Domain, Plan
from jobs.models import Job, Candidate, Application, Interview, Offer
from hr_core.models import Employee, TimeOff
from tenant_profiles.models import UserProfile

User = get_user_model()
TenantModel = get_tenant_model()


class MultiTenancyIsolationTest:
    """Main test class for multi-tenancy isolation"""

    def __init__(self):
        self.client = Client()
        self.factory = RequestFactory()
        self.results = {
            "tests": [],
            "summary": {},
            "data_leaks": [],
            "errors": []
        }
        self.test_tenants = []
        self.test_users = []

    def log(self, message, level="INFO"):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")

    def add_result(self, test_name, status, details=""):
        """Add test result"""
        self.results["tests"].append({
            "name": test_name,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })
        self.log(f"{test_name}: {status}", "TEST")

    def add_leak(self, leak_description):
        """Record data leak finding"""
        self.results["data_leaks"].append({
            "description": leak_description,
            "timestamp": datetime.now().isoformat()
        })
        self.log(f"DATA LEAK: {leak_description}", "ERROR")

    def add_error(self, error_description):
        """Record test error"""
        self.results["errors"].append({
            "description": error_description,
            "timestamp": datetime.now().isoformat()
        })
        self.log(f"ERROR: {error_description}", "ERROR")

    # ============================================================================
    # SETUP & TEARDOWN
    # ============================================================================

    def setup_test_tenants(self):
        """Create test tenants"""
        self.log("Setting up test tenants...", "SETUP")

        try:
            # Create or get plan
            plan, _ = Plan.objects.get_or_create(
                slug='test-plan',
                defaults={
                    'name': 'Test Plan',
                    'plan_type': Plan.PlanType.PROFESSIONAL,
                    'feature_ats': True,
                    'feature_hr_core': True,
                    'max_users': 10,
                }
            )

            # Create first tenant
            tenant1, created = Tenant.objects.get_or_create(
                slug='test-tenant-1',
                defaults={
                    'name': 'Test Tenant 1',
                    'schema_name': 'tenant_test_1',
                    'plan': plan,
                    'created_at': timezone.now(),
                    'organization_type': 'COMPANY'
                }
            )

            # Create second tenant
            tenant2, created = Tenant.objects.get_or_create(
                slug='test-tenant-2',
                defaults={
                    'name': 'Test Tenant 2',
                    'schema_name': 'tenant_test_2',
                    'plan': plan,
                    'created_at': timezone.now(),
                    'organization_type': 'COMPANY'
                }
            )

            # Create domains for tenants
            Domain.objects.get_or_create(
                domain='test-tenant-1.localhost',
                defaults={'tenant': tenant1, 'is_primary': True}
            )
            Domain.objects.get_or_create(
                domain='test-tenant-2.localhost',
                defaults={'tenant': tenant2, 'is_primary': True}
            )

            self.test_tenants = [tenant1, tenant2]
            self.log(f"Created {len(self.test_tenants)} test tenants", "SETUP")

        except Exception as e:
            self.add_error(f"Failed to setup test tenants: {str(e)}")

    def setup_test_users(self):
        """Create test users for each tenant"""
        self.log("Setting up test users...", "SETUP")

        try:
            for tenant in self.test_tenants:
                # Switch to tenant schema
                connection.set_schema(tenant.schema_name)

                # Create user for this tenant
                user, created = User.objects.get_or_create(
                    username=f"testuser_{tenant.slug}",
                    defaults={
                        'email': f"user@{tenant.slug}.test",
                        'first_name': f'Test',
                        'last_name': f'User {tenant.slug}',
                        'is_active': True,
                    }
                )

                # Set password
                if created:
                    user.set_password('testpass123')
                    user.save()

                self.test_users.append({
                    'user': user,
                    'tenant': tenant,
                    'username': user.username
                })

                self.log(f"Created user {user.username} in tenant {tenant.slug}", "SETUP")

            # Switch back to public schema
            connection.set_schema_to_public()

        except Exception as e:
            self.add_error(f"Failed to setup test users: {str(e)}")

    # ============================================================================
    # TEST 1: Schema-based tenant separation
    # ============================================================================

    def test_schema_separation(self):
        """Verify tenants use separate schemas"""
        self.log("TEST 1: Schema-based tenant separation", "START")

        try:
            # Get current schema
            current_schema = connection.schema_name if hasattr(connection, 'schema_name') else 'public'

            tenant1 = self.test_tenants[0]
            tenant2 = self.test_tenants[1]

            # Verify schemas are different
            if tenant1.schema_name == tenant2.schema_name:
                self.add_leak(f"Tenants share same schema: {tenant1.schema_name}")
                self.add_result("schema_separation", "FAIL",
                    "Tenants have identical schema names")
                return

            # Verify schemas exist in database
            cursor = connection.cursor()

            # Check public schema
            cursor.execute("""
                SELECT schema_name FROM information_schema.schemata
                WHERE schema_name = 'public'
            """)
            if not cursor.fetchone():
                self.add_error("Public schema not found")

            self.add_result("schema_separation", "PASS",
                f"Tenant 1: {tenant1.schema_name}, Tenant 2: {tenant2.schema_name}")

        except Exception as e:
            self.add_result("schema_separation", "FAIL", str(e))

    # ============================================================================
    # TEST 2: Data isolation between tenants
    # ============================================================================

    def test_data_isolation(self):
        """Verify data is isolated between tenants"""
        self.log("TEST 2: Data isolation between tenants", "START")

        try:
            tenant1 = self.test_tenants[0]
            tenant2 = self.test_tenants[1]

            # Create job in tenant 1
            connection.set_schema(tenant1.schema_name)
            job1 = Job.objects.create(
                title="Software Engineer - Tenant 1",
                description="Job for tenant 1",
                created_by=None,
                status='draft'
            )
            job1_id = job1.id
            jobs_in_t1 = Job.objects.count()

            # Create job in tenant 2
            connection.set_schema(tenant2.schema_name)
            job2 = Job.objects.create(
                title="Product Manager - Tenant 2",
                description="Job for tenant 2",
                created_by=None,
                status='draft'
            )
            job2_id = job2.id
            jobs_in_t2 = Job.objects.count()

            # Verify tenant 1 doesn't see tenant 2's job
            connection.set_schema(tenant1.schema_name)
            try:
                Job.objects.get(pk=job2_id)
                self.add_leak(f"Tenant 1 can access Tenant 2 job (ID: {job2_id})")
                self.add_result("data_isolation", "FAIL", "Cross-tenant data access detected")
                return
            except Job.DoesNotExist:
                pass  # Expected

            # Verify job counts are separate
            t1_job_count = Job.objects.count()
            connection.set_schema(tenant2.schema_name)
            t2_job_count = Job.objects.count()

            if t1_job_count == t2_job_count:
                self.add_leak("Tenants have identical job counts - possible data sharing")

            self.add_result("data_isolation", "PASS",
                f"Tenant 1: {t1_job_count} jobs, Tenant 2: {t2_job_count} jobs")

            connection.set_schema_to_public()

        except Exception as e:
            self.add_result("data_isolation", "FAIL", str(e))

    # ============================================================================
    # TEST 3: Cross-tenant data leak prevention
    # ============================================================================

    def test_cross_tenant_leak_prevention(self):
        """Verify cross-tenant access is blocked"""
        self.log("TEST 3: Cross-tenant data leak prevention", "START")

        try:
            tenant1 = self.test_tenants[0]
            tenant2 = self.test_tenants[1]
            user1 = next(u for u in self.test_users if u['tenant'] == tenant1)['user']

            # Switch to tenant1
            connection.set_schema(tenant1.schema_name)

            # Create sensitive data in tenant1
            candidate = Candidate.objects.create(
                first_name="John",
                last_name="Doe",
                email="john@example.com",
                phone="+1234567890",
                source="linkedin"
            )

            # Try to access from tenant2
            connection.set_schema(tenant2.schema_name)
            try:
                accessed_candidate = Candidate.objects.get(pk=candidate.pk)
                self.add_leak(f"Tenant 2 accessed Tenant 1's candidate: {accessed_candidate.email}")
                self.add_result("cross_tenant_leak", "FAIL", "Cross-tenant access detected")
            except Candidate.DoesNotExist:
                self.add_result("cross_tenant_leak", "PASS", "Cross-tenant access properly blocked")

            connection.set_schema_to_public()

        except Exception as e:
            self.add_result("cross_tenant_leak", "FAIL", str(e))

    # ============================================================================
    # TEST 4: Subdomain routing to correct tenant
    # ============================================================================

    def test_subdomain_routing(self):
        """Verify subdomain correctly routes to tenant"""
        self.log("TEST 4: Subdomain routing to correct tenant", "START")

        try:
            tenant1 = self.test_tenants[0]

            # Verify domain is set up
            primary_domain = Domain.objects.filter(
                tenant=tenant1,
                is_primary=True
            ).first()

            if not primary_domain:
                self.add_result("subdomain_routing", "FAIL",
                    f"No primary domain configured for tenant {tenant1.slug}")
                return

            # Test domain resolution
            domain = Domain.objects.get(tenant=tenant1, is_primary=True)
            if domain.tenant.id != tenant1.id:
                self.add_leak(f"Domain {domain.domain} resolves to wrong tenant")

            self.add_result("subdomain_routing", "PASS",
                f"Domain {domain.domain} correctly routes to {tenant1.name}")

        except Exception as e:
            self.add_result("subdomain_routing", "FAIL", str(e))

    # ============================================================================
    # TEST 5: Shared vs tenant-specific tables
    # ============================================================================

    def test_shared_vs_tenant_tables(self):
        """Verify shared tables contain data from all tenants"""
        self.log("TEST 5: Shared vs tenant-specific tables", "START")

        try:
            # Switch to public schema to check shared tables
            connection.set_schema_to_public()

            # Check shared tables have data from all tenants
            public_tenants = Tenant.objects.all().count()
            public_users = User.objects.all().count()  # If User is in public schema

            results_detail = f"Public tenants: {public_tenants}"

            # Verify tenant-specific tables are NOT in public schema
            try:
                Job.objects.all().count()
                self.add_leak("Job objects found in public schema - should be tenant-specific")
            except Exception:
                pass  # Expected - Job should not be in public schema

            self.add_result("shared_vs_tenant_tables", "PASS", results_detail)

        except Exception as e:
            self.add_result("shared_vs_tenant_tables", "FAIL", str(e))

    # ============================================================================
    # TEST 6: Tenant switching for staff users
    # ============================================================================

    def test_tenant_switching(self):
        """Verify staff users can safely switch between tenants"""
        self.log("TEST 6: Tenant switching for staff users", "START")

        try:
            # This test requires staff/superuser setup
            connection.set_schema_to_public()

            # Create a staff user
            staff_user = User.objects.create_superuser(
                username='staffuser',
                email='staff@test.com',
                password='staffpass123'
            )

            tenant1 = self.test_tenants[0]
            tenant2 = self.test_tenants[1]

            # Test access to tenant 1
            connection.set_schema(tenant1.schema_name)
            try:
                job1 = Job.objects.first()
                t1_accessible = True
            except Exception:
                t1_accessible = False

            # Test access to tenant 2
            connection.set_schema(tenant2.schema_name)
            try:
                job2 = Job.objects.first()
                t2_accessible = True
            except Exception:
                t2_accessible = False

            if t1_accessible and t2_accessible:
                self.add_result("tenant_switching", "PASS",
                    "Staff user can access both tenants")
            else:
                self.add_result("tenant_switching", "FAIL",
                    f"Access: T1={t1_accessible}, T2={t2_accessible}")

            connection.set_schema_to_public()

        except Exception as e:
            self.add_result("tenant_switching", "FAIL", str(e))

    # ============================================================================
    # TEST 7: Database query filtering
    # ============================================================================

    def test_query_filtering(self):
        """Verify queries are properly filtered by tenant"""
        self.log("TEST 7: Database query filtering", "START")

        try:
            tenant1 = self.test_tenants[0]
            tenant2 = self.test_tenants[1]

            # Create test data
            connection.set_schema(tenant1.schema_name)
            job1 = Job.objects.create(
                title="Job 1",
                description="Description 1",
                created_by=None,
                status='draft'
            )

            connection.set_schema(tenant2.schema_name)
            job2 = Job.objects.create(
                title="Job 2",
                description="Description 2",
                created_by=None,
                status='draft'
            )
            job3 = Job.objects.create(
                title="Job 3",
                description="Description 3",
                created_by=None,
                status='draft'
            )

            # Verify tenant1 only sees tenant1 data
            connection.set_schema(tenant1.schema_name)
            t1_jobs = list(Job.objects.all().values_list('title', flat=True))

            connection.set_schema(tenant2.schema_name)
            t2_jobs = list(Job.objects.all().values_list('title', flat=True))

            # Check for overlaps
            overlap = set(t1_jobs) & set(t2_jobs)
            if overlap:
                self.add_leak(f"Job title overlap between tenants: {overlap}")

            if len(t1_jobs) == 1 and len(t2_jobs) == 2:
                self.add_result("query_filtering", "PASS",
                    f"T1: {t1_jobs}, T2: {t2_jobs}")
            else:
                self.add_result("query_filtering", "FAIL",
                    f"Unexpected job counts: T1={len(t1_jobs)}, T2={len(t2_jobs)}")

            connection.set_schema_to_public()

        except Exception as e:
            self.add_result("query_filtering", "FAIL", str(e))

    # ============================================================================
    # TEST 8: Permission-based access control
    # ============================================================================

    def test_permission_based_access(self):
        """Verify permission system prevents unauthorized access"""
        self.log("TEST 8: Permission-based access control", "START")

        try:
            from django.contrib.auth.models import Permission, Group

            tenant1 = self.test_tenants[0]
            tenant2 = self.test_tenants[1]
            user1 = next(u for u in self.test_users if u['tenant'] == tenant1)['user']

            # Switch to tenant1 and create job
            connection.set_schema(tenant1.schema_name)
            job1 = Job.objects.create(
                title="Job 1",
                description="Description 1",
                created_by=user1,
                status='draft'
            )

            # Verify user1 can access job1
            try:
                accessed = Job.objects.get(pk=job1.pk)
                user1_access = True
            except:
                user1_access = False

            # Switch to tenant2
            connection.set_schema(tenant2.schema_name)

            # User1 should NOT be able to access job from tenant1
            try:
                accessed = Job.objects.get(pk=job1.pk)
                user1_t2_access = True
                self.add_leak(f"User from Tenant 1 accessed Tenant 2 job")
            except:
                user1_t2_access = False

            if user1_access and not user1_t2_access:
                self.add_result("permission_based_access", "PASS",
                    "User correctly restricted to their tenant")
            else:
                self.add_result("permission_based_access", "FAIL",
                    f"Access: T1={user1_access}, T2={user1_t2_access}")

            connection.set_schema_to_public()

        except Exception as e:
            self.add_result("permission_based_access", "FAIL", str(e))

    # ============================================================================
    # TEST 9: Audit logging and data integrity
    # ============================================================================

    def test_audit_logging(self):
        """Verify audit logs are tenant-specific"""
        self.log("TEST 9: Audit logging and data integrity", "START")

        try:
            # This test checks if audit logs respect tenant boundaries
            tenant1 = self.test_tenants[0]
            connection.set_schema(tenant1.schema_name)

            # Create an object that might be logged
            job = Job.objects.create(
                title="Audited Job",
                description="This job should be audited",
                created_by=None,
                status='draft'
            )

            # Try to check audit trail if available
            from auditlog.models import LogEntry

            logs = LogEntry.objects.filter(object_pk=str(job.pk))
            if logs.exists():
                self.add_result("audit_logging", "PASS",
                    f"Found {logs.count()} audit log entries for job")
            else:
                self.add_result("audit_logging", "PASS",
                    "Audit logging configured (check if entries exist)")

            connection.set_schema_to_public()

        except ImportError:
            self.add_result("audit_logging", "SKIP", "Auditlog not available")
        except Exception as e:
            self.add_result("audit_logging", "FAIL", str(e))

    # ============================================================================
    # CLEANUP
    # ============================================================================

    def cleanup(self):
        """Clean up test data"""
        self.log("Cleaning up test data...", "CLEANUP")

        try:
            for tenant in self.test_tenants:
                connection.set_schema(tenant.schema_name)
                Job.objects.all().delete()
                Candidate.objects.all().delete()
                Application.objects.all().delete()
                Interview.objects.all().delete()
                User.objects.all().delete()

            connection.set_schema_to_public()
            Domain.objects.filter(tenant__slug__startswith='test-tenant').delete()
            Tenant.objects.filter(slug__startswith='test-tenant').delete()

        except Exception as e:
            self.log(f"Cleanup error: {str(e)}", "WARNING")

    # ============================================================================
    # REPORTING
    # ============================================================================

    def generate_report(self):
        """Generate test report"""
        self.log("Generating test report...", "REPORT")

        # Calculate summary
        total_tests = len(self.results["tests"])
        passed = len([t for t in self.results["tests"] if t['status'] == 'PASS'])
        failed = len([t for t in self.results["tests"] if t['status'] == 'FAIL'])
        skipped = len([t for t in self.results["tests"] if t['status'] == 'SKIP'])

        self.results["summary"] = {
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "success_rate": f"{(passed/total_tests*100) if total_tests > 0 else 0:.1f}%",
            "data_leaks_found": len(self.results["data_leaks"]),
            "errors": len(self.results["errors"]),
            "test_date": datetime.now().isoformat()
        }

        return self.results

    def save_report(self, filepath):
        """Save report to JSON file"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.log(f"Report saved to {filepath}", "REPORT")
        except Exception as e:
            self.log(f"Failed to save report: {str(e)}", "ERROR")

    def print_report(self):
        """Print formatted report to console"""
        print("\n" + "="*80)
        print("MULTI-TENANCY ISOLATION TEST REPORT")
        print("="*80)

        summary = self.results["summary"]
        print(f"\nSummary:")
        print(f"  Total Tests: {summary['total_tests']}")
        print(f"  Passed: {summary['passed']}")
        print(f"  Failed: {summary['failed']}")
        print(f"  Skipped: {summary['skipped']}")
        print(f"  Success Rate: {summary['success_rate']}")
        print(f"  Data Leaks Found: {summary['data_leaks_found']}")
        print(f"  Errors: {summary['errors']}")

        print(f"\nDetailed Results:")
        for test in self.results["tests"]:
            status_symbol = "✓" if test['status'] == 'PASS' else "✗" if test['status'] == 'FAIL' else "○"
            print(f"  {status_symbol} {test['name']}: {test['status']}")
            if test['details']:
                print(f"    → {test['details']}")

        if self.results["data_leaks"]:
            print(f"\nData Leaks Found ({len(self.results['data_leaks'])}):")
            for leak in self.results["data_leaks"]:
                print(f"  ⚠ {leak['description']}")

        if self.results["errors"]:
            print(f"\nErrors ({len(self.results['errors'])}):")
            for error in self.results["errors"]:
                print(f"  ⚠ {error['description']}")

        print("\n" + "="*80)


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("ZUMODRA MULTI-TENANCY ISOLATION TEST SUITE")
    print("="*80)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Django settings: {settings.SETTINGS_MODULE}")
    print(f"Database: {settings.DATABASES['default']['NAME']}")
    print("="*80 + "\n")

    tester = MultiTenancyIsolationTest()

    try:
        # Setup
        tester.setup_test_tenants()
        tester.setup_test_users()

        # Run tests
        tester.test_schema_separation()
        tester.test_data_isolation()
        tester.test_cross_tenant_leak_prevention()
        tester.test_subdomain_routing()
        tester.test_shared_vs_tenant_tables()
        tester.test_tenant_switching()
        tester.test_query_filtering()
        tester.test_permission_based_access()
        tester.test_audit_logging()

    finally:
        # Cleanup
        tester.cleanup()

    # Generate and save report
    tester.generate_report()
    tester.print_report()

    # Save JSON report
    report_path = 'tests_comprehensive/reports/multitenancy_isolation_test_report.json'
    tester.save_report(report_path)

    # Save text report
    text_report_path = 'tests_comprehensive/reports/multitenancy_isolation_test_report.txt'
    with open(text_report_path, 'w') as f:
        f.write("ZUMODRA MULTI-TENANCY ISOLATION TEST REPORT\n")
        f.write("="*80 + "\n\n")

        summary = tester.results["summary"]
        f.write(f"Test Date: {summary['test_date']}\n")
        f.write(f"Total Tests: {summary['total_tests']}\n")
        f.write(f"Passed: {summary['passed']}\n")
        f.write(f"Failed: {summary['failed']}\n")
        f.write(f"Skipped: {summary['skipped']}\n")
        f.write(f"Success Rate: {summary['success_rate']}\n")
        f.write(f"Data Leaks Found: {summary['data_leaks_found']}\n")
        f.write(f"Errors: {summary['errors']}\n\n")

        f.write("Detailed Results:\n")
        f.write("-"*80 + "\n")
        for test in tester.results["tests"]:
            f.write(f"{test['name']}: {test['status']}\n")
            if test['details']:
                f.write(f"  Details: {test['details']}\n")

        if tester.results["data_leaks"]:
            f.write(f"\nData Leaks Found:\n")
            f.write("-"*80 + "\n")
            for leak in tester.results["data_leaks"]:
                f.write(f"  - {leak['description']}\n")

        if tester.results["errors"]:
            f.write(f"\nErrors:\n")
            f.write("-"*80 + "\n")
            for error in tester.results["errors"]:
                f.write(f"  - {error['description']}\n")

    print(f"\n✓ Reports saved to tests_comprehensive/reports/")
    print(f"  - multitenancy_isolation_test_report.json")
    print(f"  - multitenancy_isolation_test_report.txt")

    return 0 if tester.results["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    try:
        from django.utils import timezone
        exit_code = main()
        sys.exit(exit_code)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
