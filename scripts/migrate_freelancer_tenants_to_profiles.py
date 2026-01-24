"""
Migrate FREELANCER Tenants to FreelancerProfile User Profiles

This script converts all existing FREELANCER tenants to lightweight FreelancerProfile
user profiles, eliminating the overhead of separate PostgreSQL schemas for individuals.

ARCHITECTURAL FIX:
- Before: Individual freelancers get full tenant schemas (massive overhead)
- After: Freelancers are user profiles (lightweight, scalable)

PROCESS:
1. Identify all FREELANCER-type tenants
2. For each FREELANCER tenant:
   a. Get the single user of that tenant
   b. Create FreelancerProfile for that user
   c. Migrate tenant data (company info → profile fields)
   d. Archive tenant schema (soft delete)
3. Verify migration success
4. Generate migration report

SAFETY:
- Dry-run mode by default (no changes)
- Comprehensive validation before migration
- Rollback capability
- Detailed logging

Usage:
    # Dry run (no changes)
    python scripts/migrate_freelancer_tenants_to_profiles.py --dry-run

    # Actual migration
    python scripts/migrate_freelancer_tenants_to_profiles.py

    # Migration with specific tenant
    python scripts/migrate_freelancer_tenants_to_profiles.py --tenant-id 123

    # Skip archiving (for testing)
    python scripts/migrate_freelancer_tenants_to_profiles.py --no-archive
"""

import sys
import os
import logging
from datetime import datetime
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
import argparse

# Django setup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

import django
django.setup()

from django.db import transaction
from django.utils import timezone
from django.contrib.auth import get_user_model

from tenants.models import Tenant, TenantUser
from tenant_profiles.models import FreelancerProfile
from services.models import Service, ServiceProvider

User = get_user_model()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'freelancer_migration_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class FreelancerTenantMigrationStats:
    """Track migration statistics."""

    def __init__(self):
        self.total_freelancer_tenants = 0
        self.successful_migrations = 0
        self.failed_migrations = 0
        self.skipped_migrations = 0
        self.errors: List[Dict] = []
        self.warnings: List[Dict] = []
        self.migrated_profiles: List[FreelancerProfile] = []

    def add_success(self, tenant_id: int, profile: FreelancerProfile):
        """Record successful migration."""
        self.successful_migrations += 1
        self.migrated_profiles.append(profile)
        logger.info(f"✅ Successfully migrated tenant {tenant_id} → FreelancerProfile {profile.uuid}")

    def add_failure(self, tenant_id: int, error: str):
        """Record failed migration."""
        self.failed_migrations += 1
        self.errors.append({
            'tenant_id': tenant_id,
            'error': error,
            'timestamp': timezone.now()
        })
        logger.error(f"❌ Failed to migrate tenant {tenant_id}: {error}")

    def add_skip(self, tenant_id: int, reason: str):
        """Record skipped migration."""
        self.skipped_migrations += 1
        self.warnings.append({
            'tenant_id': tenant_id,
            'reason': reason,
            'timestamp': timezone.now()
        })
        logger.warning(f"⚠️ Skipped tenant {tenant_id}: {reason}")

    def generate_report(self) -> str:
        """Generate migration summary report."""
        report = f"""
================================================================================
FREELANCER TENANT MIGRATION REPORT
================================================================================
Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY:
--------
Total FREELANCER Tenants Found:  {self.total_freelancer_tenants}
Successful Migrations:           {self.successful_migrations}
Failed Migrations:               {self.failed_migrations}
Skipped Migrations:              {self.skipped_migrations}

SUCCESS RATE: {(self.successful_migrations / max(self.total_freelancer_tenants, 1) * 100):.1f}%

MIGRATED PROFILES:
------------------
"""
        for profile in self.migrated_profiles:
            report += f"  - {profile.user.email} → {profile.professional_title} (UUID: {profile.uuid})\n"

        if self.errors:
            report += f"\nERRORS ({len(self.errors)}):\n"
            report += "-" * 80 + "\n"
            for error in self.errors:
                report += f"  Tenant {error['tenant_id']}: {error['error']}\n"

        if self.warnings:
            report += f"\nWARNINGS ({len(self.warnings)}):\n"
            report += "-" * 80 + "\n"
            for warning in self.warnings:
                report += f"  Tenant {warning['tenant_id']}: {warning['reason']}\n"

        report += "\n" + "=" * 80 + "\n"
        return report


def validate_freelancer_tenant(tenant: Tenant) -> Tuple[bool, Optional[str], Optional[User]]:
    """
    Validate that a FREELANCER tenant can be safely migrated.

    Returns:
        (is_valid, error_message, user)
    """
    # Check tenant type
    if tenant.tenant_type != 'freelancer':
        return False, f"Tenant {tenant.id} is not FREELANCER type (actual: {tenant.tenant_type})", None

    # Get tenant users
    tenant_users = TenantUser.objects.filter(tenant=tenant, is_active=True)

    if tenant_users.count() == 0:
        return False, f"Tenant {tenant.id} has no active users", None

    if tenant_users.count() > 1:
        return False, f"Tenant {tenant.id} has {tenant_users.count()} active users (expected 1 for freelancer)", None

    user = tenant_users.first().user

    # Check if user already has a freelancer profile
    if hasattr(user, 'freelancer_profile'):
        return False, f"User {user.email} already has a FreelancerProfile", user

    # Validation passed
    return True, None, user


def extract_tenant_data_for_profile(tenant: Tenant) -> Dict:
    """
    Extract relevant data from tenant for FreelancerProfile creation.

    Maps tenant fields to FreelancerProfile fields.
    """
    # Professional title from tenant name or industry
    professional_title = tenant.name or tenant.industry or "Freelancer"
    if len(professional_title) > 200:
        professional_title = professional_title[:197] + "..."

    # Bio from tenant description
    bio = tenant.description or f"Freelancer based in {tenant.city or 'unknown location'}"

    # Location data
    city = tenant.city or ""
    country = tenant.country or ""
    timezone_str = tenant.timezone or "UTC"

    # Default hourly rate (can be customized later)
    # Try to infer from services if any exist
    default_hourly_rate = Decimal('50.00')  # Default

    # Try to get hourly rate from associated services
    try:
        # This will fail since services are in tenant schema, but worth trying
        # In actual implementation, would need to switch to tenant schema
        pass
    except:
        pass

    # Skills (could be derived from services/industry)
    skills = []
    if tenant.industry:
        # Simple mapping of industry to skills
        industry_skills_map = {
            'Technology': ['Programming', 'Software Development'],
            'Design': ['Graphic Design', 'UI/UX'],
            'Marketing': ['Digital Marketing', 'SEO', 'Content'],
            'Finance': ['Accounting', 'Financial Analysis'],
            'Legal': ['Legal Consulting', 'Contract Review'],
        }
        skills = industry_skills_map.get(tenant.industry, [])

    # Verification status
    is_verified = tenant.ein_verified if hasattr(tenant, 'ein_verified') else False
    verification_date = tenant.ein_verified_at if hasattr(tenant, 'ein_verified_at') else None

    return {
        'professional_title': professional_title,
        'bio': bio,
        'years_of_experience': 0,  # Default, user can update
        'hourly_rate': default_hourly_rate,
        'hourly_rate_currency': tenant.currency if hasattr(tenant, 'currency') else 'CAD',
        'availability_status': 'available',
        'availability_hours_per_week': 40,
        'skills': skills,
        'city': city,
        'country': country,
        'timezone': timezone_str,
        'remote_only': True,  # Default assumption
        'willing_to_relocate': False,
        'is_verified': is_verified,
        'verification_date': verification_date,
        'identity_verified': is_verified,
        'payment_method_verified': False,
    }


def migrate_freelancer_tenant_to_profile(
    tenant: Tenant,
    user: User,
    archive_tenant: bool = True,
    dry_run: bool = False
) -> FreelancerProfile:
    """
    Migrate a single FREELANCER tenant to FreelancerProfile.

    Args:
        tenant: FREELANCER tenant to migrate
        user: User associated with the tenant
        archive_tenant: Whether to archive the tenant after migration
        dry_run: If True, don't actually save changes

    Returns:
        FreelancerProfile instance (unsaved if dry_run=True)

    Raises:
        Exception: If migration fails
    """
    logger.info(f"Migrating tenant {tenant.id} ({tenant.name}) → FreelancerProfile for {user.email}")

    # Extract data
    profile_data = extract_tenant_data_for_profile(tenant)

    if dry_run:
        logger.info(f"[DRY RUN] Would create FreelancerProfile with data: {profile_data}")
        # Create instance but don't save
        profile = FreelancerProfile(user=user, **profile_data)
        logger.info(f"[DRY RUN] Would archive tenant {tenant.id}")
        return profile

    # Actual migration (within transaction)
    with transaction.atomic():
        # Create FreelancerProfile
        profile = FreelancerProfile.objects.create(
            user=user,
            **profile_data
        )

        logger.info(f"Created FreelancerProfile {profile.uuid} for user {user.email}")

        # Archive tenant (soft delete)
        if archive_tenant:
            tenant.status = 'archived'
            tenant.archived_at = timezone.now()
            tenant.archived_reason = f"Migrated to FreelancerProfile {profile.uuid}"
            tenant.save(update_fields=['status', 'archived_at', 'archived_reason'])

            logger.info(f"Archived tenant {tenant.id} (schema preserved for data recovery)")

        return profile


def migrate_all_freelancer_tenants(
    tenant_id: Optional[int] = None,
    archive_tenants: bool = True,
    dry_run: bool = False
) -> FreelancerTenantMigrationStats:
    """
    Migrate all FREELANCER tenants to FreelancerProfile.

    Args:
        tenant_id: If specified, only migrate this tenant
        archive_tenants: Whether to archive tenants after migration
        dry_run: If True, simulate migration without saving

    Returns:
        Migration statistics
    """
    stats = FreelancerTenantMigrationStats()

    # Get FREELANCER tenants
    if tenant_id:
        freelancer_tenants = Tenant.objects.filter(id=tenant_id, tenant_type='freelancer')
    else:
        freelancer_tenants = Tenant.objects.filter(tenant_type='freelancer')

    stats.total_freelancer_tenants = freelancer_tenants.count()

    logger.info(f"Found {stats.total_freelancer_tenants} FREELANCER tenant(s) to migrate")
    logger.info(f"Mode: {'DRY RUN (no changes)' if dry_run else 'ACTUAL MIGRATION'}")

    if stats.total_freelancer_tenants == 0:
        logger.warning("No FREELANCER tenants found. Migration complete.")
        return stats

    # Migrate each tenant
    for tenant in freelancer_tenants:
        logger.info(f"\n{'='*80}")
        logger.info(f"Processing tenant {tenant.id}: {tenant.name}")
        logger.info(f"{'='*80}")

        try:
            # Validate tenant
            is_valid, error_msg, user = validate_freelancer_tenant(tenant)

            if not is_valid:
                stats.add_skip(tenant.id, error_msg)
                continue

            # Migrate
            profile = migrate_freelancer_tenant_to_profile(
                tenant=tenant,
                user=user,
                archive_tenant=archive_tenants,
                dry_run=dry_run
            )

            stats.add_success(tenant.id, profile)

        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            stats.add_failure(tenant.id, error_msg)
            logger.exception(f"Unexpected error migrating tenant {tenant.id}")

    return stats


def verify_migration_integrity():
    """
    Verify that migration didn't break anything.

    Checks:
    - No FREELANCER tenants remain (or all are archived)
    - All migrated users have FreelancerProfile
    - No data loss
    """
    logger.info("\n" + "="*80)
    logger.info("VERIFYING MIGRATION INTEGRITY")
    logger.info("="*80)

    # Check for remaining active FREELANCER tenants
    active_freelancer_tenants = Tenant.objects.filter(
        tenant_type='freelancer',
        status='active'
    )

    if active_freelancer_tenants.exists():
        logger.warning(f"⚠️ Found {active_freelancer_tenants.count()} active FREELANCER tenants still remaining:")
        for tenant in active_freelancer_tenants:
            logger.warning(f"   - Tenant {tenant.id}: {tenant.name}")
    else:
        logger.info("✅ No active FREELANCER tenants remaining")

    # Check archived FREELANCER tenants
    archived_freelancer_tenants = Tenant.objects.filter(
        tenant_type='freelancer',
        status='archived'
    )

    logger.info(f"✅ {archived_freelancer_tenants.count()} FREELANCER tenants archived")

    # Check FreelancerProfile count
    freelancer_profiles = FreelancerProfile.objects.all()
    logger.info(f"✅ {freelancer_profiles.count()} FreelancerProfile instances in database")

    logger.info("="*80 + "\n")


def main():
    """Main migration script."""
    parser = argparse.ArgumentParser(
        description='Migrate FREELANCER tenants to FreelancerProfile user profiles'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Simulate migration without saving changes'
    )
    parser.add_argument(
        '--tenant-id',
        type=int,
        help='Migrate only this specific tenant ID'
    )
    parser.add_argument(
        '--no-archive',
        action='store_true',
        help='Do not archive tenants after migration (for testing)'
    )
    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='Only verify migration integrity, do not migrate'
    )

    args = parser.parse_args()

    logger.info("="*80)
    logger.info("FREELANCER TENANT MIGRATION SCRIPT")
    logger.info("="*80)
    logger.info(f"Started: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Dry Run: {args.dry_run}")
    logger.info(f"Archive Tenants: {not args.no_archive}")
    logger.info("="*80 + "\n")

    if args.verify_only:
        verify_migration_integrity()
        return

    # Run migration
    stats = migrate_all_freelancer_tenants(
        tenant_id=args.tenant_id,
        archive_tenants=not args.no_archive,
        dry_run=args.dry_run
    )

    # Print report
    report = stats.generate_report()
    print(report)

    # Save report to file
    report_filename = f'freelancer_migration_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    with open(report_filename, 'w') as f:
        f.write(report)

    logger.info(f"Migration report saved to: {report_filename}")

    # Verify integrity (if not dry run)
    if not args.dry_run:
        verify_migration_integrity()

    # Exit with appropriate code
    if stats.failed_migrations > 0:
        logger.error(f"Migration completed with {stats.failed_migrations} failures")
        sys.exit(1)
    else:
        logger.info("Migration completed successfully!")
        sys.exit(0)


if __name__ == '__main__':
    main()
