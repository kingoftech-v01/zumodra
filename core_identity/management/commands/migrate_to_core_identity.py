"""
Data Migration: custom_account_u → core_identity

Migrates data from old models to new architecture:
- PublicProfile → UserIdentity + MarketplaceProfile (optional)
- No changes to CustomUser (already in PUBLIC schema)

Author: Zumodra Team
Date: 2026-01-17
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Migrate data from custom_account_u to core_identity architecture'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Run migration without committing changes (test mode)',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output for each record',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        verbose = options['verbose']

        self.stdout.write(self.style.WARNING(
            '=' * 80
        ))
        self.stdout.write(self.style.WARNING(
            'DATA MIGRATION: custom_account_u → core_identity'
        ))
        self.stdout.write(self.style.WARNING(
            '=' * 80
        ))

        if dry_run:
            self.stdout.write(self.style.NOTICE(
                '\n⚠️  DRY RUN MODE - No changes will be committed\n'
            ))

        # Import models (do this here to avoid circular imports)
        try:
            # Try importing old model
            from core_identity.models_old import PublicProfile
            old_model_exists = True
        except (ImportError, AttributeError):
            self.stdout.write(self.style.WARNING(
                '\n⚠️  Old PublicProfile model not found.'
            ))
            self.stdout.write(self.style.NOTICE(
                'If you have already migrated, this is expected.\n'
            ))
            old_model_exists = False

        from core_identity.models import UserIdentity, MarketplaceProfile, CustomUser

        if not old_model_exists:
            self.stdout.write(self.style.WARNING(
                'Skipping migration - old model does not exist.\n'
            ))
            return

        # Get statistics
        total_profiles = PublicProfile.objects.count()
        total_users = CustomUser.objects.count()

        self.stdout.write(f'\n📊 Migration Statistics:')
        self.stdout.write(f'   - Total CustomUser records: {total_users}')
        self.stdout.write(f'   - Total PublicProfile records: {total_profiles}')
        self.stdout.write(f'   - Users without PublicProfile: {total_users - total_profiles}\n')

        if total_profiles == 0:
            self.stdout.write(self.style.SUCCESS(
                '✅ No PublicProfile records to migrate.\n'
            ))
            return

        # Confirmation prompt
        if not dry_run:
            self.stdout.write(self.style.WARNING(
                '⚠️  This will modify data in the PUBLIC schema.\n'
            ))
            confirm = input('Continue? [y/N]: ')
            if confirm.lower() != 'y':
                self.stdout.write(self.style.ERROR('Migration cancelled.\n'))
                return

        # Run migration
        self.stdout.write('\n🚀 Starting migration...\n')

        migrated_identities = 0
        migrated_marketplace = 0
        errors = []

        for profile in PublicProfile.objects.select_related('user').all():
            try:
                with transaction.atomic():
                    # 1. Migrate to UserIdentity (ALWAYS created)
                    identity, identity_created = self._migrate_to_user_identity(
                        profile, verbose, dry_run
                    )
                    if identity_created:
                        migrated_identities += 1

                    # 2. Migrate to MarketplaceProfile (ONLY if active freelancer)
                    marketplace_created = self._migrate_to_marketplace_profile(
                        profile, verbose, dry_run
                    )
                    if marketplace_created:
                        migrated_marketplace += 1

                    if dry_run:
                        # Rollback transaction in dry-run mode
                        transaction.set_rollback(True)

            except Exception as e:
                error_msg = f"User {profile.user.email}: {str(e)}"
                errors.append(error_msg)
                logger.error(f"Migration error: {error_msg}")
                if verbose:
                    self.stdout.write(self.style.ERROR(f'   ❌ {error_msg}'))

        # Summary
        self.stdout.write('\n' + '=' * 80)
        self.stdout.write(self.style.SUCCESS('📊 MIGRATION SUMMARY'))
        self.stdout.write('=' * 80 + '\n')

        self.stdout.write(f'Total PublicProfile records: {total_profiles}')
        self.stdout.write(self.style.SUCCESS(
            f'✅ UserIdentity created: {migrated_identities}'
        ))
        self.stdout.write(self.style.SUCCESS(
            f'✅ MarketplaceProfile created: {migrated_marketplace}'
        ))

        if errors:
            self.stdout.write(self.style.ERROR(
                f'\n❌ Errors: {len(errors)}'
            ))
            for error in errors[:10]:  # Show first 10 errors
                self.stdout.write(self.style.ERROR(f'   - {error}'))
            if len(errors) > 10:
                self.stdout.write(self.style.ERROR(
                    f'   ... and {len(errors) - 10} more errors'
                ))
        else:
            self.stdout.write(self.style.SUCCESS('\n✅ No errors!\n'))

        if dry_run:
            self.stdout.write(self.style.NOTICE(
                '\n⚠️  DRY RUN COMPLETE - No changes committed\n'
            ))
            self.stdout.write(self.style.NOTICE(
                'Run without --dry-run to apply changes.\n'
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                '\n✅ MIGRATION COMPLETE!\n'
            ))
            self.stdout.write(self.style.NOTICE(
                'Next steps:\n'
                '1. Run: python manage.py migrate_to_tenant_profiles\n'
                '2. Update all imports across codebase\n'
                '3. Run tests to verify migration\n'
            ))

    def _migrate_to_user_identity(self, profile, verbose, dry_run):
        """
        Migrate PublicProfile → UserIdentity.

        UserIdentity is ALWAYS created for every user.
        """
        from core_identity.models import UserIdentity

        # Check if already exists
        if UserIdentity.objects.filter(user=profile.user).exists():
            if verbose:
                self.stdout.write(
                    f'   ⏭️  UserIdentity already exists for {profile.user.email}'
                )
            return UserIdentity.objects.get(user=profile.user), False

        # Create UserIdentity
        identity = UserIdentity(
            user=profile.user,
            display_name=profile.display_name,
            avatar=profile.avatar,
            bio=profile.bio,
            phone=profile.phone,
            location_city=profile.location_city or '',
            location_country=profile.location_country or '',
            linkedin_url=profile.linkedin_url or '',
            github_url=profile.github_url or '',
            twitter_handle='',  # New field, not in PublicProfile
            website_url='',  # New field, not in PublicProfile
            timezone=profile.timezone or 'America/Toronto',
        )

        if not dry_run:
            identity.save()

        if verbose:
            self.stdout.write(self.style.SUCCESS(
                f'   ✅ UserIdentity created for {profile.user.email}'
            ))

        return identity, True

    def _migrate_to_marketplace_profile(self, profile, verbose, dry_run):
        """
        Migrate PublicProfile → MarketplaceProfile.

        MarketplaceProfile is ONLY created if user has freelancer/marketplace data:
        - available_for_work = True
        - OR hourly_rate_min is set
        - OR professional_title is set
        """
        from core_identity.models import MarketplaceProfile

        # Check if already exists
        if MarketplaceProfile.objects.filter(user=profile.user).exists():
            if verbose:
                self.stdout.write(
                    f'   ⏭️  MarketplaceProfile already exists for {profile.user.email}'
                )
            return False

        # Determine if user should have MarketplaceProfile
        is_freelancer = (
            profile.available_for_work or
            profile.hourly_rate_min is not None or
            (profile.professional_title and profile.professional_title.strip())
        )

        if not is_freelancer:
            if verbose:
                self.stdout.write(
                    f'   ⏭️  {profile.user.email} - No marketplace data, skipping'
                )
            return False

        # Create MarketplaceProfile
        marketplace = MarketplaceProfile(
            user=profile.user,
            # IMPORTANT: Set is_active based on available_for_work
            is_active=profile.available_for_work,
            activated_at=timezone.now() if profile.available_for_work else None,
            professional_title=profile.professional_title or 'Freelancer',
            skills=profile.skills or [],
            available_for_work=profile.available_for_work,
            hourly_rate_min=profile.hourly_rate_min,
            hourly_rate_max=profile.hourly_rate_max,
            rate_currency='CAD',  # Default, can be updated later
            portfolio_url=profile.portfolio_url or '',
            cv_file=profile.cv_file or '',
            profile_visibility=profile.profile_visibility or 'private',
            completed_projects=0,  # New field, initialize to 0
            total_earnings=0,  # New field, initialize to 0
            average_rating=None,  # New field, no data yet
        )

        if not dry_run:
            marketplace.save()

        if verbose:
            status = 'ACTIVE' if marketplace.is_active else 'INACTIVE'
            self.stdout.write(self.style.SUCCESS(
                f'   ✅ MarketplaceProfile created for {profile.user.email} ({status})'
            ))

        return True
