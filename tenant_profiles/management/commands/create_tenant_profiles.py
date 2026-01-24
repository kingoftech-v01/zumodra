"""
Management command to create TenantProfile for all existing TenantUsers.
Backfills TenantProfile records and performs initial sync from PublicProfile.

Usage:
    python manage.py create_tenant_profiles
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from django_tenants.utils import tenant_context

from tenants.models import Tenant
from tenant_profiles.models import TenantUser, TenantProfile
from tenant_profiles.services import ProfileSyncService


class Command(BaseCommand):
    help = 'Create TenantProfile for all existing TenantUsers and perform initial sync'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Optional: Only process specific tenant by schema_name',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without actually creating',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)
        specific_tenant = options.get('tenant')

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))

        # Get tenants to process
        if specific_tenant:
            tenants = Tenant.objects.filter(schema_name=specific_tenant)
            if not tenants.exists():
                self.stdout.write(self.style.ERROR(f'Tenant with schema_name "{specific_tenant}" not found'))
                return
        else:
            tenants = Tenant.objects.exclude(schema_name='public')

        total_created = 0
        total_synced = 0
        total_errors = 0

        self.stdout.write(self.style.SUCCESS(f'Processing {tenants.count()} tenant(s)...'))

        for tenant in tenants:
            self.stdout.write(f'\n--- Processing tenant: {tenant.name} ({tenant.schema_name}) ---')

            try:
                with tenant_context(tenant):
                    tenant_users = TenantUser.objects.select_related('user', 'department').all()
                    self.stdout.write(f'Found {tenant_users.count()} TenantUser records')

                    for tenant_user in tenant_users:
                        try:
                            # Check if TenantProfile already exists
                            existing_profile = TenantProfile.objects.filter(
                                user=tenant_user.user,
                                tenant=tenant
                            ).first()

                            if existing_profile:
                                self.stdout.write(
                                    self.style.WARNING(
                                        f'  ⏭️  Skipped: {tenant_user.user.email} (profile already exists)'
                                    )
                                )
                                continue

                            if dry_run:
                                self.stdout.write(
                                    self.style.SUCCESS(
                                        f'  ✓ Would create: {tenant_user.user.email} '
                                        f'(job_title: {tenant_user.job_title or "Employee"})'
                                    )
                                )
                                total_created += 1
                                continue

                            # Create TenantProfile (actual creation)
                            with transaction.atomic():
                                profile = TenantProfile.objects.create(
                                    user=tenant_user.user,
                                    tenant=tenant,
                                    job_title=tenant_user.job_title or 'Employee',
                                    department=tenant_user.department,
                                )

                                # Trigger initial sync from PublicProfile
                                sync_result = ProfileSyncService.sync_on_invitation_acceptance(
                                    user=tenant_user.user,
                                    tenant=tenant
                                )

                                total_created += 1

                                if sync_result.get('success'):
                                    synced_fields = sync_result.get('synced_fields', [])
                                    total_synced += 1
                                    self.stdout.write(
                                        self.style.SUCCESS(
                                            f'  ✓ Created & Synced: {tenant_user.user.email} '
                                            f'({len(synced_fields)} fields: {", ".join(synced_fields[:3])}...)'
                                        )
                                    )
                                else:
                                    self.stdout.write(
                                        self.style.WARNING(
                                            f'  ⚠️  Created but sync failed: {tenant_user.user.email} '
                                            f'- {sync_result.get("error", "Unknown error")}'
                                        )
                                    )

                        except Exception as e:
                            total_errors += 1
                            self.stdout.write(
                                self.style.ERROR(
                                    f'  ✗ Error processing {tenant_user.user.email}: {str(e)}'
                                )
                            )

            except Exception as e:
                total_errors += 1
                self.stdout.write(
                    self.style.ERROR(f'Error processing tenant {tenant.name}: {str(e)}')
                )

        # Summary
        self.stdout.write('\n' + '=' * 70)
        self.stdout.write(self.style.SUCCESS('\nSUMMARY:'))
        self.stdout.write(f'  Tenants processed: {tenants.count()}')
        self.stdout.write(f'  TenantProfiles created: {total_created}')
        self.stdout.write(f'  Successful syncs: {total_synced}')

        if total_errors > 0:
            self.stdout.write(self.style.ERROR(f'  Errors encountered: {total_errors}'))
        else:
            self.stdout.write(self.style.SUCCESS(f'  Errors: 0'))

        if dry_run:
            self.stdout.write(self.style.WARNING('\nDRY RUN COMPLETE - No changes were made'))
        else:
            self.stdout.write(self.style.SUCCESS('\nCOMPLETE'))
