"""Create UserStatus records for all existing users in tenant schemas."""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django_tenants.utils import schema_context
from tenants.models import Tenant
from messages_sys.models import UserStatus

User = get_user_model()


class Command(BaseCommand):
    help = 'Create UserStatus records for users who do not have one'

    def add_arguments(self, parser):
        parser.add_argument(
            '--schema',
            type=str,
            help='Specific tenant schema to process (optional)'
        )

    def handle(self, *args, **options):
        schema_name = options.get('schema')

        if schema_name:
            tenants = Tenant.objects.filter(schema_name=schema_name)
            if not tenants.exists():
                self.stdout.write(
                    self.style.ERROR(f'Tenant with schema "{schema_name}" not found')
                )
                return
        else:
            tenants = Tenant.objects.all()

        total_created = 0
        total_existing = 0

        for tenant in tenants:
            self.stdout.write(f'\nProcessing tenant: {tenant.name} ({tenant.schema_name})')

            with schema_context(tenant.schema_name):
                users = User.objects.all()
                created_count = 0
                existing_count = 0

                for user in users:
                    user_status, created = UserStatus.objects.get_or_create(
                        user=user,
                        defaults={
                            'is_online': False,
                            'last_seen': None
                        }
                    )

                    if created:
                        created_count += 1
                        self.stdout.write(f'  Created UserStatus for: {user.email}')
                    else:
                        existing_count += 1

                self.stdout.write(
                    self.style.SUCCESS(
                        f'  Created: {created_count}, Already existed: {existing_count}'
                    )
                )

                total_created += created_count
                total_existing += existing_count

        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(
            self.style.SUCCESS(f'Total UserStatus records created: {total_created}')
        )
        self.stdout.write(f'Total already existing: {total_existing}')
