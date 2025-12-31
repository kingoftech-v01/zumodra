"""
Management command to create a superuser for a specific tenant.
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import connection
from tenants.models import Tenant
from accounts.models import TenantUser, UserProfile

User = get_user_model()


class Command(BaseCommand):
    help = 'Create a superuser account for a specific tenant'

    def add_arguments(self, parser):
        parser.add_argument(
            'tenant_slug',
            type=str,
            help='Tenant slug or schema name'
        )
        parser.add_argument(
            'email',
            type=str,
            help='User email address'
        )
        parser.add_argument(
            '--password',
            type=str,
            help='User password (will prompt if not provided)'
        )
        parser.add_argument(
            '--first-name',
            type=str,
            default='',
            help='User first name'
        )
        parser.add_argument(
            '--last-name',
            type=str,
            default='',
            help='User last name'
        )
        parser.add_argument(
            '--role',
            type=str,
            default='owner',
            choices=['owner', 'admin'],
            help='Tenant role (default: owner)'
        )
        parser.add_argument(
            '--no-input',
            action='store_true',
            help='Do not prompt for any input'
        )
        parser.add_argument(
            '--update-existing',
            action='store_true',
            help='Update existing user if found'
        )

    def handle(self, *args, **options):
        tenant_slug = options['tenant_slug']
        email = options['email']
        password = options.get('password')
        first_name = options.get('first_name', '')
        last_name = options.get('last_name', '')
        role = options.get('role', 'owner')
        no_input = options.get('no_input', False)
        update_existing = options.get('update_existing', False)

        # Validate email
        if '@' not in email:
            raise CommandError(f"Invalid email address: {email}")

        # Find tenant
        try:
            tenant = Tenant.objects.get(slug=tenant_slug)
        except Tenant.DoesNotExist:
            try:
                tenant = Tenant.objects.get(schema_name=tenant_slug)
            except Tenant.DoesNotExist:
                raise CommandError(f"Tenant not found: {tenant_slug}")

        self.stdout.write(f"Creating superuser for tenant: {tenant.name}")

        # Get password if not provided
        if not password:
            if no_input:
                raise CommandError("Password required with --no-input flag")
            import getpass
            password = getpass.getpass("Password: ")
            password_confirm = getpass.getpass("Password (again): ")
            if password != password_confirm:
                raise CommandError("Passwords do not match")

        if len(password) < 8:
            raise CommandError("Password must be at least 8 characters")

        # Switch to tenant schema
        connection.set_schema(tenant.schema_name)

        try:
            # Check if user exists
            existing_user = User.objects.filter(email=email).first()

            if existing_user:
                if not update_existing:
                    raise CommandError(
                        f"User with email {email} already exists. "
                        "Use --update-existing to update."
                    )
                user = existing_user
                user.set_password(password)
                user.is_superuser = True
                user.is_staff = True
                if first_name:
                    user.first_name = first_name
                if last_name:
                    user.last_name = last_name
                user.save()
                self.stdout.write(f"Updated existing user: {email}")
            else:
                # Create new user
                user = User.objects.create_superuser(
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name,
                )
                self.stdout.write(f"Created new superuser: {email}")

            # Create or update TenantUser
            role_enum = (
                TenantUser.UserRole.OWNER if role == 'owner'
                else TenantUser.UserRole.ADMIN
            )

            tenant_user, created = TenantUser.objects.update_or_create(
                user=user,
                tenant=tenant,
                defaults={
                    'role': role_enum,
                    'is_active': True,
                    'is_primary_tenant': True,
                }
            )

            if created:
                self.stdout.write(f"Created TenantUser with role: {role}")
            else:
                self.stdout.write(f"Updated TenantUser with role: {role}")

            # Create UserProfile if it doesn't exist
            profile, created = UserProfile.objects.get_or_create(
                user=user,
                defaults={
                    'profile_type': UserProfile.ProfileType.ADMIN,
                }
            )

            if created:
                self.stdout.write("Created UserProfile")

            self.stdout.write(self.style.SUCCESS(f"""
Superuser created/updated successfully!

Tenant: {tenant.name}
Email: {email}
Role: {role}
Is Superuser: {user.is_superuser}
Is Staff: {user.is_staff}
"""))

        except Exception as e:
            raise CommandError(f"Failed to create superuser: {e}")
        finally:
            # Reset to public schema
            connection.set_schema_to_public()
