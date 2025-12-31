"""
Management command to create a new tenant.
"""

from django.core.management.base import BaseCommand, CommandError
from tenants.models import Tenant, Plan, Domain
from tenants.services import TenantService


class Command(BaseCommand):
    help = 'Create a new tenant with associated domain and settings'

    def add_arguments(self, parser):
        parser.add_argument('name', type=str, help='Tenant/Organization name')
        parser.add_argument('owner_email', type=str, help='Owner email address')
        parser.add_argument(
            '--domain',
            type=str,
            help='Primary domain (optional, will generate subdomain if not provided)'
        )
        parser.add_argument(
            '--plan',
            type=str,
            default='free',
            help='Plan slug (default: free)'
        )
        parser.add_argument(
            '--skip-trial',
            action='store_true',
            help='Skip trial period and activate immediately'
        )

    def handle(self, *args, **options):
        name = options['name']
        owner_email = options['owner_email']
        domain = options.get('domain')
        plan_slug = options.get('plan', 'free')
        skip_trial = options.get('skip_trial', False)

        # Validate email
        if '@' not in owner_email:
            raise CommandError(f"Invalid email address: {owner_email}")

        # Get plan
        plan = None
        if plan_slug:
            try:
                plan = Plan.objects.get(slug=plan_slug, is_active=True)
            except Plan.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(f"Plan '{plan_slug}' not found, using default")
                )

        self.stdout.write(f"Creating tenant: {name}")

        try:
            tenant = TenantService.create_tenant(
                name=name,
                owner_email=owner_email,
                plan=plan,
                domain=domain
            )

            if skip_trial:
                tenant.activate()
                self.stdout.write(self.style.SUCCESS("Trial skipped, tenant activated"))

            self.stdout.write(self.style.SUCCESS(f"""
Tenant created successfully!

Name: {tenant.name}
Slug: {tenant.slug}
Schema: {tenant.schema_name}
Status: {tenant.get_status_display()}
Domain: {tenant.domains.first().domain if tenant.domains.exists() else 'N/A'}
Owner: {tenant.owner_email}
Plan: {tenant.plan.name if tenant.plan else 'None'}
Trial ends: {tenant.trial_ends_at.strftime('%Y-%m-%d') if tenant.trial_ends_at else 'N/A'}
"""))

        except Exception as e:
            raise CommandError(f"Failed to create tenant: {e}")
