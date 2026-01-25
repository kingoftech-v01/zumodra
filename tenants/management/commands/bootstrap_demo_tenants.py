"""
Bootstrap Demo Tenant Management Command

Creates ONE demo company tenant (tenant_type=COMPANY).
Individual freelancers are now FreelancerProfile user profiles (not tenants).

This command is idempotent - running it multiple times will refresh the demo data
without creating duplicates.

Usage:
    python manage.py bootstrap_demo_tenants
    python manage.py bootstrap_demo_tenants --reset  # Delete and recreate
    python manage.py bootstrap_demo_tenants --dry-run  # Preview changes

Environment variable:
    CREATE_DEMO_TENANT=1  # Enable demo tenant creation in entrypoint
"""

import os
import random
import uuid
from datetime import timedelta
from decimal import Decimal

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone
from django.utils.text import slugify

User = get_user_model()

# =============================================================================
# DEMO DATA CONFIGURATION
# =============================================================================

def _get_demo_domain():
    """Get the base domain for demo tenant from centralized config."""
    domain = os.environ.get('TENANT_BASE_DOMAIN') or os.environ.get('BASE_DOMAIN')
    if not domain:
        domain = getattr(settings, 'TENANT_BASE_DOMAIN', None)
    if not domain:
        domain = getattr(settings, 'PRIMARY_DOMAIN', None)
    if not domain:
        domain = os.environ.get('PRIMARY_DOMAIN', 'localhost')
    return domain

def _get_demo_email_domain():
    """Get email domain for demo users - uses demo subdomain of primary domain."""
    primary = os.environ.get('PRIMARY_DOMAIN') or getattr(settings, 'PRIMARY_DOMAIN', 'localhost')
    return f"demo.{primary}"

BASE_DOMAIN = _get_demo_domain()
EMAIL_DOMAIN = _get_demo_email_domain()

# Demo tenant configuration (COMPANY type only)
DEMO_TENANTS = [
    {
        'name': 'Demo Company',
        'slug': 'demo-company',
        'schema': 'demo_company',
        'domain': f'demo-company.{BASE_DOMAIN}',
        'owner_email': f'company@{EMAIL_DOMAIN}',
        'tenant_type': 'company',  # COMPANY type - can create jobs, have employees
        'ein_number': '12-3456789',  # Demo EIN
    },
    # REMOVED: Demo Freelancer tenant
    # Individual freelancers are now FreelancerProfile user profiles (not tenants)
]

# Users for company tenant
COMPANY_USERS = {
    'owner': {
        'email': f'company.owner@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Alice',
        'last_name': 'Johnson',
        'role': 'OWNER',
        'is_superuser': False,
    },
    'hr_manager': {
        'email': f'company.hr@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Sarah',
        'last_name': 'Martinez',
        'role': 'HR_MANAGER',
    },
    'recruiter': {
        'email': f'company.recruiter@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Michael',
        'last_name': 'Chen',
        'role': 'RECRUITER',
    },
    'employee': {
        'email': f'company.employee@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'John',
        'last_name': 'Smith',
        'role': 'EMPLOYEE',
    },
}

# REMOVED: FREELANCER_USER
# Individual freelancers are now FreelancerProfile user profiles (not tenants)

JOB_CATEGORIES = [
    ('Engineering', 'ph-code', '#3B82F6'),
    ('Design', 'ph-palette', '#EC4899'),
    ('Marketing', 'ph-megaphone', '#10B981'),
    ('Sales', 'ph-chart-line-up', '#F59E0B'),
]

SERVICE_CATEGORIES = [
    ('Web Development', 'ph-globe', '#3B82F6'),
    ('Mobile Development', 'ph-device-mobile', '#8B5CF6'),
    ('UI/UX Design', 'ph-figma-logo', '#EC4899'),
    ('Content Writing', 'ph-pencil', '#6366F1'),
]


class Command(BaseCommand):
    help = 'Bootstrap demo company tenant (COMPANY type only)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Delete existing demo tenants and recreate from scratch'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Preview what would be created without making changes'
        )

    def handle(self, *args, **options):
        self.reset = options.get('reset', False)
        self.dry_run = options.get('dry_run', False)
        self.verbosity = options.get('verbosity', 1)

        if self.dry_run:
            self.stdout.write(self.style.WARNING('=== DRY RUN MODE ===\n'))

        self.stdout.write(self.style.MIGRATE_HEADING('Bootstrapping Demo Tenants'))
        self.stdout.write('=' * 60)

        try:
            self._bootstrap()
        except Exception as e:
            raise CommandError(f'Failed to bootstrap demo tenants: {e}')
        finally:
            connection.set_schema_to_public()

    def _bootstrap(self):
        """Main bootstrap logic."""
        from tenants.models import Tenant, Plan, Domain

        # Step 1: Setup plans
        self._log_step(1, 'Setting up subscription plans')
        if not self.dry_run:
            call_command('setup_plans', verbosity=0)

        # Step 2: Create both demo tenants
        for i, config in enumerate(DEMO_TENANTS, start=2):
            self._log_step(i, f"Creating demo tenant: {config['name']} (type: {config['tenant_type'].upper()})")

            # IMPORTANT: Switch to public schema before checking/creating tenant
            connection.set_schema_to_public()

            # Check if tenant exists
            existing = Tenant.objects.filter(slug=config['slug']).first()
            if existing:
                if self.reset:
                    self._log_info(f"   Deleting existing tenant: {existing.slug}")
                    if not self.dry_run:
                        # Delete using raw SQL to avoid cascade issues with cross-schema FKs
                        from django.db import connection as conn
                        tenant_id = existing.id
                        schema_name = existing.schema_name

                        # First, drop the tenant schema (this removes all tenant data)
                        with conn.cursor() as cursor:
                            cursor.execute(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE;")

                        # Delete all public schema records that reference this tenant
                        # Find all tables with FK to tenants_tenant and delete records
                        with conn.cursor() as cursor:
                            # Query to find all tables with foreign keys to tenants_tenant
                            cursor.execute("""
                                SELECT DISTINCT
                                    tc.table_schema,
                                    tc.table_name,
                                    kcu.column_name
                                FROM information_schema.table_constraints AS tc
                                JOIN information_schema.key_column_usage AS kcu
                                    ON tc.constraint_name = kcu.constraint_name
                                    AND tc.table_schema = kcu.table_schema
                                JOIN information_schema.constraint_column_usage AS ccu
                                    ON ccu.constraint_name = tc.constraint_name
                                    AND ccu.table_schema = tc.table_schema
                                WHERE tc.constraint_type = 'FOREIGN KEY'
                                    AND ccu.table_name = 'tenants_tenant'
                                    AND tc.table_schema = 'public'
                            """)

                            fk_tables = cursor.fetchall()

                            # Delete from each table that has FK to tenant
                            for schema, table, column in fk_tables:
                                try:
                                    cursor.execute(f'DELETE FROM "{schema}"."{table}" WHERE {column} = %s', [tenant_id])
                                except Exception as e:
                                    self._log_info(f"      Warning: Could not delete from {table}: {e}")

                            # Finally, delete the tenant record
                            cursor.execute("DELETE FROM tenants_tenant WHERE id = %s", [tenant_id])
                else:
                    self._log_info(f"   Tenant exists, skipping: {config['slug']}")
                    continue

            if self.dry_run:
                self.stdout.write(f"   Would create tenant: {config['name']}")
                continue

            # Create tenant
            tenant = self._create_tenant(config)

            # Switch to tenant schema
            connection.set_schema(tenant.schema_name)

            # Create users based on tenant type
            # Create company users (all tenants are COMPANY type now)
            self._log_info("   Creating company users (4 users)")
            users = self._create_users(tenant, COMPANY_USERS)

            # Create ATS data (jobs)
            self._log_info("   Creating ATS data (jobs, candidates)")
            self._create_ats_data(tenant, users)

            # Create HR data (employees, time-off)
            self._log_info("   Creating HR data (employees, time-off)")
            self._create_hr_data(tenant, users)

            # Create marketplace data (services)
            self._log_info("   Creating marketplace data (services)")
            self._create_marketplace_data(tenant, users, config['tenant_type'])

            # Summary for this tenant
            self._print_tenant_summary(tenant, config)

        # Final summary
        self._print_final_summary()

    def _log_step(self, step, message):
        """Log a step with consistent formatting."""
        self.stdout.write(f"\n[{step}] {message}...")

    def _log_info(self, message):
        """Log info message."""
        self.stdout.write(message)

    def _create_tenant(self, config):
        """Create a demo tenant with specified type."""
        from tenants.models import Tenant, Plan, Domain

        plan = Plan.objects.filter(plan_type=Plan.PlanType.PROFESSIONAL).first()
        if not plan:
            plan = Plan.objects.first()

        tenant = Tenant(
            name=config['name'],
            slug=config['slug'],
            schema_name=config['schema'],
            owner_email=config['owner_email'],
            plan=plan,
            status=Tenant.TenantStatus.TRIAL,
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=30),
            tenant_type=config['tenant_type'],  # Set tenant type!
            ein_number=config['ein_number'],
            ein_verified=False,  # Not verified by default
        )
        tenant.save()
        tenant.activate()

        # CRITICAL: Explicitly run migrations for tenant schema
        # Don't rely on auto_create_schema - it's unreliable for TENANT_APPS
        self.stdout.write(self.style.WARNING(
            f"   Running migrations for tenant schema: {tenant.schema_name}..."
        ))

        from django_tenants.utils import schema_context

        try:
            with schema_context(tenant.schema_name):
                call_command(
                    'migrate_schemas',
                    schema_name=tenant.schema_name,
                    verbosity=1,
                    interactive=False
                )
            self.stdout.write(self.style.SUCCESS(
                f"   ✓ Migrations completed for tenant: {tenant.schema_name}"
            ))
        except Exception as e:
            self.stdout.write(self.style.ERROR(
                f"   ✗ FATAL: Migration failed for tenant {tenant.schema_name}: {str(e)}"
            ))
            # Clean up the broken tenant
            tenant.delete()
            raise CommandError(
                f"Tenant migration failed for {config['name']}: {str(e)}. "
                "Tenant has been rolled back."
            )

        # Add domain
        Domain.objects.get_or_create(
            domain=config['domain'],
            defaults={'tenant': tenant, 'is_primary': True}
        )

        self.stdout.write(self.style.SUCCESS(
            f"   Created: {tenant.name} ({tenant.schema_name}) - Type: {tenant.tenant_type.upper()}"
        ))
        return tenant

    def _create_users(self, tenant, user_configs):
        """Create users for a tenant."""
        from tenant_profiles.models import TenantUser, TenantProfile
        from custom_account_u.models import PublicProfile

        users = {}

        for key, config in user_configs.items():
            user, created = User.objects.get_or_create(
                email=config['email'],
                defaults={
                    'username': config['email'].split('@')[0],
                    'first_name': config['first_name'],
                    'last_name': config['last_name'],
                    'is_active': True,
                    'is_staff': config.get('is_superuser', False),
                    'is_superuser': config.get('is_superuser', False),
                }
            )

            if created or not user.password:
                user.set_password(config['password'])
                user.save()

            # PublicProfile is auto-created by signal, but let's populate it with demo data
            if created or not hasattr(user, 'public_profile'):
                # Temporarily switch to public schema to update PublicProfile
                current_schema = connection.schema_name
                connection.set_schema_to_public()

                try:
                    public_profile = PublicProfile.objects.get(user=user)
                    public_profile.phone = f'+1555{random.randint(1000000, 9999999)}'
                    public_profile.bio = f'Demo {config["role"].lower().replace("_", " ")} user for {tenant.name}.'
                    public_profile.professional_title = config["role"].replace("_", " ").title()
                    public_profile.city = 'Montreal'
                    public_profile.country = 'CA'
                    public_profile.available_for_work = True
                    public_profile.save()
                except PublicProfile.DoesNotExist:
                    # Create if signal didn't fire
                    PublicProfile.objects.create(
                        user=user,
                        display_name=f'{user.first_name} {user.last_name}',
                        phone=f'+1555{random.randint(1000000, 9999999)}',
                        bio=f'Demo {config["role"].lower().replace("_", " ")} user for {tenant.name}.',
                        professional_title=config["role"].replace("_", " ").title(),
                        city='Montreal',
                        country='CA',
                        available_for_work=True,
                    )
                finally:
                    # Switch back to tenant schema
                    connection.set_schema(current_schema)

            # Create TenantUser
            TenantUser.objects.get_or_create(
                user=user,
                tenant=tenant,
                defaults={
                    'role': config['role'],
                    'is_active': True,
                    'is_primary_tenant': True,
                }
            )

            # Create TenantProfile (in tenant schema)
            TenantProfile.objects.get_or_create(
                user=user,
                tenant=tenant,
                defaults={
                    'job_title': config["role"].replace("_", " ").title(),
                    'full_name': f'{user.first_name} {user.last_name}',
                }
            )

            users[key] = user

        return users

    def _create_ats_data(self, tenant, users):
        """Create ATS data (jobs, candidates) - ONLY for COMPANY tenants."""
        from jobs.models import JobPosting, JobCategory, Pipeline, PipelineStage

        owner = users['owner']

        # Create job categories
        categories = []
        for name, icon, color in JOB_CATEGORIES:
            cat, _ = JobCategory.objects.get_or_create(
                name=name,
                tenant=tenant,
                defaults={'slug': slugify(name), 'icon': icon, 'color': color}
            )
            categories.append(cat)

        # Create pipeline
        pipeline, _ = Pipeline.objects.get_or_create(
            name='Standard Pipeline',
            tenant=tenant,
            defaults={'is_default': True, 'created_by': owner}
        )

        stages_config = [
            ('New', 'new', '#6B7280'),
            ('Screening', 'screening', '#3B82F6'),
            ('Interview', 'interview', '#8B5CF6'),
            ('Offer', 'offer', '#10B981'),
            ('Hired', 'hired', '#059669'),
            ('Rejected', 'rejected', '#EF4444'),
        ]

        for i, (name, stage_type, color) in enumerate(stages_config):
            PipelineStage.objects.get_or_create(
                pipeline=pipeline,
                name=name,
                defaults={'stage_type': stage_type, 'color': color, 'order': i}
            )

        # Create 3 job postings
        job_titles = ['Senior Software Engineer', 'Product Designer', 'Marketing Manager']
        for i, title in enumerate(job_titles):
            JobPosting.objects.get_or_create(
                reference_code=f'DEMO-{str(i + 1).zfill(4)}',
                tenant=tenant,
                defaults={
                    'title': title,
                    'slug': slugify(f'{title}-{i}'),
                    'description': f'Demo job posting for {title}',
                    'requirements': '- 3+ years experience\n- Strong skills',
                    'benefits': '- Competitive salary\n- Remote work',
                    'job_type': 'full_time',
                    'experience_level': 'mid',
                    'remote_policy': 'hybrid',
                    'location_city': 'Montreal',
                    'location_country': 'Canada',
                    'salary_min': Decimal(70000),
                    'salary_max': Decimal(120000),
                    'category': random.choice(categories),
                    'pipeline': pipeline,
                    'status': JobPosting.JobStatus.OPEN,
                    'published_at': timezone.now(),
                    'created_by': owner,
                }
            )

        self.stdout.write(f"      Jobs: {len(job_titles)}")

    def _create_hr_data(self, tenant, users):
        """Create HR data - ONLY for COMPANY tenants."""
        from hr_core.models import Employee, TimeOffType

        # Create time-off types
        TimeOffType.objects.get_or_create(
            code='PTO',
            tenant=tenant,
            defaults={
                'name': 'Paid Time Off',
                'is_accrued': True,
                'accrual_rate': Decimal('1.25'),
                'max_balance': Decimal('25'),
            }
        )
        TimeOffType.objects.get_or_create(
            code='SICK',
            tenant=tenant,
            defaults={
                'name': 'Sick Leave',
                'is_accrued': True,
                'accrual_rate': Decimal('0.5'),
                'max_balance': Decimal('12'),
            }
        )

        # Create employee record for employee user
        if 'employee' in users:
            emp_user = users['employee']
            Employee.objects.get_or_create(
                user=emp_user,
                tenant=tenant,
                defaults={
                    'employee_id': 'EMP-0001',
                    'job_title': 'Software Engineer',
                    'hire_date': timezone.now().date() - timedelta(days=365),
                    'status': 'active',
                    'employment_type': 'full_time',
                    'base_salary': Decimal(80000),
                    'pto_balance': Decimal(15),
                }
            )

        self.stdout.write(f"      Time-off types: 2, Employees: 1")

    def _create_marketplace_data(self, tenant, users, tenant_type):
        """Create marketplace/services data for BOTH tenant types."""
        try:
            from services.models import ServiceCategory, ServiceProvider, Service
        except ImportError:
            self.stdout.write(self.style.WARNING("      Marketplace models not available, skipping"))
            return

        owner = users['owner']

        # Create service categories
        categories = []
        for name, icon, color in SERVICE_CATEGORIES:
            cat, _ = ServiceCategory.objects.get_or_create(
                name=name,
                tenant=tenant,
                defaults={'slug': slugify(name), 'icon': icon, 'color': color}
            )
            categories.append(cat)

        # Create service provider
        provider, _ = ServiceProvider.objects.get_or_create(
            user=owner,
            tenant=tenant,
            defaults={
                'display_name': f'{owner.first_name} {owner.last_name}',
                'bio': f'Demo {tenant_type} provider',
                'tagline': 'Quality services delivered',
                'hourly_rate': Decimal(100),
                'availability_status': 'available',
                'is_verified': True,
                'marketplace_enabled': True,  # Enable marketplace
                'rating_avg': Decimal('4.5'),
                'total_reviews': 10,
            }
        )

        # Create 2 services
        service_names = ['Web Development', 'Consulting'] if tenant_type == 'company' else ['Freelance Development', 'Design Services']
        for i, name in enumerate(service_names):
            Service.objects.get_or_create(
                slug=slugify(f'{name}-{tenant.slug}'),
                tenant=tenant,
                defaults={
                    'name': name,
                    'description': f'Demo service: {name}',
                    'short_description': f'{name} service',
                    'provider': provider,
                    'category': random.choice(categories),
                    'service_type': 'fixed',
                    'price': Decimal(random.randint(500, 2000)),
                    'currency': 'CAD',
                    'is_active': True,
                    'is_public': True,  # Publish to marketplace
                }
            )

        self.stdout.write(f"      Services: {len(service_names)}, Provider: 1")

    def _print_tenant_summary(self, tenant, config):
        """Print summary for a single tenant."""
        self.stdout.write(f"\n   {self.style.SUCCESS('✓')} {config['name']} created successfully!")

    def _print_final_summary(self):
        """Print final summary."""
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('DEMO TENANTS BOOTSTRAP COMPLETE!'))
        self.stdout.write('=' * 60)

        self.stdout.write('\n' + self.style.MIGRATE_HEADING('Demo Tenant Created:'))
        for config in DEMO_TENANTS:
            self.stdout.write(f"\n  {config['name']} ({config['tenant_type'].upper()}):")
            self.stdout.write(f"    Domain: {config['domain']}")
            self.stdout.write(f"    Schema: {config['schema']}")
            self.stdout.write(f"    Users: 4 (owner, hr_manager, recruiter, employee)")
            self.stdout.write(f"    Features: Jobs (ATS), Services, HR, Marketplace")

        self.stdout.write('\n' + self.style.MIGRATE_HEADING('Login Credentials:'))
        self.stdout.write('-' * 40)

        self.stdout.write(f"\n  DEMO COMPANY:")
        for key, config in COMPANY_USERS.items():
            self.stdout.write(f"    {key}: {config['email']} / {config['password']}")

        self.stdout.write('\n' + '=' * 60)
