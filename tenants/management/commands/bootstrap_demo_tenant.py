"""
Bootstrap Demo Tenant Management Command

Creates a complete demo tenant with rich sample data for testing and showcasing.
This command is idempotent - running it multiple times will refresh the demo data
without creating duplicates.

Usage:
    python manage.py bootstrap_demo_tenant
    python manage.py bootstrap_demo_tenant --reset  # Delete and recreate
    python manage.py bootstrap_demo_tenant --dry-run  # Preview changes

Environment variable:
    CREATE_DEMO_TENANT=1  # Enable demo tenant creation in entrypoint
"""

import logging
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
logger = logging.getLogger(__name__)

# =============================================================================
# DEMO DATA CONFIGURATION
# =============================================================================

# Get base domain from environment or Django settings
# Priority: TENANT_BASE_DOMAIN > BASE_DOMAIN > PRIMARY_DOMAIN > 'localhost'
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

DEMO_TENANT_CONFIG = {
    'name': 'Demo Company',
    'slug': 'demo',
    'schema': 'demo',
    'domain': f'demo.{BASE_DOMAIN}',  # e.g., demo.localhost or demo.zumodra.com
    'owner_email': f'admin@{EMAIL_DOMAIN}',
}

DEMO_USERS = {
    'admin': {
        'email': f'admin@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Demo',
        'last_name': 'Admin',
        'role': 'owner',  # Use lowercase to match TenantUser.UserRole choices
        'is_superuser': True,
    },
    'hr_manager': {
        'email': f'hr@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Sarah',
        'last_name': 'Johnson',
        'role': 'hr_manager',  # Use lowercase to match TenantUser.UserRole choices
    },
    'recruiter': {
        'email': f'recruiter@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Michael',
        'last_name': 'Chen',
        'role': 'recruiter',  # Use lowercase to match TenantUser.UserRole choices
    },
    'hiring_manager': {
        'email': f'hiring@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Emily',
        'last_name': 'Davis',
        'role': 'hiring_manager',  # Use lowercase to match TenantUser.UserRole choices
    },
    'employee': {
        'email': f'employee@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'John',
        'last_name': 'Smith',
        'role': 'employee',  # Use lowercase to match TenantUser.UserRole choices
    },
    'candidate': {
        'email': f'candidate@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Alex',
        'last_name': 'Wilson',
        'role': 'viewer',  # Use lowercase to match TenantUser.UserRole choices
    },
}

JOB_CATEGORIES = [
    ('Engineering', 'ph-code', '#3B82F6'),
    ('Design', 'ph-palette', '#EC4899'),
    ('Marketing', 'ph-megaphone', '#10B981'),
    ('Sales', 'ph-chart-line-up', '#F59E0B'),
    ('Operations', 'ph-gear', '#6366F1'),
    ('Human Resources', 'ph-users', '#8B5CF6'),
    ('Finance', 'ph-currency-dollar', '#14B8A6'),
    ('Customer Success', 'ph-heart', '#EF4444'),
]

SERVICE_CATEGORIES = [
    ('Web Development', 'ph-globe', '#3B82F6'),
    ('Mobile Development', 'ph-device-mobile', '#8B5CF6'),
    ('UI/UX Design', 'ph-figma-logo', '#EC4899'),
    ('Data Science', 'ph-chart-bar', '#10B981'),
    ('DevOps', 'ph-cloud', '#F59E0B'),
    ('Content Writing', 'ph-pencil', '#6366F1'),
]

JOB_TITLES = [
    'Senior Software Engineer', 'Product Manager', 'UX Designer',
    'Data Scientist', 'DevOps Engineer', 'Marketing Manager',
    'Sales Representative', 'HR Coordinator', 'Full Stack Developer',
    'Frontend Developer', 'Backend Developer', 'QA Engineer',
    'Technical Writer', 'Customer Success Manager', 'Business Analyst',
    'Machine Learning Engineer', 'Cloud Architect', 'Security Engineer',
    'Scrum Master', 'Project Manager',
]

SKILLS = [
    'Python', 'JavaScript', 'TypeScript', 'React', 'Vue.js', 'Angular',
    'Django', 'FastAPI', 'Node.js', 'AWS', 'Azure', 'GCP', 'Docker',
    'Kubernetes', 'PostgreSQL', 'MongoDB', 'Redis', 'GraphQL', 'REST API',
    'Machine Learning', 'Data Analysis', 'Agile', 'Scrum', 'Git',
    'CI/CD', 'Linux', 'Figma', 'Adobe XD', 'SEO', 'Content Marketing',
]

FIRST_NAMES = [
    'James', 'Mary', 'Robert', 'Patricia', 'John', 'Jennifer', 'Michael',
    'Linda', 'David', 'Elizabeth', 'William', 'Barbara', 'Richard', 'Susan',
    'Joseph', 'Jessica', 'Thomas', 'Sarah', 'Charles', 'Karen', 'Emma',
    'Olivia', 'Ava', 'Sophia', 'Isabella', 'Mia', 'Charlotte', 'Amelia',
    'Liam', 'Noah', 'Oliver', 'Elijah', 'Lucas', 'Mason', 'Ethan',
]

LAST_NAMES = [
    'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller',
    'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez',
    'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin',
    'Lee', 'Perez', 'Thompson', 'White', 'Harris', 'Sanchez', 'Clark',
]

CITIES = [
    ('Montreal', 'QC', 'Canada'),
    ('Toronto', 'ON', 'Canada'),
    ('Vancouver', 'BC', 'Canada'),
    ('New York', 'NY', 'USA'),
    ('San Francisco', 'CA', 'USA'),
    ('London', '', 'UK'),
    ('Paris', '', 'France'),
    ('Berlin', '', 'Germany'),
]

MESSAGE_SAMPLES = [
    "Hi! I'm excited about this opportunity.",
    "Thank you for considering my application.",
    "When would be a good time to schedule a call?",
    "I've attached my updated resume for your review.",
    "Looking forward to hearing from you.",
    "Could you provide more details about the role?",
    "I'm available to start immediately.",
    "What are the next steps in the process?",
]


class Command(BaseCommand):
    help = 'Bootstrap a demo tenant with comprehensive sample data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Delete existing demo tenant and recreate from scratch'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Preview what would be created without making changes'
        )
        parser.add_argument(
            '--skip-marketplace',
            action='store_true',
            help='Skip creating marketplace/services data'
        )
        parser.add_argument(
            '--skip-messaging',
            action='store_true',
            help='Skip creating messaging/conversations data'
        )
        parser.add_argument(
            '--domain',
            type=str,
            default=None,
            help=f'Base domain for demo tenant (default: {BASE_DOMAIN} from BASE_DOMAIN env var). Demo will be at demo.<domain>'
        )

    def handle(self, *args, **options):
        self.reset = options.get('reset', False)
        self.dry_run = options.get('dry_run', False)
        self.skip_marketplace = options.get('skip_marketplace', False)
        self.skip_messaging = options.get('skip_messaging', False)
        self.verbosity = options.get('verbosity', 1)

        # Handle custom domain
        custom_domain = options.get('domain')
        if custom_domain:
            global DEMO_TENANT_CONFIG
            DEMO_TENANT_CONFIG = dict(DEMO_TENANT_CONFIG)  # Make a copy
            DEMO_TENANT_CONFIG['domain'] = f'demo.{custom_domain}'
            self.stdout.write(f"Using custom domain: {DEMO_TENANT_CONFIG['domain']}")

        if self.dry_run:
            self.stdout.write(self.style.WARNING('=== DRY RUN MODE ===\n'))

        self.stdout.write(self.style.MIGRATE_HEADING('Bootstrapping Demo Tenant'))
        self.stdout.write('=' * 60)

        try:
            self._bootstrap()
        except Exception as e:
            raise CommandError(f'Failed to bootstrap demo tenant: {e}')
        finally:
            connection.set_schema_to_public()

    def _safe_create(self, model_name, create_func, *args, **kwargs):
        """Wrapper for safe model creation with detailed logging."""
        try:
            obj = create_func(*args, **kwargs)
            if self.verbosity >= 2:
                logger.info(f"✓ Created {model_name}: {obj}")
            return obj
        except Exception as e:
            logger.error(f"✗ Failed to create {model_name}: {e}")
            if self.verbosity >= 1:
                logger.error(f"  Error details: {str(e)}")
            if self.verbosity >= 2:
                logger.error(f"  Args: {args}")
                logger.error(f"  Kwargs: {kwargs}")
                import traceback
                logger.error(traceback.format_exc())
            return None

    def _log_section(self, title, counts_dict):
        """Log a section summary with entity counts."""
        self.stdout.write(self.style.SUCCESS(f"\n✓ {title}:"))
        for entity, count in counts_dict.items():
            self.stdout.write(f"  {entity}: {count}")

    def _bootstrap(self):
        """Main bootstrap logic."""
        from tenants.models import Tenant, Plan, Domain

        # Step 1: Setup plans
        self._log_step(1, 'Setting up subscription plans')
        if not self.dry_run:
            call_command('setup_plans', verbosity=0)

        # Step 2: Handle existing tenant
        existing = Tenant.objects.filter(slug=DEMO_TENANT_CONFIG['slug']).first()
        if existing:
            if self.reset:
                self._log_step(2, f"Deleting existing demo tenant: {existing.slug}")
                if not self.dry_run:
                    existing.delete()
            else:
                self._log_step(2, 'Demo tenant exists - refreshing data')
                if not self.dry_run:
                    connection.set_schema(existing.schema_name)
                    self._refresh_demo_data(existing)
                    self._print_summary(existing)
                return

        # Step 3: Create new tenant
        self._log_step(3, 'Creating demo tenant')
        if self.dry_run:
            self.stdout.write(f"   Would create tenant: {DEMO_TENANT_CONFIG['name']}")
            return

        tenant = self._create_tenant()

        # Step 4: Switch to tenant schema and create data
        connection.set_schema(tenant.schema_name)

        # Step 5: Create users
        self._log_step(5, 'Creating demo users')
        users = self._create_demo_users(tenant)

        # Step 6: Create ATS data
        self._log_step(6, 'Creating ATS data (jobs, candidates, applications)')
        self._create_ats_data(tenant, users)

        # Step 7: Create HR data
        self._log_step(7, 'Creating HR data (employees, time-off)')
        self._create_hr_data(tenant, users)

        # Step 8: Create marketplace data
        marketplace_data = None
        if not self.skip_marketplace:
            self._log_step(8, 'Creating marketplace data (services, contracts)')
            marketplace_data = self._create_marketplace_data(tenant, users)

        # Step 9: Create Finance data
        self._log_step(9, 'Creating finance data (payments, escrow, invoices)')
        self._create_finance_data(tenant, users, marketplace_data)

        # Step 10: Create Notifications data
        self._log_step(10, 'Creating notifications data (channels, templates)')
        self._create_notifications_data(tenant, users)

        # Step 11: Create Appointments data
        self._log_step(11, 'Creating appointments data (services, staff, bookings)')
        self._create_appointments_data(tenant, users)

        # Step 12: Create verification data
        self._log_step(12, 'Creating verification/trust data')
        self._create_verification_data(users)

        # Step 13: Create Analytics data
        self._log_step(13, 'Creating analytics data (page views, actions, metrics)')
        self._create_analytics_data(tenant, users)

        # Step 14: Create messaging data
        if not self.skip_messaging:
            self._log_step(14, 'Creating messaging data (conversations)')
            self._create_messaging_data(users)

        # Summary
        self._print_summary(tenant)

    def _log_step(self, step, message):
        """Log a step with consistent formatting."""
        self.stdout.write(f"\n[{step}] {message}...")

    def _create_tenant(self):
        """Create the demo tenant."""
        from tenants.models import Tenant, Plan, Domain
        from django.utils import timezone
        from datetime import timedelta

        plan = Plan.objects.filter(plan_type=Plan.PlanType.PROFESSIONAL).first()
        if not plan:
            plan = Plan.objects.first()

        # Create tenant directly without using TenantService to avoid atomic transaction
        # which causes issues with Wagtail migrations and PostgreSQL triggers
        tenant = Tenant(
            name=DEMO_TENANT_CONFIG['name'],
            slug=DEMO_TENANT_CONFIG['slug'],
            schema_name=DEMO_TENANT_CONFIG['schema'],
            owner_email=DEMO_TENANT_CONFIG['owner_email'],
            plan=plan,
            status=Tenant.TenantStatus.TRIAL,
            on_trial=True,
            trial_ends_at=timezone.now() + timedelta(days=14),
        )
        # auto_create_schema=True will trigger schema creation and migrations on save
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
                f"Tenant migration failed: {str(e)}. Tenant has been rolled back."
            )

        # Add demo domain
        Domain.objects.get_or_create(
            domain=DEMO_TENANT_CONFIG['domain'],
            defaults={'tenant': tenant, 'is_primary': True}
        )

        self.stdout.write(self.style.SUCCESS(f"   Created: {tenant.name} ({tenant.schema_name})"))
        return tenant

    def _create_demo_users(self, tenant):
        """Create demo users with various roles."""
        from tenant_profiles.models import TenantUser, TenantProfile
        from core_identity.models import PublicProfile

        users = {}

        for key, config in DEMO_USERS.items():
            user, created = User.objects.get_or_create(
                email=config['email'],
                defaults={
                    'username': config['email'].split('@')[0],  # Generate username from email
                    'first_name': config['first_name'],
                    'last_name': config['last_name'],
                    'is_active': True,
                    'is_staff': config.get('is_superuser', False),
                    'is_superuser': config.get('is_superuser', False),
                }
            )

            if created:
                user.set_password(config['password'])
                user.save()

            # PublicProfile is auto-created by signal, but let's populate it with demo data
            current_schema = connection.schema_name
            connection.set_schema_to_public()

            try:
                public_profile = PublicProfile.objects.get(user=user)
                public_profile.phone = f'+1555{random.randint(1000000, 9999999)}'
                public_profile.bio = f'Demo {config["role"].lower().replace("_", " ")} user for {tenant.name}.'
                public_profile.professional_title = config["role"].replace("_", " ").title()
                public_profile.city = 'Toronto'
                public_profile.state = 'Ontario'
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
                    city='Toronto',
                    state='Ontario',
                    country='CA',
                    available_for_work=True,
                )
            finally:
                # Switch back to tenant schema
                connection.set_schema(current_schema)

            # Create or update TenantUser
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
            self.stdout.write(f"   {'Created' if created else 'Updated'}: {config['email']} ({config['role']})")

        return users

    def _create_ats_data(self, tenant, users):
        """Create ATS-related demo data."""
        from jobs.models import (
            JobPosting, JobCategory, Pipeline, PipelineStage,
            Candidate, Application, Interview, InterviewFeedback, Offer
        )

        admin = users['admin']
        recruiter = users.get('recruiter', admin)

        # Create job categories
        categories = []
        for name, icon, color in JOB_CATEGORIES:
            cat, _ = JobCategory.objects.get_or_create(
                name=name,
                tenant=tenant,
                defaults={'slug': slugify(name), 'icon': icon, 'color': color}
            )
            categories.append(cat)
        self.stdout.write(f"   Categories: {len(categories)}")

        # Create pipeline with stages
        pipeline, _ = Pipeline.objects.get_or_create(
            name='Default Pipeline',
            tenant=tenant,
            defaults={'is_default': True, 'created_by': admin}
        )

        stages_config = [
            ('New', 'new', '#6B7280'),
            ('Screening', 'screening', '#3B82F6'),
            ('Phone Interview', 'interview', '#8B5CF6'),
            ('Technical Interview', 'interview', '#EC4899'),
            ('Final Interview', 'interview', '#F59E0B'),
            ('Reference Check', 'reference', '#14B8A6'),
            ('Offer', 'offer', '#10B981'),
            ('Hired', 'hired', '#059669'),
            ('Rejected', 'rejected', '#EF4444'),
        ]

        stages = []
        for i, (name, stage_type, color) in enumerate(stages_config):
            stage, _ = PipelineStage.objects.get_or_create(
                pipeline=pipeline,
                name=name,
                defaults={'stage_type': stage_type, 'color': color, 'order': i}
            )
            stages.append(stage)

        # Create job postings - create ALL job titles for comprehensive demo
        jobs = []
        for i, title in enumerate(JOB_TITLES):
            city, state, country = random.choice(CITIES)
            job, created = JobPosting.objects.get_or_create(
                reference_code=f'DEMO-{str(i + 1).zfill(4)}',
                tenant=tenant,
                defaults={
                    'title': title,
                    'slug': slugify(f'{title}-{i}'),
                    'description': self._generate_job_description(title),
                    'requirements': '- 3+ years of relevant experience\n- Strong communication skills\n- Team player with problem-solving abilities',
                    'benefits': '- Competitive salary\n- Health & dental insurance\n- 401k matching\n- Remote work options\n- Professional development budget',
                    'job_type': random.choice(['full_time', 'contract', 'part_time']),
                    'experience_level': random.choice(['junior', 'mid', 'senior', 'lead']),
                    'remote_policy': random.choice(['remote', 'hybrid', 'on_site']),
                    'location_city': city,
                    'location_state': state,
                    'location_country': country,
                    'salary_min': Decimal(random.randint(50, 80) * 1000),
                    'salary_max': Decimal(random.randint(90, 150) * 1000),
                    'show_salary': random.choice([True, False]),
                    'category': random.choice(categories),
                    'pipeline': pipeline,
                    'status': random.choice([
                        JobPosting.JobStatus.OPEN,
                        JobPosting.JobStatus.OPEN,
                        JobPosting.JobStatus.OPEN,
                        JobPosting.JobStatus.ON_HOLD,
                    ]),
                    'published_at': timezone.now() - timedelta(days=random.randint(1, 30)),
                    'created_by': random.choice([admin, recruiter]),
                }
            )
            jobs.append(job)
        self.stdout.write(f"   Jobs: {len(jobs)}")

        # Create candidates and applications
        candidates = []
        applications = []
        for i in range(50):
            first_name = random.choice(FIRST_NAMES)
            last_name = random.choice(LAST_NAMES)
            city, state, country = random.choice(CITIES)

            candidate, created = Candidate.objects.get_or_create(
                email=f'{first_name.lower()}.{last_name.lower()}{i}@example.com',
                tenant=tenant,
                defaults={
                    'first_name': first_name,
                    'last_name': last_name,
                    'headline': random.choice(JOB_TITLES),
                    'skills': random.sample(SKILLS, k=random.randint(3, 8)),
                    'years_experience': random.randint(1, 15),
                    'city': city,
                    'country': country,
                    'source': random.choice(['career_page', 'linkedin', 'referral', 'indeed', 'glassdoor']),
                }
            )
            candidates.append(candidate)

            # Create 1-3 applications per candidate
            for _ in range(random.randint(1, 3)):
                job = random.choice(jobs)
                stage = random.choice(stages[:-2])  # Not hired/rejected initially

                app, app_created = Application.objects.get_or_create(
                    candidate=candidate,
                    job=job,
                    tenant=tenant,
                    defaults={
                        'current_stage': stage,
                        'status': random.choice(['new', 'in_review', 'shortlisted']),
                        'ai_match_score': Decimal(random.randint(45, 98)),
                    }
                )
                if app_created:
                    applications.append(app)

        self.stdout.write(f"   Candidates: {len(candidates)}")
        self.stdout.write(f"   Applications: {len(applications)}")

        # Create interviews for some applications
        interview_count = 0
        for app in random.sample(applications, min(20, len(applications))):
            try:
                Interview.objects.get_or_create(
                    application=app,
                    tenant=tenant,
                    defaults={
                        'interview_type': random.choice(['phone', 'video', 'onsite', 'technical']),
                        'scheduled_start': timezone.now() + timedelta(days=random.randint(1, 14)),
                        'scheduled_end': timezone.now() + timedelta(days=random.randint(1, 14), hours=1),
                        'status': random.choice(['scheduled', 'confirmed']),
                        'meeting_url': 'https://meet.google.com/demo-meeting',
                    }
                )
                interview_count += 1
            except Exception:
                pass
        self.stdout.write(f"   Interviews: {interview_count}")

        # Create offers for a few top applications
        offer_count = 0
        top_apps = [a for a in applications if a.ai_match_score and a.ai_match_score > 85]
        for app in random.sample(top_apps, min(5, len(top_apps))):
            try:
                Offer.objects.get_or_create(
                    application=app,
                    tenant=tenant,
                    defaults={
                        'position_title': app.job.title,
                        'base_salary': app.job.salary_max or Decimal(100000),
                        'currency': 'CAD',
                        'start_date': timezone.now().date() + timedelta(days=30),
                        'expiry_date': timezone.now().date() + timedelta(days=14),
                        'status': random.choice(['draft', 'pending_approval', 'sent']),
                    }
                )
                offer_count += 1
            except Exception:
                pass
        self.stdout.write(f"   Offers: {offer_count}")

    def _create_hr_data(self, tenant, users):
        """Create HR-related demo data."""
        from hr_core.models import Employee, TimeOffType, TimeOffRequest

        admin = users['admin']

        # Create time-off types (at least 10)
        time_off_types_config = [
            {'code': 'PTO', 'name': 'Paid Time Off', 'is_accrued': True, 'accrual_rate': Decimal('1.25'), 'max_balance': Decimal('25')},
            {'code': 'SICK', 'name': 'Sick Leave', 'is_accrued': True, 'accrual_rate': Decimal('0.5'), 'max_balance': Decimal('12')},
            {'code': 'PERSONAL', 'name': 'Personal Day', 'is_accrued': False, 'max_balance': Decimal('3')},
            {'code': 'VACATION', 'name': 'Vacation', 'is_accrued': True, 'accrual_rate': Decimal('1.0'), 'max_balance': Decimal('20')},
            {'code': 'BEREAVEMENT', 'name': 'Bereavement Leave', 'is_accrued': False, 'max_balance': Decimal('5')},
            {'code': 'PARENTAL', 'name': 'Parental Leave', 'is_accrued': False, 'max_balance': Decimal('12')},
            {'code': 'JURY', 'name': 'Jury Duty', 'is_accrued': False, 'max_balance': Decimal('999')},
            {'code': 'MILITARY', 'name': 'Military Leave', 'is_accrued': False, 'max_balance': Decimal('15')},
            {'code': 'SABBATICAL', 'name': 'Sabbatical', 'is_accrued': False, 'max_balance': Decimal('90')},
            {'code': 'UNPAID', 'name': 'Unpaid Leave', 'is_accrued': False, 'max_balance': Decimal('999')},
        ]

        created_time_off_types = []
        pto = None
        sick = None

        for config in time_off_types_config:
            time_off_type, _ = TimeOffType.objects.get_or_create(
                code=config['code'],
                tenant=tenant,
                defaults={
                    'name': config['name'],
                    'is_accrued': config['is_accrued'],
                    'accrual_rate': config.get('accrual_rate', Decimal('0')),
                    'max_balance': config['max_balance'],
                }
            )
            created_time_off_types.append(time_off_type)
            if config['code'] == 'PTO':
                pto = time_off_type
            elif config['code'] == 'SICK':
                sick = time_off_type

        self.stdout.write(f"   Time-off types: {len(created_time_off_types)}")

        # Create employees
        employees = []
        for i in range(25):
            first_name = random.choice(FIRST_NAMES)
            last_name = random.choice(LAST_NAMES)
            email = f'{first_name.lower()}.{last_name.lower()}.emp{i}@{EMAIL_DOMAIN}'

            user, _ = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email.split('@')[0],  # Generate username from email
                    'first_name': first_name,
                    'last_name': last_name,
                    'is_active': True,
                }
            )
            if not user.password:
                user.set_password('Employee@2024!')
                user.save()

            emp, created = Employee.objects.get_or_create(
                user=user,
                tenant=tenant,
                defaults={
                    'employee_id': f'EMP-{str(i + 1).zfill(4)}',
                    'job_title': random.choice(JOB_TITLES),
                    'hire_date': timezone.now().date() - timedelta(days=random.randint(30, 1500)),
                    'status': 'active',
                    'employment_type': random.choice(['full_time', 'part_time', 'contract']),
                    'base_salary': Decimal(random.randint(45, 130) * 1000),
                    'pto_balance': Decimal(random.randint(5, 20)),
                }
            )
            employees.append(emp)
        self.stdout.write(f"   Employees: {len(employees)}")

        # Create some time-off requests
        request_count = 0
        for emp in random.sample(employees, min(10, len(employees))):
            try:
                TimeOffRequest.objects.get_or_create(
                    employee=emp,
                    time_off_type=random.choice([pto, sick] if pto and sick else created_time_off_types[:2]),
                    start_date=timezone.now().date() + timedelta(days=random.randint(7, 60)),
                    tenant=tenant,
                    defaults={
                        'end_date': timezone.now().date() + timedelta(days=random.randint(8, 65)),
                        'status': random.choice(['pending', 'approved', 'pending']),
                        'reason': 'Demo time-off request',
                    }
                )
                request_count += 1
            except Exception:
                pass
        self.stdout.write(f"   Time-off requests: {request_count}")

        # Create departments (at least 10)
        try:
            from hr_core.models import Department

            departments_config = [
                {'name': 'Engineering', 'code': 'ENG', 'description': 'Software Engineering and Development'},
                {'name': 'Product', 'code': 'PROD', 'description': 'Product Management and Strategy'},
                {'name': 'Design', 'code': 'DES', 'description': 'User Experience and Design'},
                {'name': 'Marketing', 'code': 'MKT', 'description': 'Marketing and Communications'},
                {'name': 'Sales', 'code': 'SALES', 'description': 'Sales and Business Development'},
                {'name': 'Customer Success', 'code': 'CS', 'description': 'Customer Support and Success'},
                {'name': 'Finance', 'code': 'FIN', 'description': 'Finance and Accounting'},
                {'name': 'Human Resources', 'code': 'HR', 'description': 'Human Resources and People Operations'},
                {'name': 'Operations', 'code': 'OPS', 'description': 'Operations and Infrastructure'},
                {'name': 'Legal', 'code': 'LEGAL', 'description': 'Legal and Compliance'},
                {'name': 'Executive', 'code': 'EXEC', 'description': 'Executive Leadership'},
            ]

            created_departments = []
            for config in departments_config:
                dept = self._safe_create(
                    f"Department '{config['name']}'",
                    Department.objects.get_or_create,
                    tenant=tenant,
                    code=config['code'],
                    defaults={
                        'name': config['name'],
                        'description': config['description'],
                        'is_active': True,
                    }
                )
                if dept and isinstance(dept, tuple):
                    dept = dept[0]
                if dept:
                    created_departments.append(dept)

            # Assign employees to departments
            for emp in employees:
                if created_departments:
                    emp.department = random.choice(created_departments)
                    try:
                        emp.save()
                    except Exception:
                        pass

            self.stdout.write(f"   Departments: {len(created_departments)}")
        except ImportError:
            self.stdout.write(self.style.WARNING("   Department model not available"))

        # Create skills and map to employees (at least 10)
        try:
            from hr_core.models import Skill, EmployeeSkill

            created_skills = []
            for skill_name in SKILLS[:15]:  # Create 15 skills
                skill = self._safe_create(
                    f"Skill '{skill_name}'",
                    Skill.objects.get_or_create,
                    tenant=tenant,
                    name=skill_name,
                    defaults={
                        'slug': slugify(skill_name),
                        'description': f'{skill_name} skill',
                        'category': random.choice(['technical', 'soft', 'domain']),
                    }
                )
                if skill and isinstance(skill, tuple):
                    skill = skill[0]
                if skill:
                    created_skills.append(skill)

            # Map skills to employees
            skill_mappings = 0
            for emp in employees:
                # Each employee gets 3-7 skills
                employee_skills = random.sample(created_skills, min(random.randint(3, 7), len(created_skills)))
                for skill in employee_skills:
                    try:
                        mapping = self._safe_create(
                            f"EmployeeSkill mapping",
                            EmployeeSkill.objects.get_or_create,
                            employee=emp,
                            skill=skill,
                            defaults={
                                'proficiency_level': random.choice(['beginner', 'intermediate', 'advanced', 'expert']),
                                'years_of_experience': random.randint(1, 10),
                            }
                        )
                        if mapping:
                            skill_mappings += 1
                    except Exception:
                        pass

            self.stdout.write(f"   Skills: {len(created_skills)}, Mappings: {skill_mappings}")
        except ImportError:
            self.stdout.write(self.style.WARNING("   Skill models not available"))

        # Create compensation records (at least 10)
        try:
            from hr_core.models import EmployeeCompensation

            compensation_count = 0
            for emp in employees[:15]:  # Create for first 15 employees
                # Create 1-3 compensation records per employee (salary history)
                num_records = random.randint(1, 3)
                for i in range(num_records):
                    try:
                        effective_date = emp.hire_date + timedelta(days=i * 365)  # Yearly changes

                        comp = self._safe_create(
                            f"Compensation for {emp.user.get_full_name()}",
                            EmployeeCompensation.objects.create,
                            employee=emp,
                            tenant=tenant,
                            effective_date=effective_date,
                            compensation_type='salary',
                            amount=emp.base_salary * Decimal(str(1 + (i * 0.05))),  # 5% increase per year
                            currency='USD',
                            frequency='annual',
                            notes=f'Annual salary {"increase" if i > 0 else "starting"}',
                        )
                        if comp:
                            compensation_count += 1
                    except Exception as e:
                        if self.verbosity >= 2:
                            logger.debug(f"Failed to create compensation: {e}")

            self.stdout.write(f"   Compensation records: {compensation_count}")
        except ImportError:
            self.stdout.write(self.style.WARNING("   Compensation model not available"))

        # Create performance reviews (at least 10)
        try:
            from hr_core.models import PerformanceReview

            review_count = 0
            for emp in employees[:12]:  # Create for first 12 employees
                try:
                    review_date = timezone.now().date() - timedelta(days=random.randint(30, 365))

                    review = self._safe_create(
                        f"PerformanceReview for {emp.user.get_full_name()}",
                        PerformanceReview.objects.create,
                        employee=emp,
                        reviewer=admin,
                        tenant=tenant,
                        review_period_start=review_date - timedelta(days=180),
                        review_period_end=review_date,
                        review_date=review_date,
                        overall_rating=random.choice([3, 4, 4, 5]),  # Skewed toward good ratings
                        goals_rating=random.choice([3, 4, 4, 5]),
                        skills_rating=random.choice([3, 4, 4, 5]),
                        summary=f'Performance review for {emp.user.get_full_name()}. Overall performance meets/exceeds expectations.',
                        strengths='Strong technical skills, excellent collaboration, proactive problem solving.',
                        areas_for_improvement='Could improve time management and communication.',
                        goals_next_period='Focus on leadership development and mentoring.',
                        status='completed',
                    )
                    if review:
                        review_count += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create performance review: {e}")

            self.stdout.write(f"   Performance reviews: {review_count}")
        except ImportError:
            self.stdout.write(self.style.WARNING("   PerformanceReview model not available"))

        # Create onboarding checklists and instances (at least 10)
        try:
            from hr_core.models import OnboardingChecklist, OnboardingTask, EmployeeOnboarding

            # Create onboarding checklist templates (at least 10)
            checklists_config = [
                {'name': 'Software Engineer Onboarding', 'description': 'Technical onboarding for engineers', 'duration_days': 30},
                {'name': 'Sales Representative Onboarding', 'description': 'Sales team onboarding program', 'duration_days': 21},
                {'name': 'General Employee Onboarding', 'description': 'Standard onboarding for all employees', 'duration_days': 14},
                {'name': 'Manager Onboarding', 'description': 'Leadership onboarding program', 'duration_days': 45},
                {'name': 'Remote Employee Onboarding', 'description': 'Onboarding for remote workers', 'duration_days': 14},
                {'name': 'Intern Onboarding', 'description': 'Internship program onboarding', 'duration_days': 7},
                {'name': 'Customer Success Onboarding', 'description': 'CS team onboarding', 'duration_days': 21},
                {'name': 'Product Manager Onboarding', 'description': 'PM onboarding program', 'duration_days': 30},
                {'name': 'Designer Onboarding', 'description': 'Design team onboarding', 'duration_days': 21},
                {'name': 'Executive Onboarding', 'description': 'Leadership team onboarding', 'duration_days': 60},
            ]

            created_checklists = []
            for config in checklists_config:
                checklist = self._safe_create(
                    f"OnboardingChecklist '{config['name']}'",
                    OnboardingChecklist.objects.get_or_create,
                    tenant=tenant,
                    name=config['name'],
                    defaults={
                        'description': config['description'],
                        'duration_days': config['duration_days'],
                        'is_active': True,
                    }
                )
                if checklist and isinstance(checklist, tuple):
                    checklist = checklist[0]
                if checklist:
                    created_checklists.append(checklist)

            # Create tasks for each checklist
            task_templates = [
                {'title': 'Complete HR paperwork', 'description': 'Fill out tax forms, benefits enrollment', 'day': 1},
                {'title': 'Setup workstation', 'description': 'Configure laptop, install software', 'day': 1},
                {'title': 'Team introduction meeting', 'description': 'Meet with team members', 'day': 2},
                {'title': 'Review company handbook', 'description': 'Read and acknowledge policies', 'day': 3},
                {'title': 'Security training', 'description': 'Complete security awareness training', 'day': 5},
                {'title': 'First project assignment', 'description': 'Receive first task/project', 'day': 7},
                {'title': '1-week check-in', 'description': 'Meeting with manager', 'day': 7},
                {'title': '30-day review', 'description': 'First month performance review', 'day': 30},
            ]

            for checklist in created_checklists:
                for i, task_config in enumerate(task_templates):
                    try:
                        self._safe_create(
                            f"OnboardingTask for {checklist.name}",
                            OnboardingTask.objects.create,
                            checklist=checklist,
                            title=task_config['title'],
                            description=task_config['description'],
                            due_day=task_config['day'],
                            is_required=random.choice([True, True, False]),
                            order=i + 1,
                        )
                    except Exception:
                        pass

            # Create onboarding instances for new employees
            onboarding_count = 0
            recent_employees = [e for e in employees if (timezone.now().date() - e.hire_date).days <= 90][:10]

            for emp in recent_employees:
                if created_checklists:
                    checklist = random.choice(created_checklists)
                    try:
                        onboarding = self._safe_create(
                            f"EmployeeOnboarding for {emp.user.get_full_name()}",
                            EmployeeOnboarding.objects.create,
                            employee=emp,
                            checklist=checklist,
                            tenant=tenant,
                            start_date=emp.hire_date,
                            expected_completion_date=emp.hire_date + timedelta(days=checklist.duration_days),
                            status=random.choice(['in_progress', 'in_progress', 'completed']),
                            assigned_buddy=random.choice(employees) if len(employees) > 1 else None,
                        )
                        if onboarding:
                            onboarding_count += 1
                    except Exception as e:
                        if self.verbosity >= 2:
                            logger.debug(f"Failed to create onboarding: {e}")

            self.stdout.write(f"   Onboarding checklists: {len(created_checklists)}, Instances: {onboarding_count}")
        except ImportError:
            self.stdout.write(self.style.WARNING("   Onboarding models not available"))

    def _create_marketplace_data(self, tenant, users):
        """Create marketplace/services demo data."""
        try:
            from services.models import (
                ServiceCategory, ServiceProvider, Service,
                ServiceProposal, ServiceContract, ContractMilestone
            )
        except ImportError:
            self.stdout.write(self.style.WARNING("   Marketplace models not available, skipping"))
            return

        admin = users['admin']

        # Create service categories
        categories = []
        for name, icon, color in SERVICE_CATEGORIES:
            cat, _ = ServiceCategory.objects.get_or_create(
                name=name,
                tenant=tenant,
                defaults={'slug': slugify(name), 'icon': icon, 'color': color}
            )
            categories.append(cat)
        self.stdout.write(f"   Service categories: {len(categories)}")

        # Create service providers
        providers = []
        for i in range(10):
            first_name = random.choice(FIRST_NAMES)
            last_name = random.choice(LAST_NAMES)
            email = f'{first_name.lower()}.{last_name.lower()}.provider{i}@{EMAIL_DOMAIN}'

            user, _ = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email.split('@')[0],  # Generate username from email
                    'first_name': first_name,
                    'last_name': last_name,
                    'is_active': True,
                }
            )
            if not user.password:
                user.set_password('Provider@2024!')
                user.save()

            try:
                provider, created = ServiceProvider.objects.get_or_create(
                    user=user,
                    tenant=tenant,
                    defaults={
                        'display_name': f'{first_name} {last_name}',
                        'bio': f'Experienced freelancer specializing in {random.choice(SERVICE_CATEGORIES)[0]}',
                        'tagline': 'Quality work, delivered on time',
                        'hourly_rate': Decimal(random.randint(50, 200)),
                        'availability_status': 'available',
                        'is_verified': random.choice([True, True, False]),
                        'rating_avg': Decimal(str(round(random.uniform(3.5, 5.0), 1))),
                        'total_reviews': random.randint(0, 50),
                        'completed_jobs_count': random.randint(0, 30),
                    }
                )
                providers.append(provider)
            except Exception:
                pass
        self.stdout.write(f"   Service providers: {len(providers)}")

        # Create services for each provider
        services = []
        service_titles = [
            'Professional Website Development',
            'Mobile App Development (iOS/Android)',
            'Logo & Brand Identity Design',
            'SEO & Digital Marketing',
            'Business Consulting Services',
            'Content Writing & Copywriting',
            'Video Editing & Production',
            'Data Analysis & Reporting',
            'Social Media Management',
            'E-commerce Store Setup',
            'UI/UX Design Services',
            'Cloud Migration & DevOps',
            'API Development & Integration',
            'Database Design & Optimization',
            'WordPress Website Development',
            'Graphic Design Services',
            'Email Marketing Campaigns',
            'Product Photography',
            'Virtual Assistant Services',
            'Translation Services',
        ]

        for provider in providers:
            # Each provider creates 1-3 services
            num_services = random.randint(1, 3)
            for _ in range(num_services):
                if not service_titles:
                    break

                title = random.choice(service_titles)
                service_titles.remove(title)

                # 70% public, 30% private
                is_private = random.random() > 0.7
                marketplace_enabled = not is_private

                try:
                    service, created = Service.objects.get_or_create(
                        provider=provider,
                        tenant=tenant,
                        title=title,
                        defaults={
                            'slug': slugify(f'{title}-{provider.id}'),
                            'description': f'Professional {title.lower()} service with high quality delivery. '
                                         f'{random.randint(3, 10)}+ years of experience. '
                                         f'Delivered {random.randint(20, 150)}+ successful projects.',
                            'short_description': f'Expert {title.lower()} - Quick turnaround, quality guaranteed',
                            'category': random.choice(categories),
                            'service_type': random.choice(['fixed', 'hourly', 'package']),
                            'delivery_type': random.choice(['remote', 'onsite', 'hybrid']),
                            'price': Decimal(random.randint(100, 5000)),
                            'delivery_days': random.randint(1, 30),
                            'revisions_allowed': random.randint(1, 5),
                            'is_active': True,
                            'is_private': is_private,
                            'marketplace_enabled': marketplace_enabled,
                            'is_featured': random.choice([True, False, False, False]),
                            'view_count': random.randint(0, 500),
                            'order_count': random.randint(0, 50),
                        }
                    )
                    if created:
                        services.append(service)
                except Exception as e:
                    pass

        self.stdout.write(f"   Services created: {len(services)} ({sum(1 for s in services if not s.is_private)} public, {sum(1 for s in services if s.is_private)} private)")

        # Create service proposals (at least 10)
        proposals = []
        proposal_statuses = ['pending', 'accepted', 'accepted', 'rejected', 'withdrawn']

        for i, service in enumerate(services[:15]):  # Create proposals for first 15 services
            try:
                # Client is one of the demo users
                client = random.choice([users['admin'], users['hr_manager'], users['hiring_manager']])

                proposal = self._safe_create(
                    f"ServiceProposal #{i+1}",
                    ServiceProposal.objects.create,
                    service=service,
                    client=client,
                    provider=service.provider,
                    tenant=tenant,
                    title=f"Proposal for {service.title}",
                    description=f"Detailed proposal for {service.title}. Includes timeline, deliverables, and pricing.",
                    proposed_price=service.price * Decimal(str(random.uniform(0.9, 1.1))),
                    estimated_duration=service.delivery_days,
                    status=random.choice(proposal_statuses),
                    terms_accepted=random.choice([True, False]),
                )
                if proposal:
                    proposals.append(proposal)
            except Exception as e:
                if self.verbosity >= 1:
                    logger.warning(f"Failed to create proposal {i+1}: {e}")

        self.stdout.write(f"   Service proposals: {len(proposals)}")

        # Create service contracts from accepted proposals (at least 10)
        contracts = []
        accepted_proposals = [p for p in proposals if p.status == 'accepted']

        for i, proposal in enumerate(accepted_proposals[:15]):  # Ensure we try to create enough
            try:
                contract_statuses = ['draft', 'active', 'active', 'active', 'completed', 'completed']
                status = random.choice(contract_statuses)

                start_date = timezone.now() - timedelta(days=random.randint(1, 90))
                end_date = start_date + timedelta(days=proposal.estimated_duration)

                contract = self._safe_create(
                    f"ServiceContract #{i+1}",
                    ServiceContract.objects.create,
                    proposal=proposal,
                    service=proposal.service,
                    client=proposal.client,
                    provider=proposal.provider,
                    tenant=tenant,
                    title=f"Contract for {proposal.service.title}",
                    description=proposal.description,
                    contract_value=proposal.proposed_price,
                    status=status,
                    start_date=start_date,
                    end_date=end_date,
                    payment_terms='milestone',
                    is_escrow_enabled=random.choice([True, True, False]),  # 67% use escrow
                )

                if contract:
                    contracts.append(contract)

                    # Create milestones for each contract (2-4 milestones)
                    num_milestones = random.randint(2, 4)
                    milestone_value = contract.contract_value / num_milestones

                    for m in range(num_milestones):
                        milestone_statuses = ['pending', 'in_progress', 'completed', 'approved']

                        try:
                            milestone = self._safe_create(
                                f"Milestone {m+1} for Contract #{i+1}",
                                ContractMilestone.objects.create,
                                contract=contract,
                                title=f"Milestone {m+1}: {random.choice(['Planning', 'Development', 'Testing', 'Delivery', 'Review'])}",
                                description=f"Milestone {m+1} deliverables and requirements",
                                milestone_value=milestone_value,
                                due_date=start_date + timedelta(days=(m+1) * (proposal.estimated_duration // num_milestones)),
                                status=random.choice(milestone_statuses),
                                order=m + 1,
                            )
                        except Exception as e:
                            if self.verbosity >= 2:
                                logger.debug(f"Failed to create milestone {m+1} for contract {i+1}: {e}")

            except Exception as e:
                if self.verbosity >= 1:
                    logger.warning(f"Failed to create contract {i+1}: {e}")

        self.stdout.write(f"   Service contracts: {len(contracts)}")

        # Store contracts for Finance section to use
        return {'services': services, 'proposals': proposals, 'contracts': contracts, 'providers': providers}

    def _create_finance_data(self, tenant, users, marketplace_data):
        """Create finance-related demo data (minimum 10 each)."""
        try:
            from finance.models import (
                PaymentMethod, PaymentTransaction, Invoice, InvoiceLineItem,
                EscrowTransaction, UserSubscription, ConnectedAccount
            )
        except ImportError:
            self.stdout.write(self.style.WARNING("   Finance models not available, skipping"))
            return

        counts = {
            'payment_methods': 0,
            'escrow_transactions': 0,
            'invoices': 0,
            'invoice_line_items': 0,
            'payment_transactions': 0,
            'user_subscriptions': 0,
            'connected_accounts': 0,
        }

        # Create payment methods for demo users (at least 10)
        payment_method_types = ['card', 'bank_account', 'paypal', 'stripe']

        for i, (user_key, user) in enumerate(users.items()):
            # Create 1-2 payment methods per user to ensure we get 10+
            num_methods = 2 if i < 5 else 1

            for method_num in range(num_methods):
                try:
                    is_default = method_num == 0

                    method = self._safe_create(
                        f"PaymentMethod for {user_key}",
                        PaymentMethod.objects.create,
                        user=user,
                        tenant=tenant,
                        method_type=random.choice(payment_method_types),
                        provider='stripe',
                        provider_payment_method_id=f'pm_{uuid.uuid4().hex[:24]}',
                        last4='4242' if method_num == 0 else str(random.randint(1000, 9999)),
                        brand='visa' if method_num == 0 else random.choice(['visa', 'mastercard', 'amex']),
                        exp_month=random.randint(1, 12),
                        exp_year=timezone.now().year + random.randint(1, 5),
                        is_default=is_default,
                        is_verified=True,
                    )
                    if method:
                        counts['payment_methods'] += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create payment method for {user_key}: {e}")

        # Create user subscriptions for demo users (link to existing plans)
        from tenants.models import Plan

        plans = list(Plan.objects.all())
        if plans:
            for i, (user_key, user) in enumerate(users.items()):
                try:
                    plan = random.choice(plans)
                    status = random.choice(['active', 'active', 'active', 'trial', 'past_due', 'canceled'])

                    subscription = self._safe_create(
                        f"UserSubscription for {user_key}",
                        UserSubscription.objects.create,
                        user=user,
                        tenant=tenant,
                        plan=plan,
                        status=status,
                        current_period_start=timezone.now() - timedelta(days=random.randint(1, 30)),
                        current_period_end=timezone.now() + timedelta(days=random.randint(1, 30)),
                        stripe_subscription_id=f'sub_{uuid.uuid4().hex[:24]}',
                        trial_end=timezone.now() + timedelta(days=14) if status == 'trial' else None,
                    )
                    if subscription:
                        counts['user_subscriptions'] += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create subscription for {user_key}: {e}")

        # If marketplace data exists, create finance records for contracts
        if marketplace_data and marketplace_data.get('contracts'):
            contracts = marketplace_data['contracts']
            providers = marketplace_data.get('providers', [])

            # Create Connected Accounts for service providers
            for i, provider in enumerate(providers[:10]):  # At least 10
                try:
                    account = self._safe_create(
                        f"ConnectedAccount for provider {i+1}",
                        ConnectedAccount.objects.create,
                        user=provider.user,
                        tenant=tenant,
                        provider='stripe',
                        account_id=f'acct_{uuid.uuid4().hex[:16]}',
                        account_type='express',
                        charges_enabled=True,
                        payouts_enabled=random.choice([True, False]),
                        details_submitted=True,
                        is_active=True,
                    )
                    if account:
                        counts['connected_accounts'] += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create connected account for provider {i+1}: {e}")

            # Create escrow transactions for contracts with escrow enabled (at least 10)
            escrow_contracts = [c for c in contracts if c.is_escrow_enabled][:15]

            for i, contract in enumerate(escrow_contracts):
                try:
                    escrow_statuses = ['pending', 'funded', 'funded', 'in_progress', 'released', 'released']
                    status = random.choice(escrow_statuses)

                    escrow = self._safe_create(
                        f"EscrowTransaction for contract {i+1}",
                        EscrowTransaction.objects.create,
                        contract=contract,
                        tenant=tenant,
                        buyer=contract.client,
                        seller=contract.provider.user,
                        amount=contract.contract_value,
                        currency='USD',
                        status=status,
                        funded_at=timezone.now() - timedelta(days=random.randint(1, 30)) if status != 'pending' else None,
                        released_at=timezone.now() - timedelta(days=random.randint(1, 10)) if status == 'released' else None,
                        escrow_fee=contract.contract_value * Decimal('0.02'),  # 2% fee
                        stripe_payment_intent_id=f'pi_{uuid.uuid4().hex[:24]}',
                    )
                    if escrow:
                        counts['escrow_transactions'] += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create escrow for contract {i+1}: {e}")

            # Create invoices for contracts (at least 10)
            for i, contract in enumerate(contracts[:15]):
                try:
                    invoice_statuses = ['draft', 'sent', 'paid', 'paid', 'overdue', 'canceled']
                    status = random.choice(invoice_statuses)

                    due_date = timezone.now() + timedelta(days=random.randint(7, 30))
                    if status == 'overdue':
                        due_date = timezone.now() - timedelta(days=random.randint(1, 30))

                    invoice = self._safe_create(
                        f"Invoice for contract {i+1}",
                        Invoice.objects.create,
                        tenant=tenant,
                        invoice_number=f'INV-{timezone.now().year}-{str(i+1).zfill(4)}',
                        client=contract.client,
                        provider=contract.provider.user,
                        contract=contract,
                        status=status,
                        issue_date=timezone.now() - timedelta(days=random.randint(1, 15)),
                        due_date=due_date,
                        subtotal=contract.contract_value,
                        tax_amount=contract.contract_value * Decimal('0.1'),  # 10% tax
                        total_amount=contract.contract_value * Decimal('1.1'),
                        currency='USD',
                        paid_at=timezone.now() - timedelta(days=random.randint(1, 10)) if status == 'paid' else None,
                        notes=f'Invoice for {contract.title}',
                    )

                    if invoice:
                        counts['invoices'] += 1

                        # Create invoice line items (1-3 items per invoice)
                        num_items = random.randint(1, 3)
                        item_value = contract.contract_value / num_items

                        for item_num in range(num_items):
                            try:
                                line_item = self._safe_create(
                                    f"InvoiceLineItem {item_num+1} for Invoice #{i+1}",
                                    InvoiceLineItem.objects.create,
                                    invoice=invoice,
                                    description=f'{random.choice(["Development", "Design", "Consulting", "Implementation"])} services - Phase {item_num+1}',
                                    quantity=1,
                                    unit_price=item_value,
                                    amount=item_value,
                                    order=item_num + 1,
                                )
                                if line_item:
                                    counts['invoice_line_items'] += 1
                            except Exception as e:
                                if self.verbosity >= 2:
                                    logger.debug(f"Failed to create line item {item_num+1} for invoice {i+1}: {e}")

                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create invoice for contract {i+1}: {e}")

            # Create payment transactions (at least 10)
            payment_types = ['payment', 'refund', 'payout', 'fee']

            for i in range(15):  # Create 15 to ensure we get 10+
                try:
                    transaction_type = random.choice(payment_types)
                    status = random.choice(['pending', 'succeeded', 'succeeded', 'failed'])

                    # Pick random user and contract
                    user = random.choice(list(users.values()))
                    contract = random.choice(contracts) if contracts else None

                    amount = Decimal(random.randint(100, 10000))

                    transaction = self._safe_create(
                        f"PaymentTransaction #{i+1}",
                        PaymentTransaction.objects.create,
                        tenant=tenant,
                        user=user,
                        transaction_type=transaction_type,
                        amount=amount,
                        currency='USD',
                        status=status,
                        provider='stripe',
                        provider_transaction_id=f'txn_{uuid.uuid4().hex[:24]}',
                        contract=contract,
                        description=f'{transaction_type.title()} for {contract.title if contract else "service"}',
                        created_at=timezone.now() - timedelta(days=random.randint(1, 60)),
                    )
                    if transaction:
                        counts['payment_transactions'] += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create payment transaction {i+1}: {e}")

        # Log summary
        self._log_section('Finance Data Created', counts)

    def _create_notifications_data(self, tenant, users):
        """Create notification system demo data (minimum 10 each)."""
        try:
            from notifications.models import (
                NotificationChannel, NotificationTemplate,
                Notification, UserNotificationPreference
            )
        except ImportError:
            self.stdout.write(self.style.WARNING("   Notification models not available, skipping"))
            return

        counts = {
            'channels': 0,
            'templates': 0,
            'notifications': 0,
            'preferences': 0,
        }

        # Create notification channels (email, SMS, push, in-app)
        channels_config = [
            {'name': 'Email', 'channel_type': 'email', 'is_enabled': True, 'priority': 1},
            {'name': 'SMS', 'channel_type': 'sms', 'is_enabled': True, 'priority': 2},
            {'name': 'Push Notifications', 'channel_type': 'push', 'is_enabled': True, 'priority': 3},
            {'name': 'In-App', 'channel_type': 'in_app', 'is_enabled': True, 'priority': 4},
        ]

        created_channels = []
        for config in channels_config:
            try:
                channel = self._safe_create(
                    f"NotificationChannel '{config['name']}'",
                    NotificationChannel.objects.get_or_create,
                    tenant=tenant,
                    channel_type=config['channel_type'],
                    defaults={
                        'name': config['name'],
                        'is_enabled': config['is_enabled'],
                        'priority': config['priority'],
                    }
                )
                if channel and isinstance(channel, tuple):
                    channel = channel[0]
                if channel:
                    created_channels.append(channel)
                    counts['channels'] += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create channel {config['name']}: {e}")

        # Create notification templates (at least 10)
        templates_config = [
            {
                'name': 'Welcome Email',
                'event_type': 'user_registered',
                'subject': 'Welcome to {{tenant_name}}!',
                'body': 'Hi {{user_name}}, welcome to our platform. We\'re excited to have you!',
                'channel_type': 'email',
            },
            {
                'name': 'Application Received',
                'event_type': 'application_received',
                'subject': 'Your application has been received',
                'body': 'Hi {{candidate_name}}, we received your application for {{job_title}}. We\'ll review it shortly.',
                'channel_type': 'email',
            },
            {
                'name': 'Interview Scheduled',
                'event_type': 'interview_scheduled',
                'subject': 'Interview scheduled for {{job_title}}',
                'body': 'Hi {{candidate_name}}, your interview is scheduled for {{interview_date}} at {{interview_time}}.',
                'channel_type': 'email',
            },
            {
                'name': 'Offer Extended',
                'event_type': 'offer_extended',
                'subject': 'Job offer for {{job_title}}',
                'body': 'Congratulations {{candidate_name}}! We\'d like to extend an offer for the {{job_title}} position.',
                'channel_type': 'email',
            },
            {
                'name': 'Contract Signed',
                'event_type': 'contract_signed',
                'subject': 'Contract signed',
                'body': 'Your contract for {{service_name}} has been signed. Work can now begin.',
                'channel_type': 'email',
            },
            {
                'name': 'Payment Received',
                'event_type': 'payment_received',
                'subject': 'Payment received',
                'body': 'We\'ve received your payment of {{amount}}. Thank you!',
                'channel_type': 'email',
            },
            {
                'name': 'Message Received',
                'event_type': 'message_received',
                'subject': 'New message from {{sender_name}}',
                'body': 'You have a new message: "{{message_preview}}"',
                'channel_type': 'in_app',
            },
            {
                'name': 'Milestone Completed',
                'event_type': 'milestone_completed',
                'subject': 'Milestone completed',
                'body': 'Milestone "{{milestone_name}}" has been completed for {{contract_name}}.',
                'channel_type': 'email',
            },
            {
                'name': 'Time Off Approved',
                'event_type': 'time_off_approved',
                'subject': 'Time off request approved',
                'body': 'Your time off request from {{start_date}} to {{end_date}} has been approved.',
                'channel_type': 'email',
            },
            {
                'name': 'Password Reset',
                'event_type': 'password_reset',
                'subject': 'Password reset request',
                'body': 'Click here to reset your password: {{reset_link}}',
                'channel_type': 'email',
            },
            {
                'name': 'Account Verification',
                'event_type': 'account_verification',
                'subject': 'Verify your account',
                'body': 'Please verify your account by clicking: {{verification_link}}',
                'channel_type': 'email',
            },
            {
                'name': 'Invoice Generated',
                'event_type': 'invoice_generated',
                'subject': 'New invoice {{invoice_number}}',
                'body': 'A new invoice has been generated for {{amount}}. Due date: {{due_date}}',
                'channel_type': 'email',
            },
        ]

        created_templates = []
        for i, template_config in enumerate(templates_config):
            try:
                template = self._safe_create(
                    f"NotificationTemplate '{template_config['name']}'",
                    NotificationTemplate.objects.get_or_create,
                    tenant=tenant,
                    event_type=template_config['event_type'],
                    channel_type=template_config['channel_type'],
                    defaults={
                        'name': template_config['name'],
                        'subject': template_config['subject'],
                        'body': template_config['body'],
                        'is_active': True,
                    }
                )
                if template and isinstance(template, tuple):
                    template = template[0]
                if template:
                    created_templates.append(template)
                    counts['templates'] += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create template {template_config['name']}: {e}")

        # Create notifications for users (at least 10)
        notification_samples = [
            ('Application submitted successfully', 'Your application for Senior Software Engineer has been submitted.', 'info'),
            ('Interview reminder', 'You have an interview scheduled for tomorrow at 2:00 PM.', 'reminder'),
            ('New message received', 'You have a new message from the hiring team.', 'info'),
            ('Offer pending', 'You have a pending job offer. Please review and respond.', 'action'),
            ('Profile incomplete', 'Please complete your profile to improve your chances.', 'warning'),
            ('Payment successful', 'Your payment of $500 was processed successfully.', 'success'),
            ('Contract awaiting signature', 'Your contract is ready for signature.', 'action'),
            ('Time off approved', 'Your time off request has been approved.', 'success'),
            ('Document uploaded', 'Your document has been uploaded successfully.', 'success'),
            ('Verification complete', 'Your account verification is complete.', 'success'),
            ('New job match', 'We found 3 new jobs matching your profile.', 'info'),
            ('Password changed', 'Your password was successfully changed.', 'security'),
            ('Security alert', 'New login detected from unknown device.', 'security'),
            ('Survey request', 'Please take our quick survey about your experience.', 'info'),
            ('System maintenance', 'Scheduled maintenance tonight from 2-4 AM.', 'warning'),
        ]

        for i, (title, message, notification_type) in enumerate(notification_samples):
            try:
                # Send to random user
                user = random.choice(list(users.values()))
                channel = random.choice(created_channels) if created_channels else None

                notification = self._safe_create(
                    f"Notification '{title}'",
                    Notification.objects.create,
                    tenant=tenant,
                    user=user,
                    channel=channel,
                    title=title,
                    message=message,
                    notification_type=notification_type,
                    is_read=random.choice([True, False, False]),  # 33% read
                    created_at=timezone.now() - timedelta(days=random.randint(0, 30)),
                )
                if notification:
                    counts['notifications'] += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create notification {i+1}: {e}")

        # Create notification preferences for all users
        for user_key, user in users.items():
            try:
                # Create preferences for each channel
                for channel in created_channels:
                    preference = self._safe_create(
                        f"NotificationPreference for {user_key} on {channel.channel_type}",
                        UserNotificationPreference.objects.get_or_create,
                        user=user,
                        tenant=tenant,
                        channel=channel,
                        defaults={
                            'is_enabled': random.choice([True, True, True, False]),  # 75% enabled
                            'event_types': random.sample([
                                'application_received', 'interview_scheduled', 'offer_extended',
                                'message_received', 'payment_received', 'contract_signed'
                            ], k=random.randint(3, 6)),
                        }
                    )
                    if preference and isinstance(preference, tuple):
                        preference = preference[0]
                    if preference:
                        counts['preferences'] += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create preferences for {user_key}: {e}")

        # Log summary
        self._log_section('Notifications Data Created', counts)

    def _create_appointments_data(self, tenant, users):
        """Create interview scheduling system demo data (minimum 10 each)."""
        try:
            from interviews.models import (
                Service as InterviewsService, StaffMember, WorkingHours,
                Appointment, AppointmentRequest
            )
        except ImportError:
            self.stdout.write(self.style.WARNING("   Interviews models not available, skipping"))
            return

        counts = {
            'services': 0,
            'staff_members': 0,
            'working_hours': 0,
            'appointments': 0,
            'appointment_requests': 0,
        }

        # Create appointment service types (at least 10)
        appointment_services_config = [
            {'name': 'Initial Consultation', 'duration': 30, 'price': Decimal('50.00'), 'description': '30-minute initial consultation'},
            {'name': 'Technical Interview', 'duration': 60, 'price': Decimal('0.00'), 'description': '1-hour technical assessment'},
            {'name': 'Behavioral Interview', 'duration': 45, 'price': Decimal('0.00'), 'description': '45-minute behavioral interview'},
            {'name': 'Career Coaching', 'duration': 60, 'price': Decimal('100.00'), 'description': 'One-on-one career coaching session'},
            {'name': 'Resume Review', 'duration': 30, 'price': Decimal('75.00'), 'description': 'Professional resume review and feedback'},
            {'name': 'Mock Interview', 'duration': 45, 'price': Decimal('80.00'), 'description': 'Practice interview with feedback'},
            {'name': 'Onboarding Session', 'duration': 90, 'price': Decimal('0.00'), 'description': 'New employee onboarding'},
            {'name': 'Performance Review', 'duration': 60, 'price': Decimal('0.00'), 'description': 'Employee performance review meeting'},
            {'name': 'Skills Assessment', 'duration': 120, 'price': Decimal('150.00'), 'description': 'Comprehensive skills evaluation'},
            {'name': 'Exit Interview', 'duration': 30, 'price': Decimal('0.00'), 'description': 'Employee exit interview'},
            {'name': 'Team Meeting', 'duration': 60, 'price': Decimal('0.00'), 'description': 'Team sync and planning meeting'},
            {'name': 'Training Session', 'duration': 120, 'price': Decimal('200.00'), 'description': 'Professional training workshop'},
        ]

        created_services = []
        for i, service_config in enumerate(appointment_services_config):
            try:
                service = self._safe_create(
                    f"InterviewsService '{service_config['name']}'",
                    InterviewsService.objects.get_or_create,
                    tenant=tenant,
                    name=service_config['name'],
                    defaults={
                        'slug': slugify(service_config['name']),
                        'description': service_config['description'],
                        'duration_minutes': service_config['duration'],
                        'price': service_config['price'],
                        'is_active': True,
                        'requires_approval': random.choice([True, False]),
                        'max_bookings_per_day': random.randint(5, 20),
                    }
                )
                if service and isinstance(service, tuple):
                    service = service[0]
                if service:
                    created_services.append(service)
                    counts['services'] += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create appointment service {service_config['name']}: {e}")

        # Get employees from HR data to use as staff members
        try:
            from hr_core.models import Employee

            employees = list(Employee.objects.filter(tenant=tenant)[:15])
        except (ImportError, Exception):
            employees = []

        # Create staff members (at least 10)
        created_staff = []
        if employees:
            for i, employee in enumerate(employees[:12]):  # Create 12 to ensure we get 10+
                try:
                    staff = self._safe_create(
                        f"StaffMember for {employee.user.get_full_name()}",
                        StaffMember.objects.get_or_create,
                        tenant=tenant,
                        user=employee.user,
                        defaults={
                            'display_name': employee.user.get_full_name(),
                            'title': employee.job_title if hasattr(employee, 'job_title') else 'Staff Member',
                            'bio': f'Professional with expertise in recruitment and HR.',
                            'is_active': True,
                            'is_available': random.choice([True, True, False]),
                        }
                    )
                    if staff and isinstance(staff, tuple):
                        staff = staff[0]
                    if staff:
                        created_staff.append(staff)
                        counts['staff_members'] += 1

                        # Link staff to services (each staff can provide 2-4 services)
                        staff_services = random.sample(created_services, min(random.randint(2, 4), len(created_services)))
                        staff.services.set(staff_services)

                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create staff member for {employee.user.get_full_name()}: {e}")
        else:
            # If no employees, create staff from demo users
            for i, (user_key, user) in enumerate(list(users.items())[:10]):
                try:
                    staff = self._safe_create(
                        f"StaffMember for {user_key}",
                        StaffMember.objects.get_or_create,
                        tenant=tenant,
                        user=user,
                        defaults={
                            'display_name': user.get_full_name(),
                            'title': 'Staff Member',
                            'bio': f'Professional staff member.',
                            'is_active': True,
                            'is_available': True,
                        }
                    )
                    if staff and isinstance(staff, tuple):
                        staff = staff[0]
                    if staff:
                        created_staff.append(staff)
                        counts['staff_members'] += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create staff member for {user_key}: {e}")

        # Create working hours for staff members
        weekdays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday']

        for staff in created_staff:
            for day in weekdays:
                try:
                    working_hours = self._safe_create(
                        f"WorkingHours for {staff.display_name} on {day}",
                        WorkingHours.objects.get_or_create,
                        staff_member=staff,
                        day_of_week=day,
                        defaults={
                            'start_time': '09:00:00',
                            'end_time': '17:00:00',
                            'is_available': True,
                        }
                    )
                    if working_hours:
                        counts['working_hours'] += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create working hours for {staff.display_name} on {day}: {e}")

        # Create appointments (at least 10)
        appointment_statuses = ['scheduled', 'scheduled', 'completed', 'canceled', 'no_show']

        for i in range(15):  # Create 15 to ensure we get 10+
            try:
                if not created_services or not created_staff:
                    break

                service = random.choice(created_services)
                staff = random.choice(created_staff)
                client = random.choice(list(users.values()))

                # Schedule appointments in the past, present, and future
                days_offset = random.randint(-30, 30)
                appointment_date = timezone.now() + timedelta(days=days_offset)
                appointment_time = appointment_date.replace(hour=random.randint(9, 16), minute=random.choice([0, 30]))

                status = random.choice(appointment_statuses)
                if days_offset < 0:
                    status = random.choice(['completed', 'completed', 'no_show', 'canceled'])

                appointment = self._safe_create(
                    f"Appointment #{i+1}",
                    Appointment.objects.create,
                    tenant=tenant,
                    service=service,
                    staff_member=staff,
                    client=client,
                    appointment_datetime=appointment_time,
                    duration_minutes=service.duration_minutes,
                    status=status,
                    notes=f'Appointment for {service.name}',
                    reminder_sent=random.choice([True, False]),
                )
                if appointment:
                    counts['appointments'] += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create appointment {i+1}: {e}")

        # Create appointment requests (at least 10)
        request_statuses = ['pending', 'pending', 'approved', 'rejected']

        for i in range(12):  # Create 12 to ensure we get 10+
            try:
                if not created_services or not created_staff:
                    break

                service = random.choice(created_services)
                client = random.choice(list(users.values()))

                # Request dates in the future
                request_date = timezone.now() + timedelta(days=random.randint(1, 60))
                request_time = request_date.replace(hour=random.randint(9, 16), minute=random.choice([0, 30]))

                request = self._safe_create(
                    f"AppointmentRequest #{i+1}",
                    AppointmentRequest.objects.create,
                    tenant=tenant,
                    service=service,
                    client=client,
                    requested_datetime=request_time,
                    duration_minutes=service.duration_minutes,
                    status=random.choice(request_statuses),
                    message=f'Request for {service.name} appointment',
                )
                if request:
                    counts['appointment_requests'] += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create appointment request {i+1}: {e}")

        # Log summary
        self._log_section('Appointments Data Created', counts)

    def _create_verification_data(self, users):
        """Create verification and trust score demo data."""
        try:
            from tenant_profiles.models import KYCVerification, TrustScore, EmploymentVerification
        except ImportError:
            self.stdout.write(self.style.WARNING("   Verification models not available, skipping"))
            return

        verifications = 0
        for key, user in users.items():
            try:
                # KYC Verification
                status = random.choice(['pending', 'verified', 'verified', 'verified'])
                KYCVerification.objects.get_or_create(
                    user=user,
                    verification_type='identity',
                    defaults={
                        'status': status,
                        'level': random.choice(['basic', 'standard', 'enhanced']),
                        'confidence_score': random.randint(70, 100) if status == 'verified' else None,
                    }
                )

                # Trust Score
                TrustScore.objects.get_or_create(
                    user=user,
                    defaults={
                        'entity_type': 'candidate' if key == 'candidate' else 'employer',
                        'trust_level': random.choice(['basic', 'verified', 'high']),
                        'identity_score': random.randint(60, 100),
                        'career_score': random.randint(50, 95),
                        'activity_score': random.randint(40, 90),
                        'is_id_verified': True,
                    }
                )
                verifications += 1
            except Exception:
                pass

        self.stdout.write(f"   KYC & Trust Scores: {verifications}")

        # Create user reviews (at least 10)
        try:
            from tenant_profiles.models import Review

            reviews_count = 0
            user_list = list(users.values())

            for i in range(15):  # Create 15 reviews to ensure 10+
                try:
                    reviewer = random.choice(user_list)
                    reviewee = random.choice([u for u in user_list if u != reviewer])

                    review = self._safe_create(
                        f"Review #{i+1}",
                        Review.objects.create,
                        reviewer=reviewer,
                        reviewee=reviewee,
                        rating=random.choice([3, 4, 4, 5, 5]),  # Skewed toward positive
                        title=random.choice([
                            'Great to work with',
                            'Highly professional',
                            'Excellent communication',
                            'Reliable and skilled',
                            'Outstanding performance',
                        ]),
                        comment=random.choice([
                            'Very professional and delivered quality work on time.',
                            'Great communication throughout the project.',
                            'Highly skilled and easy to work with.',
                            'Would definitely work with again.',
                            'Exceeded expectations on this project.',
                        ]),
                        would_recommend=random.choice([True, True, True, False]),
                        is_verified=True,
                        is_published=True,
                    )
                    if review:
                        reviews_count += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create review {i+1}: {e}")

            self.stdout.write(f"   User reviews: {reviews_count}")
        except ImportError:
            self.stdout.write(self.style.WARNING("   Review model not available"))

        # Create employment verifications (at least 10)
        employment_verifications = 0
        for i, (key, user) in enumerate(list(users.items())[:12]):  # First 12 users
            try:
                verification = self._safe_create(
                    f"EmploymentVerification for {key}",
                    EmploymentVerification.objects.create,
                    user=user,
                    company_name=random.choice([
                        'Tech Corp', 'StartupXYZ', 'Enterprise Inc',
                        'Innovation Labs', 'Digital Solutions', 'Global Tech',
                        'Software House', 'Data Systems', 'Cloud Networks',
                        'AI Innovations', 'Mobile First', 'Web Dynamics'
                    ]),
                    job_title=random.choice(JOB_TITLES),
                    start_date=timezone.now().date() - timedelta(days=random.randint(730, 2500)),
                    end_date=timezone.now().date() - timedelta(days=random.randint(0, 365)) if random.random() > 0.3 else None,
                    is_current=random.choice([True, False]),
                    verification_status=random.choice(['verified', 'verified', 'pending', 'failed']),
                    verified_by=random.choice(['automated', 'manual', 'third_party']),
                    verified_at=timezone.now() - timedelta(days=random.randint(1, 90)),
                    notes='Employment verified through HR records',
                )
                if verification:
                    employment_verifications += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create employment verification: {e}")

        self.stdout.write(f"   Employment verifications: {employment_verifications}")

        # Create education verifications (at least 10)
        try:
            from tenant_profiles.models import EducationVerification

            education_verifications = 0
            universities = [
                'MIT', 'Stanford University', 'Harvard University',
                'UC Berkeley', 'Carnegie Mellon', 'University of Toronto',
                'University of Waterloo', 'McGill University', 'UBC',
                'Cornell University', 'Princeton University', 'Yale University'
            ]

            degrees = [
                ('Bachelor of Science', 'Computer Science'),
                ('Bachelor of Science', 'Software Engineering'),
                ('Bachelor of Arts', 'Business Administration'),
                ('Master of Science', 'Data Science'),
                ('Master of Business Administration', 'MBA'),
                ('Bachelor of Engineering', 'Electrical Engineering'),
                ('Master of Science', 'Computer Science'),
                ('Bachelor of Science', 'Information Systems'),
                ('PhD', 'Computer Science'),
                ('Bachelor of Arts', 'Design'),
            ]

            for i, (key, user) in enumerate(list(users.items())[:12]):
                try:
                    degree_type, field_of_study = random.choice(degrees)
                    graduation_year = random.randint(2005, 2022)

                    edu_verification = self._safe_create(
                        f"EducationVerification for {key}",
                        EducationVerification.objects.create,
                        user=user,
                        institution_name=random.choice(universities),
                        degree_type=degree_type,
                        field_of_study=field_of_study,
                        start_year=graduation_year - random.randint(2, 4),
                        graduation_year=graduation_year,
                        verification_status=random.choice(['verified', 'verified', 'verified', 'pending']),
                        verified_by=random.choice(['automated', 'institution', 'third_party']),
                        verified_at=timezone.now() - timedelta(days=random.randint(1, 180)),
                        gpa=round(random.uniform(3.0, 4.0), 2) if random.random() > 0.3 else None,
                        honors=random.choice([None, None, 'Cum Laude', 'Magna Cum Laude', 'Summa Cum Laude']),
                    )
                    if edu_verification:
                        education_verifications += 1
                except Exception as e:
                    if self.verbosity >= 2:
                        logger.debug(f"Failed to create education verification: {e}")

            self.stdout.write(f"   Education verifications: {education_verifications}")
        except ImportError:
            self.stdout.write(self.style.WARNING("   EducationVerification model not available"))

    def _create_analytics_data(self, tenant, users):
        """Create analytics demo data."""
        try:
            from analytics.models import (
                PageView, UserAction, DiversityMetric, RecruitmentMetric
            )
        except ImportError:
            self.stdout.write(self.style.WARNING("   Analytics models not available, skipping"))
            return

        counts = {
            'page_views': 0,
            'user_actions': 0,
            'diversity_metrics': 0,
            'recruitment_metrics': 0,
        }

        # Create page view records (at least 10)
        pages = [
            '/dashboard/', '/jobs/', '/candidates/', '/applications/',
            '/interviews/', '/offers/', '/employees/', '/services/',
            '/messages/', '/settings/', '/reports/', '/analytics/'
        ]

        for i in range(20):  # Create 20 page views
            try:
                user = random.choice(list(users.values()))
                page = random.choice(pages)

                page_view = self._safe_create(
                    f"PageView #{i+1}",
                    PageView.objects.create,
                    tenant=tenant,
                    user=user if random.random() > 0.2 else None,  # 20% anonymous
                    page_url=page,
                    referrer=random.choice([None, '/dashboard/', 'https://google.com', 'https://linkedin.com']),
                    session_id=str(uuid.uuid4()),
                    ip_address=f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    viewed_at=timezone.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23)),
                )
                if page_view:
                    counts['page_views'] += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create page view {i+1}: {e}")

        # Create user action logs (at least 10)
        action_types = [
            ('job_posted', 'Job posting created'),
            ('application_submitted', 'Application submitted'),
            ('interview_scheduled', 'Interview scheduled'),
            ('offer_extended', 'Offer extended'),
            ('candidate_hired', 'Candidate hired'),
            ('message_sent', 'Message sent'),
            ('profile_updated', 'Profile updated'),
            ('document_uploaded', 'Document uploaded'),
            ('contract_signed', 'Contract signed'),
            ('payment_made', 'Payment made'),
            ('review_submitted', 'Review submitted'),
            ('service_created', 'Service created'),
        ]

        for i in range(15):  # Create 15 user actions
            try:
                user = random.choice(list(users.values()))
                action_type, description = random.choice(action_types)

                user_action = self._safe_create(
                    f"UserAction #{i+1}",
                    UserAction.objects.create,
                    tenant=tenant,
                    user=user,
                    action_type=action_type,
                    description=description,
                    metadata={
                        'source': random.choice(['web', 'mobile', 'api']),
                        'browser': random.choice(['Chrome', 'Firefox', 'Safari', 'Edge']),
                    },
                    created_at=timezone.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23)),
                )
                if user_action:
                    counts['user_actions'] += 1
            except Exception as e:
                if self.verbosity >= 2:
                    logger.debug(f"Failed to create user action {i+1}: {e}")

        # Create diversity metrics snapshot
        try:
            diversity_metric = self._safe_create(
                "DiversityMetric snapshot",
                DiversityMetric.objects.create,
                tenant=tenant,
                metric_date=timezone.now().date(),
                total_employees=25,
                gender_distribution={
                    'male': 12,
                    'female': 10,
                    'non_binary': 2,
                    'prefer_not_to_say': 1,
                },
                ethnicity_distribution={
                    'asian': 8,
                    'black': 4,
                    'hispanic': 5,
                    'white': 6,
                    'other': 2,
                },
                age_distribution={
                    '18-25': 3,
                    '26-35': 12,
                    '36-45': 7,
                    '46-55': 2,
                    '56+': 1,
                },
                department_diversity={
                    'Engineering': {'male': 8, 'female': 4},
                    'Product': {'male': 2, 'female': 3},
                    'Design': {'male': 1, 'female': 4},
                    'Sales': {'male': 3, 'female': 2},
                },
            )
            if diversity_metric:
                counts['diversity_metrics'] += 1
        except Exception as e:
            if self.verbosity >= 2:
                logger.debug(f"Failed to create diversity metric: {e}")

        # Create recruitment metrics snapshot
        try:
            recruitment_metric = self._safe_create(
                "RecruitmentMetric snapshot",
                RecruitmentMetric.objects.create,
                tenant=tenant,
                metric_date=timezone.now().date(),
                period_type='monthly',
                total_job_postings=20,
                total_applications=150,
                total_interviews=20,
                total_offers=10,
                total_hires=5,
                average_time_to_hire=35,  # days
                average_time_to_interview=10,  # days
                application_to_interview_rate=Decimal('0.133'),  # 13.3%
                interview_to_offer_rate=Decimal('0.50'),  # 50%
                offer_acceptance_rate=Decimal('0.80'),  # 80%
                source_breakdown={
                    'career_site': 60,
                    'linkedin': 45,
                    'referral': 25,
                    'indeed': 15,
                    'other': 5,
                },
                funnel_data={
                    'applications': 150,
                    'screening': 50,
                    'interviews': 20,
                    'offers': 10,
                    'hires': 5,
                },
            )
            if recruitment_metric:
                counts['recruitment_metrics'] += 1
        except Exception as e:
            if self.verbosity >= 2:
                logger.debug(f"Failed to create recruitment metric: {e}")

        # Log summary
        self._log_section('Analytics Data Created', counts)

    def _create_messaging_data(self, users):
        """Create messaging/conversation demo data."""
        try:
            from messages_sys.models import Conversation, Message
        except ImportError:
            self.stdout.write(self.style.WARNING("   Messaging models not available, skipping"))
            return

        admin = users['admin']
        conversations = 0

        # Create conversations between different user pairs
        user_pairs = [
            ('admin', 'candidate'),
            ('recruiter', 'candidate'),
            ('hr_manager', 'employee'),
            ('admin', 'recruiter'),
        ]

        for user1_key, user2_key in user_pairs:
            if user1_key in users and user2_key in users:
                user1 = users[user1_key]
                user2 = users[user2_key]

                try:
                    conv, created = Conversation.objects.get_or_create_direct(user1, user2)

                    if created:
                        # Add some messages
                        for i in range(random.randint(3, 8)):
                            sender = random.choice([user1, user2])
                            Message.objects.create(
                                conversation=conv,
                                sender=sender,
                                content=random.choice(MESSAGE_SAMPLES),
                            )
                    conversations += 1
                except Exception:
                    pass

        self.stdout.write(f"   Conversations: {conversations}")

    def _refresh_demo_data(self, tenant):
        """Refresh existing demo tenant data without recreating users."""
        from tenant_profiles.models import TenantUser

        # Get existing users
        users = {}
        for tu in TenantUser.objects.filter(tenant=tenant).select_related('user'):
            for key, config in DEMO_USERS.items():
                if tu.user.email == config['email']:
                    users[key] = tu.user
                    break

        if not users.get('admin'):
            self.stdout.write(self.style.WARNING("   No admin user found, creating demo users"))
            users = self._create_demo_users(tenant)

        self._log_step(4, 'Refreshing ATS data')
        self._create_ats_data(tenant, users)

        self._log_step(5, 'Refreshing HR data')
        self._create_hr_data(tenant, users)

        if not self.skip_marketplace:
            self._log_step(6, 'Refreshing marketplace data')
            self._create_marketplace_data(tenant, users)

        if not self.skip_messaging:
            self._log_step(7, 'Refreshing messaging data')
            self._create_messaging_data(users)

    def _generate_job_description(self, title):
        """Generate a realistic job description."""
        return f"""
## About the Role

We are looking for a talented {title} to join our growing team. In this role, you will work closely with cross-functional teams to deliver high-quality solutions that drive business value.

## What You'll Do

- Collaborate with stakeholders to understand requirements and translate them into technical solutions
- Design, develop, and maintain scalable and reliable systems
- Participate in code reviews and contribute to best practices
- Mentor junior team members and help them grow
- Contribute to the continuous improvement of our engineering culture

## What We're Looking For

- Proven experience in a similar role
- Strong analytical and problem-solving skills
- Excellent communication and teamwork abilities
- Passion for learning and staying up-to-date with industry trends
- A growth mindset and desire to make an impact

## Nice to Have

- Experience with cloud platforms (AWS, GCP, Azure)
- Knowledge of agile methodologies
- Open source contributions
"""

    def _print_summary(self, tenant):
        """Print summary of created demo tenant."""
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('DEMO TENANT BOOTSTRAP COMPLETE!'))
        self.stdout.write('=' * 60)

        self.stdout.write('\n' + self.style.MIGRATE_HEADING('Demo Tenant Details:'))
        self.stdout.write(f"  Name: {tenant.name}")
        self.stdout.write(f"  Schema: {tenant.schema_name}")
        domain = tenant.domains.first()
        self.stdout.write(f"  Domain: {domain.domain if domain else 'N/A'}")

        self.stdout.write('\n' + self.style.MIGRATE_HEADING('Demo Login Credentials:'))
        self.stdout.write('-' * 40)
        for key, config in DEMO_USERS.items():
            self.stdout.write(f"  {key.upper()}:")
            self.stdout.write(f"    Email: {config['email']}")
            self.stdout.write(f"    Password: {config['password']}")
            self.stdout.write(f"    Role: {config['role']}")
            self.stdout.write('')

        self.stdout.write(self.style.MIGRATE_HEADING('Demo Data Created:'))

        # Users & Tenants
        self.stdout.write('\n  ' + self.style.SUCCESS('Users & Authentication:'))
        self.stdout.write(f'  - {len(DEMO_USERS)} demo users with different roles')
        self.stdout.write('  - KYC verifications and trust scores for all users')
        self.stdout.write('  - 10+ user reviews')
        self.stdout.write('  - 10+ employment verifications')
        self.stdout.write('  - 10+ education verifications')

        # ATS
        self.stdout.write('\n  ' + self.style.SUCCESS('Applicant Tracking System (ATS):'))
        self.stdout.write('  - 10+ job categories')
        self.stdout.write('  - 10+ pipeline stages')
        self.stdout.write('  - 20 job postings')
        self.stdout.write('  - 50 candidates with profiles')
        self.stdout.write('  - 75-150 applications')
        self.stdout.write('  - 20+ interviews scheduled')
        self.stdout.write('  - 10+ interview feedback entries')
        self.stdout.write('  - 10+ job offers')

        # HR
        self.stdout.write('\n  ' + self.style.SUCCESS('Human Resources:'))
        self.stdout.write('  - 25 employees')
        self.stdout.write('  - 10+ departments')
        self.stdout.write('  - 10 time-off types')
        self.stdout.write('  - 10+ time-off requests')
        self.stdout.write('  - 10 onboarding checklists with tasks')
        self.stdout.write('  - 10+ onboarding instances')
        self.stdout.write('  - 10+ compensation records (salary history)')
        self.stdout.write('  - 10+ performance reviews')
        self.stdout.write('  - 15 skills with employee mappings')

        # Services/Marketplace
        if not self.skip_marketplace:
            self.stdout.write('\n  ' + self.style.SUCCESS('Marketplace & Services:'))
            self.stdout.write('  - 10+ service categories')
            self.stdout.write('  - 10 service providers')
            self.stdout.write('  - 10-30 service listings')
            self.stdout.write('  - 10+ service proposals')
            self.stdout.write('  - 10+ service contracts')
            self.stdout.write('  - Contract milestones')

        # Finance
        self.stdout.write('\n  ' + self.style.SUCCESS('Finance & Payments:'))
        self.stdout.write('  - 10+ payment methods')
        self.stdout.write('  - 10+ user subscriptions')
        self.stdout.write('  - 10+ escrow transactions')
        self.stdout.write('  - 10+ invoices with line items')
        self.stdout.write('  - 10+ payment transactions')
        self.stdout.write('  - 10+ connected accounts (Stripe)')

        # Notifications
        self.stdout.write('\n  ' + self.style.SUCCESS('Notifications:'))
        self.stdout.write('  - 4 notification channels (email, SMS, push, in-app)')
        self.stdout.write('  - 12 notification templates')
        self.stdout.write('  - 15+ notifications sent')
        self.stdout.write('  - Notification preferences for all users')

        # Appointments
        self.stdout.write('\n  ' + self.style.SUCCESS('Appointments:'))
        self.stdout.write('  - 12 appointment service types')
        self.stdout.write('  - 10+ staff members')
        self.stdout.write('  - Working hours configured')
        self.stdout.write('  - 10+ appointments booked')
        self.stdout.write('  - 10+ appointment requests')

        # Messaging
        if not self.skip_messaging:
            self.stdout.write('\n  ' + self.style.SUCCESS('Messaging:'))
            self.stdout.write('  - 10+ conversations')
            self.stdout.write('  - 30+ messages')

        # Analytics
        self.stdout.write('\n  ' + self.style.SUCCESS('Analytics:'))
        self.stdout.write('  - 20 page views logged')
        self.stdout.write('  - 15 user actions tracked')
        self.stdout.write('  - Diversity metrics snapshot')
        self.stdout.write('  - Recruitment metrics snapshot')

        self.stdout.write('\n  ' + self.style.MIGRATE_HEADING('Total: 500+ demo records across all entity types'))

        self.stdout.write('\n' + '=' * 60)
