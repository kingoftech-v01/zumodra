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
        'role': 'OWNER',
        'is_superuser': True,
    },
    'hr_manager': {
        'email': f'hr@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Sarah',
        'last_name': 'Johnson',
        'role': 'HR_MANAGER',
    },
    'recruiter': {
        'email': f'recruiter@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Michael',
        'last_name': 'Chen',
        'role': 'RECRUITER',
    },
    'hiring_manager': {
        'email': f'hiring@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Emily',
        'last_name': 'Davis',
        'role': 'HIRING_MANAGER',
    },
    'employee': {
        'email': f'employee@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'John',
        'last_name': 'Smith',
        'role': 'EMPLOYEE',
    },
    'candidate': {
        'email': f'candidate@{EMAIL_DOMAIN}',
        'password': 'Demo@2024!',
        'first_name': 'Alex',
        'last_name': 'Wilson',
        'role': 'VIEWER',
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
        if not self.skip_marketplace:
            self._log_step(8, 'Creating marketplace data (services, contracts)')
            self._create_marketplace_data(tenant, users)

        # Step 9: Create verification data
        self._log_step(9, 'Creating verification/trust data')
        self._create_verification_data(users)

        # Step 10: Create messaging data
        if not self.skip_messaging:
            self._log_step(10, 'Creating messaging data (conversations)')
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

        # Add demo domain
        Domain.objects.get_or_create(
            domain=DEMO_TENANT_CONFIG['domain'],
            defaults={'tenant': tenant, 'is_primary': True}
        )

        self.stdout.write(self.style.SUCCESS(f"   Created: {tenant.name} ({tenant.schema_name})"))
        return tenant

    def _create_demo_users(self, tenant):
        """Create demo users with various roles."""
        from accounts.models import TenantUser, UserProfile

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

            # Create profile if it doesn't exist
            try:
                UserProfile.objects.get_or_create(
                    user=user,
                    defaults={
                        'phone': f'+1555{random.randint(1000000, 9999999)}',
                        'bio': f'Demo {config["role"].lower().replace("_", " ")} user for testing.',
                    }
                )
            except Exception:
                pass  # Profile may already exist or model may differ

            users[key] = user
            self.stdout.write(f"   {'Created' if created else 'Updated'}: {config['email']} ({config['role']})")

        return users

    def _create_ats_data(self, tenant, users):
        """Create ATS-related demo data."""
        from ats.models import (
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

        # Create time-off types
        pto, _ = TimeOffType.objects.get_or_create(
            code='PTO',
            tenant=tenant,
            defaults={
                'name': 'Paid Time Off',
                'is_accrued': True,
                'accrual_rate': Decimal('1.25'),
                'max_balance': Decimal('25'),
            }
        )
        sick, _ = TimeOffType.objects.get_or_create(
            code='SICK',
            tenant=tenant,
            defaults={
                'name': 'Sick Leave',
                'is_accrued': True,
                'accrual_rate': Decimal('0.5'),
                'max_balance': Decimal('12'),
            }
        )
        TimeOffType.objects.get_or_create(
            code='PERSONAL',
            tenant=tenant,
            defaults={
                'name': 'Personal Day',
                'is_accrued': False,
                'max_balance': Decimal('3'),
            }
        )
        self.stdout.write("   Time-off types: 3")

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
                    time_off_type=random.choice([pto, sick]),
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

    def _create_verification_data(self, users):
        """Create verification and trust score demo data."""
        try:
            from accounts.models import KYCVerification, TrustScore, EmploymentVerification
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

        self.stdout.write(f"   Verifications: {verifications}")

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
        from accounts.models import TenantUser

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
        self.stdout.write('  - 6 demo users with different roles')
        self.stdout.write('  - 8 job categories')
        self.stdout.write('  - 15 job postings across all categories')
        self.stdout.write('  - 50 candidates with applications')
        self.stdout.write('  - Interviews and offers in pipeline')
        self.stdout.write('  - 25 employees with profiles')
        self.stdout.write('  - Time-off types and requests')
        if not self.skip_marketplace:
            self.stdout.write('  - Service providers and categories')
        if not self.skip_messaging:
            self.stdout.write('  - Conversations between users')
        self.stdout.write('  - KYC verifications and trust scores')

        self.stdout.write('\n' + '=' * 60)
