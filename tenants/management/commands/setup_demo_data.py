"""
Management command to set up demo tenant with sample data.
Creates a complete demo environment for testing and showcasing.
"""

import random
from datetime import timedelta
from decimal import Decimal
from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command
from django.contrib.auth import get_user_model
from django.db import connection
from django.utils import timezone
from django.utils.text import slugify

User = get_user_model()


class Command(BaseCommand):
    help = 'Set up a demo tenant with sample data for testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant-name',
            type=str,
            default='Demo Company',
            help='Name for the demo tenant (default: Demo Company)'
        )
        # Build default email from centralized domain config
        from django.conf import settings
        import os
        primary_domain = os.environ.get('PRIMARY_DOMAIN') or getattr(settings, 'PRIMARY_DOMAIN', 'localhost')
        default_email = f'demo@demo.{primary_domain}'

        parser.add_argument(
            '--admin-email',
            type=str,
            default=default_email,
            help=f'Admin email for demo tenant (default: {default_email})'
        )
        parser.add_argument(
            '--admin-password',
            type=str,
            default='demo123!',
            help='Admin password (default: demo123!)'
        )
        parser.add_argument(
            '--num-jobs',
            type=int,
            default=10,
            help='Number of sample job postings to create (default: 10)'
        )
        parser.add_argument(
            '--num-candidates',
            type=int,
            default=50,
            help='Number of sample candidates to create (default: 50)'
        )
        parser.add_argument(
            '--num-employees',
            type=int,
            default=20,
            help='Number of sample employees to create (default: 20)'
        )
        parser.add_argument(
            '--skip-plans',
            action='store_true',
            help='Skip creating default plans (use existing)'
        )
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Delete existing demo tenant and recreate'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without making changes'
        )

    def handle(self, *args, **options):
        tenant_name = options['tenant_name']
        admin_email = options['admin_email']
        admin_password = options['admin_password']
        num_jobs = options['num_jobs']
        num_candidates = options['num_candidates']
        num_employees = options['num_employees']
        skip_plans = options.get('skip_plans', False)
        reset = options.get('reset', False)
        dry_run = options.get('dry_run', False)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        self.stdout.write("Setting up demo environment...")
        self.stdout.write(f"  Tenant: {tenant_name}")
        self.stdout.write(f"  Admin: {admin_email}")
        self.stdout.write(f"  Jobs: {num_jobs}")
        self.stdout.write(f"  Candidates: {num_candidates}")
        self.stdout.write(f"  Employees: {num_employees}")

        if dry_run:
            self.stdout.write(self.style.WARNING("\n[DRY RUN] Would create all demo data"))
            return

        try:
            # Import here to avoid circular imports
            from tenants.models import Tenant, Plan, Domain
            from tenants.services import TenantService

            # Setup default plans
            if not skip_plans:
                self.stdout.write("\n1. Setting up plans...")
                call_command('setup_plans')

            # Check for existing demo tenant
            tenant_slug = slugify(tenant_name)
            existing = Tenant.objects.filter(slug=tenant_slug).first()

            if existing:
                if reset:
                    self.stdout.write(f"\n2. Deleting existing demo tenant: {tenant_slug}")
                    existing.delete()
                else:
                    raise CommandError(
                        f"Demo tenant '{tenant_slug}' already exists. "
                        "Use --reset to recreate."
                    )

            # Create demo tenant
            self.stdout.write("\n2. Creating demo tenant...")
            plan = Plan.objects.filter(plan_type=Plan.PlanType.PROFESSIONAL).first()

            tenant = TenantService.create_tenant(
                name=tenant_name,
                owner_email=admin_email,
                plan=plan,
            )
            tenant.activate()

            self.stdout.write(self.style.SUCCESS(f"   Created tenant: {tenant.name}"))
            self.stdout.write(f"   Schema: {tenant.schema_name}")

            # Switch to tenant schema
            connection.set_schema(tenant.schema_name)

            # Create admin user
            self.stdout.write("\n3. Creating admin user...")
            admin = User.objects.create_superuser(
                email=admin_email,
                password=admin_password,
                first_name='Demo',
                last_name='Admin',
            )
            self.stdout.write(self.style.SUCCESS(f"   Created admin: {admin_email}"))

            # Create sample data
            self._create_sample_data(
                tenant, admin, num_jobs, num_candidates, num_employees
            )

            # Summary
            self.stdout.write("\n" + "=" * 50)
            self.stdout.write(self.style.SUCCESS("Demo setup complete!"))
            self.stdout.write(f"\nLogin credentials:")
            self.stdout.write(f"  Email: {admin_email}")
            self.stdout.write(f"  Password: {admin_password}")
            self.stdout.write(f"\nTenant URL: {tenant.domains.first().domain if tenant.domains.exists() else 'N/A'}")

        except Exception as e:
            raise CommandError(f"Failed to setup demo: {e}")
        finally:
            connection.set_schema_to_public()

    def _create_sample_data(self, tenant, admin, num_jobs, num_candidates, num_employees):
        """Create sample data for the demo tenant."""
        from jobs.models import (
            JobPosting, JobCategory, Pipeline, PipelineStage,
            Candidate, Application
        )
        from hr_core.models import Employee, TimeOffType

        # Create job categories
        self.stdout.write("\n4. Creating job categories...")
        categories = []
        for name in ['Engineering', 'Design', 'Marketing', 'Sales', 'Operations', 'HR']:
            cat, _ = JobCategory.objects.get_or_create(
                name=name,
                defaults={'slug': slugify(name)}
            )
            categories.append(cat)

        # Create default pipeline
        self.stdout.write("\n5. Creating recruitment pipeline...")
        pipeline, _ = Pipeline.objects.get_or_create(
            name='Default Pipeline',
            defaults={'is_default': True, 'created_by': admin}
        )

        stages = [
            ('New', 'new', '#6B7280'),
            ('Screening', 'screening', '#3B82F6'),
            ('Phone Interview', 'interview', '#8B5CF6'),
            ('Technical Interview', 'interview', '#EC4899'),
            ('Final Interview', 'interview', '#F59E0B'),
            ('Offer', 'offer', '#10B981'),
            ('Hired', 'hired', '#059669'),
            ('Rejected', 'rejected', '#EF4444'),
        ]

        for i, (name, stage_type, color) in enumerate(stages):
            PipelineStage.objects.get_or_create(
                pipeline=pipeline,
                name=name,
                defaults={'stage_type': stage_type, 'color': color, 'order': i}
            )

        # Create time-off types
        self.stdout.write("\n6. Creating time-off types...")
        TimeOffType.objects.get_or_create(
            code='PTO',
            defaults={
                'name': 'Paid Time Off',
                'is_accrued': True,
                'accrual_rate': Decimal('0.77'),
                'max_balance': Decimal('20'),
            }
        )
        TimeOffType.objects.get_or_create(
            code='SICK',
            defaults={
                'name': 'Sick Leave',
                'is_accrued': True,
                'accrual_rate': Decimal('0.38'),
                'max_balance': Decimal('10'),
            }
        )

        # Create sample jobs
        self.stdout.write(f"\n7. Creating {num_jobs} sample jobs...")
        job_titles = [
            'Senior Software Engineer', 'Product Manager', 'UX Designer',
            'Data Scientist', 'DevOps Engineer', 'Marketing Manager',
            'Sales Representative', 'HR Coordinator', 'Full Stack Developer',
            'Frontend Developer', 'Backend Developer', 'QA Engineer',
            'Technical Writer', 'Customer Success Manager', 'Business Analyst'
        ]

        # Sample locations with coordinates for map view
        locations = [
            {'city': 'Montreal', 'country': 'Canada', 'lat': 45.5017, 'lon': -73.5673},
            {'city': 'Toronto', 'country': 'Canada', 'lat': 43.6532, 'lon': -79.3832},
            {'city': 'Vancouver', 'country': 'Canada', 'lat': 49.2827, 'lon': -123.1207},
            {'city': 'Ottawa', 'country': 'Canada', 'lat': 45.4215, 'lon': -75.6972},
            {'city': 'Calgary', 'country': 'Canada', 'lat': 51.0447, 'lon': -114.0719},
        ]

        jobs = []
        for i in range(min(num_jobs, len(job_titles))):
            title = job_titles[i]
            location = locations[i % len(locations)]  # Cycle through locations

            # Import Point for PostGIS coordinates
            from django.contrib.gis.geos import Point

            job = JobPosting.objects.create(
                title=title,
                reference_code=f'JOB-{str(i + 1).zfill(4)}',
                slug=slugify(title),
                description=f'We are looking for a talented {title} to join our team.',
                requirements='- 3+ years of experience\n- Strong communication skills',
                benefits='- Health insurance\n- 401k matching\n- Remote work options',
                job_type=random.choice(['full_time', 'contract']),
                experience_level=random.choice(['mid', 'senior', 'lead']),
                remote_policy=random.choice(['remote', 'hybrid', 'on_site']),
                location_city=location['city'],
                location_country=location['country'],
                location_coordinates=Point(location['lon'], location['lat'], srid=4326),  # PostGIS Point (lon, lat)
                salary_min=Decimal(random.randint(60, 100) * 1000),
                salary_max=Decimal(random.randint(100, 150) * 1000),
                show_salary=random.choice([True, False]),
                category=random.choice(categories),
                pipeline=pipeline,
                status=JobPosting.JobStatus.OPEN,
                published_at=timezone.now(),
                created_by=admin,
                # Career page visibility
                published_on_career_page=True,
                is_internal_only=False,
            )
            jobs.append(job)

        self.stdout.write(self.style.SUCCESS(f"   Created {len(jobs)} jobs"))

        # Manually sync jobs to PublicJobCatalog
        self.stdout.write("   Syncing jobs to public catalog...")
        from core.sync.job_sync import JobPublicSyncService
        sync_service = JobPublicSyncService()
        synced_count = 0
        for job in jobs:
            try:
                catalog_entry = sync_service.sync_to_public(job)
                if catalog_entry:
                    synced_count += 1
            except Exception as e:
                self.stdout.write(self.style.WARNING(f"   Failed to sync job {job.title}: {e}"))
        self.stdout.write(self.style.SUCCESS(f"   Synced {synced_count}/{len(jobs)} jobs to public catalog"))

        # Create sample candidates
        self.stdout.write(f"\n8. Creating {num_candidates} sample candidates...")
        first_names = ['John', 'Jane', 'Mike', 'Sarah', 'David', 'Emily', 'Chris', 'Lisa', 'Alex', 'Kim']
        last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Martinez', 'Taylor']
        skills = ['Python', 'JavaScript', 'React', 'Django', 'AWS', 'Docker', 'SQL', 'Machine Learning', 'UI/UX', 'Agile']

        candidates = []
        for i in range(num_candidates):
            first_name = random.choice(first_names)
            last_name = random.choice(last_names)
            candidate = Candidate.objects.create(
                first_name=first_name,
                last_name=last_name,
                email=f'{first_name.lower()}.{last_name.lower()}{i}@example.com',
                headline=f'{random.choice(job_titles)}',
                skills=random.sample(skills, k=random.randint(2, 5)),
                years_experience=random.randint(1, 15),
                city='Montreal',
                country='Canada',
                source=random.choice(['career_page', 'linkedin', 'referral']),
            )
            candidates.append(candidate)

            # Create application for random job
            if jobs:
                Application.objects.create(
                    candidate=candidate,
                    job=random.choice(jobs),
                    status=random.choice(['new', 'in_review', 'shortlisted']),
                    ai_match_score=Decimal(random.randint(50, 95)),
                )

        self.stdout.write(self.style.SUCCESS(f"   Created {len(candidates)} candidates"))

        # Create sample employees
        self.stdout.write(f"\n9. Creating {num_employees} sample employees...")
        employees_created = 0
        for i in range(num_employees):
            first_name = random.choice(first_names)
            last_name = random.choice(last_names)
            # Use tenant-specific email domain from centralized config
            primary_domain = getattr(settings, 'PRIMARY_DOMAIN', 'localhost')
            email = f'{first_name.lower()}.{last_name.lower()}.emp{i}@{tenant.slug}.{primary_domain}'

            user = User.objects.create_user(
                email=email,
                password='employee123!',
                first_name=first_name,
                last_name=last_name,
            )

            Employee.objects.create(
                user=user,
                employee_id=f'EMP-{str(i + 1).zfill(4)}',
                job_title=random.choice(job_titles),
                hire_date=timezone.now().date() - timedelta(days=random.randint(30, 1000)),
                status='active',
                employment_type='full_time',
                base_salary=Decimal(random.randint(50, 120) * 1000),
                pto_balance=Decimal(random.randint(5, 20)),
            )
            employees_created += 1

        self.stdout.write(self.style.SUCCESS(f"   Created {employees_created} employees"))
