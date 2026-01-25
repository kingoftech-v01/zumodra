import os
import sys
import django
import random
from decimal import Decimal
from datetime import timedelta

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
sys.path.insert(0, '/app')
django.setup()

from django.utils import timezone
from django.utils.text import slugify
from django.contrib.auth import get_user_model
from django_tenants.utils import schema_context
from django.contrib.gis.geos import Point

User = get_user_model()

def populate_demo_data(tenant_schema='demo_company', num_jobs=20, num_candidates=100):
    """Populate demo data for a tenant."""

    print(f'Populating data for tenant schema: {tenant_schema}')

    with schema_context(tenant_schema):
        from jobs.models import (
            JobPosting, JobCategory, Pipeline, PipelineStage,
            Candidate, Application
        )
        from hr_core.models import Employee, TimeOffType

        # Get or create admin user
        admin = User.objects.filter(is_superuser=True).first()
        if not admin:
            print('ERROR: No admin user found')
            return

        print(f'Using admin user: {admin.email}')

        # Create job categories
        print('\n1. Creating job categories...')
        categories = []
        for name in ['Engineering', 'Design', 'Marketing', 'Sales', 'Operations', 'HR', 'Finance', 'Legal']:
            cat, created = JobCategory.objects.get_or_create(
                name=name,
                defaults={'slug': slugify(name)}
            )
            categories.append(cat)
            if created:
                print(f'   Created category: {name}')

        # Get or create pipeline
        print('\n2. Setting up recruitment pipeline...')
        pipeline = Pipeline.objects.filter(is_default=True).first()
        if not pipeline:
            pipeline = Pipeline.objects.create(
                name='Default Pipeline',
                is_default=True,
                created_by=admin
            )
            print('   Created default pipeline')

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
                PipelineStage.objects.create(
                    pipeline=pipeline,
                    name=name,
                    stage_type=stage_type,
                    color=color,
                    order=i
                )
                print(f'   Created stage: {name}')
        else:
            print(f'   Using existing pipeline: {pipeline.name}')

        # Create time-off types
        print('\n3. Creating time-off types...')
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
        print('   Created/verified time-off types')

        # Create sample jobs
        print(f'\n4. Creating {num_jobs} sample jobs...')
        job_titles = [
            'Senior Software Engineer', 'Product Manager', 'UX Designer',
            'Data Scientist', 'DevOps Engineer', 'Marketing Manager',
            'Sales Representative', 'HR Coordinator', 'Full Stack Developer',
            'Frontend Developer', 'Backend Developer', 'QA Engineer',
            'Technical Writer', 'Customer Success Manager', 'Business Analyst',
            'Security Engineer', 'Mobile Developer', 'Cloud Architect',
            'Scrum Master', 'Technical Lead', 'Solutions Architect',
            'Site Reliability Engineer', 'Data Engineer', 'ML Engineer'
        ]

        locations = [
            {'city': 'Montreal', 'country': 'Canada', 'lat': 45.5017, 'lon': -73.5673},
            {'city': 'Toronto', 'country': 'Canada', 'lat': 43.6532, 'lon': -79.3832},
            {'city': 'Vancouver', 'country': 'Canada', 'lat': 49.2827, 'lon': -123.1207},
            {'city': 'Ottawa', 'country': 'Canada', 'lat': 45.4215, 'lon': -75.6972},
            {'city': 'Calgary', 'country': 'Canada', 'lat': 51.0447, 'lon': -114.0719},
            {'city': 'Edmonton', 'country': 'Canada', 'lat': 53.5461, 'lon': -113.4938},
            {'city': 'New York', 'country': 'USA', 'lat': 40.7128, 'lon': -74.0060},
            {'city': 'San Francisco', 'country': 'USA', 'lat': 37.7749, 'lon': -122.4194},
        ]

        # Get existing job count
        existing_jobs = JobPosting.objects.count()
        jobs_to_create = num_jobs - existing_jobs

        jobs = list(JobPosting.objects.all())

        if jobs_to_create > 0:
            for i in range(jobs_to_create):
                title = job_titles[i % len(job_titles)]
                location = locations[i % len(locations)]
                job_num = existing_jobs + i + 1

                job = JobPosting.objects.create(
                    title=title,
                    reference_code=f'JOB-{str(job_num).zfill(4)}',
                    slug=slugify(f'{title}-{job_num}'),
                    description=f'''We are looking for a talented {title} to join our growing team.

**About the Role:**
In this role, you will work on cutting-edge projects and collaborate with a talented team of professionals. You'll have the opportunity to make a significant impact on our products and services.

**Key Responsibilities:**
- Design and implement innovative solutions
- Collaborate with cross-functional teams
- Mentor junior team members
- Participate in code reviews and technical discussions
- Contribute to architectural decisions
''',
                    requirements='''**Required Qualifications:**
- 3+ years of relevant experience
- Strong technical and communication skills
- Bachelor's degree in Computer Science or related field
- Experience with modern development practices
- Proven track record of delivering quality results

**Nice to Have:**
- Master's degree
- Industry certifications
- Open source contributions
- Public speaking experience
''',
                    benefits='''**What We Offer:**
- Competitive salary and equity
- Comprehensive health insurance
- 401k matching program
- Flexible remote work options
- Professional development budget
- Generous PTO and parental leave
- Modern equipment and tools
- Collaborative team culture
''',
                    job_type=random.choice(['full_time', 'contract', 'full_time', 'full_time']),
                    experience_level=random.choice(['mid', 'senior', 'lead']),
                    remote_policy=random.choice(['remote', 'hybrid', 'on_site', 'hybrid']),
                    location_city=location['city'],
                    location_country=location['country'],
                    location_coordinates=Point(location['lon'], location['lat'], srid=4326),
                    salary_min=Decimal(random.randint(60, 100) * 1000),
                    salary_max=Decimal(random.randint(100, 180) * 1000),
                    show_salary=random.choice([True, False, True]),
                    category=random.choice(categories),
                    pipeline=pipeline,
                    status='open',
                    published_at=timezone.now() - timedelta(days=random.randint(1, 30)),
                    created_by=admin,
                    published_on_career_page=True,
                    is_internal_only=False,
                )
                jobs.append(job)

            print(f'   Created {jobs_to_create} new jobs (total: {len(jobs)})')
        else:
            print(f'   Already have {existing_jobs} jobs, skipping job creation')

        # Create sample candidates
        print(f'\n5. Creating {num_candidates} sample candidates...')
        first_names = ['John', 'Jane', 'Mike', 'Sarah', 'David', 'Emily', 'Chris', 'Lisa', 'Alex', 'Kim',
                      'Ryan', 'Emma', 'Daniel', 'Olivia', 'James', 'Sophia', 'Robert', 'Ava', 'William', 'Mia']
        last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
                     'Martinez', 'Taylor', 'Anderson', 'Thomas', 'Jackson', 'White', 'Harris', 'Martin']
        skills = ['Python', 'JavaScript', 'React', 'Django', 'AWS', 'Docker', 'SQL', 'Machine Learning',
                 'UI/UX', 'Agile', 'TypeScript', 'Node.js', 'Kubernetes', 'PostgreSQL', 'GraphQL']

        existing_candidates = Candidate.objects.count()
        candidates_to_create = num_candidates - existing_candidates

        candidates = list(Candidate.objects.all())

        if candidates_to_create > 0:
            for i in range(candidates_to_create):
                first_name = random.choice(first_names)
                last_name = random.choice(last_names)
                candidate_num = existing_candidates + i + 1

                candidate = Candidate.objects.create(
                    first_name=first_name,
                    last_name=last_name,
                    email=f'{first_name.lower()}.{last_name.lower()}{candidate_num}@example.com',
                    headline=f'{random.choice(job_titles)}',
                    skills=random.sample(skills, k=random.randint(3, 7)),
                    years_experience=random.randint(1, 15),
                    city=random.choice(['Montreal', 'Toronto', 'Vancouver', 'Ottawa']),
                    country='Canada',
                    source=random.choice(['career_page', 'linkedin', 'referral', 'indeed', 'glassdoor']),
                )
                candidates.append(candidate)

                # Create 1-3 applications for each candidate
                num_applications = random.randint(1, min(3, len(jobs)))
                selected_jobs = random.sample(jobs, num_applications)

                for job in selected_jobs:
                    Application.objects.create(
                        candidate=candidate,
                        job=job,
                        status=random.choice(['new', 'in_review', 'shortlisted', 'interviewing']),
                        ai_match_score=Decimal(random.randint(50, 98)),
                    )

            print(f'   Created {candidates_to_create} new candidates (total: {len(candidates)})')
        else:
            print(f'   Already have {existing_candidates} candidates, skipping candidate creation')

        # Create sample employees
        print(f'\n6. Creating additional employees...')
        existing_employees = Employee.objects.count()
        num_employees = 15
        employees_to_create = max(0, num_employees - existing_employees)

        if employees_to_create > 0:
            for i in range(employees_to_create):
                first_name = random.choice(first_names)
                last_name = random.choice(last_names)
                emp_num = existing_employees + i + 1
                email = f'{first_name.lower()}.{last_name.lower()}.emp{emp_num}@demo.example.com'

                # Check if user already exists
                if not User.objects.filter(email=email).exists():
                    user = User.objects.create_user(
                        email=email,
                        password='employee123!',
                        first_name=first_name,
                        last_name=last_name,
                    )

                    Employee.objects.create(
                        user=user,
                        employee_id=f'EMP-{str(emp_num).zfill(4)}',
                        job_title=random.choice(job_titles),
                        hire_date=timezone.now().date() - timedelta(days=random.randint(30, 1000)),
                        status='active',
                        employment_type='full_time',
                        base_salary=Decimal(random.randint(50, 150) * 1000),
                        pto_balance=Decimal(random.randint(5, 20)),
                    )

            print(f'   Created {employees_to_create} new employees (total: {Employee.objects.count()})')
        else:
            print(f'   Already have {existing_employees} employees, skipping employee creation')

        # Create interviews
        print(f'\n7. Creating interviews...')
        from jobs.models import Interview
        existing_interviews = Interview.objects.count()
        interviews_to_create = max(0, 15 - existing_interviews)

        if interviews_to_create > 0 and candidates:
            applications = Application.objects.filter(
                status__in=['in_review', 'shortlisted', 'interviewing']
            )[:interviews_to_create]

            for app in applications:
                Interview.objects.create(
                    application=app,
                    title=f'{app.job.title} - Interview',
                    interview_type='technical',
                    scheduled_at=timezone.now() + timedelta(days=random.randint(1, 14)),
                    duration_minutes=random.choice([30, 45, 60]),
                    status=random.choice(['scheduled', 'completed']),
                )

            print(f'   Created {interviews_to_create} interviews (total: {Interview.objects.count()})')
        else:
            print(f'   Already have {existing_interviews} interviews, skipping interview creation')

        # Final counts
        print(f'\n\n=== DEMO DATA SUMMARY ===')
        print(f'Jobs: {JobPosting.objects.count()}')
        print(f'Candidates: {Candidate.objects.count()}')
        print(f'Applications: {Application.objects.count()}')
        print(f'Employees: {Employee.objects.count()}')
        print(f'Interviews: {Interview.objects.count()}')
        print(f'Categories: {JobCategory.objects.count()}')
        print(f'Pipeline Stages: {PipelineStage.objects.count()}')
        print(f'\nDemo data population complete!')

if __name__ == '__main__':
    populate_demo_data(tenant_schema='demo_company', num_jobs=20, num_candidates=100)
