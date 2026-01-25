#!/usr/bin/env python
"""
Comprehensive Test Data Seeding Script
Creates realistic test data for all Django apps
"""
import os
import sys
import random
from datetime import datetime, timedelta
from decimal import Decimal

# Django setup
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')
import django
django.setup()

from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction
from faker import Faker

fake = Faker()
User = get_user_model()


class DataSeeder:
    """Base class for seeding data"""

    def __init__(self):
        self.created_objects = {}
        self.errors = []

    def log(self, message):
        """Log message with timestamp"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def seed_users(self, count=10):
        """Create test users"""
        self.log(f"Creating {count} test users...")
        users = []

        try:
            # Create superuser if doesn't exist
            if not User.objects.filter(email='admin@zumodra.com').exists():
                admin = User.objects.create_superuser(
                    email='admin@zumodra.com',
                    password='admin123',
                    first_name='Admin',
                    last_name='User'
                )
                users.append(admin)
                self.log("  ✓ Created superuser: admin@zumodra.com")

            # Create regular users
            for i in range(count):
                try:
                    user = User.objects.create_user(
                        email=fake.email(),
                        password='password123',
                        first_name=fake.first_name(),
                        last_name=fake.last_name(),
                        is_active=True
                    )
                    users.append(user)
                except Exception as e:
                    self.errors.append(f"User creation error: {e}")

            self.created_objects['users'] = users
            self.log(f"  ✓ Created {len(users)} users")
            return users

        except Exception as e:
            self.log(f"  ✗ Error creating users: {e}")
            self.errors.append(f"User seeding error: {e}")
            return []

    def seed_tenants(self):
        """Seed tenant data"""
        self.log("Seeding tenants app...")
        try:
            from tenants.models import Tenant

            tenants = []
            for i in range(5):
                tenant, created = Tenant.objects.get_or_create(
                    name=fake.company(),
                    defaults={
                        'slug': fake.slug(),
                        'is_active': True,
                    }
                )
                if created:
                    tenants.append(tenant)

            self.created_objects['tenants'] = tenants
            self.log(f"  ✓ Created {len(tenants)} tenants")
            return tenants

        except ImportError:
            self.log("  ⊘ Tenants app not available")
        except Exception as e:
            self.log(f"  ✗ Error: {e}")
            self.errors.append(f"Tenants: {e}")

    def seed_jobs(self):
        """Seed job postings"""
        self.log("Seeding jobs app...")
        try:
            from jobs.models import Job

            users = self.created_objects.get('users', [])
            if not users:
                self.log("  ⊘ No users available, skipping jobs")
                return

            jobs = []
            for i in range(15):
                try:
                    job = Job.objects.create(
                        title=fake.job(),
                        description=fake.text(500),
                        company=fake.company(),
                        location=fake.city(),
                        salary_min=random.randint(30000, 80000),
                        salary_max=random.randint(80000, 150000),
                        is_active=True,
                        created_by=random.choice(users)
                    )
                    jobs.append(job)
                except Exception as e:
                    self.errors.append(f"Job creation: {e}")

            self.created_objects['jobs'] = jobs
            self.log(f"  ✓ Created {len(jobs)} job postings")
            return jobs

        except ImportError:
            self.log("  ⊘ Jobs app not available")
        except Exception as e:
            self.log(f"  ✗ Error: {e}")
            self.errors.append(f"Jobs: {e}")

    def seed_services(self):
        """Seed services"""
        self.log("Seeding services app...")
        try:
            from services.models import Service

            users = self.created_objects.get('users', [])
            if not users:
                self.log("  ⊘ No users available, skipping services")
                return

            services = []
            for i in range(10):
                try:
                    service = Service.objects.create(
                        name=fake.bs(),
                        description=fake.text(300),
                        price=Decimal(str(random.randint(100, 5000))),
                        is_active=True,
                        created_by=random.choice(users)
                    )
                    services.append(service)
                except Exception as e:
                    self.errors.append(f"Service creation: {e}")

            self.created_objects['services'] = services
            self.log(f"  ✓ Created {len(services)} services")
            return services

        except ImportError:
            self.log("  ⊘ Services app not available")
        except Exception as e:
            self.log(f"  ✗ Error: {e}")
            self.errors.append(f"Services: {e}")

    def seed_blog(self):
        """Seed blog posts"""
        self.log("Seeding blog app...")
        try:
            from blog.models import Post

            users = self.created_objects.get('users', [])
            if not users:
                self.log("  ⊘ No users available, skipping blog")
                return

            posts = []
            for i in range(20):
                try:
                    post = Post.objects.create(
                        title=fake.sentence(),
                        content=fake.text(1000),
                        author=random.choice(users),
                        published=random.choice([True, False]),
                        created_at=timezone.now() - timedelta(days=random.randint(1, 365))
                    )
                    posts.append(post)
                except Exception as e:
                    self.errors.append(f"Blog post creation: {e}")

            self.created_objects['blog_posts'] = posts
            self.log(f"  ✓ Created {len(posts)} blog posts")
            return posts

        except ImportError:
            self.log("  ⊘ Blog app not available")
        except Exception as e:
            self.log(f"  ✗ Error: {e}")
            self.errors.append(f"Blog: {e}")

    def seed_projects(self):
        """Seed projects"""
        self.log("Seeding projects app...")
        try:
            from projects.models import Project

            users = self.created_objects.get('users', [])
            if not users:
                self.log("  ⊘ No users available, skipping projects")
                return

            projects = []
            for i in range(12):
                try:
                    project = Project.objects.create(
                        name=fake.catch_phrase(),
                        description=fake.text(400),
                        budget=Decimal(str(random.randint(1000, 50000))),
                        status=random.choice(['draft', 'active', 'completed', 'cancelled']),
                        owner=random.choice(users)
                    )
                    projects.append(project)
                except Exception as e:
                    self.errors.append(f"Project creation: {e}")

            self.created_objects['projects'] = projects
            self.log(f"  ✓ Created {len(projects)} projects")
            return projects

        except ImportError:
            self.log("  ⊘ Projects app not available")
        except Exception as e:
            self.log(f"  ✗ Error: {e}")
            self.errors.append(f"Projects: {e}")

    def seed_notifications(self):
        """Seed notifications"""
        self.log("Seeding notifications app...")
        try:
            from notifications.models import Notification

            users = self.created_objects.get('users', [])
            if not users:
                self.log("  ⊘ No users available, skipping notifications")
                return

            notifications = []
            for user in users[:5]:  # Create notifications for first 5 users
                for i in range(random.randint(3, 8)):
                    try:
                        notification = Notification.objects.create(
                            recipient=user,
                            title=fake.sentence(),
                            message=fake.text(200),
                            is_read=random.choice([True, False])
                        )
                        notifications.append(notification)
                    except Exception as e:
                        self.errors.append(f"Notification creation: {e}")

            self.created_objects['notifications'] = notifications
            self.log(f"  ✓ Created {len(notifications)} notifications")
            return notifications

        except ImportError:
            self.log("  ⊘ Notifications app not available")
        except Exception as e:
            self.log(f"  ✗ Error: {e}")
            self.errors.append(f"Notifications: {e}")

    def seed_appointments(self):
        """Seed appointments"""
        self.log("Seeding appointments app...")
        try:
            from appointment.models import Appointment

            users = self.created_objects.get('users', [])
            if not users or len(users) < 2:
                self.log("  ⊘ Not enough users available, skipping appointments")
                return

            appointments = []
            for i in range(10):
                try:
                    start_time = timezone.now() + timedelta(days=random.randint(1, 30))
                    appointment = Appointment.objects.create(
                        client=random.choice(users),
                        provider=random.choice(users),
                        start_time=start_time,
                        end_time=start_time + timedelta(hours=random.randint(1, 3)),
                        status=random.choice(['scheduled', 'completed', 'cancelled']),
                        notes=fake.text(200)
                    )
                    appointments.append(appointment)
                except Exception as e:
                    self.errors.append(f"Appointment creation: {e}")

            self.created_objects['appointments'] = appointments
            self.log(f"  ✓ Created {len(appointments)} appointments")
            return appointments

        except ImportError:
            self.log("  ⊘ Appointments app not available")
        except Exception as e:
            self.log(f"  ✗ Error: {e}")
            self.errors.append(f"Appointments: {e}")

    def seed_invoices(self):
        """Seed billing/invoices"""
        self.log("Seeding billing app...")
        try:
            from billing.models import Invoice

            users = self.created_objects.get('users', [])
            if not users:
                self.log("  ⊘ No users available, skipping invoices")
                return

            invoices = []
            for i in range(15):
                try:
                    invoice = Invoice.objects.create(
                        client=random.choice(users),
                        amount=Decimal(str(random.randint(100, 10000))),
                        status=random.choice(['draft', 'sent', 'paid', 'overdue']),
                        due_date=timezone.now() + timedelta(days=random.randint(7, 60)),
                        invoice_number=f"INV-{random.randint(1000, 9999)}"
                    )
                    invoices.append(invoice)
                except Exception as e:
                    self.errors.append(f"Invoice creation: {e}")

            self.created_objects['invoices'] = invoices
            self.log(f"  ✓ Created {len(invoices)} invoices")
            return invoices

        except ImportError:
            self.log("  ⊘ Billing app not available")
        except Exception as e:
            self.log(f"  ✗ Error: {e}")
            self.errors.append(f"Billing: {e}")

    def seed_all(self):
        """Seed all apps"""
        self.log("\n" + "=" * 80)
        self.log("STARTING DATA SEEDING")
        self.log("=" * 80 + "\n")

        with transaction.atomic():
            # Core data
            self.seed_users(count=10)
            self.seed_tenants()

            # App-specific data
            self.seed_jobs()
            self.seed_services()
            self.seed_blog()
            self.seed_projects()
            self.seed_notifications()
            self.seed_appointments()
            self.seed_invoices()

        self.log("\n" + "=" * 80)
        self.log("DATA SEEDING COMPLETE")
        self.log("=" * 80 + "\n")

        # Summary
        self.log("Summary:")
        for key, items in self.created_objects.items():
            if isinstance(items, list):
                self.log(f"  {key}: {len(items)} created")

        if self.errors:
            self.log(f"\nErrors encountered: {len(self.errors)}")
            for error in self.errors[:10]:  # Show first 10 errors
                self.log(f"  - {error}")

        # Generate report
        self.generate_report()

    def generate_report(self):
        """Generate seeding report"""
        import json
        from pathlib import Path

        report_dir = Path('test_results')
        report_dir.mkdir(exist_ok=True)

        report_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {key: len(items) if isinstance(items, list) else 0
                       for key, items in self.created_objects.items()},
            'errors': self.errors
        }

        # JSON report
        json_path = report_dir / 'seed_data_report.json'
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        # Markdown report
        md_path = report_dir / 'seed_data_report.md'
        with open(md_path, 'w') as f:
            f.write("# Test Data Seeding Report\n\n")
            f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
            f.write("## Created Objects\n\n")
            f.write("| Category | Count |\n")
            f.write("|----------|-------|\n")
            for key, items in self.created_objects.items():
                count = len(items) if isinstance(items, list) else 0
                f.write(f"| {key} | {count} |\n")

            if self.errors:
                f.write("\n## Errors\n\n")
                for error in self.errors:
                    f.write(f"- {error}\n")

        self.log(f"\nReports saved:")
        self.log(f"  - {json_path}")
        self.log(f"  - {md_path}")


def main():
    """Main entry point"""
    seeder = DataSeeder()
    seeder.seed_all()


if __name__ == '__main__':
    main()
