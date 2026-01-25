"""
Management command to set up a beta tenant for early adopters.
Creates a tenant with beta-specific feature flags and configuration.
"""

import os
from datetime import timedelta
from decimal import Decimal
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection
from django.utils import timezone
from django.utils.text import slugify

User = get_user_model()


def _get_beta_domain():
    """Get beta domain from centralized configuration."""
    # Try environment first (for management command context)
    domain = os.environ.get('TENANT_BASE_DOMAIN') or os.environ.get('BASE_DOMAIN')
    if not domain:
        domain = getattr(settings, 'TENANT_BASE_DOMAIN', None)
    if not domain:
        domain = getattr(settings, 'PRIMARY_DOMAIN', 'localhost')
    return domain


def _get_site_url():
    """Get site URL from centralized configuration."""
    url = os.environ.get('SITE_URL')
    if not url:
        url = getattr(settings, 'SITE_URL', '')
    if not url and getattr(settings, 'DEBUG', False):
        port = os.environ.get('WEB_PORT', '8002')
        url = f"http://localhost:{port}"
    return url


def _get_protocol():
    """Get protocol based on environment."""
    site_url = _get_site_url()
    if site_url and site_url.startswith('https://'):
        return 'https'
    if getattr(settings, 'DEBUG', False):
        return 'http'
    return 'https'


class Command(BaseCommand):
    help = 'Set up a beta tenant for early adopter testing'

    def add_arguments(self, parser):
        parser.add_argument(
            'tenant_name',
            type=str,
            help='Name for the beta tenant'
        )
        parser.add_argument(
            'owner_email',
            type=str,
            help='Owner email for the beta tenant'
        )
        parser.add_argument(
            '--password',
            type=str,
            help='Admin password (auto-generated if not provided)'
        )
        parser.add_argument(
            '--plan',
            type=str,
            choices=['beta_starter', 'beta_professional', 'beta_enterprise'],
            default='beta_professional',
            help='Beta plan tier (default: beta_professional)'
        )
        parser.add_argument(
            '--trial-days',
            type=int,
            default=60,
            help='Extended trial period in days (default: 60 for beta)'
        )
        parser.add_argument(
            '--domain',
            type=str,
            help=f'Custom domain for tenant (default: slug.beta.{_get_beta_domain()})'
        )
        parser.add_argument(
            '--skip-welcome-email',
            action='store_true',
            help='Skip sending welcome email'
        )
        parser.add_argument(
            '--features',
            type=str,
            nargs='+',
            help='Additional feature flags to enable (e.g., ai_matching video_interviews)'
        )

    def handle(self, *args, **options):
        tenant_name = options['tenant_name']
        owner_email = options['owner_email']
        password = options.get('password')
        plan_type = options['plan']
        trial_days = options['trial_days']
        custom_domain = options.get('domain')
        skip_email = options.get('skip_welcome_email', False)
        extra_features = options.get('features') or []

        self.stdout.write(self.style.NOTICE("=" * 60))
        self.stdout.write(self.style.NOTICE("   Zumodra Beta Tenant Setup"))
        self.stdout.write(self.style.NOTICE("=" * 60))
        self.stdout.write(f"\nTenant: {tenant_name}")
        self.stdout.write(f"Owner: {owner_email}")
        self.stdout.write(f"Plan: {plan_type}")
        self.stdout.write(f"Trial: {trial_days} days")

        try:
            from tenants.models import Tenant, Plan, Domain, TenantSettings

            # Ensure beta plans exist
            self._ensure_beta_plans()

            # Get or create the beta plan
            plan = Plan.objects.get(slug=plan_type)

            # Enable extra features on the plan
            if extra_features:
                for feature in extra_features:
                    feature_attr = f'feature_{feature}'
                    if hasattr(plan, feature_attr):
                        setattr(plan, feature_attr, True)
                        self.stdout.write(f"  Enabled: {feature}")
                plan.save()

            # Check for existing tenant
            tenant_slug = slugify(tenant_name)
            if Tenant.objects.filter(slug=tenant_slug).exists():
                raise CommandError(
                    f"Tenant '{tenant_slug}' already exists. "
                    "Choose a different name."
                )

            # Create the tenant
            self.stdout.write("\n1. Creating beta tenant...")
            tenant = Tenant.objects.create(
                name=tenant_name,
                slug=tenant_slug,
                schema_name=tenant_slug.replace('-', '_'),
                owner_email=owner_email,
                plan=plan,
                status=Tenant.TenantStatus.TRIAL,
                on_trial=True,
                trial_ends_at=timezone.now() + timedelta(days=trial_days),
                industry='Beta Tester',
                company_size='1-10',
            )
            self.stdout.write(self.style.SUCCESS(f"   Created: {tenant.name}"))
            self.stdout.write(f"   Schema: {tenant.schema_name}")

            # Create domain using centralized config
            base_domain = _get_beta_domain()
            domain_name = custom_domain or f"{tenant_slug}.beta.{base_domain}"
            Domain.objects.create(
                domain=domain_name,
                tenant=tenant,
                is_primary=True,
            )
            self.stdout.write(f"   Domain: {domain_name}")

            # Create tenant settings with beta defaults
            self.stdout.write("\n2. Configuring beta settings...")
            TenantSettings.objects.create(
                tenant=tenant,
                primary_color='#6366F1',  # Indigo for beta
                secondary_color='#4F46E5',
                accent_color='#10B981',
                default_language='en',
                default_timezone='America/Toronto',
                career_page_enabled=True,
                career_page_title=f'{tenant_name} Careers',
                notify_new_application=True,
                notify_interview_scheduled=True,
                daily_digest_enabled=True,  # Enable for beta feedback
            )
            self.stdout.write(self.style.SUCCESS("   Beta settings configured"))

            # Switch to tenant schema and create admin user
            connection.set_schema(tenant.schema_name)

            self.stdout.write("\n3. Creating admin user...")
            if not password:
                password = User.objects.make_random_password(length=16)

            admin = User.objects.create_superuser(
                email=owner_email,
                password=password,
                first_name='Beta',
                last_name='Admin',
            )
            self.stdout.write(self.style.SUCCESS(f"   Admin created: {owner_email}"))

            # Create initial data
            self._create_beta_starter_data(tenant, admin)

            # Send welcome email (unless skipped)
            if not skip_email:
                self._send_welcome_email(tenant, admin, password, domain_name)
                self.stdout.write("\n5. Welcome email sent")
            else:
                self.stdout.write("\n5. Welcome email skipped")

            # Summary
            protocol = _get_protocol()
            self.stdout.write("\n" + "=" * 60)
            self.stdout.write(self.style.SUCCESS("Beta tenant setup complete!"))
            self.stdout.write("=" * 60)
            self.stdout.write(f"\n  Tenant URL: {protocol}://{domain_name}")
            self.stdout.write(f"  Admin URL: {protocol}://{domain_name}/admin/")
            self.stdout.write(f"  API URL: {protocol}://{domain_name}/api/v1/")
            self.stdout.write(f"\n  Login Credentials:")
            self.stdout.write(f"    Email: {owner_email}")
            self.stdout.write(f"    Password: {password}")
            self.stdout.write(f"\n  Trial expires: {tenant.trial_ends_at.strftime('%Y-%m-%d')}")
            self.stdout.write(f"\n  Beta Plan Features:")
            for feature in plan.get_features_list()[:10]:
                self.stdout.write(f"    - {feature}")

            self.stdout.write("\n" + "=" * 60)
            self.stdout.write(self.style.WARNING(
                "IMPORTANT: Add the domain to your /etc/hosts for local testing:"
            ))
            self.stdout.write(f"  127.0.0.1  {domain_name}")
            self.stdout.write("=" * 60)

        except Exception as e:
            raise CommandError(f"Failed to setup beta tenant: {e}")
        finally:
            connection.set_schema_to_public()

    def _ensure_beta_plans(self):
        """Create beta-specific plans if they don't exist."""
        from tenants.models import Plan

        beta_plans = [
            {
                'name': 'Beta Starter',
                'slug': 'beta_starter',
                'plan_type': Plan.PlanType.STARTER,
                'description': 'Beta program - Starter tier with extended trial',
                'price_monthly': Decimal('0.00'),  # Free during beta
                'max_users': 10,
                'max_job_postings': 25,
                'max_candidates_per_month': 250,
                'max_circusales': 2,
                'storage_limit_gb': 10,
                'feature_ats': True,
                'feature_hr_core': True,
                'feature_analytics': True,
                'feature_api_access': True,
                'feature_real_time_messaging': True,
                'feature_appointments': True,
                'feature_career_pages': True,
                'feature_data_export': True,
            },
            {
                'name': 'Beta Professional',
                'slug': 'beta_professional',
                'plan_type': Plan.PlanType.PROFESSIONAL,
                'description': 'Beta program - Professional tier with all features',
                'price_monthly': Decimal('0.00'),  # Free during beta
                'max_users': 50,
                'max_job_postings': 100,
                'max_candidates_per_month': 1000,
                'max_circusales': 10,
                'storage_limit_gb': 50,
                'feature_ats': True,
                'feature_hr_core': True,
                'feature_analytics': True,
                'feature_api_access': True,
                'feature_custom_pipelines': True,
                'feature_ai_matching': True,
                'feature_bulk_actions': True,
                'feature_advanced_filters': True,
                'feature_marketplace': True,
                'feature_escrow_payments': True,
                'feature_real_time_messaging': True,
                'feature_appointments': True,
                'feature_newsletter': True,
                'feature_crm': True,
                'feature_geospatial': True,
                'feature_multi_circusale': True,
                'feature_webhooks': True,
                'feature_career_pages': True,
                'feature_data_export': True,
                'feature_calendar_sync': True,
            },
            {
                'name': 'Beta Enterprise',
                'slug': 'beta_enterprise',
                'plan_type': Plan.PlanType.ENTERPRISE,
                'description': 'Beta program - Enterprise tier with all features',
                'price_monthly': Decimal('0.00'),  # Free during beta
                'max_users': 500,
                'max_job_postings': 1000,
                'max_candidates_per_month': 10000,
                'max_circusales': 100,
                'storage_limit_gb': 500,
                'feature_ats': True,
                'feature_hr_core': True,
                'feature_analytics': True,
                'feature_api_access': True,
                'feature_custom_pipelines': True,
                'feature_ai_matching': True,
                'feature_video_interviews': True,
                'feature_esignature': True,
                'feature_sso': True,
                'feature_audit_logs': True,
                'feature_custom_branding': True,
                'feature_priority_support': True,
                'feature_bulk_actions': True,
                'feature_advanced_filters': True,
                'feature_diversity_analytics': True,
                'feature_compliance_tools': True,
                'feature_marketplace': True,
                'feature_escrow_payments': True,
                'feature_real_time_messaging': True,
                'feature_appointments': True,
                'feature_newsletter': True,
                'feature_crm': True,
                'feature_geospatial': True,
                'feature_multi_circusale': True,
                'feature_custom_domains': True,
                'feature_webhooks': True,
                'feature_2fa_required': True,
                'feature_ip_whitelist': True,
                'feature_wagtail_cms': True,
                'feature_career_pages': True,
                'feature_events': True,
                'feature_slack_integration': True,
                'feature_calendar_sync': True,
                'feature_linkedin_import': True,
                'feature_background_checks': True,
                'feature_data_export': True,
            },
        ]

        for plan_data in beta_plans:
            Plan.objects.update_or_create(
                slug=plan_data['slug'],
                defaults=plan_data
            )
            self.stdout.write(f"   Plan ready: {plan_data['name']}")

    def _create_beta_starter_data(self, tenant, admin):
        """Create minimal starter data for beta tenants."""
        self.stdout.write("\n4. Creating starter data...")

        try:
            from jobs.models import Pipeline, PipelineStage, JobCategory

            # Create default pipeline
            pipeline, created = Pipeline.objects.get_or_create(
                name='Default Pipeline',
                defaults={'is_default': True, 'created_by': admin}
            )

            if created:
                stages = [
                    ('New', 'new', '#6B7280', 0),
                    ('Screening', 'screening', '#3B82F6', 1),
                    ('Interview', 'interview', '#8B5CF6', 2),
                    ('Offer', 'offer', '#10B981', 3),
                    ('Hired', 'hired', '#059669', 4),
                    ('Rejected', 'rejected', '#EF4444', 5),
                ]
                for name, stage_type, color, order in stages:
                    PipelineStage.objects.create(
                        pipeline=pipeline,
                        name=name,
                        stage_type=stage_type,
                        color=color,
                        order=order
                    )
                self.stdout.write("   Default pipeline created")

            # Create basic job categories
            categories = ['Engineering', 'Design', 'Marketing', 'Sales', 'Operations']
            for cat_name in categories:
                JobCategory.objects.get_or_create(
                    name=cat_name,
                    defaults={'slug': slugify(cat_name)}
                )
            self.stdout.write("   Job categories created")

        except ImportError:
            self.stdout.write(self.style.WARNING("   ATS app not available, skipping starter data"))

    def _send_welcome_email(self, tenant, admin, password, domain):
        """Send welcome email to beta tenant admin."""
        try:
            from django.core.mail import send_mail
            from django.conf import settings

            protocol = _get_protocol()
            subject = f"Welcome to Zumodra Beta - {tenant.name}"
            message = f"""
Welcome to Zumodra Beta!

Your beta account for {tenant.name} has been created.

Login Details:
--------------
URL: {protocol}://{domain}
Email: {admin.email}
Password: {password}

Quick Start:
1. Log in to your dashboard
2. Complete your company profile
3. Create your first job posting
4. Invite team members

Beta Program Benefits:
- 60-day extended trial
- All Professional features enabled
- Priority support channel
- Direct feedback line to product team

Need Help?
- Documentation: https://docs.zumodra.com
- Beta Support: beta@zumodra.com
- Feedback Form: https://zumodra.com/beta-feedback

We're excited to have you as a beta tester!

Best regards,
The Zumodra Team
"""
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [admin.email],
                fail_silently=True,
            )
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"   Could not send email: {e}"))
