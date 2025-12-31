"""
Management command to set up default subscription plans.
"""

from django.core.management.base import BaseCommand
from tenants.models import Plan


class Command(BaseCommand):
    help = 'Create default subscription plans'

    def handle(self, *args, **options):
        plans = [
            {
                'name': 'Free',
                'slug': 'free',
                'plan_type': Plan.PlanType.FREE,
                'description': 'Perfect for small teams getting started',
                'price_monthly': 0,
                'price_yearly': 0,
                'max_users': 3,
                'max_job_postings': 3,
                'max_candidates_per_month': 50,
                'max_circusales': 1,
                'storage_limit_gb': 1,
                'feature_ats': True,
                'feature_hr_core': False,
                'feature_analytics': False,
                'feature_api_access': False,
                'feature_custom_pipelines': False,
                'feature_data_export': True,
                'sort_order': 1,
            },
            {
                'name': 'Starter',
                'slug': 'starter',
                'plan_type': Plan.PlanType.STARTER,
                'description': 'For growing teams with basic HR needs',
                'price_monthly': 49,
                'price_yearly': 490,
                'max_users': 10,
                'max_job_postings': 10,
                'max_candidates_per_month': 200,
                'max_circusales': 2,
                'storage_limit_gb': 10,
                'feature_ats': True,
                'feature_hr_core': True,
                'feature_analytics': True,
                'feature_api_access': False,
                'feature_custom_pipelines': True,
                'feature_data_export': True,
                'feature_bulk_actions': True,
                'sort_order': 2,
            },
            {
                'name': 'Professional',
                'slug': 'professional',
                'plan_type': Plan.PlanType.PROFESSIONAL,
                'description': 'Full-featured ATS and HR for scaling teams',
                'price_monthly': 149,
                'price_yearly': 1490,
                'max_users': 50,
                'max_job_postings': 50,
                'max_candidates_per_month': 1000,
                'max_circusales': 5,
                'storage_limit_gb': 50,
                'feature_ats': True,
                'feature_hr_core': True,
                'feature_analytics': True,
                'feature_api_access': True,
                'feature_custom_pipelines': True,
                'feature_ai_matching': True,
                'feature_esignature': True,
                'feature_audit_logs': True,
                'feature_data_export': True,
                'feature_bulk_actions': True,
                'feature_advanced_filters': True,
                'is_popular': True,
                'sort_order': 3,
            },
            {
                'name': 'Enterprise',
                'slug': 'enterprise',
                'plan_type': Plan.PlanType.ENTERPRISE,
                'description': 'Enterprise-grade features with dedicated support',
                'price_monthly': 499,
                'price_yearly': 4990,
                'max_users': 500,
                'max_job_postings': 500,
                'max_candidates_per_month': 10000,
                'max_circusales': 50,
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
                'feature_data_export': True,
                'feature_bulk_actions': True,
                'feature_advanced_filters': True,
                'feature_diversity_analytics': True,
                'feature_compliance_tools': True,
                'sort_order': 4,
            },
        ]

        created_count = 0
        updated_count = 0

        for plan_data in plans:
            plan, created = Plan.objects.update_or_create(
                slug=plan_data['slug'],
                defaults=plan_data
            )

            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f"Created plan: {plan.name}"))
            else:
                updated_count += 1
                self.stdout.write(f"Updated plan: {plan.name}")

        self.stdout.write(self.style.SUCCESS(
            f"\nDone! Created {created_count}, updated {updated_count} plans."
        ))
