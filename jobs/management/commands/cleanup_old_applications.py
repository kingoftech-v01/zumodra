"""
Management command to clean up old applications based on retention policies.
Handles GDPR compliance and data retention requirements.
"""

from datetime import timedelta
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone
from tenants.models import Tenant
from jobs.models import Application, Candidate, ApplicationActivity, ApplicationNote


class Command(BaseCommand):
    help = 'Clean up old applications based on retention policies'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant slug (processes all active tenants if not specified)'
        )
        parser.add_argument(
            '--rejected-days',
            type=int,
            default=365,
            help='Delete rejected applications older than N days (default: 365)'
        )
        parser.add_argument(
            '--withdrawn-days',
            type=int,
            default=180,
            help='Delete withdrawn applications older than N days (default: 180)'
        )
        parser.add_argument(
            '--closed-job-days',
            type=int,
            default=730,
            help='Delete applications for closed jobs older than N days (default: 730)'
        )
        parser.add_argument(
            '--respect-consent',
            action='store_true',
            default=True,
            help='Respect candidate data retention consent dates'
        )
        parser.add_argument(
            '--anonymize',
            action='store_true',
            help='Anonymize instead of delete (GDPR compliant)'
        )
        parser.add_argument(
            '--include-candidates',
            action='store_true',
            help='Also clean up candidates with no applications'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without making changes'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed progress'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant')
        rejected_days = options.get('rejected_days', 365)
        withdrawn_days = options.get('withdrawn_days', 180)
        closed_job_days = options.get('closed_job_days', 730)
        respect_consent = options.get('respect_consent', True)
        anonymize = options.get('anonymize', False)
        include_candidates = options.get('include_candidates', False)
        dry_run = options.get('dry_run', False)
        verbose = options.get('verbose', False)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        if anonymize:
            self.stdout.write("Mode: Anonymization (GDPR compliant)")
        else:
            self.stdout.write("Mode: Deletion")

        # Determine tenants to process
        if tenant_slug:
            try:
                tenants = [Tenant.objects.get(slug=tenant_slug)]
            except Tenant.DoesNotExist:
                raise CommandError(f"Tenant not found: {tenant_slug}")
        else:
            tenants = Tenant.objects.filter(
                status__in=[
                    Tenant.TenantStatus.ACTIVE,
                    Tenant.TenantStatus.TRIAL,
                ]
            )

        total_stats = {
            'tenants': 0,
            'applications_deleted': 0,
            'applications_anonymized': 0,
            'activities_deleted': 0,
            'notes_deleted': 0,
            'candidates_cleaned': 0,
        }

        for tenant in tenants:
            self.stdout.write(f"\nProcessing tenant: {tenant.name}")
            total_stats['tenants'] += 1

            connection.set_schema(tenant.schema_name)

            try:
                stats = self._cleanup_tenant(
                    rejected_days, withdrawn_days, closed_job_days,
                    respect_consent, anonymize, include_candidates,
                    dry_run, verbose
                )

                for key in stats:
                    total_stats[key] += stats[key]

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))
            finally:
                connection.set_schema_to_public()

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Cleanup Summary:"))
        self.stdout.write(f"  Tenants processed: {total_stats['tenants']}")
        if anonymize:
            self.stdout.write(f"  Applications anonymized: {total_stats['applications_anonymized']}")
        else:
            self.stdout.write(f"  Applications deleted: {total_stats['applications_deleted']}")
        self.stdout.write(f"  Activities deleted: {total_stats['activities_deleted']}")
        self.stdout.write(f"  Notes deleted: {total_stats['notes_deleted']}")
        self.stdout.write(f"  Candidates cleaned: {total_stats['candidates_cleaned']}")

    def _cleanup_tenant(self, rejected_days, withdrawn_days, closed_job_days,
                        respect_consent, anonymize, include_candidates,
                        dry_run, verbose):
        """Cleanup applications for a tenant."""
        stats = {
            'applications_deleted': 0,
            'applications_anonymized': 0,
            'activities_deleted': 0,
            'notes_deleted': 0,
            'candidates_cleaned': 0,
        }

        # 1. Cleanup rejected applications
        rejected_cutoff = timezone.now() - timedelta(days=rejected_days)
        rejected_apps = Application.objects.filter(
            status=Application.ApplicationStatus.REJECTED,
            rejected_at__lt=rejected_cutoff
        )

        if respect_consent:
            rejected_apps = rejected_apps.exclude(
                candidate__data_retention_until__gt=timezone.now().date()
            )

        count = rejected_apps.count()
        if count > 0:
            self.stdout.write(f"  Found {count} old rejected applications")
            stats.update(
                self._process_applications(rejected_apps, anonymize, dry_run, verbose)
            )

        # 2. Cleanup withdrawn applications
        withdrawn_cutoff = timezone.now() - timedelta(days=withdrawn_days)
        withdrawn_apps = Application.objects.filter(
            status=Application.ApplicationStatus.WITHDRAWN,
            updated_at__lt=withdrawn_cutoff
        )

        if respect_consent:
            withdrawn_apps = withdrawn_apps.exclude(
                candidate__data_retention_until__gt=timezone.now().date()
            )

        count = withdrawn_apps.count()
        if count > 0:
            self.stdout.write(f"  Found {count} old withdrawn applications")
            stats.update(
                self._process_applications(withdrawn_apps, anonymize, dry_run, verbose)
            )

        # 3. Cleanup applications for closed jobs
        closed_cutoff = timezone.now() - timedelta(days=closed_job_days)
        closed_job_apps = Application.objects.filter(
            job__status__in=['closed', 'filled', 'cancelled'],
            job__closed_at__lt=closed_cutoff
        ).exclude(
            status=Application.ApplicationStatus.HIRED
        )

        if respect_consent:
            closed_job_apps = closed_job_apps.exclude(
                candidate__data_retention_until__gt=timezone.now().date()
            )

        count = closed_job_apps.count()
        if count > 0:
            self.stdout.write(f"  Found {count} applications for old closed jobs")
            stats.update(
                self._process_applications(closed_job_apps, anonymize, dry_run, verbose)
            )

        # 4. Cleanup orphaned candidates
        if include_candidates:
            orphaned = Candidate.objects.filter(applications__isnull=True)

            # Only candidates past their retention date
            if respect_consent:
                orphaned = orphaned.filter(
                    data_retention_until__lt=timezone.now().date()
                ) | orphaned.filter(data_retention_until__isnull=True)

            count = orphaned.count()
            if count > 0:
                self.stdout.write(f"  Found {count} orphaned candidates")
                if not dry_run:
                    if anonymize:
                        for candidate in orphaned:
                            self._anonymize_candidate(candidate)
                    else:
                        orphaned.delete()
                    stats['candidates_cleaned'] = count
                else:
                    stats['candidates_cleaned'] = count

        return stats

    def _process_applications(self, queryset, anonymize, dry_run, verbose):
        """Process a queryset of applications for cleanup."""
        stats = {
            'applications_deleted': 0,
            'applications_anonymized': 0,
            'activities_deleted': 0,
            'notes_deleted': 0,
        }

        if dry_run:
            count = queryset.count()
            if anonymize:
                stats['applications_anonymized'] = count
            else:
                stats['applications_deleted'] = count
            return stats

        for app in queryset.iterator():
            if verbose:
                self.stdout.write(
                    f"    Processing: {app.candidate.full_name} -> {app.job.title}"
                )

            # Delete related records
            activities_count, _ = ApplicationActivity.objects.filter(application=app).delete()
            notes_count, _ = ApplicationNote.objects.filter(application=app).delete()

            stats['activities_deleted'] += activities_count
            stats['notes_deleted'] += notes_count

            if anonymize:
                self._anonymize_application(app)
                stats['applications_anonymized'] += 1
            else:
                app.delete()
                stats['applications_deleted'] += 1

        return stats

    def _anonymize_application(self, application):
        """Anonymize an application instead of deleting."""
        application.cover_letter = "[ANONYMIZED]"
        application.custom_answers = {}
        application.additional_documents = []
        application.rejection_feedback = "[ANONYMIZED]" if application.rejection_feedback else ""
        application.save()

        # Also anonymize the candidate if this is their only application
        candidate = application.candidate
        if candidate.applications.count() == 1:
            self._anonymize_candidate(candidate)

    def _anonymize_candidate(self, candidate):
        """Anonymize candidate data for GDPR compliance."""
        candidate.first_name = "Anonymized"
        candidate.last_name = f"User-{candidate.uuid.hex[:8]}"
        candidate.email = f"anonymized-{candidate.uuid.hex[:8]}@deleted.local"
        candidate.phone = ""
        candidate.headline = ""
        candidate.summary = ""
        candidate.current_company = ""
        candidate.current_title = ""
        candidate.city = ""
        candidate.state = ""
        candidate.country = ""
        candidate.resume = None
        candidate.resume_text = ""
        candidate.cover_letter = ""
        candidate.skills = []
        candidate.education = []
        candidate.certifications = []
        candidate.work_experience = []
        candidate.linkedin_url = ""
        candidate.github_url = ""
        candidate.twitter_url = ""
        candidate.website_url = ""
        candidate.desired_salary_min = None
        candidate.desired_salary_max = None
        candidate.save()
