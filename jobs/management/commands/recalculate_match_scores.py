"""
Management command to recalculate AI match scores for candidates.
Updates the ai_match_score field on Application records.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone
from tenants.models import Tenant
from jobs.models import Application, JobPosting, Candidate


class Command(BaseCommand):
    help = 'Recalculate AI match scores for candidate applications'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant',
            type=str,
            help='Specific tenant slug (processes all active tenants if not specified)'
        )
        parser.add_argument(
            '--job',
            type=str,
            help='Specific job reference code'
        )
        parser.add_argument(
            '--candidate',
            type=str,
            help='Specific candidate email'
        )
        parser.add_argument(
            '--status',
            type=str,
            nargs='+',
            choices=[s[0] for s in Application.ApplicationStatus.choices],
            help='Only recalculate for applications with these statuses'
        )
        parser.add_argument(
            '--stale-days',
            type=int,
            default=0,
            help='Only recalculate scores older than N days (default: 0 = all)'
        )
        parser.add_argument(
            '--min-score',
            type=float,
            help='Only recalculate scores below this threshold'
        )
        parser.add_argument(
            '--algorithm',
            type=str,
            default='skills_matching',
            choices=['skills_matching', 'full_ai', 'hybrid'],
            help='Matching algorithm to use (default: skills_matching)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be updated without making changes'
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=50,
            help='Number of applications to process at a time (default: 50)'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed progress'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant')
        job_code = options.get('job')
        candidate_email = options.get('candidate')
        statuses = options.get('status')
        stale_days = options.get('stale_days', 0)
        min_score = options.get('min_score')
        algorithm = options.get('algorithm', 'skills_matching')
        dry_run = options.get('dry_run', False)
        batch_size = options.get('batch_size', 50)
        verbose = options.get('verbose', False)

        if dry_run:
            self.stdout.write(self.style.WARNING("=== DRY RUN MODE ===\n"))

        self.stdout.write(f"Using algorithm: {algorithm}")

        # Determine tenants to process
        if tenant_slug:
            try:
                tenants = [Tenant.objects.get(slug=tenant_slug)]
            except Tenant.DoesNotExist:
                raise CommandError(f"Tenant not found: {tenant_slug}")
        else:
            tenants = Tenant.objects.filter(status=Tenant.TenantStatus.ACTIVE)

        total_stats = {
            'tenants': 0,
            'processed': 0,
            'updated': 0,
            'errors': 0,
        }

        for tenant in tenants:
            self.stdout.write(f"\nProcessing tenant: {tenant.name}")
            total_stats['tenants'] += 1

            connection.set_schema(tenant.schema_name)

            try:
                stats = self._process_tenant(
                    job_code, candidate_email, statuses, stale_days,
                    min_score, algorithm, dry_run, batch_size, verbose
                )
                total_stats['processed'] += stats['processed']
                total_stats['updated'] += stats['updated']
                total_stats['errors'] += stats['errors']

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Error: {e}"))
                total_stats['errors'] += 1
            finally:
                connection.set_schema_to_public()

        # Print summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("Recalculation Summary:"))
        self.stdout.write(f"  Tenants processed: {total_stats['tenants']}")
        self.stdout.write(f"  Applications processed: {total_stats['processed']}")
        self.stdout.write(f"  Scores updated: {total_stats['updated']}")
        self.stdout.write(f"  Errors: {total_stats['errors']}")

    def _process_tenant(self, job_code, candidate_email, statuses, stale_days,
                        min_score, algorithm, dry_run, batch_size, verbose):
        """Process applications for a tenant."""
        stats = {'processed': 0, 'updated': 0, 'errors': 0}

        # Build queryset
        queryset = Application.objects.select_related('candidate', 'job')

        if job_code:
            queryset = queryset.filter(job__reference_code=job_code)

        if candidate_email:
            queryset = queryset.filter(candidate__email=candidate_email)

        if statuses:
            queryset = queryset.filter(status__in=statuses)
        else:
            # Default: only active applications
            queryset = queryset.exclude(
                status__in=[
                    Application.ApplicationStatus.REJECTED,
                    Application.ApplicationStatus.WITHDRAWN,
                    Application.ApplicationStatus.HIRED,
                ]
            )

        if stale_days > 0:
            cutoff = timezone.now() - timezone.timedelta(days=stale_days)
            queryset = queryset.filter(updated_at__lt=cutoff)

        if min_score is not None:
            queryset = queryset.filter(ai_match_score__lt=min_score) | \
                       queryset.filter(ai_match_score__isnull=True)

        total = queryset.count()
        self.stdout.write(f"  Found {total} applications to process")

        if total == 0:
            return stats

        for i, application in enumerate(queryset.iterator()):
            try:
                stats['processed'] += 1
                old_score = application.ai_match_score

                # Calculate new score
                new_score = self._calculate_score(
                    application.candidate, application.job, algorithm
                )

                if verbose:
                    self.stdout.write(
                        f"    {application.candidate.full_name} -> {application.job.title}: "
                        f"{old_score} -> {new_score:.2f}"
                    )

                if not dry_run:
                    application.ai_match_score = new_score
                    application.save(update_fields=['ai_match_score', 'updated_at'])
                    stats['updated'] += 1

                elif old_score != new_score:
                    stats['updated'] += 1

            except Exception as e:
                stats['errors'] += 1
                if verbose:
                    self.stdout.write(self.style.ERROR(f"    Error: {e}"))

            if (i + 1) % batch_size == 0:
                self.stdout.write(f"  Processed {i + 1}/{total}...")

        return stats

    def _calculate_score(self, candidate, job, algorithm):
        """Calculate match score using specified algorithm."""
        if algorithm == 'skills_matching':
            return self._skills_matching_score(candidate, job)
        elif algorithm == 'full_ai':
            return self._ai_matching_score(candidate, job)
        elif algorithm == 'hybrid':
            skills_score = self._skills_matching_score(candidate, job)
            # AI score would be calculated here if available
            return skills_score
        else:
            return 0.0

    def _skills_matching_score(self, candidate, job):
        """Calculate score based on skill overlap."""
        if not candidate.skills or not job.required_skills:
            return 50.0  # Neutral score if no skills to compare

        candidate_skills = set(s.lower().strip() for s in candidate.skills)
        required_skills = set(s.lower().strip() for s in job.required_skills)
        preferred_skills = set(s.lower().strip() for s in (job.preferred_skills or []))

        # Calculate matches
        required_matches = len(candidate_skills & required_skills)
        preferred_matches = len(candidate_skills & preferred_skills)

        # Calculate scores
        if len(required_skills) > 0:
            required_score = (required_matches / len(required_skills)) * 70
        else:
            required_score = 50

        if len(preferred_skills) > 0:
            preferred_score = (preferred_matches / len(preferred_skills)) * 20
        else:
            preferred_score = 10

        # Experience bonus
        experience_bonus = 0
        if candidate.years_experience:
            if job.experience_level == JobPosting.ExperienceLevel.ENTRY:
                if candidate.years_experience <= 2:
                    experience_bonus = 10
            elif job.experience_level == JobPosting.ExperienceLevel.JUNIOR:
                if 1 <= candidate.years_experience <= 3:
                    experience_bonus = 10
            elif job.experience_level == JobPosting.ExperienceLevel.MID:
                if 3 <= candidate.years_experience <= 6:
                    experience_bonus = 10
            elif job.experience_level == JobPosting.ExperienceLevel.SENIOR:
                if candidate.years_experience >= 5:
                    experience_bonus = 10
            elif job.experience_level == JobPosting.ExperienceLevel.LEAD:
                if candidate.years_experience >= 8:
                    experience_bonus = 10

        total_score = required_score + preferred_score + experience_bonus
        return min(100.0, max(0.0, total_score))

    def _ai_matching_score(self, candidate, job):
        """Calculate score using AI/ML model."""
        # This would integrate with an AI service like OpenAI
        # For now, fall back to skills matching
        try:
            from ai_matching.services import AIMatchingService
            service = AIMatchingService()
            return service.calculate_match(candidate, job)
        except ImportError:
            return self._skills_matching_score(candidate, job)
