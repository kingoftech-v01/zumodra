"""
ATS QuerySets - Optimized database queries for the Applicant Tracking System.

This module provides custom QuerySet classes with optimized methods for:
- Reducing N+1 query problems via select_related and prefetch_related
- Efficient filtering with database-level aggregations
- Full-text search capabilities
- Time-based and status-based filtering
"""

from datetime import timedelta
from decimal import Decimal

from django.db import models
from django.db.models import (
    Count, Avg, F, Q, Case, When, Value, FloatField,
    ExpressionWrapper, DurationField, IntegerField,
    Subquery, OuterRef, Exists
)
from django.db.models.functions import Coalesce, Now, ExtractDay
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.utils import timezone


class JobPostingQuerySet(models.QuerySet):
    """
    Optimized QuerySet for JobPosting model.

    Provides methods for efficient querying of job postings with
    applicant counts, status filtering, and department grouping.
    """

    def with_applicant_count(self):
        """
        Annotate each job posting with the count of applicants.

        This uses a subquery approach to avoid GROUP BY issues and
        allows for further filtering without affecting the count.

        Returns:
            QuerySet: JobPostings annotated with 'applicant_count'
        """
        return self.annotate(
            applicant_count=Count('applications', distinct=True)
        )

    def with_applicant_stats(self):
        """
        Annotate job postings with detailed applicant statistics.

        Includes counts by status: new, in_review, interviewing, hired, rejected.

        Returns:
            QuerySet: JobPostings with multiple count annotations
        """
        return self.annotate(
            applicant_count=Count('applications', distinct=True),
            new_applicants=Count(
                'applications',
                filter=Q(applications__status='new'),
                distinct=True
            ),
            in_review_count=Count(
                'applications',
                filter=Q(applications__status='in_review'),
                distinct=True
            ),
            interviewing_count=Count(
                'applications',
                filter=Q(applications__status='interviewing'),
                distinct=True
            ),
            hired_count=Count(
                'applications',
                filter=Q(applications__status='hired'),
                distinct=True
            ),
            rejected_count=Count(
                'applications',
                filter=Q(applications__status='rejected'),
                distinct=True
            ),
        )

    def active(self):
        """
        Filter to only active (open) job postings.

        Returns:
            QuerySet: Only jobs with status='open'
        """
        return self.filter(status='open')

    def published(self):
        """
        Filter to published job postings (open and published on career page).

        Returns:
            QuerySet: Jobs that are open and published
        """
        return self.filter(
            status='open',
            published_on_career_page=True
        )

    def accepting_applications(self):
        """
        Filter to jobs currently accepting applications.

        Checks status is open AND deadline hasn't passed (if set).

        Returns:
            QuerySet: Jobs accepting applications
        """
        now = timezone.now()
        return self.filter(
            status='open'
        ).filter(
            Q(application_deadline__isnull=True) |
            Q(application_deadline__gt=now)
        )

    def by_department(self, category_id):
        """
        Filter jobs by department/category.

        Args:
            category_id: The JobCategory ID to filter by

        Returns:
            QuerySet: Jobs in the specified category
        """
        return self.filter(category_id=category_id)

    def by_category_hierarchy(self, category):
        """
        Filter jobs by category including child categories.

        Args:
            category: JobCategory instance (will include children)

        Returns:
            QuerySet: Jobs in category or its children
        """
        # Get category and all its children
        category_ids = [category.id]
        category_ids.extend(
            category.children.values_list('id', flat=True)
        )
        return self.filter(category_id__in=category_ids)

    def by_location(self, city=None, country=None, remote_only=False):
        """
        Filter jobs by location criteria.

        Args:
            city: City name to filter by
            country: Country name to filter by
            remote_only: If True, only return remote jobs

        Returns:
            QuerySet: Jobs matching location criteria
        """
        qs = self
        if remote_only:
            qs = qs.filter(remote_policy='remote')
        if city:
            qs = qs.filter(location_city__iexact=city)
        if country:
            qs = qs.filter(location_country__iexact=country)
        return qs

    def by_experience_level(self, *levels):
        """
        Filter jobs by experience level(s).

        Args:
            *levels: One or more experience level values

        Returns:
            QuerySet: Jobs with specified experience levels
        """
        return self.filter(experience_level__in=levels)

    def by_job_type(self, *types):
        """
        Filter jobs by employment type(s).

        Args:
            *types: One or more job type values

        Returns:
            QuerySet: Jobs with specified types
        """
        return self.filter(job_type__in=types)

    def requiring_skill(self, skill):
        """
        Filter jobs requiring a specific skill.

        Uses PostgreSQL array contains operator.

        Args:
            skill: Skill name to search for

        Returns:
            QuerySet: Jobs requiring the skill
        """
        return self.filter(required_skills__contains=[skill])

    def requiring_any_skill(self, skills):
        """
        Filter jobs requiring any of the specified skills.

        Args:
            skills: List of skill names

        Returns:
            QuerySet: Jobs requiring at least one of the skills
        """
        return self.filter(required_skills__overlap=skills)

    def in_salary_range(self, min_salary=None, max_salary=None, currency='CAD'):
        """
        Filter jobs within a salary range.

        Args:
            min_salary: Minimum salary (job's max must be >= this)
            max_salary: Maximum salary (job's min must be <= this)
            currency: Salary currency code

        Returns:
            QuerySet: Jobs within salary range
        """
        qs = self.filter(salary_currency=currency)
        if min_salary is not None:
            qs = qs.filter(
                Q(salary_max__gte=min_salary) | Q(salary_max__isnull=True)
            )
        if max_salary is not None:
            qs = qs.filter(
                Q(salary_min__lte=max_salary) | Q(salary_min__isnull=True)
            )
        return qs

    def search(self, query):
        """
        Full-text search on job title and description.

        Uses PostgreSQL full-text search with ranking.

        Args:
            query: Search query string

        Returns:
            QuerySet: Jobs matching the search, ordered by relevance
        """
        search_query = SearchQuery(query, config='english')
        return self.filter(
            search_vector=search_query
        ).annotate(
            search_rank=SearchRank(F('search_vector'), search_query)
        ).order_by('-search_rank')

    def search_fallback(self, query):
        """
        Fallback search using LIKE queries when search_vector not populated.

        Args:
            query: Search query string

        Returns:
            QuerySet: Jobs matching title or description
        """
        return self.filter(
            Q(title__icontains=query) |
            Q(description__icontains=query) |
            Q(requirements__icontains=query)
        )

    def with_related(self):
        """
        Optimize queries by pre-fetching related objects.

        Returns:
            QuerySet: With select_related for foreign keys
        """
        return self.select_related(
            'category',
            'pipeline',
            'hiring_manager',
            'recruiter',
            'created_by'
        )

    def posted_between(self, start_date, end_date):
        """
        Filter jobs published within a date range.

        Args:
            start_date: Start of date range
            end_date: End of date range

        Returns:
            QuerySet: Jobs published in the range
        """
        return self.filter(
            published_at__gte=start_date,
            published_at__lte=end_date
        )

    def closing_soon(self, days=7):
        """
        Filter jobs with deadlines within specified days.

        Args:
            days: Number of days to look ahead

        Returns:
            QuerySet: Jobs closing soon
        """
        now = timezone.now()
        deadline = now + timedelta(days=days)
        return self.filter(
            application_deadline__gte=now,
            application_deadline__lte=deadline
        )


class CandidateQuerySet(models.QuerySet):
    """
    Optimized QuerySet for Candidate model.

    Provides methods for searching candidates by skills, location,
    and application status with efficient database queries.
    """

    def with_application_status(self):
        """
        Annotate candidates with their latest application status.

        Returns:
            QuerySet: Candidates with 'latest_application_status' annotation
        """
        from ats.models import Application

        latest_application = Application.objects.filter(
            candidate=OuterRef('pk')
        ).order_by('-applied_at')

        return self.annotate(
            latest_application_status=Subquery(
                latest_application.values('status')[:1]
            ),
            application_count=Count('applications', distinct=True)
        )

    def with_application_count(self):
        """
        Annotate candidates with total application count.

        Returns:
            QuerySet: Candidates with 'application_count'
        """
        return self.annotate(
            application_count=Count('applications', distinct=True)
        )

    def searchable(self, query):
        """
        Full-text search on candidate name, skills, and resume.

        Uses PostgreSQL search_vector if populated, falls back to LIKE.
        Fixed N+1 query issue by avoiding qs.exists() which causes an extra query.

        Args:
            query: Search query string

        Returns:
            QuerySet: Matching candidates ordered by relevance
        """
        search_query = SearchQuery(query, config='english')

        # Check if any candidates have search_vector populated using a single query
        # Instead of calling exists() which causes N+1, we use a conditional approach
        # that returns a single queryset without extra database hits
        search_vector_qs = self.filter(
            search_vector=search_query
        ).annotate(
            search_rank=SearchRank(F('search_vector'), search_query)
        )

        # Use UNION-like approach: try search_vector first, fall back to LIKE
        # This avoids the N+1 caused by the exists() check
        fallback_qs = self.filter(
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(email__icontains=query) |
            Q(headline__icontains=query) |
            Q(skills__icontains=query) |
            Q(resume_text__icontains=query)
        ).annotate(
            search_rank=Value(0.0, output_field=FloatField())
        )

        # Combine: prioritize full-text search results, then fallback
        # Using Coalesce-style logic via CASE WHEN in annotation
        # Return full-text results if search_vector is populated, otherwise fallback
        return self.filter(
            Q(search_vector=search_query) |
            (
                Q(search_vector__isnull=True) &
                (
                    Q(first_name__icontains=query) |
                    Q(last_name__icontains=query) |
                    Q(email__icontains=query) |
                    Q(headline__icontains=query) |
                    Q(skills__icontains=query) |
                    Q(resume_text__icontains=query)
                )
            )
        ).annotate(
            search_rank=Case(
                When(search_vector=search_query,
                     then=SearchRank(F('search_vector'), search_query)),
                default=Value(0.0),
                output_field=FloatField()
            )
        ).order_by('-search_rank')

    def search_name(self, query):
        """
        Search candidates by name only.

        Args:
            query: Name search string

        Returns:
            QuerySet: Candidates matching name
        """
        return self.filter(
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        )

    def by_skills(self, skills, match_all=False):
        """
        Filter candidates by skills.

        Args:
            skills: List of skill names
            match_all: If True, candidate must have ALL skills

        Returns:
            QuerySet: Candidates with matching skills
        """
        if match_all:
            return self.filter(skills__contains=skills)
        return self.filter(skills__overlap=skills)

    def by_skill(self, skill):
        """
        Filter candidates having a specific skill.

        Args:
            skill: Skill name

        Returns:
            QuerySet: Candidates with the skill
        """
        return self.filter(skills__contains=[skill])

    def by_source(self, source):
        """
        Filter candidates by acquisition source.

        Args:
            source: Source value (e.g., 'linkedin', 'referral')

        Returns:
            QuerySet: Candidates from the source
        """
        return self.filter(source=source)

    def by_location(self, city=None, country=None):
        """
        Filter candidates by location.

        Args:
            city: City name
            country: Country name

        Returns:
            QuerySet: Candidates in location
        """
        qs = self
        if city:
            qs = qs.filter(city__iexact=city)
        if country:
            qs = qs.filter(country__iexact=country)
        return qs

    def willing_to_relocate(self):
        """
        Filter candidates willing to relocate.

        Returns:
            QuerySet: Candidates with willing_to_relocate=True
        """
        return self.filter(willing_to_relocate=True)

    def by_experience(self, min_years=None, max_years=None):
        """
        Filter candidates by years of experience.

        Args:
            min_years: Minimum years required
            max_years: Maximum years allowed

        Returns:
            QuerySet: Candidates in experience range
        """
        qs = self
        if min_years is not None:
            qs = qs.filter(years_experience__gte=min_years)
        if max_years is not None:
            qs = qs.filter(years_experience__lte=max_years)
        return qs

    def in_salary_range(self, min_salary=None, max_salary=None):
        """
        Filter candidates by desired salary range.

        Args:
            min_salary: Min of candidate's desired range must be <= this
            max_salary: Max of candidate's desired range must be >= this

        Returns:
            QuerySet: Candidates in salary range
        """
        qs = self
        if min_salary is not None:
            qs = qs.filter(
                Q(desired_salary_min__lte=min_salary) |
                Q(desired_salary_min__isnull=True)
            )
        if max_salary is not None:
            qs = qs.filter(
                Q(desired_salary_max__gte=max_salary) |
                Q(desired_salary_max__isnull=True)
            )
        return qs

    def active(self):
        """
        Filter to active candidates (with consent and not expired).

        Returns:
            QuerySet: Active candidates
        """
        today = timezone.now().date()
        return self.filter(
            consent_to_store=True
        ).filter(
            Q(data_retention_until__isnull=True) |
            Q(data_retention_until__gte=today)
        )

    def recently_active(self, days=30):
        """
        Filter candidates active within specified days.

        Args:
            days: Number of days to look back

        Returns:
            QuerySet: Recently active candidates
        """
        cutoff = timezone.now() - timedelta(days=days)
        return self.filter(last_activity_at__gte=cutoff)

    def with_resume(self):
        """
        Filter candidates who have uploaded a resume.

        Returns:
            QuerySet: Candidates with resumes
        """
        return self.exclude(Q(resume='') | Q(resume__isnull=True))

    def by_tags(self, tags, match_all=False):
        """
        Filter candidates by tags.

        Args:
            tags: List of tag strings
            match_all: If True, must have all tags

        Returns:
            QuerySet: Candidates with matching tags
        """
        if match_all:
            return self.filter(tags__contains=tags)
        return self.filter(tags__overlap=tags)

    def referred_by_employee(self):
        """
        Filter candidates who were referred.

        Returns:
            QuerySet: Referred candidates
        """
        return self.filter(
            source='referral',
            referred_by__isnull=False
        )

    def with_related(self):
        """
        Optimize queries by pre-fetching related objects.

        Returns:
            QuerySet: With related data prefetched
        """
        return self.select_related('user', 'referred_by').prefetch_related(
            'applications',
            'applications__job'
        )


class ApplicationQuerySet(models.QuerySet):
    """
    Optimized QuerySet for Application model.

    Provides methods for filtering by pipeline stage, calculating
    time metrics, and managing application workflows.
    """

    def with_stage_duration(self):
        """
        Annotate applications with time spent in current stage.

        Returns:
            QuerySet: Applications with 'stage_duration' annotation
        """
        return self.annotate(
            stage_duration=ExpressionWrapper(
                Now() - Coalesce(
                    F('last_stage_change_at'),
                    F('applied_at')
                ),
                output_field=DurationField()
            ),
            days_in_stage=ExtractDay(
                Now() - Coalesce(
                    F('last_stage_change_at'),
                    F('applied_at')
                )
            )
        )

    def with_time_to_hire(self):
        """
        Annotate hired applications with time-to-hire duration.

        Returns:
            QuerySet: With 'time_to_hire' for hired applications
        """
        return self.filter(
            status='hired'
        ).annotate(
            time_to_hire=ExpressionWrapper(
                F('hired_at') - F('applied_at'),
                output_field=DurationField()
            )
        )

    def by_pipeline_stage(self, stage):
        """
        Filter applications in a specific pipeline stage.

        Args:
            stage: PipelineStage instance or ID

        Returns:
            QuerySet: Applications in the stage
        """
        if hasattr(stage, 'id'):
            return self.filter(current_stage_id=stage.id)
        return self.filter(current_stage_id=stage)

    def by_stage_type(self, stage_type):
        """
        Filter applications by pipeline stage type.

        Args:
            stage_type: Stage type value (e.g., 'interview', 'offer')

        Returns:
            QuerySet: Applications in stages of that type
        """
        return self.filter(current_stage__stage_type=stage_type)

    def pending_review(self):
        """
        Filter applications awaiting review (new or in_review).

        Returns:
            QuerySet: Applications needing attention
        """
        return self.filter(
            status__in=['new', 'in_review']
        )

    def new_applications(self):
        """
        Filter only new applications.

        Returns:
            QuerySet: New applications
        """
        return self.filter(status='new')

    def active(self):
        """
        Filter active applications (not rejected/withdrawn/hired).

        Returns:
            QuerySet: Active applications still in process
        """
        return self.exclude(
            status__in=['rejected', 'withdrawn', 'hired']
        )

    def by_job(self, job):
        """
        Filter applications for a specific job.

        Args:
            job: JobPosting instance or ID

        Returns:
            QuerySet: Applications for the job
        """
        if hasattr(job, 'id'):
            return self.filter(job_id=job.id)
        return self.filter(job_id=job)

    def by_candidate(self, candidate):
        """
        Filter applications by candidate.

        Args:
            candidate: Candidate instance or ID

        Returns:
            QuerySet: Applications from the candidate
        """
        if hasattr(candidate, 'id'):
            return self.filter(candidate_id=candidate.id)
        return self.filter(candidate_id=candidate)

    def assigned_to(self, user):
        """
        Filter applications assigned to a specific user.

        Args:
            user: User instance or ID

        Returns:
            QuerySet: Applications assigned to user
        """
        if hasattr(user, 'id'):
            return self.filter(assigned_to_id=user.id)
        return self.filter(assigned_to_id=user)

    def unassigned(self):
        """
        Filter applications not assigned to anyone.

        Returns:
            QuerySet: Unassigned applications
        """
        return self.filter(assigned_to__isnull=True)

    def stale(self, days=14):
        """
        Filter applications that have been in current stage too long.

        Args:
            days: Days threshold for staleness

        Returns:
            QuerySet: Stale applications needing attention
        """
        cutoff = timezone.now() - timedelta(days=days)
        return self.filter(
            Q(last_stage_change_at__lt=cutoff) |
            Q(last_stage_change_at__isnull=True, applied_at__lt=cutoff)
        ).exclude(
            status__in=['rejected', 'withdrawn', 'hired']
        )

    def high_rated(self, min_rating=4.0):
        """
        Filter applications with high overall ratings.

        Args:
            min_rating: Minimum rating threshold

        Returns:
            QuerySet: High-rated applications
        """
        return self.filter(
            overall_rating__gte=Decimal(str(min_rating))
        )

    def high_match_score(self, min_score=80):
        """
        Filter applications with high AI match scores.

        Args:
            min_score: Minimum match score (0-100)

        Returns:
            QuerySet: High-scoring applications
        """
        return self.filter(ai_match_score__gte=min_score)

    def from_source(self, source):
        """
        Filter applications by UTM source.

        Args:
            source: UTM source value

        Returns:
            QuerySet: Applications from source
        """
        return self.filter(utm_source=source)

    def applied_between(self, start_date, end_date):
        """
        Filter applications submitted in a date range.

        Args:
            start_date: Start of range
            end_date: End of range

        Returns:
            QuerySet: Applications in range
        """
        return self.filter(
            applied_at__gte=start_date,
            applied_at__lte=end_date
        )

    def applied_today(self):
        """
        Filter applications submitted today.

        Returns:
            QuerySet: Today's applications
        """
        today = timezone.now().date()
        return self.filter(applied_at__date=today)

    def applied_this_week(self):
        """
        Filter applications submitted this week.

        Returns:
            QuerySet: This week's applications
        """
        today = timezone.now()
        week_start = today - timedelta(days=today.weekday())
        return self.filter(applied_at__gte=week_start)

    def with_interviews(self):
        """
        Filter applications that have scheduled interviews.

        Returns:
            QuerySet: Applications with interviews
        """
        return self.filter(interviews__isnull=False).distinct()

    def without_interviews(self):
        """
        Filter applications without any interviews.

        Returns:
            QuerySet: Applications lacking interviews
        """
        return self.filter(interviews__isnull=True)

    def with_offers(self):
        """
        Filter applications that have received offers.

        Returns:
            QuerySet: Applications with offers
        """
        return self.filter(offers__isnull=False).distinct()

    def with_related(self):
        """
        Optimize queries by pre-fetching related objects.

        Returns:
            QuerySet: With foreign keys and related sets prefetched
        """
        return self.select_related(
            'candidate',
            'job',
            'job__category',
            'current_stage',
            'assigned_to'
        ).prefetch_related(
            'interviews',
            'notes',
            'offers',
            'activities'
        )

    def with_feedback_count(self):
        """
        Annotate applications with count of interview feedback.

        Returns:
            QuerySet: With 'feedback_count' annotation
        """
        return self.annotate(
            interview_count=Count('interviews', distinct=True),
            feedback_count=Count('interviews__feedback', distinct=True)
        )


class InterviewQuerySet(models.QuerySet):
    """
    Optimized QuerySet for Interview model.

    Provides methods for filtering upcoming interviews, those
    needing feedback, and filtering by interviewer.
    """

    def upcoming(self, days=7):
        """
        Filter interviews scheduled in the next N days.

        Args:
            days: Number of days to look ahead

        Returns:
            QuerySet: Upcoming interviews
        """
        now = timezone.now()
        end_date = now + timedelta(days=days)
        return self.filter(
            scheduled_start__gte=now,
            scheduled_start__lte=end_date,
            status__in=['scheduled', 'confirmed']
        ).order_by('scheduled_start')

    def today(self):
        """
        Filter interviews scheduled for today.

        Returns:
            QuerySet: Today's interviews
        """
        today = timezone.now().date()
        return self.filter(
            scheduled_start__date=today
        ).order_by('scheduled_start')

    def this_week(self):
        """
        Filter interviews scheduled this week.

        Returns:
            QuerySet: This week's interviews
        """
        today = timezone.now()
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=7)
        return self.filter(
            scheduled_start__gte=week_start,
            scheduled_start__lt=week_end
        ).order_by('scheduled_start')

    def needs_feedback(self):
        """
        Filter completed interviews missing feedback.

        Returns:
            QuerySet: Interviews needing feedback submission
        """
        from ats.models import InterviewFeedback

        # Interviews that are completed but have interviewers
        # who haven't submitted feedback
        return self.filter(
            status='completed'
        ).annotate(
            interviewer_count=Count('interviewers', distinct=True),
            feedback_count=Count('feedback', distinct=True)
        ).filter(
            interviewer_count__gt=F('feedback_count')
        )

    def awaiting_feedback(self):
        """
        Alternative: completed interviews with no feedback at all.

        Returns:
            QuerySet: Interviews with zero feedback
        """
        return self.filter(
            status='completed',
            feedback__isnull=True
        ).distinct()

    def by_interviewer(self, user):
        """
        Filter interviews where user is an interviewer.

        Args:
            user: User instance or ID

        Returns:
            QuerySet: User's interviews as interviewer
        """
        return self.filter(interviewers=user)

    def by_organizer(self, user):
        """
        Filter interviews organized by a user.

        Args:
            user: User instance or ID

        Returns:
            QuerySet: Interviews organized by user
        """
        if hasattr(user, 'id'):
            return self.filter(organizer_id=user.id)
        return self.filter(organizer_id=user)

    def by_type(self, interview_type):
        """
        Filter interviews by type.

        Args:
            interview_type: Interview type value

        Returns:
            QuerySet: Interviews of that type
        """
        return self.filter(interview_type=interview_type)

    def by_status(self, status):
        """
        Filter interviews by status.

        Args:
            status: Status value

        Returns:
            QuerySet: Interviews with status
        """
        return self.filter(status=status)

    def scheduled(self):
        """
        Filter scheduled (not yet completed) interviews.

        Returns:
            QuerySet: Pending interviews
        """
        return self.filter(status__in=['scheduled', 'confirmed'])

    def completed(self):
        """
        Filter completed interviews.

        Returns:
            QuerySet: Completed interviews
        """
        return self.filter(status='completed')

    def cancelled(self):
        """
        Filter cancelled interviews.

        Returns:
            QuerySet: Cancelled interviews
        """
        return self.filter(status='cancelled')

    def for_application(self, application):
        """
        Filter interviews for a specific application.

        Args:
            application: Application instance or ID

        Returns:
            QuerySet: Interviews for the application
        """
        if hasattr(application, 'id'):
            return self.filter(application_id=application.id)
        return self.filter(application_id=application)

    def for_candidate(self, candidate):
        """
        Filter interviews for a specific candidate (across all applications).

        Args:
            candidate: Candidate instance or ID

        Returns:
            QuerySet: All candidate's interviews
        """
        if hasattr(candidate, 'id'):
            return self.filter(application__candidate_id=candidate.id)
        return self.filter(application__candidate_id=candidate)

    def for_job(self, job):
        """
        Filter interviews for a specific job posting.

        Args:
            job: JobPosting instance or ID

        Returns:
            QuerySet: Interviews for the job
        """
        if hasattr(job, 'id'):
            return self.filter(application__job_id=job.id)
        return self.filter(application__job_id=job)

    def overdue(self):
        """
        Filter interviews that should have been completed but aren't.

        Returns:
            QuerySet: Overdue interviews
        """
        now = timezone.now()
        return self.filter(
            scheduled_end__lt=now,
            status__in=['scheduled', 'confirmed']
        )

    def not_notified(self):
        """
        Filter interviews where notifications haven't been sent.

        Returns:
            QuerySet: Interviews pending notifications
        """
        return self.filter(
            Q(candidate_notified=False) | Q(interviewers_notified=False)
        )

    def with_related(self):
        """
        Optimize queries by pre-fetching related objects.

        Returns:
            QuerySet: With related data prefetched
        """
        return self.select_related(
            'application',
            'application__candidate',
            'application__job',
            'organizer'
        ).prefetch_related(
            'interviewers',
            'feedback'
        )

    def with_feedback_stats(self):
        """
        Annotate interviews with feedback statistics.

        Returns:
            QuerySet: With feedback count and average rating
        """
        return self.annotate(
            feedback_count=Count('feedback', distinct=True),
            avg_rating=Avg('feedback__overall_rating')
        )


class PipelineStageQuerySet(models.QuerySet):
    """
    Optimized QuerySet for PipelineStage model.
    """

    def active(self):
        """Filter active stages."""
        return self.filter(is_active=True)

    def by_pipeline(self, pipeline):
        """Filter stages for a specific pipeline."""
        if hasattr(pipeline, 'id'):
            return self.filter(pipeline_id=pipeline.id)
        return self.filter(pipeline_id=pipeline)

    def ordered(self):
        """Return stages in display order."""
        return self.order_by('order')

    def with_application_count(self):
        """Annotate stages with count of applications."""
        return self.annotate(
            application_count=Count('applications', distinct=True),
            active_application_count=Count(
                'applications',
                filter=~Q(applications__status__in=['rejected', 'withdrawn', 'hired']),
                distinct=True
            )
        )

    def hiring_stages(self):
        """Filter terminal success stages (hired)."""
        return self.filter(stage_type='hired')

    def rejection_stages(self):
        """Filter terminal failure stages (rejected, withdrawn)."""
        return self.filter(stage_type__in=['rejected', 'withdrawn'])


class OfferQuerySet(models.QuerySet):
    """
    Optimized QuerySet for Offer model.
    """

    def pending(self):
        """Filter offers awaiting response."""
        return self.filter(status='sent')

    def pending_approval(self):
        """Filter offers awaiting internal approval."""
        return self.filter(status='pending_approval')

    def accepted(self):
        """Filter accepted offers."""
        return self.filter(status='accepted')

    def declined(self):
        """Filter declined offers."""
        return self.filter(status='declined')

    def expired(self):
        """Filter expired offers."""
        today = timezone.now().date()
        return self.filter(
            status='sent',
            expiration_date__lt=today
        )

    def expiring_soon(self, days=3):
        """Filter offers expiring within N days."""
        today = timezone.now().date()
        deadline = today + timedelta(days=days)
        return self.filter(
            status='sent',
            expiration_date__gte=today,
            expiration_date__lte=deadline
        )

    def by_job(self, job):
        """Filter offers for a specific job."""
        if hasattr(job, 'id'):
            return self.filter(application__job_id=job.id)
        return self.filter(application__job_id=job)

    def with_related(self):
        """Optimize queries by pre-fetching related objects."""
        return self.select_related(
            'application',
            'application__candidate',
            'application__job',
            'created_by',
            'approved_by'
        )
