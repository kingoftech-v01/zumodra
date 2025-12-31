"""
ATS Filters - Django Filter classes for REST API filtering

This module provides comprehensive filtering for:
- Job Postings (status, department, location, salary range)
- Candidates (skills, source, stage)
- Applications (stage, rating, date range)
- Interviews and Offers
"""

import django_filters
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta

from .models import (
    JobCategory, Pipeline, PipelineStage, JobPosting,
    Candidate, Application, ApplicationActivity, ApplicationNote,
    Interview, InterviewFeedback, Offer, SavedSearch
)


# ==================== JOB CATEGORY FILTERS ====================

class JobCategoryFilter(django_filters.FilterSet):
    """Filter for job categories."""
    name = django_filters.CharFilter(lookup_expr='icontains')
    parent = django_filters.NumberFilter(field_name='parent_id')
    is_root = django_filters.BooleanFilter(method='filter_is_root')
    has_jobs = django_filters.BooleanFilter(method='filter_has_jobs')

    class Meta:
        model = JobCategory
        fields = ['name', 'parent', 'is_active', 'is_root', 'has_jobs']

    def filter_is_root(self, queryset, name, value):
        if value:
            return queryset.filter(parent__isnull=True)
        return queryset.filter(parent__isnull=False)

    def filter_has_jobs(self, queryset, name, value):
        if value:
            return queryset.filter(jobs__status='open').distinct()
        return queryset


# ==================== PIPELINE FILTERS ====================

class PipelineFilter(django_filters.FilterSet):
    """Filter for pipelines."""
    name = django_filters.CharFilter(lookup_expr='icontains')
    created_by = django_filters.NumberFilter(field_name='created_by_id')
    created_after = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte'
    )
    created_before = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte'
    )

    class Meta:
        model = Pipeline
        fields = ['name', 'is_default', 'is_active', 'created_by']


class PipelineStageFilter(django_filters.FilterSet):
    """Filter for pipeline stages."""
    pipeline = django_filters.NumberFilter(field_name='pipeline_id')
    stage_type = django_filters.ChoiceFilter(choices=PipelineStage.StageType.choices)
    name = django_filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = PipelineStage
        fields = ['pipeline', 'stage_type', 'name', 'is_active']


# ==================== JOB POSTING FILTERS ====================

class JobPostingFilter(django_filters.FilterSet):
    """
    Comprehensive filter for job postings.

    Supports:
    - Status filtering (open, closed, draft, etc.)
    - Department/category filtering
    - Location filtering (city, state, country, remote)
    - Salary range filtering
    - Job type and experience level
    - Date range filtering
    - Keyword search
    """

    # Basic filters
    status = django_filters.ChoiceFilter(choices=JobPosting.JobStatus.choices)
    category = django_filters.NumberFilter(field_name='category_id')
    pipeline = django_filters.NumberFilter(field_name='pipeline_id')

    # Job type filters
    job_type = django_filters.ChoiceFilter(choices=JobPosting.JobType.choices)
    experience_level = django_filters.ChoiceFilter(
        choices=JobPosting.ExperienceLevel.choices
    )
    remote_policy = django_filters.ChoiceFilter(
        choices=JobPosting.RemotePolicy.choices
    )

    # Location filters
    location_city = django_filters.CharFilter(lookup_expr='icontains')
    location_state = django_filters.CharFilter(lookup_expr='icontains')
    location_country = django_filters.CharFilter(lookup_expr='icontains')
    location = django_filters.CharFilter(method='filter_location')
    is_remote = django_filters.BooleanFilter(method='filter_is_remote')

    # Salary filters
    salary_min = django_filters.NumberFilter(
        field_name='salary_min',
        lookup_expr='gte'
    )
    salary_max = django_filters.NumberFilter(
        field_name='salary_max',
        lookup_expr='lte'
    )
    salary_range = django_filters.CharFilter(method='filter_salary_range')
    salary_currency = django_filters.CharFilter(lookup_expr='iexact')

    # Skills filters
    required_skills = django_filters.CharFilter(method='filter_required_skills')
    any_skill = django_filters.CharFilter(method='filter_any_skill')

    # People filters
    hiring_manager = django_filters.NumberFilter(field_name='hiring_manager_id')
    recruiter = django_filters.NumberFilter(field_name='recruiter_id')
    created_by = django_filters.NumberFilter(field_name='created_by_id')

    # Boolean filters
    is_featured = django_filters.BooleanFilter()
    is_internal_only = django_filters.BooleanFilter()
    has_deadline = django_filters.BooleanFilter(method='filter_has_deadline')
    deadline_soon = django_filters.BooleanFilter(method='filter_deadline_soon')

    # Date filters
    created_after = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte'
    )
    created_before = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte'
    )
    published_after = django_filters.DateTimeFilter(
        field_name='published_at',
        lookup_expr='gte'
    )
    published_before = django_filters.DateTimeFilter(
        field_name='published_at',
        lookup_expr='lte'
    )

    # Search filter
    search = django_filters.CharFilter(method='filter_search')

    # Application count filters
    min_applications = django_filters.NumberFilter(method='filter_min_applications')
    max_applications = django_filters.NumberFilter(method='filter_max_applications')

    class Meta:
        model = JobPosting
        fields = [
            'status', 'category', 'pipeline', 'job_type', 'experience_level',
            'remote_policy', 'location_city', 'location_state', 'location_country',
            'salary_currency', 'hiring_manager', 'recruiter', 'created_by',
            'is_featured', 'is_internal_only'
        ]

    def filter_location(self, queryset, name, value):
        """Search across all location fields."""
        return queryset.filter(
            Q(location_city__icontains=value) |
            Q(location_state__icontains=value) |
            Q(location_country__icontains=value)
        )

    def filter_is_remote(self, queryset, name, value):
        """Filter for remote-friendly jobs."""
        if value:
            return queryset.filter(
                remote_policy__in=['remote', 'hybrid', 'flexible']
            )
        return queryset.filter(remote_policy='on_site')

    def filter_salary_range(self, queryset, name, value):
        """Filter by salary range (format: 'min-max')."""
        try:
            parts = value.split('-')
            if len(parts) == 2:
                min_val, max_val = int(parts[0]), int(parts[1])
                return queryset.filter(
                    Q(salary_min__gte=min_val) | Q(salary_min__isnull=True),
                    Q(salary_max__lte=max_val) | Q(salary_max__isnull=True)
                )
        except (ValueError, IndexError):
            pass
        return queryset

    def filter_required_skills(self, queryset, name, value):
        """Filter jobs that require ALL specified skills (comma-separated)."""
        skills = [s.strip().lower() for s in value.split(',')]
        for skill in skills:
            queryset = queryset.filter(required_skills__icontains=skill)
        return queryset

    def filter_any_skill(self, queryset, name, value):
        """Filter jobs that require ANY of the specified skills."""
        skills = [s.strip().lower() for s in value.split(',')]
        q_objects = Q()
        for skill in skills:
            q_objects |= Q(required_skills__icontains=skill)
            q_objects |= Q(preferred_skills__icontains=skill)
        return queryset.filter(q_objects)

    def filter_has_deadline(self, queryset, name, value):
        """Filter jobs with/without application deadline."""
        if value:
            return queryset.filter(application_deadline__isnull=False)
        return queryset.filter(application_deadline__isnull=True)

    def filter_deadline_soon(self, queryset, name, value):
        """Filter jobs with deadline within 7 days."""
        if value:
            deadline = timezone.now() + timedelta(days=7)
            return queryset.filter(
                application_deadline__isnull=False,
                application_deadline__lte=deadline,
                application_deadline__gte=timezone.now()
            )
        return queryset

    def filter_search(self, queryset, name, value):
        """Full-text search across multiple fields."""
        return queryset.filter(
            Q(title__icontains=value) |
            Q(description__icontains=value) |
            Q(requirements__icontains=value) |
            Q(reference_code__icontains=value) |
            Q(team__icontains=value)
        )

    def filter_min_applications(self, queryset, name, value):
        """Filter jobs with minimum number of applications."""
        from django.db.models import Count
        return queryset.annotate(
            app_count=Count('applications')
        ).filter(app_count__gte=value)

    def filter_max_applications(self, queryset, name, value):
        """Filter jobs with maximum number of applications."""
        from django.db.models import Count
        return queryset.annotate(
            app_count=Count('applications')
        ).filter(app_count__lte=value)


# ==================== CANDIDATE FILTERS ====================

class CandidateFilter(django_filters.FilterSet):
    """
    Comprehensive filter for candidates.

    Supports:
    - Skills filtering (exact match, any skill)
    - Source filtering
    - Location filtering
    - Experience filtering
    - Application stage filtering
    - Date range filtering
    - Tag filtering
    """

    # Name and contact filters
    name = django_filters.CharFilter(method='filter_name')
    email = django_filters.CharFilter(lookup_expr='icontains')

    # Professional filters
    headline = django_filters.CharFilter(lookup_expr='icontains')
    current_company = django_filters.CharFilter(lookup_expr='icontains')
    current_title = django_filters.CharFilter(lookup_expr='icontains')
    min_experience = django_filters.NumberFilter(
        field_name='years_experience',
        lookup_expr='gte'
    )
    max_experience = django_filters.NumberFilter(
        field_name='years_experience',
        lookup_expr='lte'
    )

    # Location filters
    city = django_filters.CharFilter(lookup_expr='icontains')
    state = django_filters.CharFilter(lookup_expr='icontains')
    country = django_filters.CharFilter(lookup_expr='icontains')
    location = django_filters.CharFilter(method='filter_location')
    willing_to_relocate = django_filters.BooleanFilter()

    # Skills filters
    skills = django_filters.CharFilter(method='filter_skills_all')
    any_skill = django_filters.CharFilter(method='filter_skills_any')

    # Source filters
    source = django_filters.ChoiceFilter(choices=Candidate.Source.choices)
    referred_by = django_filters.NumberFilter(field_name='referred_by_id')

    # Tags filter
    tags = django_filters.CharFilter(method='filter_tags')

    # Salary expectations
    salary_min = django_filters.NumberFilter(
        field_name='desired_salary_min',
        lookup_expr='gte'
    )
    salary_max = django_filters.NumberFilter(
        field_name='desired_salary_max',
        lookup_expr='lte'
    )

    # Language filters
    languages = django_filters.CharFilter(method='filter_languages')

    # Date filters
    created_after = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte'
    )
    created_before = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte'
    )
    last_activity_after = django_filters.DateTimeFilter(
        field_name='last_activity_at',
        lookup_expr='gte'
    )

    # Application stage filter (candidates in specific stage)
    in_stage = django_filters.NumberFilter(method='filter_in_stage')
    applied_to_job = django_filters.NumberFilter(method='filter_applied_to_job')

    # Boolean filters
    has_resume = django_filters.BooleanFilter(method='filter_has_resume')
    has_linkedin = django_filters.BooleanFilter(method='filter_has_linkedin')
    has_github = django_filters.BooleanFilter(method='filter_has_github')

    # Search filter
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = Candidate
        fields = [
            'source', 'willing_to_relocate', 'city', 'state', 'country'
        ]

    def filter_name(self, queryset, name, value):
        """Search by first or last name."""
        return queryset.filter(
            Q(first_name__icontains=value) |
            Q(last_name__icontains=value)
        )

    def filter_location(self, queryset, name, value):
        """Search across all location fields."""
        return queryset.filter(
            Q(city__icontains=value) |
            Q(state__icontains=value) |
            Q(country__icontains=value)
        )

    def filter_skills_all(self, queryset, name, value):
        """Filter candidates with ALL specified skills."""
        skills = [s.strip().lower() for s in value.split(',')]
        for skill in skills:
            queryset = queryset.filter(skills__icontains=skill)
        return queryset

    def filter_skills_any(self, queryset, name, value):
        """Filter candidates with ANY of the specified skills."""
        skills = [s.strip().lower() for s in value.split(',')]
        q_objects = Q()
        for skill in skills:
            q_objects |= Q(skills__icontains=skill)
        return queryset.filter(q_objects)

    def filter_tags(self, queryset, name, value):
        """Filter by tags (comma-separated)."""
        tags = [t.strip().lower() for t in value.split(',')]
        q_objects = Q()
        for tag in tags:
            q_objects |= Q(tags__icontains=tag)
        return queryset.filter(q_objects)

    def filter_languages(self, queryset, name, value):
        """Filter by languages (comma-separated)."""
        languages = [l.strip().lower() for l in value.split(',')]
        for lang in languages:
            queryset = queryset.filter(languages__icontains=lang)
        return queryset

    def filter_in_stage(self, queryset, name, value):
        """Filter candidates who have applications in a specific stage."""
        return queryset.filter(applications__current_stage_id=value).distinct()

    def filter_applied_to_job(self, queryset, name, value):
        """Filter candidates who applied to a specific job."""
        return queryset.filter(applications__job_id=value).distinct()

    def filter_has_resume(self, queryset, name, value):
        """Filter candidates with/without resume."""
        if value:
            return queryset.exclude(resume='').exclude(resume__isnull=True)
        return queryset.filter(Q(resume='') | Q(resume__isnull=True))

    def filter_has_linkedin(self, queryset, name, value):
        """Filter candidates with LinkedIn profile."""
        if value:
            return queryset.exclude(linkedin_url='')
        return queryset.filter(linkedin_url='')

    def filter_has_github(self, queryset, name, value):
        """Filter candidates with GitHub profile."""
        if value:
            return queryset.exclude(github_url='')
        return queryset.filter(github_url='')

    def filter_search(self, queryset, name, value):
        """Full-text search across multiple fields."""
        return queryset.filter(
            Q(first_name__icontains=value) |
            Q(last_name__icontains=value) |
            Q(email__icontains=value) |
            Q(headline__icontains=value) |
            Q(current_company__icontains=value) |
            Q(current_title__icontains=value) |
            Q(summary__icontains=value) |
            Q(resume_text__icontains=value)
        )


# ==================== APPLICATION FILTERS ====================

class ApplicationFilter(django_filters.FilterSet):
    """
    Comprehensive filter for applications.

    Supports:
    - Stage filtering
    - Rating filtering
    - Date range filtering
    - Job and candidate filtering
    - Status filtering
    - AI match score filtering
    """

    # Relationship filters
    job = django_filters.NumberFilter(field_name='job_id')
    candidate = django_filters.NumberFilter(field_name='candidate_id')
    current_stage = django_filters.NumberFilter(field_name='current_stage_id')
    assigned_to = django_filters.NumberFilter(field_name='assigned_to_id')

    # Status filter
    status = django_filters.ChoiceFilter(
        choices=Application.ApplicationStatus.choices
    )
    statuses = django_filters.CharFilter(method='filter_statuses')

    # Rating filters
    min_rating = django_filters.NumberFilter(
        field_name='overall_rating',
        lookup_expr='gte'
    )
    max_rating = django_filters.NumberFilter(
        field_name='overall_rating',
        lookup_expr='lte'
    )
    has_rating = django_filters.BooleanFilter(method='filter_has_rating')

    # AI Match Score filters
    min_ai_score = django_filters.NumberFilter(
        field_name='ai_match_score',
        lookup_expr='gte'
    )
    max_ai_score = django_filters.NumberFilter(
        field_name='ai_match_score',
        lookup_expr='lte'
    )
    has_ai_score = django_filters.BooleanFilter(method='filter_has_ai_score')

    # Date filters
    applied_after = django_filters.DateTimeFilter(
        field_name='applied_at',
        lookup_expr='gte'
    )
    applied_before = django_filters.DateTimeFilter(
        field_name='applied_at',
        lookup_expr='lte'
    )
    applied_today = django_filters.BooleanFilter(method='filter_applied_today')
    applied_this_week = django_filters.BooleanFilter(method='filter_applied_this_week')

    # Stage change filters
    stage_changed_after = django_filters.DateTimeFilter(
        field_name='last_stage_change_at',
        lookup_expr='gte'
    )
    stage_changed_before = django_filters.DateTimeFilter(
        field_name='last_stage_change_at',
        lookup_expr='lte'
    )

    # UTM filters
    utm_source = django_filters.CharFilter(lookup_expr='iexact')
    utm_medium = django_filters.CharFilter(lookup_expr='iexact')
    utm_campaign = django_filters.CharFilter(lookup_expr='iexact')

    # Boolean filters
    has_cover_letter = django_filters.BooleanFilter(method='filter_has_cover_letter')
    has_interviews = django_filters.BooleanFilter(method='filter_has_interviews')
    has_offers = django_filters.BooleanFilter(method='filter_has_offers')
    is_unassigned = django_filters.BooleanFilter(method='filter_is_unassigned')

    # Rejection filter
    rejection_reason = django_filters.CharFilter(lookup_expr='icontains')

    # Search filter
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = Application
        fields = [
            'job', 'candidate', 'status', 'current_stage', 'assigned_to'
        ]

    def filter_statuses(self, queryset, name, value):
        """Filter by multiple statuses (comma-separated)."""
        statuses = [s.strip() for s in value.split(',')]
        return queryset.filter(status__in=statuses)

    def filter_has_rating(self, queryset, name, value):
        """Filter applications with/without rating."""
        if value:
            return queryset.filter(overall_rating__isnull=False)
        return queryset.filter(overall_rating__isnull=True)

    def filter_has_ai_score(self, queryset, name, value):
        """Filter applications with/without AI match score."""
        if value:
            return queryset.filter(ai_match_score__isnull=False)
        return queryset.filter(ai_match_score__isnull=True)

    def filter_applied_today(self, queryset, name, value):
        """Filter applications from today."""
        if value:
            today_start = timezone.now().replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            return queryset.filter(applied_at__gte=today_start)
        return queryset

    def filter_applied_this_week(self, queryset, name, value):
        """Filter applications from this week."""
        if value:
            week_start = timezone.now() - timedelta(days=7)
            return queryset.filter(applied_at__gte=week_start)
        return queryset

    def filter_has_cover_letter(self, queryset, name, value):
        """Filter applications with/without cover letter."""
        if value:
            return queryset.exclude(cover_letter='')
        return queryset.filter(cover_letter='')

    def filter_has_interviews(self, queryset, name, value):
        """Filter applications with scheduled interviews."""
        if value:
            return queryset.filter(interviews__isnull=False).distinct()
        return queryset.filter(interviews__isnull=True)

    def filter_has_offers(self, queryset, name, value):
        """Filter applications with offers."""
        if value:
            return queryset.filter(offers__isnull=False).distinct()
        return queryset.filter(offers__isnull=True)

    def filter_is_unassigned(self, queryset, name, value):
        """Filter unassigned applications."""
        if value:
            return queryset.filter(assigned_to__isnull=True)
        return queryset.filter(assigned_to__isnull=False)

    def filter_search(self, queryset, name, value):
        """Search by candidate name, email, or job title."""
        return queryset.filter(
            Q(candidate__first_name__icontains=value) |
            Q(candidate__last_name__icontains=value) |
            Q(candidate__email__icontains=value) |
            Q(job__title__icontains=value) |
            Q(job__reference_code__icontains=value)
        )


# ==================== INTERVIEW FILTERS ====================

class InterviewFilter(django_filters.FilterSet):
    """Filter for interviews."""

    application = django_filters.NumberFilter(field_name='application_id')
    interview_type = django_filters.ChoiceFilter(
        choices=Interview.InterviewType.choices
    )
    status = django_filters.ChoiceFilter(choices=Interview.InterviewStatus.choices)
    organizer = django_filters.NumberFilter(field_name='organizer_id')
    interviewer = django_filters.NumberFilter(method='filter_interviewer')

    # Date filters
    scheduled_after = django_filters.DateTimeFilter(
        field_name='scheduled_start',
        lookup_expr='gte'
    )
    scheduled_before = django_filters.DateTimeFilter(
        field_name='scheduled_start',
        lookup_expr='lte'
    )
    today = django_filters.BooleanFilter(method='filter_today')
    this_week = django_filters.BooleanFilter(method='filter_this_week')
    upcoming = django_filters.BooleanFilter(method='filter_upcoming')

    # Boolean filters
    needs_feedback = django_filters.BooleanFilter(method='filter_needs_feedback')
    candidate_notified = django_filters.BooleanFilter()

    class Meta:
        model = Interview
        fields = [
            'application', 'interview_type', 'status', 'organizer'
        ]

    def filter_interviewer(self, queryset, name, value):
        """Filter by interviewer."""
        return queryset.filter(interviewers__id=value)

    def filter_today(self, queryset, name, value):
        """Filter interviews scheduled for today."""
        if value:
            today_start = timezone.now().replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            today_end = today_start + timedelta(days=1)
            return queryset.filter(
                scheduled_start__gte=today_start,
                scheduled_start__lt=today_end
            )
        return queryset

    def filter_this_week(self, queryset, name, value):
        """Filter interviews scheduled for this week."""
        if value:
            now = timezone.now()
            week_start = now - timedelta(days=now.weekday())
            week_end = week_start + timedelta(days=7)
            return queryset.filter(
                scheduled_start__gte=week_start,
                scheduled_start__lt=week_end
            )
        return queryset

    def filter_upcoming(self, queryset, name, value):
        """Filter upcoming (future) interviews."""
        if value:
            return queryset.filter(scheduled_start__gte=timezone.now())
        return queryset.filter(scheduled_start__lt=timezone.now())

    def filter_needs_feedback(self, queryset, name, value):
        """Filter completed interviews missing feedback."""
        if value:
            return queryset.filter(
                status='completed'
            ).exclude(
                feedback__isnull=False
            )
        return queryset


# ==================== OFFER FILTERS ====================

class OfferFilter(django_filters.FilterSet):
    """Filter for offers."""

    application = django_filters.NumberFilter(field_name='application_id')
    status = django_filters.ChoiceFilter(choices=Offer.OfferStatus.choices)
    created_by = django_filters.NumberFilter(field_name='created_by_id')
    approved_by = django_filters.NumberFilter(field_name='approved_by_id')

    # Salary filters
    min_salary = django_filters.NumberFilter(
        field_name='base_salary',
        lookup_expr='gte'
    )
    max_salary = django_filters.NumberFilter(
        field_name='base_salary',
        lookup_expr='lte'
    )
    salary_currency = django_filters.CharFilter(lookup_expr='iexact')

    # Date filters
    created_after = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte'
    )
    created_before = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte'
    )
    start_date_after = django_filters.DateFilter(
        field_name='start_date',
        lookup_expr='gte'
    )
    start_date_before = django_filters.DateFilter(
        field_name='start_date',
        lookup_expr='lte'
    )

    # Boolean filters
    expiring_soon = django_filters.BooleanFilter(method='filter_expiring_soon')
    requires_signature = django_filters.BooleanFilter()
    is_signed = django_filters.BooleanFilter(method='filter_is_signed')
    pending_approval = django_filters.BooleanFilter(method='filter_pending_approval')

    class Meta:
        model = Offer
        fields = [
            'application', 'status', 'created_by', 'approved_by',
            'salary_currency', 'requires_signature'
        ]

    def filter_expiring_soon(self, queryset, name, value):
        """Filter offers expiring within 3 days."""
        if value:
            deadline = timezone.now().date() + timedelta(days=3)
            return queryset.filter(
                expiration_date__isnull=False,
                expiration_date__lte=deadline,
                status='sent'
            )
        return queryset

    def filter_is_signed(self, queryset, name, value):
        """Filter signed/unsigned offers."""
        if value:
            return queryset.filter(signed_at__isnull=False)
        return queryset.filter(signed_at__isnull=True)

    def filter_pending_approval(self, queryset, name, value):
        """Filter offers pending approval."""
        if value:
            return queryset.filter(status='pending_approval')
        return queryset


# ==================== SAVED SEARCH FILTERS ====================

class SavedSearchFilter(django_filters.FilterSet):
    """Filter for saved searches."""

    user = django_filters.NumberFilter(field_name='user_id')
    name = django_filters.CharFilter(lookup_expr='icontains')
    is_alert_enabled = django_filters.BooleanFilter()
    alert_frequency = django_filters.CharFilter()

    class Meta:
        model = SavedSearch
        fields = ['user', 'name', 'is_alert_enabled', 'alert_frequency']
