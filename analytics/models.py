"""
Analytics Models - HR, Recruitment, and Diversity Analytics

This module implements analytics models for:
- Recruitment metrics (daily/weekly/monthly snapshots)
- Diversity metrics (anonymized demographic data)
- Hiring funnel metrics (stage conversion rates)
- Time-to-hire metrics
- Source effectiveness metrics
- Employee retention metrics
- Time-off analytics
- Performance distribution
"""

import uuid
from decimal import Decimal
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.validators import MinValueValidator, MaxValueValidator


# ==================== EXISTING MODELS ====================

class PageView(models.Model):
    """Track page views for analytics"""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='page_views'
    )
    session_key = models.CharField(max_length=40, blank=True)
    path = models.CharField(max_length=500)
    referrer = models.CharField(max_length=500, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['path', '-timestamp']),
            models.Index(fields=['user', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.path} at {self.timestamp}"


class UserAction(models.Model):
    """Track user actions for analytics"""
    ACTION_TYPES = [
        ('service_view', 'Service Viewed'),
        ('service_like', 'Service Liked'),
        ('service_create', 'Service Created'),
        ('proposal_submit', 'Proposal Submitted'),
        ('proposal_accept', 'Proposal Accepted'),
        ('contract_create', 'Contract Created'),
        ('contract_complete', 'Contract Completed'),
        ('review_create', 'Review Created'),
        ('profile_update', 'Profile Updated'),
        ('search', 'Search Performed'),
        # HR Actions
        ('job_view', 'Job Viewed'),
        ('job_apply', 'Job Applied'),
        ('candidate_review', 'Candidate Reviewed'),
        ('interview_schedule', 'Interview Scheduled'),
        ('offer_sent', 'Offer Sent'),
        ('employee_onboard', 'Employee Onboarded'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='user_actions'
    )
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    description = models.TextField(blank=True)

    # Generic relation to any object
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')

    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'action_type', '-timestamp']),
            models.Index(fields=['action_type', '-timestamp']),
        ]

    def __str__(self):
        user_str = self.user.email if self.user else 'Anonymous'
        return f"{user_str} - {self.get_action_type_display()} at {self.timestamp}"


class SearchQuery(models.Model):
    """Track search queries for analytics and improvement"""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='search_queries'
    )
    query = models.CharField(max_length=500, db_index=True)
    results_count = models.PositiveIntegerField(default=0)
    filters_used = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = 'Search Queries'

    def __str__(self):
        return f'"{self.query}" ({self.results_count} results)'


class DashboardMetric(models.Model):
    """Store calculated metrics for dashboard"""
    METRIC_TYPES = [
        ('daily_revenue', 'Daily Revenue'),
        ('monthly_revenue', 'Monthly Revenue'),
        ('active_users', 'Active Users'),
        ('new_users', 'New Users'),
        ('total_services', 'Total Services'),
        ('active_contracts', 'Active Contracts'),
        ('completed_contracts', 'Completed Contracts'),
        ('conversion_rate', 'Conversion Rate'),
        # HR Metrics
        ('open_positions', 'Open Positions'),
        ('total_applications', 'Total Applications'),
        ('avg_time_to_hire', 'Average Time to Hire'),
        ('offer_acceptance_rate', 'Offer Acceptance Rate'),
        ('employee_turnover', 'Employee Turnover Rate'),
    ]

    metric_type = models.CharField(max_length=50, choices=METRIC_TYPES, db_index=True)
    value = models.DecimalField(max_digits=15, decimal_places=2)
    metadata = models.JSONField(default=dict, blank=True)
    date = models.DateField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-date', 'metric_type']
        unique_together = ['metric_type', 'date']

    def __str__(self):
        return f"{self.get_metric_type_display()}: {self.value} on {self.date}"


# ==================== RECRUITMENT METRICS ====================

class RecruitmentMetric(models.Model):
    """
    Daily/weekly/monthly recruitment snapshots.
    Tracks key recruitment KPIs over time.
    """

    class PeriodType(models.TextChoices):
        DAILY = 'daily', _('Daily')
        WEEKLY = 'weekly', _('Weekly')
        MONTHLY = 'monthly', _('Monthly')
        QUARTERLY = 'quarterly', _('Quarterly')
        YEARLY = 'yearly', _('Yearly')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    period_type = models.CharField(
        max_length=20,
        choices=PeriodType.choices,
        default=PeriodType.DAILY
    )
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Job Metrics
    open_positions = models.PositiveIntegerField(default=0)
    new_positions = models.PositiveIntegerField(default=0)
    closed_positions = models.PositiveIntegerField(default=0)
    filled_positions = models.PositiveIntegerField(default=0)
    cancelled_positions = models.PositiveIntegerField(default=0)

    # Application Metrics
    total_applications = models.PositiveIntegerField(default=0)
    new_applications = models.PositiveIntegerField(default=0)
    applications_in_review = models.PositiveIntegerField(default=0)
    applications_shortlisted = models.PositiveIntegerField(default=0)
    applications_rejected = models.PositiveIntegerField(default=0)
    applications_withdrawn = models.PositiveIntegerField(default=0)

    # Interview Metrics
    interviews_scheduled = models.PositiveIntegerField(default=0)
    interviews_completed = models.PositiveIntegerField(default=0)
    interviews_cancelled = models.PositiveIntegerField(default=0)
    interviews_no_show = models.PositiveIntegerField(default=0)

    # Offer Metrics
    offers_extended = models.PositiveIntegerField(default=0)
    offers_accepted = models.PositiveIntegerField(default=0)
    offers_declined = models.PositiveIntegerField(default=0)
    offers_expired = models.PositiveIntegerField(default=0)

    # Hires
    total_hires = models.PositiveIntegerField(default=0)

    # Rates (calculated)
    application_to_interview_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Percentage of applications that reach interview stage')
    )
    interview_to_offer_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Percentage of interviews that result in offers')
    )
    offer_acceptance_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Percentage of offers accepted')
    )
    overall_conversion_rate = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Application to hire conversion rate')
    )

    # Time Metrics (in days)
    avg_time_to_fill = models.DecimalField(
        max_digits=7,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Average days from job posting to hire')
    )
    avg_time_to_hire = models.DecimalField(
        max_digits=7,
        decimal_places=2,
        null=True,
        blank=True,
        help_text=_('Average days from application to hire')
    )

    # Cost Metrics
    total_recruitment_cost = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True
    )
    cost_per_hire = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True
    )
    cost_per_application = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True
    )

    # Department breakdown (JSON)
    by_department = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Metrics broken down by department')
    )

    # Location breakdown (JSON)
    by_location = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Metrics broken down by location')
    )

    # Job type breakdown (JSON)
    by_job_type = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Metrics broken down by job type')
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Recruitment Metric')
        verbose_name_plural = _('Recruitment Metrics')
        ordering = ['-period_start']
        unique_together = ['period_type', 'period_start']
        indexes = [
            models.Index(fields=['period_type', 'period_start']),
            models.Index(fields=['-period_start']),
        ]

    def __str__(self):
        return f"Recruitment Metrics ({self.get_period_type_display()}) - {self.period_start}"


class DiversityMetric(models.Model):
    """
    Anonymized demographic data for diversity analytics.
    EEOC compliant - no individual identification possible.
    """

    class PeriodType(models.TextChoices):
        MONTHLY = 'monthly', _('Monthly')
        QUARTERLY = 'quarterly', _('Quarterly')
        YEARLY = 'yearly', _('Yearly')

    class MetricScope(models.TextChoices):
        APPLICANTS = 'applicants', _('Applicants')
        INTERVIEWED = 'interviewed', _('Interviewed Candidates')
        HIRED = 'hired', _('New Hires')
        EMPLOYEES = 'employees', _('Current Employees')
        LEADERSHIP = 'leadership', _('Leadership')
        DEPARTED = 'departed', _('Departed Employees')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    period_type = models.CharField(
        max_length=20,
        choices=PeriodType.choices,
        default=PeriodType.QUARTERLY
    )
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)
    scope = models.CharField(
        max_length=20,
        choices=MetricScope.choices,
        default=MetricScope.EMPLOYEES
    )

    # Total count for the scope
    total_count = models.PositiveIntegerField(default=0)

    # Gender Distribution (EEOC categories)
    gender_male_count = models.PositiveIntegerField(default=0)
    gender_female_count = models.PositiveIntegerField(default=0)
    gender_nonbinary_count = models.PositiveIntegerField(default=0)
    gender_not_disclosed_count = models.PositiveIntegerField(default=0)

    # Ethnicity Distribution (EEOC categories)
    ethnicity_white_count = models.PositiveIntegerField(default=0)
    ethnicity_black_count = models.PositiveIntegerField(default=0)
    ethnicity_hispanic_count = models.PositiveIntegerField(default=0)
    ethnicity_asian_count = models.PositiveIntegerField(default=0)
    ethnicity_native_american_count = models.PositiveIntegerField(default=0)
    ethnicity_pacific_islander_count = models.PositiveIntegerField(default=0)
    ethnicity_two_or_more_count = models.PositiveIntegerField(default=0)
    ethnicity_not_disclosed_count = models.PositiveIntegerField(default=0)

    # Age Distribution (ranges only - no exact ages)
    age_under_25_count = models.PositiveIntegerField(default=0)
    age_25_34_count = models.PositiveIntegerField(default=0)
    age_35_44_count = models.PositiveIntegerField(default=0)
    age_45_54_count = models.PositiveIntegerField(default=0)
    age_55_64_count = models.PositiveIntegerField(default=0)
    age_65_plus_count = models.PositiveIntegerField(default=0)
    age_not_disclosed_count = models.PositiveIntegerField(default=0)

    # Veteran Status
    veteran_count = models.PositiveIntegerField(default=0)
    non_veteran_count = models.PositiveIntegerField(default=0)
    veteran_not_disclosed_count = models.PositiveIntegerField(default=0)

    # Disability Status
    disability_yes_count = models.PositiveIntegerField(default=0)
    disability_no_count = models.PositiveIntegerField(default=0)
    disability_not_disclosed_count = models.PositiveIntegerField(default=0)

    # Department breakdown (JSON - only if min threshold met)
    by_department = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Anonymized metrics by department (min 5 per category)')
    )

    # Level breakdown (JSON)
    by_level = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Anonymized metrics by job level')
    )

    # Calculated percentages (for quick access)
    gender_percentages = models.JSONField(default=dict, blank=True)
    ethnicity_percentages = models.JSONField(default=dict, blank=True)
    age_percentages = models.JSONField(default=dict, blank=True)

    # Comparison metrics
    industry_benchmark = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Industry benchmarks for comparison')
    )

    # Anonymization threshold
    min_category_size = models.PositiveIntegerField(
        default=5,
        help_text=_('Minimum count to display category (for anonymization)')
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Diversity Metric')
        verbose_name_plural = _('Diversity Metrics')
        ordering = ['-period_start']
        unique_together = ['period_type', 'period_start', 'scope']
        indexes = [
            models.Index(fields=['period_type', 'scope', 'period_start']),
            models.Index(fields=['-period_start', 'scope']),
        ]

    def __str__(self):
        return f"Diversity Metrics ({self.get_scope_display()}) - {self.period_start}"

    def calculate_percentages(self):
        """Calculate all percentage distributions."""
        if self.total_count == 0:
            return

        def pct(count):
            return round((count / self.total_count) * 100, 2) if self.total_count > 0 else 0

        self.gender_percentages = {
            'male': pct(self.gender_male_count),
            'female': pct(self.gender_female_count),
            'nonbinary': pct(self.gender_nonbinary_count),
            'not_disclosed': pct(self.gender_not_disclosed_count),
        }

        self.ethnicity_percentages = {
            'white': pct(self.ethnicity_white_count),
            'black': pct(self.ethnicity_black_count),
            'hispanic': pct(self.ethnicity_hispanic_count),
            'asian': pct(self.ethnicity_asian_count),
            'native_american': pct(self.ethnicity_native_american_count),
            'pacific_islander': pct(self.ethnicity_pacific_islander_count),
            'two_or_more': pct(self.ethnicity_two_or_more_count),
            'not_disclosed': pct(self.ethnicity_not_disclosed_count),
        }

        self.age_percentages = {
            'under_25': pct(self.age_under_25_count),
            '25_34': pct(self.age_25_34_count),
            '35_44': pct(self.age_35_44_count),
            '45_54': pct(self.age_45_54_count),
            '55_64': pct(self.age_55_64_count),
            '65_plus': pct(self.age_65_plus_count),
            'not_disclosed': pct(self.age_not_disclosed_count),
        }

    def anonymize_small_categories(self):
        """Replace counts below threshold with 'suppressed' for privacy."""
        fields_to_check = [
            'gender_male_count', 'gender_female_count', 'gender_nonbinary_count',
            'ethnicity_white_count', 'ethnicity_black_count', 'ethnicity_hispanic_count',
            'ethnicity_asian_count', 'ethnicity_native_american_count',
            'ethnicity_pacific_islander_count', 'ethnicity_two_or_more_count',
        ]
        suppressed_fields = []
        for field in fields_to_check:
            value = getattr(self, field)
            if 0 < value < self.min_category_size:
                suppressed_fields.append(field)
        return suppressed_fields


class HiringFunnelMetric(models.Model):
    """
    Stage conversion rates in the hiring funnel.
    Tracks how candidates flow through pipeline stages.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Optional filters
    job = models.ForeignKey(
        'ats.JobPosting',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='funnel_metrics'
    )
    department = models.CharField(max_length=100, blank=True)
    job_type = models.CharField(max_length=50, blank=True)

    # Funnel Stages (counts)
    stage_applied = models.PositiveIntegerField(default=0)
    stage_screening = models.PositiveIntegerField(default=0)
    stage_phone_interview = models.PositiveIntegerField(default=0)
    stage_technical_assessment = models.PositiveIntegerField(default=0)
    stage_onsite_interview = models.PositiveIntegerField(default=0)
    stage_reference_check = models.PositiveIntegerField(default=0)
    stage_offer = models.PositiveIntegerField(default=0)
    stage_hired = models.PositiveIntegerField(default=0)

    # Rejection/Drop-off at each stage
    dropped_at_screening = models.PositiveIntegerField(default=0)
    dropped_at_phone = models.PositiveIntegerField(default=0)
    dropped_at_technical = models.PositiveIntegerField(default=0)
    dropped_at_onsite = models.PositiveIntegerField(default=0)
    dropped_at_reference = models.PositiveIntegerField(default=0)
    dropped_at_offer = models.PositiveIntegerField(default=0)

    # Conversion Rates (stage to stage)
    rate_applied_to_screening = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    rate_screening_to_phone = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    rate_phone_to_technical = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    rate_technical_to_onsite = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    rate_onsite_to_reference = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    rate_reference_to_offer = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    rate_offer_to_hired = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )

    # Overall metrics
    overall_conversion_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Applied to hired conversion rate')
    )
    avg_days_in_funnel = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True
    )

    # Time spent at each stage (avg days)
    avg_days_screening = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    avg_days_phone = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    avg_days_technical = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    avg_days_onsite = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    avg_days_reference = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    avg_days_offer = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    # Bottleneck identification
    bottleneck_stage = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Stage with lowest conversion rate')
    )
    bottleneck_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )

    # Detailed breakdown (JSON)
    stage_details = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Detailed metrics per stage')
    )

    # Comparison with previous period
    comparison_period = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Comparison with previous period')
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Hiring Funnel Metric')
        verbose_name_plural = _('Hiring Funnel Metrics')
        ordering = ['-period_start']
        indexes = [
            models.Index(fields=['-period_start']),
            models.Index(fields=['job', '-period_start']),
        ]

    def __str__(self):
        job_str = f" - {self.job.title}" if self.job else ""
        return f"Hiring Funnel{job_str} ({self.period_start} to {self.period_end})"

    def calculate_conversion_rates(self):
        """Calculate all stage-to-stage conversion rates."""
        def safe_rate(numerator, denominator):
            return round((numerator / denominator) * 100, 2) if denominator > 0 else None

        self.rate_applied_to_screening = safe_rate(self.stage_screening, self.stage_applied)
        self.rate_screening_to_phone = safe_rate(self.stage_phone_interview, self.stage_screening)
        self.rate_phone_to_technical = safe_rate(self.stage_technical_assessment, self.stage_phone_interview)
        self.rate_technical_to_onsite = safe_rate(self.stage_onsite_interview, self.stage_technical_assessment)
        self.rate_onsite_to_reference = safe_rate(self.stage_reference_check, self.stage_onsite_interview)
        self.rate_reference_to_offer = safe_rate(self.stage_offer, self.stage_reference_check)
        self.rate_offer_to_hired = safe_rate(self.stage_hired, self.stage_offer)
        self.overall_conversion_rate = safe_rate(self.stage_hired, self.stage_applied)

        # Identify bottleneck
        rates = {
            'screening': self.rate_applied_to_screening,
            'phone': self.rate_screening_to_phone,
            'technical': self.rate_phone_to_technical,
            'onsite': self.rate_technical_to_onsite,
            'reference': self.rate_onsite_to_reference,
            'offer': self.rate_reference_to_offer,
            'hired': self.rate_offer_to_hired,
        }
        valid_rates = {k: v for k, v in rates.items() if v is not None}
        if valid_rates:
            self.bottleneck_stage = min(valid_rates, key=valid_rates.get)
            self.bottleneck_rate = valid_rates[self.bottleneck_stage]


class TimeToHireMetric(models.Model):
    """
    Time-to-hire analytics broken down by various dimensions.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Filter dimensions
    department = models.CharField(max_length=100, blank=True)
    job_type = models.CharField(max_length=50, blank=True)
    experience_level = models.CharField(max_length=50, blank=True)
    location = models.CharField(max_length=200, blank=True)

    # Time-to-fill metrics (from job posting)
    total_positions_filled = models.PositiveIntegerField(default=0)
    avg_time_to_fill = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True,
        help_text=_('Average days from job posting to accepted offer')
    )
    median_time_to_fill = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True
    )
    min_time_to_fill = models.DecimalField(max_digits=7, decimal_places=2, null=True, blank=True)
    max_time_to_fill = models.DecimalField(max_digits=7, decimal_places=2, null=True, blank=True)

    # Time-to-hire metrics (from application)
    total_hires = models.PositiveIntegerField(default=0)
    avg_time_to_hire = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True,
        help_text=_('Average days from application to start date')
    )
    median_time_to_hire = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True
    )
    min_time_to_hire = models.DecimalField(max_digits=7, decimal_places=2, null=True, blank=True)
    max_time_to_hire = models.DecimalField(max_digits=7, decimal_places=2, null=True, blank=True)

    # Time in each stage (average days)
    avg_time_in_screening = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    avg_time_in_interview = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    avg_time_in_assessment = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    avg_time_in_offer = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    # Time to first contact
    avg_time_to_first_contact = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Days from application to first recruiter contact')
    )

    # Time to decision
    avg_time_to_decision = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Days from final interview to decision')
    )

    # Distribution breakdown
    time_distribution = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Distribution of time-to-hire (buckets)')
    )

    # Trend data
    trend_vs_previous_period = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True,
        help_text=_('Percentage change from previous period')
    )

    # By source breakdown
    by_source = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Time-to-hire by candidate source')
    )

    # Target vs actual
    target_time_to_fill = models.PositiveIntegerField(
        null=True, blank=True,
        help_text=_('Target days to fill position')
    )
    positions_within_target = models.PositiveIntegerField(default=0)
    target_achievement_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Time to Hire Metric')
        verbose_name_plural = _('Time to Hire Metrics')
        ordering = ['-period_start']
        indexes = [
            models.Index(fields=['-period_start']),
            models.Index(fields=['department', '-period_start']),
        ]

    def __str__(self):
        return f"Time-to-Hire Metrics ({self.period_start} to {self.period_end})"


class SourceEffectivenessMetric(models.Model):
    """
    Track effectiveness of different candidate sources.
    """

    class SourceType(models.TextChoices):
        CAREER_PAGE = 'career_page', _('Career Page')
        LINKEDIN = 'linkedin', _('LinkedIn')
        INDEED = 'indeed', _('Indeed')
        GLASSDOOR = 'glassdoor', _('Glassdoor')
        REFERRAL = 'referral', _('Employee Referral')
        AGENCY = 'agency', _('Recruitment Agency')
        UNIVERSITY = 'university', _('University/Campus')
        JOB_FAIR = 'job_fair', _('Job Fair')
        SOCIAL_MEDIA = 'social_media', _('Social Media')
        DIRECT = 'direct', _('Direct Application')
        OTHER = 'other', _('Other')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)
    source = models.CharField(max_length=30, choices=SourceType.choices)
    source_detail = models.CharField(
        max_length=200,
        blank=True,
        help_text=_('Specific source detail (e.g., agency name)')
    )

    # Volume metrics
    total_applicants = models.PositiveIntegerField(default=0)
    qualified_applicants = models.PositiveIntegerField(default=0)
    interviewed = models.PositiveIntegerField(default=0)
    offers_extended = models.PositiveIntegerField(default=0)
    hires = models.PositiveIntegerField(default=0)

    # Quality metrics
    qualification_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Percentage of applicants that qualify')
    )
    interview_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    hire_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Percentage of applicants that get hired')
    )

    # Performance of hires from this source
    avg_performance_rating = models.DecimalField(
        max_digits=3, decimal_places=2, null=True, blank=True,
        help_text=_('Average performance rating of hires')
    )
    retention_rate_6_months = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    retention_rate_12_months = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )

    # Time metrics
    avg_time_to_hire = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True
    )

    # Cost metrics
    total_cost = models.DecimalField(
        max_digits=12, decimal_places=2, null=True, blank=True,
        help_text=_('Total cost for this source')
    )
    cost_per_applicant = models.DecimalField(
        max_digits=10, decimal_places=2, null=True, blank=True
    )
    cost_per_hire = models.DecimalField(
        max_digits=10, decimal_places=2, null=True, blank=True
    )

    # ROI calculation
    roi_score = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True,
        help_text=_('Return on investment score')
    )

    # Effectiveness score (composite)
    effectiveness_score = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Composite effectiveness score (0-100)')
    )

    # Job type breakdown
    by_job_type = models.JSONField(default=dict, blank=True)

    # Department breakdown
    by_department = models.JSONField(default=dict, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Source Effectiveness Metric')
        verbose_name_plural = _('Source Effectiveness Metrics')
        ordering = ['-period_start', '-effectiveness_score']
        unique_together = ['period_start', 'period_end', 'source', 'source_detail']
        indexes = [
            models.Index(fields=['-period_start', 'source']),
            models.Index(fields=['source', '-effectiveness_score']),
        ]

    def __str__(self):
        return f"{self.get_source_display()} ({self.period_start})"

    def calculate_effectiveness_score(self):
        """Calculate composite effectiveness score."""
        weights = {
            'hire_rate': 0.25,
            'retention_rate_12_months': 0.25,
            'avg_performance_rating': 0.20,
            'cost_efficiency': 0.15,
            'time_efficiency': 0.15,
        }

        score = 0
        components = 0

        if self.hire_rate is not None:
            score += float(self.hire_rate) * weights['hire_rate']
            components += weights['hire_rate']

        if self.retention_rate_12_months is not None:
            score += float(self.retention_rate_12_months) * weights['retention_rate_12_months']
            components += weights['retention_rate_12_months']

        if self.avg_performance_rating is not None:
            # Normalize to 0-100 scale (assuming 5-point rating)
            normalized = (float(self.avg_performance_rating) / 5) * 100
            score += normalized * weights['avg_performance_rating']
            components += weights['avg_performance_rating']

        if components > 0:
            self.effectiveness_score = Decimal(str(round(score / components, 2)))


class EmployeeRetentionMetric(models.Model):
    """
    Employee retention and turnover analytics.
    """

    class PeriodType(models.TextChoices):
        MONTHLY = 'monthly', _('Monthly')
        QUARTERLY = 'quarterly', _('Quarterly')
        YEARLY = 'yearly', _('Yearly')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    period_type = models.CharField(
        max_length=20,
        choices=PeriodType.choices,
        default=PeriodType.MONTHLY
    )
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Filter dimensions
    department = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=200, blank=True)
    job_level = models.CharField(max_length=50, blank=True)

    # Headcount
    starting_headcount = models.PositiveIntegerField(default=0)
    ending_headcount = models.PositiveIntegerField(default=0)
    average_headcount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    # New hires
    new_hires = models.PositiveIntegerField(default=0)
    new_hire_retention_90_days = models.PositiveIntegerField(
        default=0,
        help_text=_('New hires who stayed past 90 days')
    )

    # Departures
    total_departures = models.PositiveIntegerField(default=0)
    voluntary_departures = models.PositiveIntegerField(default=0)
    involuntary_departures = models.PositiveIntegerField(default=0)
    retirement_departures = models.PositiveIntegerField(default=0)

    # Turnover rates
    overall_turnover_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Total departures / average headcount')
    )
    voluntary_turnover_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    involuntary_turnover_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )

    # Retention rates
    overall_retention_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    new_hire_retention_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('New hire 90-day retention')
    )

    # Tenure breakdown
    departures_under_1_year = models.PositiveIntegerField(default=0)
    departures_1_to_3_years = models.PositiveIntegerField(default=0)
    departures_3_to_5_years = models.PositiveIntegerField(default=0)
    departures_over_5_years = models.PositiveIntegerField(default=0)

    # Departure reasons (JSON)
    departure_reasons = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Breakdown of voluntary departure reasons')
    )

    # High performer retention
    high_performer_departures = models.PositiveIntegerField(default=0)
    high_performer_retention_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )

    # Cost impact
    estimated_turnover_cost = models.DecimalField(
        max_digits=12, decimal_places=2, null=True, blank=True
    )
    cost_per_departure = models.DecimalField(
        max_digits=10, decimal_places=2, null=True, blank=True
    )

    # Average tenure
    avg_tenure_departed = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Average tenure of departed employees (years)')
    )
    avg_tenure_current = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Average tenure of current employees (years)')
    )

    # By department breakdown
    by_department = models.JSONField(default=dict, blank=True)

    # By tenure breakdown
    by_tenure = models.JSONField(default=dict, blank=True)

    # Trend comparison
    trend_vs_previous = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True,
        help_text=_('Change in turnover rate vs previous period')
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Employee Retention Metric')
        verbose_name_plural = _('Employee Retention Metrics')
        ordering = ['-period_start']
        indexes = [
            models.Index(fields=['period_type', '-period_start']),
            models.Index(fields=['department', '-period_start']),
        ]

    def __str__(self):
        return f"Retention Metrics ({self.period_start} to {self.period_end})"

    def calculate_rates(self):
        """Calculate all turnover and retention rates."""
        if self.average_headcount and self.average_headcount > 0:
            avg = float(self.average_headcount)
            self.overall_turnover_rate = Decimal(str(round((self.total_departures / avg) * 100, 2)))
            self.voluntary_turnover_rate = Decimal(str(round((self.voluntary_departures / avg) * 100, 2)))
            self.involuntary_turnover_rate = Decimal(str(round((self.involuntary_departures / avg) * 100, 2)))
            self.overall_retention_rate = Decimal(str(round(100 - float(self.overall_turnover_rate), 2)))

        if self.new_hires and self.new_hires > 0:
            self.new_hire_retention_rate = Decimal(str(round(
                (self.new_hire_retention_90_days / self.new_hires) * 100, 2
            )))


class TimeOffAnalytics(models.Model):
    """
    Time-off and absence analytics.
    """

    class PeriodType(models.TextChoices):
        MONTHLY = 'monthly', _('Monthly')
        QUARTERLY = 'quarterly', _('Quarterly')
        YEARLY = 'yearly', _('Yearly')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    period_type = models.CharField(
        max_length=20,
        choices=PeriodType.choices,
        default=PeriodType.MONTHLY
    )
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Filter dimensions
    department = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=200, blank=True)

    # Total headcount for period
    total_employees = models.PositiveIntegerField(default=0)

    # Time-off totals (in days)
    total_pto_taken = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_sick_leave_taken = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_unpaid_leave_taken = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_other_leave_taken = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    # Request counts
    pto_requests = models.PositiveIntegerField(default=0)
    sick_leave_requests = models.PositiveIntegerField(default=0)
    unpaid_leave_requests = models.PositiveIntegerField(default=0)

    # Approval metrics
    requests_approved = models.PositiveIntegerField(default=0)
    requests_rejected = models.PositiveIntegerField(default=0)
    requests_pending = models.PositiveIntegerField(default=0)
    approval_rate = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    # Averages
    avg_pto_days_per_employee = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    avg_sick_days_per_employee = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )

    # PTO balance metrics
    total_pto_balance_accrued = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_pto_balance_remaining = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    avg_pto_balance_per_employee = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    pto_utilization_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Percentage of accrued PTO used')
    )

    # Absenteeism metrics
    unscheduled_absence_days = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    absenteeism_rate = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Unscheduled absences / total scheduled work days')
    )

    # Peak periods
    peak_absence_day = models.CharField(
        max_length=20,
        blank=True,
        help_text=_('Day of week with highest absences')
    )
    peak_absence_month = models.CharField(
        max_length=20,
        blank=True,
        help_text=_('Month with highest absences')
    )

    # By type breakdown
    by_leave_type = models.JSONField(default=dict, blank=True)

    # By department breakdown
    by_department = models.JSONField(default=dict, blank=True)

    # Day of week distribution
    by_day_of_week = models.JSONField(default=dict, blank=True)

    # Trend comparison
    trend_vs_previous = models.DecimalField(
        max_digits=7, decimal_places=2, null=True, blank=True
    )

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Time Off Analytics')
        verbose_name_plural = _('Time Off Analytics')
        ordering = ['-period_start']
        indexes = [
            models.Index(fields=['period_type', '-period_start']),
            models.Index(fields=['department', '-period_start']),
        ]

    def __str__(self):
        return f"Time-Off Analytics ({self.period_start} to {self.period_end})"


class PerformanceDistribution(models.Model):
    """
    Performance review distribution analytics.
    """

    class PeriodType(models.TextChoices):
        QUARTERLY = 'quarterly', _('Quarterly')
        YEARLY = 'yearly', _('Yearly')

    class ReviewCycle(models.TextChoices):
        Q1 = 'q1', _('Q1 Review')
        Q2 = 'q2', _('Q2 Review')
        Q3 = 'q3', _('Q3 Review')
        Q4 = 'q4', _('Q4 Review')
        MID_YEAR = 'mid_year', _('Mid-Year Review')
        ANNUAL = 'annual', _('Annual Review')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    period_type = models.CharField(
        max_length=20,
        choices=PeriodType.choices,
        default=PeriodType.YEARLY
    )
    review_cycle = models.CharField(
        max_length=20,
        choices=ReviewCycle.choices,
        default=ReviewCycle.ANNUAL
    )
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Filter dimensions
    department = models.CharField(max_length=100, blank=True)
    job_level = models.CharField(max_length=50, blank=True)

    # Total reviewed
    total_employees_reviewed = models.PositiveIntegerField(default=0)
    reviews_completed = models.PositiveIntegerField(default=0)
    reviews_pending = models.PositiveIntegerField(default=0)
    completion_rate = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    # Rating distribution (5-point scale)
    rating_5_count = models.PositiveIntegerField(default=0, help_text=_('Exceptional'))
    rating_4_count = models.PositiveIntegerField(default=0, help_text=_('Exceeds Expectations'))
    rating_3_count = models.PositiveIntegerField(default=0, help_text=_('Meets Expectations'))
    rating_2_count = models.PositiveIntegerField(default=0, help_text=_('Needs Improvement'))
    rating_1_count = models.PositiveIntegerField(default=0, help_text=_('Unsatisfactory'))

    # Percentages
    rating_5_pct = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    rating_4_pct = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    rating_3_pct = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    rating_2_pct = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    rating_1_pct = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    # Average rating
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)
    median_rating = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)

    # Goals metrics
    avg_goals_met_percentage = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True
    )
    employees_meeting_all_goals = models.PositiveIntegerField(default=0)
    employees_meeting_some_goals = models.PositiveIntegerField(default=0)
    employees_missing_goals = models.PositiveIntegerField(default=0)

    # Promotion/PIP recommendations
    promotion_recommendations = models.PositiveIntegerField(default=0)
    pip_recommendations = models.PositiveIntegerField(default=0)
    salary_increase_recommendations = models.PositiveIntegerField(default=0)

    # Competency scores (JSON)
    competency_averages = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Average scores by competency area')
    )

    # By department breakdown
    by_department = models.JSONField(default=dict, blank=True)

    # By level breakdown
    by_level = models.JSONField(default=dict, blank=True)

    # Rating inflation check
    rating_change_from_previous = models.DecimalField(
        max_digits=5, decimal_places=2, null=True, blank=True,
        help_text=_('Average rating change from previous cycle')
    )

    # Calibration metrics
    pre_calibration_avg = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)
    post_calibration_avg = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)
    calibration_adjustment = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Performance Distribution')
        verbose_name_plural = _('Performance Distributions')
        ordering = ['-period_start']
        indexes = [
            models.Index(fields=['review_cycle', '-period_start']),
            models.Index(fields=['department', '-period_start']),
        ]

    def __str__(self):
        return f"Performance Distribution ({self.get_review_cycle_display()}) - {self.period_start}"

    def calculate_percentages(self):
        """Calculate rating distribution percentages."""
        total = self.reviews_completed
        if total == 0:
            return

        self.rating_5_pct = Decimal(str(round((self.rating_5_count / total) * 100, 2)))
        self.rating_4_pct = Decimal(str(round((self.rating_4_count / total) * 100, 2)))
        self.rating_3_pct = Decimal(str(round((self.rating_3_count / total) * 100, 2)))
        self.rating_2_pct = Decimal(str(round((self.rating_2_count / total) * 100, 2)))
        self.rating_1_pct = Decimal(str(round((self.rating_1_count / total) * 100, 2)))

        # Calculate average rating
        total_score = (
            self.rating_5_count * 5 +
            self.rating_4_count * 4 +
            self.rating_3_count * 3 +
            self.rating_2_count * 2 +
            self.rating_1_count * 1
        )
        self.average_rating = Decimal(str(round(total_score / total, 2)))

        # Completion rate
        if self.total_employees_reviewed > 0:
            self.completion_rate = Decimal(str(round(
                (self.reviews_completed / self.total_employees_reviewed) * 100, 2
            )))


# ==================== DASHBOARD CACHE ====================

class DashboardCache(models.Model):
    """
    Cache for pre-computed dashboard data.
    """

    class DashboardType(models.TextChoices):
        RECRUITMENT = 'recruitment', _('Recruitment Dashboard')
        DIVERSITY = 'diversity', _('Diversity Dashboard')
        HR = 'hr', _('HR Dashboard')
        EXECUTIVE = 'executive', _('Executive Summary')
        RETENTION = 'retention', _('Retention Dashboard')
        PERFORMANCE = 'performance', _('Performance Dashboard')

    dashboard_type = models.CharField(
        max_length=30,
        choices=DashboardType.choices,
        primary_key=True
    )
    data = models.JSONField(default=dict)
    filters_applied = models.JSONField(default=dict, blank=True)
    generated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    is_stale = models.BooleanField(default=False)

    class Meta:
        verbose_name = _('Dashboard Cache')
        verbose_name_plural = _('Dashboard Caches')

    def __str__(self):
        return f"{self.get_dashboard_type_display()} Cache"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at


# ==================== ENHANCED MODELS FOR CYCLE 7 ====================

class TenantDashboardMetric(models.Model):
    """
    Enhanced tenant-aware pre-computed dashboard metrics.

    Supports dimensional breakdowns for more flexible analytics.
    """

    class MetricType(models.TextChoices):
        # Recruitment
        TIME_TO_HIRE = 'time_to_hire', _('Time to Hire')
        APPLICANTS_PER_JOB = 'applicants_per_job', _('Applicants per Job')
        OFFER_ACCEPTANCE = 'offer_acceptance', _('Offer Acceptance Rate')
        SOURCE_QUALITY = 'source_quality', _('Source Quality')
        INTERVIEW_COMPLETION = 'interview_completion', _('Interview Completion Rate')

        # HR
        EMPLOYEE_TURNOVER = 'employee_turnover', _('Employee Turnover')
        NEW_HIRE_RETENTION = 'new_hire_retention', _('New Hire Retention')
        HEADCOUNT_GROWTH = 'headcount_growth', _('Headcount Growth')
        ABSENTEEISM = 'absenteeism', _('Absenteeism Rate')

        # Performance
        PERFORMANCE_AVG = 'performance_avg', _('Average Performance')
        GOAL_COMPLETION = 'goal_completion', _('Goal Completion Rate')

        # Financial
        COST_PER_HIRE = 'cost_per_hire', _('Cost per Hire')
        RECRUITMENT_SPEND = 'recruitment_spend', _('Recruitment Spend')

        # Pipeline
        PIPELINE_VELOCITY = 'pipeline_velocity', _('Pipeline Velocity')
        STAGE_CONVERSION = 'stage_conversion', _('Stage Conversion Rate')

    class DimensionType(models.TextChoices):
        NONE = 'none', _('No Dimension (Aggregate)')
        DEPARTMENT = 'department', _('By Department')
        LOCATION = 'location', _('By Location')
        JOB_TYPE = 'job_type', _('By Job Type')
        SOURCE = 'source', _('By Source')
        RECRUITER = 'recruiter', _('By Recruiter')
        EXPERIENCE_LEVEL = 'experience_level', _('By Experience Level')
        TENANT = 'tenant', _('By Tenant')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Tenant isolation
    tenant_id = models.IntegerField(
        null=True, blank=True, db_index=True,
        help_text=_('Tenant ID for multi-tenant isolation')
    )

    # Metric identification
    metric_type = models.CharField(
        max_length=50,
        choices=MetricType.choices,
        db_index=True
    )
    dimension = models.CharField(
        max_length=30,
        choices=DimensionType.choices,
        default=DimensionType.NONE
    )
    dimension_value = models.CharField(
        max_length=200,
        blank=True,
        db_index=True,
        help_text=_('Value of the dimension (e.g., department name)')
    )

    # Value
    value = models.FloatField(help_text=_('Metric value'))

    # Period
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Computation metadata
    computed_at = models.DateTimeField(auto_now=True)
    is_stale = models.BooleanField(
        default=False,
        help_text=_('Whether this metric needs recomputation')
    )

    # Statistical context
    comparison_value = models.FloatField(
        null=True, blank=True,
        help_text=_('Previous period value for comparison')
    )
    change_percentage = models.FloatField(
        null=True, blank=True,
        help_text=_('Percentage change from comparison period')
    )
    benchmark_value = models.FloatField(
        null=True, blank=True,
        help_text=_('Industry benchmark for comparison')
    )

    # Additional context
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = _('Tenant Dashboard Metric')
        verbose_name_plural = _('Tenant Dashboard Metrics')
        unique_together = ['tenant_id', 'metric_type', 'dimension', 'dimension_value', 'period_start']
        ordering = ['-period_start', 'metric_type']
        indexes = [
            models.Index(fields=['tenant_id', 'metric_type', '-period_start']),
            models.Index(fields=['metric_type', 'dimension', '-period_start']),
            models.Index(fields=['computed_at']),
            models.Index(fields=['is_stale']),
        ]

    def __str__(self):
        dim_str = f" ({self.dimension_value})" if self.dimension_value else ""
        return f"{self.get_metric_type_display()}{dim_str}: {self.value} ({self.period_start})"


class RecruitingFunnel(models.Model):
    """
    Funnel analytics by pipeline with enhanced stage tracking.

    Provides detailed conversion metrics and time-in-stage analysis.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Tenant isolation
    tenant_id = models.IntegerField(
        null=True, blank=True, db_index=True
    )

    # Pipeline association
    pipeline = models.ForeignKey(
        'ats.Pipeline',
        on_delete=models.CASCADE,
        null=True, blank=True,
        related_name='funnel_analytics'
    )
    pipeline_name = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('Pipeline name (for display when pipeline deleted)')
    )

    # Period
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Stage data (JSON with flexible structure)
    # Format: {stage_name: {count: int, conversion_rate: float, avg_time_days: float}}
    stages = models.JSONField(
        default=dict,
        help_text=_(
            'Stage metrics. Format: '
            '{"Applied": {"count": 100, "conversion_rate": 0.5, "avg_time_days": 2.3}}'
        )
    )

    # Overall metrics
    overall_conversion = models.FloatField(
        null=True, blank=True,
        help_text=_('First stage to final stage conversion rate')
    )
    total_candidates = models.PositiveIntegerField(default=0)
    total_hires = models.PositiveIntegerField(default=0)

    # Time metrics
    avg_time_in_funnel = models.FloatField(
        null=True, blank=True,
        help_text=_('Average days from entry to exit')
    )
    median_time_in_funnel = models.FloatField(null=True, blank=True)

    # Bottleneck analysis
    bottleneck_stage = models.CharField(
        max_length=100,
        blank=True,
        help_text=_('Stage with lowest conversion rate')
    )
    bottleneck_conversion_rate = models.FloatField(null=True, blank=True)

    # Drop-off analysis
    drop_off_reasons = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Common reasons for candidate drop-off by stage')
    )

    # Comparison with previous period
    previous_period_conversion = models.FloatField(null=True, blank=True)
    conversion_change = models.FloatField(
        null=True, blank=True,
        help_text=_('Change in conversion rate from previous period')
    )

    # Metadata
    computed_at = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = _('Recruiting Funnel')
        verbose_name_plural = _('Recruiting Funnels')
        ordering = ['-period_start']
        indexes = [
            models.Index(fields=['tenant_id', 'pipeline', '-period_start']),
            models.Index(fields=['-period_start']),
        ]

    def __str__(self):
        pipeline_str = self.pipeline_name or (self.pipeline.name if self.pipeline else "All")
        return f"Recruiting Funnel ({pipeline_str}) - {self.period_start}"

    def identify_bottleneck(self):
        """Identify the stage with lowest conversion rate."""
        if not self.stages:
            return

        min_rate = None
        min_stage = None

        for stage_name, stage_data in self.stages.items():
            rate = stage_data.get('conversion_rate')
            if rate is not None and (min_rate is None or rate < min_rate):
                min_rate = rate
                min_stage = stage_name

        if min_stage:
            self.bottleneck_stage = min_stage
            self.bottleneck_conversion_rate = min_rate


class HiringAnalytics(models.Model):
    """
    Aggregated hiring analytics with department and period breakdown.

    Provides comprehensive hiring metrics for dashboards and reporting.
    """

    class PeriodType(models.TextChoices):
        DAILY = 'daily', _('Daily')
        WEEKLY = 'weekly', _('Weekly')
        MONTHLY = 'monthly', _('Monthly')
        QUARTERLY = 'quarterly', _('Quarterly')
        YEARLY = 'yearly', _('Yearly')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Tenant isolation
    tenant_id = models.IntegerField(
        null=True, blank=True, db_index=True
    )

    # Department filter (null for aggregate)
    department = models.ForeignKey(
        'configurations.Department',
        on_delete=models.CASCADE,
        null=True, blank=True,
        related_name='hiring_analytics'
    )
    department_name = models.CharField(max_length=100, blank=True)

    # Period
    period = models.CharField(
        max_length=20,
        choices=PeriodType.choices,
        default=PeriodType.MONTHLY
    )
    period_date = models.DateField(db_index=True)

    # Application metrics
    applications_received = models.PositiveIntegerField(default=0)
    applications_qualified = models.PositiveIntegerField(default=0)
    qualification_rate = models.FloatField(
        null=True, blank=True,
        help_text=_('Percentage of applications that meet basic requirements')
    )

    # Interview metrics
    interviews_scheduled = models.PositiveIntegerField(default=0)
    interviews_completed = models.PositiveIntegerField(default=0)
    interview_completion_rate = models.FloatField(null=True, blank=True)

    # Offer metrics
    offers_made = models.PositiveIntegerField(default=0)
    offers_accepted = models.PositiveIntegerField(default=0)
    offers_declined = models.PositiveIntegerField(default=0)
    offer_acceptance_rate = models.FloatField(null=True, blank=True)

    # Hire metrics
    hires = models.PositiveIntegerField(default=0)

    # Time metrics
    avg_time_to_hire = models.FloatField(
        null=True, blank=True,
        help_text=_('Average days from application to start date')
    )
    avg_time_to_fill = models.FloatField(
        null=True, blank=True,
        help_text=_('Average days from job posting to offer acceptance')
    )
    avg_time_to_first_contact = models.FloatField(
        null=True, blank=True,
        help_text=_('Average days from application to first recruiter contact')
    )

    # Cost metrics
    cost_per_hire = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True, blank=True
    )
    total_recruitment_cost = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True, blank=True
    )

    # Quality metrics
    quality_of_hire_score = models.FloatField(
        null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(5)],
        help_text=_('Average performance rating of new hires after 90 days')
    )
    new_hire_retention_90_day = models.FloatField(
        null=True, blank=True,
        help_text=_('Percentage of new hires remaining after 90 days')
    )

    # Source breakdown
    by_source = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Hiring metrics by candidate source')
    )

    # Job type breakdown
    by_job_type = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Hiring metrics by job type')
    )

    # Comparison
    comparison_period = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Metrics from previous comparable period')
    )

    # Computed at
    computed_at = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = _('Hiring Analytics')
        verbose_name_plural = _('Hiring Analytics')
        ordering = ['-period_date']
        unique_together = ['tenant_id', 'department', 'period', 'period_date']
        indexes = [
            models.Index(fields=['tenant_id', 'department', '-period_date']),
            models.Index(fields=['period', '-period_date']),
        ]

    def __str__(self):
        dept_str = self.department_name or "All Departments"
        return f"Hiring Analytics ({dept_str}) - {self.period_date}"

    def calculate_rates(self):
        """Calculate all rate metrics."""
        # Qualification rate
        if self.applications_received > 0:
            self.qualification_rate = self.applications_qualified / self.applications_received

        # Interview completion rate
        if self.interviews_scheduled > 0:
            self.interview_completion_rate = self.interviews_completed / self.interviews_scheduled

        # Offer acceptance rate
        total_offers_decided = self.offers_accepted + self.offers_declined
        if total_offers_decided > 0:
            self.offer_acceptance_rate = self.offers_accepted / total_offers_decided


class RecruiterPerformanceMetric(models.Model):
    """
    Individual recruiter performance metrics.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Tenant isolation
    tenant_id = models.IntegerField(
        null=True, blank=True, db_index=True
    )

    # Recruiter
    recruiter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='recruiter_performance_metrics',
        null=True, blank=True
    )
    recruiter_name = models.CharField(max_length=200, blank=True)

    # Period
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Activity metrics
    candidates_sourced = models.PositiveIntegerField(default=0)
    candidates_screened = models.PositiveIntegerField(default=0)
    interviews_conducted = models.PositiveIntegerField(default=0)
    offers_extended = models.PositiveIntegerField(default=0)
    hires_made = models.PositiveIntegerField(default=0)

    # Efficiency metrics
    avg_time_to_screen = models.FloatField(
        null=True, blank=True,
        help_text=_('Average days from application to first screen')
    )
    avg_time_to_hire = models.FloatField(null=True, blank=True)
    submissions_to_hire_ratio = models.FloatField(null=True, blank=True)

    # Quality metrics
    candidate_acceptance_rate = models.FloatField(
        null=True, blank=True,
        help_text=_('Rate of candidates who accept offers')
    )
    hiring_manager_satisfaction = models.FloatField(
        null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(5)]
    )
    quality_of_hire = models.FloatField(
        null=True, blank=True,
        help_text=_('Average performance of placed candidates')
    )

    # Pipeline metrics
    active_candidates = models.PositiveIntegerField(default=0)
    open_requisitions = models.PositiveIntegerField(default=0)

    # Comparison
    performance_score = models.FloatField(
        null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text=_('Composite performance score')
    )
    rank = models.PositiveIntegerField(
        null=True, blank=True,
        help_text=_('Rank among all recruiters for this period')
    )

    computed_at = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = _('Recruiter Performance Metric')
        verbose_name_plural = _('Recruiter Performance Metrics')
        ordering = ['-period_start', '-hires_made']
        indexes = [
            models.Index(fields=['tenant_id', 'recruiter', '-period_start']),
            models.Index(fields=['-period_start', '-performance_score']),
        ]

    def __str__(self):
        recruiter_str = self.recruiter_name or (
            self.recruiter.get_full_name() if self.recruiter else "Unknown"
        )
        return f"{recruiter_str} Performance ({self.period_start} - {self.period_end})"

    def calculate_performance_score(self):
        """Calculate composite performance score."""
        score = 0
        weights = {
            'hires': 0.30,
            'time_to_hire': 0.20,
            'acceptance_rate': 0.20,
            'quality': 0.15,
            'satisfaction': 0.15,
        }

        # Hires component (normalized to 100)
        # Assume 10 hires/month is excellent
        hires_score = min(100, (self.hires_made / 10) * 100)
        score += hires_score * weights['hires']

        # Time to hire (lower is better, assume 30 days is baseline)
        if self.avg_time_to_hire:
            time_score = max(0, 100 - (self.avg_time_to_hire - 30) * 2)
            score += time_score * weights['time_to_hire']

        # Acceptance rate
        if self.candidate_acceptance_rate:
            score += self.candidate_acceptance_rate * 100 * weights['acceptance_rate']

        # Quality of hire (5-point scale)
        if self.quality_of_hire:
            score += (self.quality_of_hire / 5) * 100 * weights['quality']

        # Hiring manager satisfaction (5-point scale)
        if self.hiring_manager_satisfaction:
            score += (self.hiring_manager_satisfaction / 5) * 100 * weights['satisfaction']

        self.performance_score = round(score, 2)


# Audit logging
from auditlog.registry import auditlog
auditlog.register(PageView)
auditlog.register(UserAction)
auditlog.register(SearchQuery)
auditlog.register(DashboardMetric)
auditlog.register(RecruitmentMetric)
auditlog.register(DiversityMetric)
auditlog.register(HiringFunnelMetric)
auditlog.register(TenantDashboardMetric)
auditlog.register(RecruitingFunnel)
auditlog.register(HiringAnalytics)
auditlog.register(RecruiterPerformanceMetric)
