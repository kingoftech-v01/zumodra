"""
Analytics Serializers - API Serializers for Analytics Data

This module provides serializers for:
- All analytics metric models
- Dashboard data responses
- Report exports
- Date range filtering
"""

from rest_framework import serializers
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from django.utils import timezone
from datetime import date, timedelta

from ..models import (
    PageView, UserAction, SearchQuery, DashboardMetric,
    RecruitmentMetric, DiversityMetric, HiringFunnelMetric,
    TimeToHireMetric, SourceEffectivenessMetric, EmployeeRetentionMetric,
    TimeOffAnalytics, PerformanceDistribution, DashboardCache
)


# ==================== BASE SERIALIZERS ====================

class DateRangeSerializer(serializers.Serializer):
    """Serializer for date range filtering."""
    start_date = serializers.DateField(required=False)
    end_date = serializers.DateField(required=False)
    period = serializers.ChoiceField(
        choices=['day', 'week', 'month', 'quarter', 'year'],
        default='month',
        required=False
    )

    def validate(self, data):
        start = data.get('start_date')
        end = data.get('end_date')

        if start and end and start > end:
            raise serializers.ValidationError(
                "start_date must be before end_date"
            )

        # Set defaults if not provided
        if not end:
            data['end_date'] = timezone.now().date()

        if not start:
            period = data.get('period', 'month')
            period_days = {
                'day': 1,
                'week': 7,
                'month': 30,
                'quarter': 90,
                'year': 365,
            }
            data['start_date'] = data['end_date'] - timedelta(
                days=period_days.get(period, 30)
            )

        return data


class PeriodInfoSerializer(serializers.Serializer):
    """Serializer for period information in responses."""
    start = serializers.DateField()
    end = serializers.DateField()
    period_type = serializers.CharField(required=False)


# ==================== EXISTING MODEL SERIALIZERS ====================

class PageViewSerializer(serializers.ModelSerializer):
    """Serializer for PageView model."""
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = PageView
        fields = [
            'id', 'user', 'user_email', 'session_key', 'path',
            'referrer', 'ip_address', 'user_agent', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class UserActionSerializer(serializers.ModelSerializer):
    """Serializer for UserAction model."""
    user_email = serializers.EmailField(source='user.email', read_only=True)
    action_display = serializers.CharField(
        source='get_action_type_display',
        read_only=True
    )

    class Meta:
        model = UserAction
        fields = [
            'id', 'user', 'user_email', 'action_type', 'action_display',
            'description', 'content_type', 'object_id', 'metadata', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class SearchQuerySerializer(serializers.ModelSerializer):
    """Serializer for SearchQuery model."""
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = SearchQuery
        fields = [
            'id', 'user', 'user_email', 'query', 'results_count',
            'filters_used', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class DashboardMetricSerializer(serializers.ModelSerializer):
    """Serializer for DashboardMetric model."""
    metric_display = serializers.CharField(
        source='get_metric_type_display',
        read_only=True
    )

    class Meta:
        model = DashboardMetric
        fields = [
            'id', 'metric_type', 'metric_display', 'value',
            'metadata', 'date', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


# ==================== RECRUITMENT ANALYTICS SERIALIZERS ====================

class RecruitmentMetricSerializer(serializers.ModelSerializer):
    """Serializer for RecruitmentMetric model."""
    period_type_display = serializers.CharField(
        source='get_period_type_display',
        read_only=True
    )

    class Meta:
        model = RecruitmentMetric
        fields = [
            'uuid', 'period_type', 'period_type_display',
            'period_start', 'period_end',
            # Job metrics
            'open_positions', 'new_positions', 'closed_positions',
            'filled_positions', 'cancelled_positions',
            # Application metrics
            'total_applications', 'new_applications', 'applications_in_review',
            'applications_shortlisted', 'applications_rejected', 'applications_withdrawn',
            # Interview metrics
            'interviews_scheduled', 'interviews_completed',
            'interviews_cancelled', 'interviews_no_show',
            # Offer metrics
            'offers_extended', 'offers_accepted', 'offers_declined', 'offers_expired',
            # Hires
            'total_hires',
            # Rates
            'application_to_interview_rate', 'interview_to_offer_rate',
            'offer_acceptance_rate', 'overall_conversion_rate',
            # Time metrics
            'avg_time_to_fill', 'avg_time_to_hire',
            # Cost metrics
            'total_recruitment_cost', 'cost_per_hire', 'cost_per_application',
            # Breakdowns
            'by_department', 'by_location', 'by_job_type',
            # Metadata
            'metadata', 'created_at', 'updated_at'
        ]
        read_only_fields = ['uuid', 'created_at', 'updated_at']


class RecruitmentMetricSummarySerializer(serializers.Serializer):
    """Summary serializer for recruitment metrics dashboard."""
    open_positions = serializers.IntegerField()
    total_applications = serializers.IntegerField()
    hires = serializers.IntegerField()
    avg_time_to_hire = serializers.DecimalField(
        max_digits=7, decimal_places=2, allow_null=True
    )
    offer_acceptance_rate = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )
    overall_conversion_rate = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )


# ==================== DIVERSITY ANALYTICS SERIALIZERS ====================

class DiversityMetricSerializer(serializers.ModelSerializer):
    """Serializer for DiversityMetric model."""
    period_type_display = serializers.CharField(
        source='get_period_type_display',
        read_only=True
    )
    scope_display = serializers.CharField(
        source='get_scope_display',
        read_only=True
    )
    suppressed_fields = serializers.SerializerMethodField()

    class Meta:
        model = DiversityMetric
        fields = [
            'uuid', 'period_type', 'period_type_display',
            'period_start', 'period_end', 'scope', 'scope_display',
            'total_count',
            # Gender
            'gender_male_count', 'gender_female_count',
            'gender_nonbinary_count', 'gender_not_disclosed_count',
            # Ethnicity
            'ethnicity_white_count', 'ethnicity_black_count',
            'ethnicity_hispanic_count', 'ethnicity_asian_count',
            'ethnicity_native_american_count', 'ethnicity_pacific_islander_count',
            'ethnicity_two_or_more_count', 'ethnicity_not_disclosed_count',
            # Age
            'age_under_25_count', 'age_25_34_count', 'age_35_44_count',
            'age_45_54_count', 'age_55_64_count', 'age_65_plus_count',
            'age_not_disclosed_count',
            # Veteran/Disability
            'veteran_count', 'non_veteran_count', 'veteran_not_disclosed_count',
            'disability_yes_count', 'disability_no_count', 'disability_not_disclosed_count',
            # Breakdowns
            'by_department', 'by_level',
            # Percentages
            'gender_percentages', 'ethnicity_percentages', 'age_percentages',
            # Benchmarks
            'industry_benchmark',
            # Anonymization
            'min_category_size', 'suppressed_fields',
            # Metadata
            'metadata', 'generated_at', 'updated_at'
        ]
        read_only_fields = ['uuid', 'generated_at', 'updated_at']

    def get_suppressed_fields(self, obj):
        """Get list of fields suppressed for anonymization."""
        return obj.anonymize_small_categories()


class AnonymizedDiversitySerializer(serializers.Serializer):
    """
    Serializer for anonymized diversity data.
    Replaces small counts with 'suppressed' for privacy.
    """
    gender = serializers.DictField()
    ethnicity = serializers.DictField()
    age = serializers.DictField()
    by_department = serializers.DictField()
    scope = serializers.CharField()
    period = PeriodInfoSerializer()
    anonymization_threshold = serializers.IntegerField()


# ==================== HIRING FUNNEL SERIALIZERS ====================

class HiringFunnelMetricSerializer(serializers.ModelSerializer):
    """Serializer for HiringFunnelMetric model."""
    job_title = serializers.CharField(source='job.title', read_only=True)

    class Meta:
        model = HiringFunnelMetric
        fields = [
            'uuid', 'period_start', 'period_end',
            'job', 'job_title', 'department', 'job_type',
            # Stage counts
            'stage_applied', 'stage_screening', 'stage_phone_interview',
            'stage_technical_assessment', 'stage_onsite_interview',
            'stage_reference_check', 'stage_offer', 'stage_hired',
            # Drop-offs
            'dropped_at_screening', 'dropped_at_phone', 'dropped_at_technical',
            'dropped_at_onsite', 'dropped_at_reference', 'dropped_at_offer',
            # Conversion rates
            'rate_applied_to_screening', 'rate_screening_to_phone',
            'rate_phone_to_technical', 'rate_technical_to_onsite',
            'rate_onsite_to_reference', 'rate_reference_to_offer',
            'rate_offer_to_hired',
            # Overall metrics
            'overall_conversion_rate', 'avg_days_in_funnel',
            # Time per stage
            'avg_days_screening', 'avg_days_phone', 'avg_days_technical',
            'avg_days_onsite', 'avg_days_reference', 'avg_days_offer',
            # Bottleneck
            'bottleneck_stage', 'bottleneck_rate',
            # Details
            'stage_details', 'comparison_period',
            # Metadata
            'metadata', 'created_at'
        ]
        read_only_fields = ['uuid', 'created_at']


class FunnelStageSerializer(serializers.Serializer):
    """Serializer for a single funnel stage (for charts)."""
    stage = serializers.CharField()
    count = serializers.IntegerField()
    conversion_rate = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )
    avg_days = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )


# ==================== TIME TO HIRE SERIALIZERS ====================

class TimeToHireMetricSerializer(serializers.ModelSerializer):
    """Serializer for TimeToHireMetric model."""

    class Meta:
        model = TimeToHireMetric
        fields = [
            'uuid', 'period_start', 'period_end',
            'department', 'job_type', 'experience_level', 'location',
            # Time-to-fill
            'total_positions_filled', 'avg_time_to_fill',
            'median_time_to_fill', 'min_time_to_fill', 'max_time_to_fill',
            # Time-to-hire
            'total_hires', 'avg_time_to_hire', 'median_time_to_hire',
            'min_time_to_hire', 'max_time_to_hire',
            # Stage times
            'avg_time_in_screening', 'avg_time_in_interview',
            'avg_time_in_assessment', 'avg_time_in_offer',
            # Other times
            'avg_time_to_first_contact', 'avg_time_to_decision',
            # Distribution
            'time_distribution',
            # Trend
            'trend_vs_previous_period',
            # By source
            'by_source',
            # Target
            'target_time_to_fill', 'positions_within_target',
            'target_achievement_rate',
            # Metadata
            'metadata', 'created_at'
        ]
        read_only_fields = ['uuid', 'created_at']


class TimeToHireSummarySerializer(serializers.Serializer):
    """Summary serializer for time-to-hire dashboard."""
    avg_days = serializers.DecimalField(
        max_digits=7, decimal_places=2, allow_null=True
    )
    median_days = serializers.DecimalField(
        max_digits=7, decimal_places=2, allow_null=True
    )
    min_days = serializers.IntegerField(allow_null=True)
    max_days = serializers.IntegerField(allow_null=True)
    total_hires = serializers.IntegerField()
    trend = serializers.DecimalField(
        max_digits=7, decimal_places=2, allow_null=True
    )


# ==================== SOURCE EFFECTIVENESS SERIALIZERS ====================

class SourceEffectivenessMetricSerializer(serializers.ModelSerializer):
    """Serializer for SourceEffectivenessMetric model."""
    source_display = serializers.CharField(
        source='get_source_display',
        read_only=True
    )

    class Meta:
        model = SourceEffectivenessMetric
        fields = [
            'uuid', 'period_start', 'period_end',
            'source', 'source_display', 'source_detail',
            # Volume
            'total_applicants', 'qualified_applicants',
            'interviewed', 'offers_extended', 'hires',
            # Quality
            'qualification_rate', 'interview_rate', 'hire_rate',
            # Performance
            'avg_performance_rating', 'retention_rate_6_months',
            'retention_rate_12_months',
            # Time
            'avg_time_to_hire',
            # Cost
            'total_cost', 'cost_per_applicant', 'cost_per_hire',
            # ROI
            'roi_score', 'effectiveness_score',
            # Breakdowns
            'by_job_type', 'by_department',
            # Metadata
            'metadata', 'created_at'
        ]
        read_only_fields = ['uuid', 'created_at']


class SourceComparisonSerializer(serializers.Serializer):
    """Serializer for comparing source effectiveness."""
    source = serializers.CharField()
    applicants = serializers.IntegerField()
    hires = serializers.IntegerField()
    hire_rate = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )
    cost_per_hire = serializers.DecimalField(
        max_digits=10, decimal_places=2, allow_null=True
    )
    effectiveness_score = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )


# ==================== RETENTION SERIALIZERS ====================

class EmployeeRetentionMetricSerializer(serializers.ModelSerializer):
    """Serializer for EmployeeRetentionMetric model."""
    period_type_display = serializers.CharField(
        source='get_period_type_display',
        read_only=True
    )

    class Meta:
        model = EmployeeRetentionMetric
        fields = [
            'uuid', 'period_type', 'period_type_display',
            'period_start', 'period_end',
            'department', 'location', 'job_level',
            # Headcount
            'starting_headcount', 'ending_headcount', 'average_headcount',
            # New hires
            'new_hires', 'new_hire_retention_90_days',
            # Departures
            'total_departures', 'voluntary_departures',
            'involuntary_departures', 'retirement_departures',
            # Turnover rates
            'overall_turnover_rate', 'voluntary_turnover_rate',
            'involuntary_turnover_rate',
            # Retention rates
            'overall_retention_rate', 'new_hire_retention_rate',
            # Tenure breakdown
            'departures_under_1_year', 'departures_1_to_3_years',
            'departures_3_to_5_years', 'departures_over_5_years',
            # Reasons
            'departure_reasons',
            # High performers
            'high_performer_departures', 'high_performer_retention_rate',
            # Cost
            'estimated_turnover_cost', 'cost_per_departure',
            # Tenure
            'avg_tenure_departed', 'avg_tenure_current',
            # Breakdowns
            'by_department', 'by_tenure',
            # Trend
            'trend_vs_previous',
            # Metadata
            'metadata', 'created_at'
        ]
        read_only_fields = ['uuid', 'created_at']


class RetentionSummarySerializer(serializers.Serializer):
    """Summary serializer for retention dashboard."""
    current_headcount = serializers.IntegerField()
    turnover_rate = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )
    retention_rate = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )
    total_departures = serializers.IntegerField()
    voluntary_departures = serializers.IntegerField()
    new_hire_retention_rate = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )


# ==================== TIME OFF SERIALIZERS ====================

class TimeOffAnalyticsSerializer(serializers.ModelSerializer):
    """Serializer for TimeOffAnalytics model."""
    period_type_display = serializers.CharField(
        source='get_period_type_display',
        read_only=True
    )

    class Meta:
        model = TimeOffAnalytics
        fields = [
            'uuid', 'period_type', 'period_type_display',
            'period_start', 'period_end',
            'department', 'location',
            'total_employees',
            # Totals
            'total_pto_taken', 'total_sick_leave_taken',
            'total_unpaid_leave_taken', 'total_other_leave_taken',
            # Requests
            'pto_requests', 'sick_leave_requests', 'unpaid_leave_requests',
            # Approvals
            'requests_approved', 'requests_rejected', 'requests_pending',
            'approval_rate',
            # Averages
            'avg_pto_days_per_employee', 'avg_sick_days_per_employee',
            # Balances
            'total_pto_balance_accrued', 'total_pto_balance_remaining',
            'avg_pto_balance_per_employee', 'pto_utilization_rate',
            # Absenteeism
            'unscheduled_absence_days', 'absenteeism_rate',
            # Peak periods
            'peak_absence_day', 'peak_absence_month',
            # Breakdowns
            'by_leave_type', 'by_department', 'by_day_of_week',
            # Trend
            'trend_vs_previous',
            # Metadata
            'metadata', 'created_at'
        ]
        read_only_fields = ['uuid', 'created_at']


# ==================== PERFORMANCE SERIALIZERS ====================

class PerformanceDistributionSerializer(serializers.ModelSerializer):
    """Serializer for PerformanceDistribution model."""
    period_type_display = serializers.CharField(
        source='get_period_type_display',
        read_only=True
    )
    review_cycle_display = serializers.CharField(
        source='get_review_cycle_display',
        read_only=True
    )

    class Meta:
        model = PerformanceDistribution
        fields = [
            'uuid', 'period_type', 'period_type_display',
            'review_cycle', 'review_cycle_display',
            'period_start', 'period_end',
            'department', 'job_level',
            # Totals
            'total_employees_reviewed', 'reviews_completed',
            'reviews_pending', 'completion_rate',
            # Rating counts
            'rating_5_count', 'rating_4_count', 'rating_3_count',
            'rating_2_count', 'rating_1_count',
            # Rating percentages
            'rating_5_pct', 'rating_4_pct', 'rating_3_pct',
            'rating_2_pct', 'rating_1_pct',
            # Averages
            'average_rating', 'median_rating',
            # Goals
            'avg_goals_met_percentage', 'employees_meeting_all_goals',
            'employees_meeting_some_goals', 'employees_missing_goals',
            # Recommendations
            'promotion_recommendations', 'pip_recommendations',
            'salary_increase_recommendations',
            # Competencies
            'competency_averages',
            # Breakdowns
            'by_department', 'by_level',
            # Changes
            'rating_change_from_previous',
            # Calibration
            'pre_calibration_avg', 'post_calibration_avg',
            'calibration_adjustment',
            # Metadata
            'metadata', 'created_at'
        ]
        read_only_fields = ['uuid', 'created_at']


class RatingDistributionSerializer(serializers.Serializer):
    """Serializer for rating distribution chart data."""
    rating = serializers.IntegerField()
    label = serializers.CharField()
    count = serializers.IntegerField()
    percentage = serializers.DecimalField(
        max_digits=5, decimal_places=2, allow_null=True
    )


# ==================== DASHBOARD SERIALIZERS ====================

class DashboardCacheSerializer(serializers.ModelSerializer):
    """Serializer for DashboardCache model."""
    dashboard_type_display = serializers.CharField(
        source='get_dashboard_type_display',
        read_only=True
    )
    is_expired = serializers.BooleanField(read_only=True)

    class Meta:
        model = DashboardCache
        fields = [
            'dashboard_type', 'dashboard_type_display',
            'data', 'filters_applied',
            'generated_at', 'expires_at', 'is_stale', 'is_expired'
        ]
        read_only_fields = ['dashboard_type', 'generated_at']


class RecruitmentDashboardSerializer(serializers.Serializer):
    """Serializer for recruitment dashboard response."""
    job_metrics = serializers.DictField()
    application_metrics = serializers.DictField()
    interview_metrics = serializers.DictField()
    offer_metrics = serializers.DictField()
    conversion_rates = serializers.DictField()
    time_to_hire = TimeToHireSummarySerializer()
    period = PeriodInfoSerializer()
    comparison = serializers.DictField(required=False)


class HRDashboardSerializer(serializers.Serializer):
    """Serializer for HR dashboard response."""
    headcount = serializers.DictField()
    retention = serializers.DictField()
    time_off = serializers.DictField()
    performance = serializers.DictField()
    period = PeriodInfoSerializer()
    comparison = serializers.DictField(required=False)


class ExecutiveSummarySerializer(serializers.Serializer):
    """Serializer for executive summary response."""
    summary = serializers.DictField()
    charts = serializers.DictField()
    period = PeriodInfoSerializer()


class TrendDataPointSerializer(serializers.Serializer):
    """Serializer for trend chart data points."""
    date = serializers.DateField()
    value = serializers.DecimalField(max_digits=15, decimal_places=2)
    label = serializers.CharField(required=False)


class ChartDataSerializer(serializers.Serializer):
    """Generic serializer for chart data."""
    labels = serializers.ListField(child=serializers.CharField())
    datasets = serializers.ListField(child=serializers.DictField())
    options = serializers.DictField(required=False)


# ==================== EXPORT SERIALIZERS ====================

class ExportRequestSerializer(serializers.Serializer):
    """Serializer for export requests."""
    format = serializers.ChoiceField(
        choices=['pdf', 'excel', 'csv'],
        default='excel'
    )
    dashboard_type = serializers.ChoiceField(
        choices=['recruitment', 'diversity', 'hr', 'executive', 'all'],
        default='all'
    )
    start_date = serializers.DateField(required=False)
    end_date = serializers.DateField(required=False)
    include_charts = serializers.BooleanField(default=True)
    include_comparison = serializers.BooleanField(default=True)


class ExportResponseSerializer(serializers.Serializer):
    """Serializer for export response."""
    file_url = serializers.URLField()
    file_name = serializers.CharField()
    file_size = serializers.IntegerField()
    format = serializers.CharField()
    generated_at = serializers.DateTimeField()
    expires_at = serializers.DateTimeField()


# ==================== CYCLE 7 ADDITIONS ====================
# Dashboard and chart-ready serializers for frontend consumption

class DashboardMetricDisplaySerializer(serializers.Serializer):
    """
    Dashboard metric display serializer for UI cards.
    Provides formatted data for dashboard widgets.
    """
    metric_name = serializers.CharField(
        help_text="Human-readable metric name"
    )
    metric_key = serializers.CharField(
        help_text="Unique identifier for the metric"
    )
    value = serializers.DecimalField(
        max_digits=15, decimal_places=2,
        help_text="Current metric value"
    )
    formatted_value = serializers.CharField(
        help_text="Formatted value for display (e.g., '$1,234' or '56%')"
    )
    previous_value = serializers.DecimalField(
        max_digits=15, decimal_places=2,
        allow_null=True, required=False,
        help_text="Previous period value for comparison"
    )
    change_percentage = serializers.DecimalField(
        max_digits=7, decimal_places=2,
        allow_null=True, required=False,
        help_text="Percentage change from previous period"
    )
    change_direction = serializers.ChoiceField(
        choices=['up', 'down', 'flat'],
        required=False,
        help_text="Direction of change"
    )
    is_positive_change = serializers.BooleanField(
        required=False,
        help_text="Whether the change direction is positive for this metric"
    )
    unit = serializers.CharField(
        required=False, allow_blank=True,
        help_text="Unit of measurement (e.g., 'days', '$', '%')"
    )
    target = serializers.DecimalField(
        max_digits=15, decimal_places=2,
        allow_null=True, required=False,
        help_text="Target value if set"
    )
    target_achievement = serializers.DecimalField(
        max_digits=5, decimal_places=2,
        allow_null=True, required=False,
        help_text="Percentage of target achieved"
    )
    icon = serializers.CharField(
        required=False,
        help_text="Icon identifier for UI"
    )
    color = serializers.CharField(
        required=False,
        help_text="Color code for UI"
    )


class TimeToHireDetailSerializer(serializers.Serializer):
    """
    Detailed time to hire metrics with breakdown.
    """
    average_days = serializers.FloatField(
        help_text="Average days from application to hire"
    )
    median_days = serializers.FloatField(
        help_text="Median days from application to hire"
    )
    min_days = serializers.IntegerField(
        allow_null=True,
        help_text="Minimum days to hire"
    )
    max_days = serializers.IntegerField(
        allow_null=True,
        help_text="Maximum days to hire"
    )
    by_department = serializers.DictField(
        help_text="Time to hire broken down by department"
    )
    by_job_level = serializers.DictField(
        required=False,
        help_text="Time to hire broken down by job level"
    )
    by_source = serializers.DictField(
        required=False,
        help_text="Time to hire broken down by candidate source"
    )
    trend = serializers.ListField(
        child=serializers.DictField(),
        help_text="Historical trend data points"
    )
    stage_breakdown = serializers.DictField(
        required=False,
        help_text="Average time spent in each hiring stage"
    )
    target_days = serializers.IntegerField(
        allow_null=True, required=False,
        help_text="Target days to hire"
    )
    positions_within_target = serializers.IntegerField(
        required=False,
        help_text="Number of positions filled within target"
    )
    target_achievement_rate = serializers.DecimalField(
        max_digits=5, decimal_places=2,
        allow_null=True, required=False,
        help_text="Percentage of positions filled within target"
    )


class SourceEffectivenessDetailSerializer(serializers.Serializer):
    """
    Detailed source effectiveness metrics.
    """
    sources = serializers.ListField(
        child=serializers.DictField(),
        help_text="List of source performance data"
    )
    best_performers = serializers.ListField(
        child=serializers.DictField(),
        help_text="Top performing sources"
    )
    worst_performers = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        help_text="Underperforming sources"
    )
    roi_by_source = serializers.DictField(
        help_text="Return on investment by source"
    )
    cost_per_hire_by_source = serializers.DictField(
        required=False,
        help_text="Cost per hire broken down by source"
    )
    quality_metrics = serializers.DictField(
        required=False,
        help_text="Hire quality metrics by source"
    )
    recommendations = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Recommendations for source optimization"
    )


class RecruitingFunnelDetailSerializer(serializers.Serializer):
    """
    Detailed recruiting funnel data for visualization.
    """
    stages = serializers.ListField(
        child=serializers.DictField(),
        help_text="Funnel stages with counts and rates"
    )
    conversion_rates = serializers.DictField(
        help_text="Stage-to-stage conversion rates"
    )
    drop_off_points = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        help_text="Where candidates are dropping off"
    )
    bottlenecks = serializers.ListField(
        child=serializers.DictField(),
        help_text="Identified bottleneck stages"
    )
    average_time_in_stage = serializers.DictField(
        required=False,
        help_text="Average time candidates spend in each stage"
    )
    comparison_with_benchmark = serializers.DictField(
        required=False,
        help_text="Comparison with industry benchmarks"
    )
    trend_by_stage = serializers.DictField(
        required=False,
        help_text="Historical trend for each stage"
    )
    improvement_suggestions = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Suggestions to improve funnel performance"
    )


class TrendDataSerializer(serializers.Serializer):
    """
    Trend data serializer for chart.js compatible output.
    """
    labels = serializers.ListField(
        child=serializers.CharField(),
        help_text="X-axis labels (dates/periods)"
    )
    datasets = serializers.ListField(
        child=serializers.DictField(),
        help_text="Chart.js compatible dataset objects"
    )
    options = serializers.DictField(
        required=False,
        help_text="Chart configuration options"
    )
    period_type = serializers.ChoiceField(
        choices=['day', 'week', 'month', 'quarter', 'year'],
        required=False,
        help_text="Granularity of trend data"
    )
    annotations = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        help_text="Chart annotations (e.g., target lines)"
    )


class ReportSerializer(serializers.Serializer):
    """
    Report metadata serializer.
    """
    id = serializers.UUIDField(
        help_text="Unique report identifier"
    )
    name = serializers.CharField(
        help_text="Report name"
    )
    description = serializers.CharField(
        required=False, allow_blank=True,
        help_text="Report description"
    )
    report_type = serializers.ChoiceField(
        choices=[
            'recruitment', 'diversity', 'hr', 'executive',
            'time_to_hire', 'source_effectiveness', 'funnel',
            'retention', 'performance', 'custom'
        ],
        help_text="Type of report"
    )
    created_by = serializers.CharField(
        required=False,
        help_text="User who created the report"
    )
    created_at = serializers.DateTimeField(
        help_text="When the report was created"
    )
    schedule = serializers.DictField(
        required=False,
        help_text="Report schedule configuration"
    )
    filters = serializers.DictField(
        required=False,
        help_text="Applied filters"
    )
    last_generated = serializers.DateTimeField(
        required=False, allow_null=True,
        help_text="Last generation timestamp"
    )
    recipients = serializers.ListField(
        child=serializers.EmailField(),
        required=False,
        help_text="Email recipients for scheduled reports"
    )


class ReportListSerializer(serializers.Serializer):
    """
    List of available reports.
    """
    reports = serializers.ListField(
        child=ReportSerializer()
    )
    total_count = serializers.IntegerField()
    page = serializers.IntegerField(required=False)
    page_size = serializers.IntegerField(required=False)


class ReportGenerationRequestSerializer(serializers.Serializer):
    """
    Request serializer for generating a report.
    """
    report_type = serializers.ChoiceField(
        choices=[
            'recruitment', 'diversity', 'hr', 'executive',
            'time_to_hire', 'source_effectiveness', 'funnel',
            'retention', 'performance', 'custom'
        ],
        help_text="Type of report to generate"
    )
    format = serializers.ChoiceField(
        choices=['pdf', 'excel', 'csv', 'json'],
        default='pdf',
        help_text="Output format"
    )
    start_date = serializers.DateField(
        required=False,
        help_text="Report start date"
    )
    end_date = serializers.DateField(
        required=False,
        help_text="Report end date"
    )
    filters = serializers.DictField(
        required=False,
        help_text="Additional filters to apply"
    )
    include_charts = serializers.BooleanField(
        default=True,
        help_text="Include charts in PDF reports"
    )
    include_comparison = serializers.BooleanField(
        default=True,
        help_text="Include comparison with previous period"
    )
    include_recommendations = serializers.BooleanField(
        default=False,
        help_text="Include AI-generated recommendations"
    )
    recipients = serializers.ListField(
        child=serializers.EmailField(),
        required=False,
        help_text="Email recipients for the report"
    )


class ReportExportResultSerializer(serializers.Serializer):
    """
    Result of report export operation.
    """
    report_id = serializers.UUIDField(
        help_text="Generated report ID"
    )
    file_url = serializers.URLField(
        required=False,
        help_text="Download URL for the report"
    )
    file_name = serializers.CharField(
        help_text="Generated file name"
    )
    file_size = serializers.IntegerField(
        help_text="File size in bytes"
    )
    format = serializers.CharField(
        help_text="File format"
    )
    generated_at = serializers.DateTimeField(
        help_text="Generation timestamp"
    )
    expires_at = serializers.DateTimeField(
        help_text="URL expiration timestamp"
    )
    pages = serializers.IntegerField(
        required=False,
        help_text="Number of pages (for PDF)"
    )
    status = serializers.ChoiceField(
        choices=['pending', 'processing', 'completed', 'failed'],
        help_text="Report generation status"
    )
    error_message = serializers.CharField(
        required=False, allow_blank=True,
        help_text="Error message if generation failed"
    )


class DashboardSummarySerializer(serializers.Serializer):
    """
    Complete dashboard summary with all widget data.
    """
    metrics = serializers.ListField(
        child=DashboardMetricDisplaySerializer(),
        help_text="Key metrics for dashboard cards"
    )
    charts = serializers.DictField(
        help_text="Chart data for dashboard visualizations"
    )
    recent_activity = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        help_text="Recent activity feed"
    )
    alerts = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        help_text="System alerts and notifications"
    )
    period = PeriodInfoSerializer(
        help_text="Current reporting period"
    )
    last_updated = serializers.DateTimeField(
        help_text="Last data refresh timestamp"
    )
    comparison_period = PeriodInfoSerializer(
        required=False,
        help_text="Comparison period info"
    )
