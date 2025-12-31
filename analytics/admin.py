"""
Analytics Admin Configuration

Admin interfaces for analytics models including:
- Recruitment metrics
- Diversity metrics
- Hiring funnel metrics
- Time-to-hire metrics
- Source effectiveness
- Employee retention
- Time-off analytics
- Performance distribution
"""

from django.contrib import admin
from django.utils.html import format_html
from .models import (
    PageView, UserAction, SearchQuery, DashboardMetric,
    RecruitmentMetric, DiversityMetric, HiringFunnelMetric,
    TimeToHireMetric, SourceEffectivenessMetric, EmployeeRetentionMetric,
    TimeOffAnalytics, PerformanceDistribution, DashboardCache
)


# ==================== EXISTING ADMIN CLASSES ====================

@admin.register(PageView)
class PageViewAdmin(admin.ModelAdmin):
    list_display = ['path', 'user', 'ip_address', 'timestamp']
    list_filter = ['timestamp']
    search_fields = ['path', 'user__email', 'ip_address']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(UserAction)
class UserActionAdmin(admin.ModelAdmin):
    list_display = ['user', 'action_type', 'description', 'timestamp']
    list_filter = ['action_type', 'timestamp']
    search_fields = ['user__email', 'description']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(SearchQuery)
class SearchQueryAdmin(admin.ModelAdmin):
    list_display = ['query', 'user', 'results_count', 'timestamp']
    list_filter = ['timestamp', 'results_count']
    search_fields = ['query', 'user__email']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(DashboardMetric)
class DashboardMetricAdmin(admin.ModelAdmin):
    list_display = ['metric_type', 'value', 'date', 'created_at']
    list_filter = ['metric_type', 'date']
    search_fields = ['metric_type']
    readonly_fields = ['created_at']
    date_hierarchy = 'date'


# ==================== RECRUITMENT ANALYTICS ADMIN ====================

@admin.register(RecruitmentMetric)
class RecruitmentMetricAdmin(admin.ModelAdmin):
    list_display = [
        'period_type', 'period_start', 'period_end',
        'open_positions', 'total_applications', 'total_hires',
        'offer_acceptance_rate_display', 'created_at'
    ]
    list_filter = ['period_type', 'period_start']
    search_fields = ['uuid']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    date_hierarchy = 'period_start'

    fieldsets = (
        ('Period', {
            'fields': ('uuid', 'period_type', 'period_start', 'period_end')
        }),
        ('Job Metrics', {
            'fields': (
                'open_positions', 'new_positions', 'closed_positions',
                'filled_positions', 'cancelled_positions'
            )
        }),
        ('Application Metrics', {
            'fields': (
                'total_applications', 'new_applications', 'applications_in_review',
                'applications_shortlisted', 'applications_rejected', 'applications_withdrawn'
            )
        }),
        ('Interview Metrics', {
            'fields': (
                'interviews_scheduled', 'interviews_completed',
                'interviews_cancelled', 'interviews_no_show'
            )
        }),
        ('Offer Metrics', {
            'fields': (
                'offers_extended', 'offers_accepted',
                'offers_declined', 'offers_expired', 'total_hires'
            )
        }),
        ('Conversion Rates', {
            'fields': (
                'application_to_interview_rate', 'interview_to_offer_rate',
                'offer_acceptance_rate', 'overall_conversion_rate'
            )
        }),
        ('Time Metrics', {
            'fields': ('avg_time_to_fill', 'avg_time_to_hire')
        }),
        ('Cost Metrics', {
            'fields': ('total_recruitment_cost', 'cost_per_hire', 'cost_per_application'),
            'classes': ('collapse',)
        }),
        ('Breakdowns', {
            'fields': ('by_department', 'by_location', 'by_job_type'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def offer_acceptance_rate_display(self, obj):
        if obj.offer_acceptance_rate:
            return f"{obj.offer_acceptance_rate}%"
        return "-"
    offer_acceptance_rate_display.short_description = "Offer Acceptance Rate"


@admin.register(DiversityMetric)
class DiversityMetricAdmin(admin.ModelAdmin):
    list_display = [
        'scope', 'period_type', 'period_start', 'total_count',
        'generated_at'
    ]
    list_filter = ['scope', 'period_type', 'period_start']
    search_fields = ['uuid']
    readonly_fields = [
        'uuid', 'generated_at', 'updated_at',
        'gender_percentages', 'ethnicity_percentages', 'age_percentages'
    ]
    date_hierarchy = 'period_start'

    fieldsets = (
        ('Period & Scope', {
            'fields': ('uuid', 'period_type', 'period_start', 'period_end', 'scope', 'total_count')
        }),
        ('Gender Distribution', {
            'fields': (
                'gender_male_count', 'gender_female_count',
                'gender_nonbinary_count', 'gender_not_disclosed_count',
                'gender_percentages'
            )
        }),
        ('Ethnicity Distribution', {
            'fields': (
                'ethnicity_white_count', 'ethnicity_black_count',
                'ethnicity_hispanic_count', 'ethnicity_asian_count',
                'ethnicity_native_american_count', 'ethnicity_pacific_islander_count',
                'ethnicity_two_or_more_count', 'ethnicity_not_disclosed_count',
                'ethnicity_percentages'
            )
        }),
        ('Age Distribution', {
            'fields': (
                'age_under_25_count', 'age_25_34_count', 'age_35_44_count',
                'age_45_54_count', 'age_55_64_count', 'age_65_plus_count',
                'age_not_disclosed_count', 'age_percentages'
            )
        }),
        ('Veteran & Disability', {
            'fields': (
                'veteran_count', 'non_veteran_count', 'veteran_not_disclosed_count',
                'disability_yes_count', 'disability_no_count', 'disability_not_disclosed_count'
            ),
            'classes': ('collapse',)
        }),
        ('Breakdowns & Benchmarks', {
            'fields': ('by_department', 'by_level', 'industry_benchmark'),
            'classes': ('collapse',)
        }),
        ('Anonymization', {
            'fields': ('min_category_size',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata', 'generated_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(HiringFunnelMetric)
class HiringFunnelMetricAdmin(admin.ModelAdmin):
    list_display = [
        'period_start', 'period_end', 'job',
        'stage_applied', 'stage_hired',
        'overall_conversion_rate_display', 'bottleneck_stage'
    ]
    list_filter = ['period_start', 'department', 'job_type']
    search_fields = ['uuid', 'job__title', 'department']
    readonly_fields = ['uuid', 'created_at']
    date_hierarchy = 'period_start'
    raw_id_fields = ['job']

    fieldsets = (
        ('Period & Filters', {
            'fields': ('uuid', 'period_start', 'period_end', 'job', 'department', 'job_type')
        }),
        ('Funnel Stages', {
            'fields': (
                'stage_applied', 'stage_screening', 'stage_phone_interview',
                'stage_technical_assessment', 'stage_onsite_interview',
                'stage_reference_check', 'stage_offer', 'stage_hired'
            )
        }),
        ('Drop-offs', {
            'fields': (
                'dropped_at_screening', 'dropped_at_phone', 'dropped_at_technical',
                'dropped_at_onsite', 'dropped_at_reference', 'dropped_at_offer'
            ),
            'classes': ('collapse',)
        }),
        ('Conversion Rates', {
            'fields': (
                'rate_applied_to_screening', 'rate_screening_to_phone',
                'rate_phone_to_technical', 'rate_technical_to_onsite',
                'rate_onsite_to_reference', 'rate_reference_to_offer',
                'rate_offer_to_hired', 'overall_conversion_rate'
            )
        }),
        ('Time Metrics', {
            'fields': (
                'avg_days_in_funnel', 'avg_days_screening', 'avg_days_phone',
                'avg_days_technical', 'avg_days_onsite', 'avg_days_reference',
                'avg_days_offer'
            ),
            'classes': ('collapse',)
        }),
        ('Bottleneck Analysis', {
            'fields': ('bottleneck_stage', 'bottleneck_rate')
        }),
        ('Additional Data', {
            'fields': ('stage_details', 'comparison_period', 'metadata', 'created_at'),
            'classes': ('collapse',)
        }),
    )

    def overall_conversion_rate_display(self, obj):
        if obj.overall_conversion_rate:
            return f"{obj.overall_conversion_rate}%"
        return "-"
    overall_conversion_rate_display.short_description = "Conversion Rate"


@admin.register(TimeToHireMetric)
class TimeToHireMetricAdmin(admin.ModelAdmin):
    list_display = [
        'period_start', 'period_end', 'department',
        'total_hires', 'avg_time_to_hire_display',
        'target_achievement_rate_display'
    ]
    list_filter = ['period_start', 'department', 'job_type', 'experience_level']
    search_fields = ['uuid', 'department', 'location']
    readonly_fields = ['uuid', 'created_at']
    date_hierarchy = 'period_start'

    fieldsets = (
        ('Period & Filters', {
            'fields': (
                'uuid', 'period_start', 'period_end',
                'department', 'job_type', 'experience_level', 'location'
            )
        }),
        ('Time-to-Fill', {
            'fields': (
                'total_positions_filled', 'avg_time_to_fill',
                'median_time_to_fill', 'min_time_to_fill', 'max_time_to_fill'
            )
        }),
        ('Time-to-Hire', {
            'fields': (
                'total_hires', 'avg_time_to_hire',
                'median_time_to_hire', 'min_time_to_hire', 'max_time_to_hire'
            )
        }),
        ('Stage Times', {
            'fields': (
                'avg_time_in_screening', 'avg_time_in_interview',
                'avg_time_in_assessment', 'avg_time_in_offer',
                'avg_time_to_first_contact', 'avg_time_to_decision'
            ),
            'classes': ('collapse',)
        }),
        ('Target vs Actual', {
            'fields': (
                'target_time_to_fill', 'positions_within_target',
                'target_achievement_rate'
            )
        }),
        ('Trends & Breakdowns', {
            'fields': ('trend_vs_previous_period', 'time_distribution', 'by_source'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata', 'created_at'),
            'classes': ('collapse',)
        }),
    )

    def avg_time_to_hire_display(self, obj):
        if obj.avg_time_to_hire:
            return f"{obj.avg_time_to_hire} days"
        return "-"
    avg_time_to_hire_display.short_description = "Avg Time to Hire"

    def target_achievement_rate_display(self, obj):
        if obj.target_achievement_rate:
            return f"{obj.target_achievement_rate}%"
        return "-"
    target_achievement_rate_display.short_description = "Target Achievement"


@admin.register(SourceEffectivenessMetric)
class SourceEffectivenessMetricAdmin(admin.ModelAdmin):
    list_display = [
        'source', 'source_detail', 'period_start',
        'total_applicants', 'hires', 'hire_rate_display',
        'effectiveness_score_display'
    ]
    list_filter = ['source', 'period_start']
    search_fields = ['uuid', 'source', 'source_detail']
    readonly_fields = ['uuid', 'created_at']
    date_hierarchy = 'period_start'

    fieldsets = (
        ('Source & Period', {
            'fields': ('uuid', 'period_start', 'period_end', 'source', 'source_detail')
        }),
        ('Volume Metrics', {
            'fields': (
                'total_applicants', 'qualified_applicants',
                'interviewed', 'offers_extended', 'hires'
            )
        }),
        ('Quality Metrics', {
            'fields': (
                'qualification_rate', 'interview_rate', 'hire_rate',
                'avg_performance_rating', 'retention_rate_6_months',
                'retention_rate_12_months'
            )
        }),
        ('Cost Metrics', {
            'fields': ('total_cost', 'cost_per_applicant', 'cost_per_hire'),
            'classes': ('collapse',)
        }),
        ('Effectiveness', {
            'fields': ('avg_time_to_hire', 'roi_score', 'effectiveness_score')
        }),
        ('Breakdowns', {
            'fields': ('by_job_type', 'by_department'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata', 'created_at'),
            'classes': ('collapse',)
        }),
    )

    def hire_rate_display(self, obj):
        if obj.hire_rate:
            return f"{obj.hire_rate}%"
        return "-"
    hire_rate_display.short_description = "Hire Rate"

    def effectiveness_score_display(self, obj):
        if obj.effectiveness_score:
            color = 'green' if obj.effectiveness_score >= 70 else 'orange' if obj.effectiveness_score >= 40 else 'red'
            return format_html(
                '<span style="color: {};">{}</span>',
                color, obj.effectiveness_score
            )
        return "-"
    effectiveness_score_display.short_description = "Effectiveness Score"


# ==================== HR ANALYTICS ADMIN ====================

@admin.register(EmployeeRetentionMetric)
class EmployeeRetentionMetricAdmin(admin.ModelAdmin):
    list_display = [
        'period_type', 'period_start', 'department',
        'starting_headcount', 'ending_headcount',
        'turnover_rate_display', 'retention_rate_display'
    ]
    list_filter = ['period_type', 'period_start', 'department']
    search_fields = ['uuid', 'department', 'location']
    readonly_fields = ['uuid', 'created_at']
    date_hierarchy = 'period_start'

    fieldsets = (
        ('Period & Filters', {
            'fields': (
                'uuid', 'period_type', 'period_start', 'period_end',
                'department', 'location', 'job_level'
            )
        }),
        ('Headcount', {
            'fields': ('starting_headcount', 'ending_headcount', 'average_headcount')
        }),
        ('New Hires', {
            'fields': ('new_hires', 'new_hire_retention_90_days', 'new_hire_retention_rate')
        }),
        ('Departures', {
            'fields': (
                'total_departures', 'voluntary_departures',
                'involuntary_departures', 'retirement_departures'
            )
        }),
        ('Rates', {
            'fields': (
                'overall_turnover_rate', 'voluntary_turnover_rate',
                'involuntary_turnover_rate', 'overall_retention_rate'
            )
        }),
        ('Tenure Breakdown', {
            'fields': (
                'departures_under_1_year', 'departures_1_to_3_years',
                'departures_3_to_5_years', 'departures_over_5_years',
                'avg_tenure_departed', 'avg_tenure_current'
            ),
            'classes': ('collapse',)
        }),
        ('High Performers', {
            'fields': ('high_performer_departures', 'high_performer_retention_rate'),
            'classes': ('collapse',)
        }),
        ('Cost Impact', {
            'fields': ('estimated_turnover_cost', 'cost_per_departure'),
            'classes': ('collapse',)
        }),
        ('Analysis', {
            'fields': ('departure_reasons', 'by_department', 'by_tenure', 'trend_vs_previous'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata', 'created_at'),
            'classes': ('collapse',)
        }),
    )

    def turnover_rate_display(self, obj):
        if obj.overall_turnover_rate:
            color = 'red' if obj.overall_turnover_rate >= 20 else 'orange' if obj.overall_turnover_rate >= 10 else 'green'
            return format_html(
                '<span style="color: {};">{}%</span>',
                color, obj.overall_turnover_rate
            )
        return "-"
    turnover_rate_display.short_description = "Turnover Rate"

    def retention_rate_display(self, obj):
        if obj.overall_retention_rate:
            return f"{obj.overall_retention_rate}%"
        return "-"
    retention_rate_display.short_description = "Retention Rate"


@admin.register(TimeOffAnalytics)
class TimeOffAnalyticsAdmin(admin.ModelAdmin):
    list_display = [
        'period_type', 'period_start', 'department',
        'total_employees', 'pto_requests',
        'approval_rate_display', 'absenteeism_rate_display'
    ]
    list_filter = ['period_type', 'period_start', 'department']
    search_fields = ['uuid', 'department', 'location']
    readonly_fields = ['uuid', 'created_at']
    date_hierarchy = 'period_start'

    fieldsets = (
        ('Period & Filters', {
            'fields': (
                'uuid', 'period_type', 'period_start', 'period_end',
                'department', 'location', 'total_employees'
            )
        }),
        ('Time-Off Totals', {
            'fields': (
                'total_pto_taken', 'total_sick_leave_taken',
                'total_unpaid_leave_taken', 'total_other_leave_taken'
            )
        }),
        ('Requests', {
            'fields': (
                'pto_requests', 'sick_leave_requests', 'unpaid_leave_requests',
                'requests_approved', 'requests_rejected', 'requests_pending',
                'approval_rate'
            )
        }),
        ('Averages', {
            'fields': ('avg_pto_days_per_employee', 'avg_sick_days_per_employee')
        }),
        ('PTO Balances', {
            'fields': (
                'total_pto_balance_accrued', 'total_pto_balance_remaining',
                'avg_pto_balance_per_employee', 'pto_utilization_rate'
            ),
            'classes': ('collapse',)
        }),
        ('Absenteeism', {
            'fields': ('unscheduled_absence_days', 'absenteeism_rate'),
            'classes': ('collapse',)
        }),
        ('Patterns', {
            'fields': ('peak_absence_day', 'peak_absence_month', 'by_day_of_week'),
            'classes': ('collapse',)
        }),
        ('Breakdowns', {
            'fields': ('by_leave_type', 'by_department', 'trend_vs_previous'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata', 'created_at'),
            'classes': ('collapse',)
        }),
    )

    def approval_rate_display(self, obj):
        if obj.approval_rate:
            return f"{obj.approval_rate}%"
        return "-"
    approval_rate_display.short_description = "Approval Rate"

    def absenteeism_rate_display(self, obj):
        if obj.absenteeism_rate:
            return f"{obj.absenteeism_rate}%"
        return "-"
    absenteeism_rate_display.short_description = "Absenteeism Rate"


@admin.register(PerformanceDistribution)
class PerformanceDistributionAdmin(admin.ModelAdmin):
    list_display = [
        'review_cycle', 'period_start', 'department',
        'total_employees_reviewed', 'reviews_completed',
        'completion_rate_display', 'average_rating'
    ]
    list_filter = ['review_cycle', 'period_type', 'period_start', 'department']
    search_fields = ['uuid', 'department']
    readonly_fields = ['uuid', 'created_at']
    date_hierarchy = 'period_start'

    fieldsets = (
        ('Period & Filters', {
            'fields': (
                'uuid', 'period_type', 'review_cycle',
                'period_start', 'period_end',
                'department', 'job_level'
            )
        }),
        ('Review Status', {
            'fields': (
                'total_employees_reviewed', 'reviews_completed',
                'reviews_pending', 'completion_rate'
            )
        }),
        ('Rating Distribution', {
            'fields': (
                ('rating_5_count', 'rating_5_pct'),
                ('rating_4_count', 'rating_4_pct'),
                ('rating_3_count', 'rating_3_pct'),
                ('rating_2_count', 'rating_2_pct'),
                ('rating_1_count', 'rating_1_pct'),
            )
        }),
        ('Averages', {
            'fields': ('average_rating', 'median_rating')
        }),
        ('Goals', {
            'fields': (
                'avg_goals_met_percentage', 'employees_meeting_all_goals',
                'employees_meeting_some_goals', 'employees_missing_goals'
            ),
            'classes': ('collapse',)
        }),
        ('Recommendations', {
            'fields': (
                'promotion_recommendations', 'pip_recommendations',
                'salary_increase_recommendations'
            )
        }),
        ('Competencies', {
            'fields': ('competency_averages',),
            'classes': ('collapse',)
        }),
        ('Breakdowns', {
            'fields': ('by_department', 'by_level'),
            'classes': ('collapse',)
        }),
        ('Calibration', {
            'fields': (
                'rating_change_from_previous', 'pre_calibration_avg',
                'post_calibration_avg', 'calibration_adjustment'
            ),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata', 'created_at'),
            'classes': ('collapse',)
        }),
    )

    def completion_rate_display(self, obj):
        if obj.completion_rate:
            color = 'green' if obj.completion_rate >= 90 else 'orange' if obj.completion_rate >= 70 else 'red'
            return format_html(
                '<span style="color: {};">{}%</span>',
                color, obj.completion_rate
            )
        return "-"
    completion_rate_display.short_description = "Completion Rate"


# ==================== CACHE ADMIN ====================

@admin.register(DashboardCache)
class DashboardCacheAdmin(admin.ModelAdmin):
    list_display = [
        'dashboard_type', 'generated_at', 'expires_at',
        'is_stale', 'is_expired_display'
    ]
    list_filter = ['dashboard_type', 'is_stale']
    readonly_fields = ['dashboard_type', 'generated_at', 'is_expired']

    def is_expired_display(self, obj):
        if obj.is_expired:
            return format_html('<span style="color: red;">Expired</span>')
        return format_html('<span style="color: green;">Valid</span>')
    is_expired_display.short_description = "Status"
