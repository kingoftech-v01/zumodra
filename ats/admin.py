"""
ATS Admin - Admin configuration for Applicant Tracking System.
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import (
    JobCategory, Pipeline, PipelineStage, JobPosting,
    Candidate, Application, ApplicationActivity, ApplicationNote,
    Interview, InterviewFeedback, Offer, SavedSearch,
    BackgroundCheck, BackgroundCheckDocument
)


@admin.register(JobCategory)
class JobCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'parent', 'sort_order', 'is_active']
    list_filter = ['is_active', 'parent']
    search_fields = ['name', 'description']
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['sort_order', 'name']


class PipelineStageInline(admin.TabularInline):
    model = PipelineStage
    extra = 1
    ordering = ['order']


@admin.register(Pipeline)
class PipelineAdmin(admin.ModelAdmin):
    list_display = ['name', 'is_default', 'is_active', 'stage_count', 'created_at']
    list_filter = ['is_default', 'is_active']
    search_fields = ['name', 'description']
    inlines = [PipelineStageInline]
    readonly_fields = ['uuid', 'created_at', 'updated_at']

    def stage_count(self, obj):
        return obj.stages.count()
    stage_count.short_description = 'Stages'


@admin.register(JobPosting)
class JobPostingAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'reference_code', 'status_badge', 'job_type',
        'location_display', 'applications_count', 'created_at'
    ]
    list_filter = [
        'status', 'job_type', 'experience_level', 'remote_policy',
        'category', 'is_featured'
    ]
    search_fields = ['title', 'reference_code', 'description']
    readonly_fields = ['uuid', 'reference_code', 'slug', 'created_at', 'updated_at']
    raw_id_fields = ['hiring_manager', 'recruiter', 'created_by', 'pipeline', 'category']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Basic Info', {
            'fields': ('title', 'reference_code', 'slug', 'category', 'status', 'pipeline')
        }),
        ('Description', {
            'fields': ('description', 'responsibilities', 'requirements', 'nice_to_have', 'benefits')
        }),
        ('Job Details', {
            'fields': ('job_type', 'experience_level', 'positions_count')
        }),
        ('Location', {
            'fields': ('remote_policy', 'location_city', 'location_state', 'location_country')
        }),
        ('Compensation', {
            'fields': (
                'salary_min', 'salary_max', 'salary_currency', 'salary_period',
                'show_salary', 'equity_offered', 'equity_range'
            )
        }),
        ('Skills', {
            'fields': ('required_skills', 'preferred_skills', 'languages_required')
        }),
        ('Team', {
            'fields': ('hiring_manager', 'recruiter', 'team', 'reports_to')
        }),
        ('Application Settings', {
            'fields': (
                'application_deadline', 'require_cover_letter', 'require_resume',
                'custom_questions'
            )
        }),
        ('Visibility', {
            'fields': (
                'is_internal_only', 'is_featured', 'published_on_career_page'
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'published_at', 'closed_at'),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'draft': 'gray',
            'open': 'green',
            'on_hold': 'orange',
            'closed': 'blue',
            'filled': 'purple',
            'cancelled': 'red',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def location_display(self, obj):
        parts = filter(None, [obj.location_city, obj.location_country])
        return ', '.join(parts) or obj.get_remote_policy_display()
    location_display.short_description = 'Location'

    def applications_count(self, obj):
        count = obj.applications.count()
        return format_html('<strong>{}</strong>', count)
    applications_count.short_description = 'Applications'


@admin.register(Candidate)
class CandidateAdmin(admin.ModelAdmin):
    list_display = [
        'full_name', 'email', 'current_title', 'source',
        'applications_count', 'created_at'
    ]
    list_filter = ['source', 'country', 'created_at']
    search_fields = ['first_name', 'last_name', 'email', 'phone']
    readonly_fields = ['uuid', 'created_at', 'updated_at', 'last_activity_at']
    raw_id_fields = ['user', 'referred_by']

    def applications_count(self, obj):
        return obj.applications.count()
    applications_count.short_description = 'Applications'


class ApplicationNoteInline(admin.TabularInline):
    model = ApplicationNote
    extra = 0
    readonly_fields = ['created_at']


class InterviewInline(admin.TabularInline):
    model = Interview
    extra = 0
    readonly_fields = ['created_at']
    fields = ['title', 'interview_type', 'status', 'scheduled_start', 'scheduled_end']


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = [
        'candidate', 'job', 'status_badge', 'current_stage',
        'overall_rating', 'applied_at'
    ]
    list_filter = ['status', 'current_stage', 'job', 'applied_at']
    search_fields = [
        'candidate__first_name', 'candidate__last_name',
        'candidate__email', 'job__title'
    ]
    readonly_fields = ['uuid', 'applied_at', 'updated_at']
    raw_id_fields = ['candidate', 'job', 'current_stage', 'assigned_to']
    inlines = [ApplicationNoteInline, InterviewInline]
    date_hierarchy = 'applied_at'

    def status_badge(self, obj):
        colors = {
            'new': 'blue',
            'in_review': 'orange',
            'shortlisted': 'teal',
            'interviewing': 'purple',
            'offer_extended': 'green',
            'hired': 'darkgreen',
            'rejected': 'red',
            'withdrawn': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(Interview)
class InterviewAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'application', 'interview_type', 'status',
        'scheduled_start', 'duration_minutes'
    ]
    list_filter = ['status', 'interview_type', 'scheduled_start']
    search_fields = ['title', 'application__candidate__email']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['application', 'organizer']
    filter_horizontal = ['interviewers']
    date_hierarchy = 'scheduled_start'


@admin.register(InterviewFeedback)
class InterviewFeedbackAdmin(admin.ModelAdmin):
    list_display = [
        'interview', 'interviewer', 'overall_rating',
        'recommendation', 'submitted_at'
    ]
    list_filter = ['recommendation', 'overall_rating', 'created_at']
    search_fields = ['interview__application__candidate__email']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['interview', 'interviewer']


@admin.register(Offer)
class OfferAdmin(admin.ModelAdmin):
    list_display = [
        'application', 'job_title', 'status_badge',
        'base_salary', 'start_date', 'created_at'
    ]
    list_filter = ['status', 'created_at']
    search_fields = ['application__candidate__email', 'job_title']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['application', 'approved_by', 'created_by']

    def status_badge(self, obj):
        colors = {
            'draft': 'gray',
            'approved': 'blue',
            'sent': 'orange',
            'accepted': 'green',
            'declined': 'red',
            'expired': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(SavedSearch)
class SavedSearchAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'is_alert_enabled', 'last_run_at', 'created_at']
    list_filter = ['is_alert_enabled', 'alert_frequency']
    search_fields = ['name', 'user__email']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['user']


class BackgroundCheckDocumentInline(admin.TabularInline):
    """Inline for background check documents/screenings."""
    model = BackgroundCheckDocument
    extra = 0
    readonly_fields = ['document_type', 'status', 'result', 'completed_at', 'created_at']
    fields = ['document_type', 'status', 'result', 'findings_summary', 'completed_at']

    def has_add_permission(self, request, obj=None):
        """Documents are created automatically by provider."""
        return False


@admin.register(BackgroundCheck)
class BackgroundCheckAdmin(admin.ModelAdmin):
    """Admin interface for background checks."""

    list_display = [
        'application', 'provider', 'package', 'status_badge', 'result_badge',
        'initiated_at', 'completed_at'
    ]
    list_filter = ['provider', 'status', 'result', 'package', 'initiated_at']
    search_fields = [
        'application__candidate__first_name',
        'application__candidate__last_name',
        'application__candidate__email',
        'external_report_id',
        'external_candidate_id'
    ]
    readonly_fields = [
        'uuid', 'external_candidate_id', 'external_report_id',
        'status', 'result', 'initiated_at', 'completed_at',
        'report_url_link', 'report_data_display', 'created_at', 'updated_at'
    ]
    raw_id_fields = ['application', 'initiated_by']
    inlines = [BackgroundCheckDocumentInline]
    date_hierarchy = 'initiated_at'

    fieldsets = (
        ('Application', {
            'fields': ('application', 'initiated_by', 'initiated_at')
        }),
        ('Provider', {
            'fields': (
                'provider', 'package', 'external_candidate_id', 'external_report_id'
            )
        }),
        ('Status', {
            'fields': ('status', 'result', 'completed_at')
        }),
        ('Consent', {
            'fields': ('consent_given', 'consent_ip_address', 'consent_timestamp')
        }),
        ('Report', {
            'fields': ('report_url_link', 'notes', 'report_data_display'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        """Display colored status badge."""
        colors = {
            'pending': 'gray',
            'invited': 'blue',
            'in_progress': 'orange',
            'completed': 'green',
            'failed': 'red',
            'cancelled': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def result_badge(self, obj):
        """Display colored result badge."""
        if not obj.result:
            return '-'

        colors = {
            'clear': 'green',
            'consider': 'orange',
            'suspended': 'red',
        }
        color = colors.get(obj.result, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_result_display()
        )
    result_badge.short_description = 'Result'

    def report_url_link(self, obj):
        """Display report URL as clickable link."""
        if obj.report_url:
            return format_html(
                '<a href="{}" target="_blank">View Report</a>',
                obj.report_url
            )
        return '-'
    report_url_link.short_description = 'Report URL'

    def report_data_display(self, obj):
        """Display formatted report data."""
        import json
        if obj.report_data:
            return format_html(
                '<pre style="max-height: 400px; overflow-y: auto;">{}</pre>',
                json.dumps(obj.report_data, indent=2)
            )
        return '-'
    report_data_display.short_description = 'Report Data'


@admin.register(BackgroundCheckDocument)
class BackgroundCheckDocumentAdmin(admin.ModelAdmin):
    """Admin interface for individual background check documents."""

    list_display = [
        'background_check', 'document_type', 'status', 'result',
        'completed_at', 'created_at'
    ]
    list_filter = ['document_type', 'status', 'result', 'completed_at']
    search_fields = [
        'background_check__application__candidate__email',
        'document_type',
        'findings_summary'
    ]
    readonly_fields = [
        'uuid', 'background_check', 'document_type', 'status', 'result',
        'completed_at', 'document_data_display', 'created_at', 'updated_at'
    ]

    fieldsets = (
        ('Background Check', {
            'fields': ('background_check',)
        }),
        ('Document Details', {
            'fields': ('document_type', 'status', 'result', 'completed_at')
        }),
        ('Findings', {
            'fields': ('findings_summary', 'document_data_display')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def document_data_display(self, obj):
        """Display formatted document data."""
        import json
        if obj.document_data:
            return format_html(
                '<pre style="max-height: 400px; overflow-y: auto;">{}</pre>',
                json.dumps(obj.document_data, indent=2)
            )
        return '-'
    document_data_display.short_description = 'Document Data'

    def has_add_permission(self, request):
        """Documents are created automatically by provider."""
        return False
