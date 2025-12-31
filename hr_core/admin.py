"""
HR Core Admin - Admin configuration for HR operations.
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import (
    Employee, TimeOffType, TimeOffRequest,
    OnboardingChecklist, OnboardingTask, EmployeeOnboarding, OnboardingTaskProgress,
    DocumentTemplate, EmployeeDocument,
    Offboarding, PerformanceReview,
    # New models
    EmployeeCompensation, TimeOffBalance, TimeOffAccrualLog,
    TimeOffBlackoutDate, SkillCategory, Skill, EmployeeSkill,
    Certification, EmployeeActivityLog, EmployeeGoal
)


@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = [
        'employee_id', 'full_name', 'job_title', 'department',
        'status_badge', 'employment_type', 'hire_date'
    ]
    list_filter = ['status', 'employment_type', 'department']
    search_fields = ['employee_id', 'user__first_name', 'user__last_name', 'user__email']
    readonly_fields = ['uuid', 'employee_id', 'created_at', 'updated_at']
    raw_id_fields = ['user', 'manager', 'department', 'from_application']
    date_hierarchy = 'hire_date'

    fieldsets = (
        ('Employee Info', {
            'fields': ('user', 'employee_id', 'status', 'employment_type')
        }),
        ('Position', {
            'fields': ('job_title', 'department', 'manager', 'team', 'work_location')
        }),
        ('Dates', {
            'fields': ('hire_date', 'start_date', 'probation_end_date', 'termination_date')
        }),
        ('Compensation', {
            'fields': ('base_salary', 'salary_currency', 'pay_frequency'),
            'classes': ('collapse',)
        }),
        ('Benefits & PTO', {
            'fields': ('pto_balance', 'sick_leave_balance', 'benefits_enrolled'),
            'classes': ('collapse',)
        }),
        ('Emergency Contact', {
            'fields': ('emergency_contact_name', 'emergency_contact_phone', 'emergency_contact_relationship'),
            'classes': ('collapse',)
        }),
        ('Work Authorization', {
            'fields': (
                'work_authorization_status', 'visa_type', 'visa_expiry',
                'work_permit_number', 'work_permit_expiry',
                'right_to_work_verified', 'right_to_work_verified_date', 'right_to_work_verified_by'
            ),
            'classes': ('collapse',)
        }),
        ('Skills & Certifications', {
            'fields': ('skills', 'certifications'),
            'classes': ('collapse',)
        }),
        ('Performance', {
            'fields': ('next_review_date', 'review_frequency_months'),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'active': 'green',
            'probation': 'blue',
            'on_leave': 'orange',
            'notice_period': 'purple',
            'terminated': 'red',
            'resigned': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(TimeOffType)
class TimeOffTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'is_accrued', 'accrual_rate', 'requires_approval', 'is_active']
    list_filter = ['is_accrued', 'requires_approval', 'is_paid', 'is_active']
    search_fields = ['name', 'code']


@admin.register(TimeOffRequest)
class TimeOffRequestAdmin(admin.ModelAdmin):
    list_display = [
        'employee', 'time_off_type', 'start_date', 'end_date',
        'total_days', 'status_badge', 'created_at'
    ]
    list_filter = ['status', 'time_off_type', 'start_date']
    search_fields = ['employee__user__email', 'employee__employee_id']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['employee', 'approver']
    date_hierarchy = 'start_date'

    def status_badge(self, obj):
        colors = {
            'pending': 'orange',
            'approved': 'green',
            'rejected': 'red',
            'cancelled': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


class OnboardingTaskInline(admin.TabularInline):
    model = OnboardingTask
    extra = 1
    ordering = ['order']


@admin.register(OnboardingChecklist)
class OnboardingChecklistAdmin(admin.ModelAdmin):
    list_display = ['name', 'employment_type', 'department', 'task_count', 'is_active']
    list_filter = ['is_active', 'employment_type']
    search_fields = ['name', 'description']
    inlines = [OnboardingTaskInline]

    def task_count(self, obj):
        return obj.tasks.count()
    task_count.short_description = 'Tasks'


class OnboardingTaskProgressInline(admin.TabularInline):
    model = OnboardingTaskProgress
    extra = 0
    readonly_fields = ['task', 'is_completed', 'completed_at', 'completed_by']
    can_delete = False


@admin.register(EmployeeOnboarding)
class EmployeeOnboardingAdmin(admin.ModelAdmin):
    list_display = ['employee', 'checklist', 'start_date', 'completion_display', 'completed_at']
    list_filter = ['checklist', 'start_date']
    search_fields = ['employee__user__email', 'employee__employee_id']
    inlines = [OnboardingTaskProgressInline]

    def completion_display(self, obj):
        pct = obj.completion_percentage
        if pct >= 100:
            color = 'green'
        elif pct >= 50:
            color = 'orange'
        else:
            color = 'red'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, f"{pct}%"
        )
    completion_display.short_description = 'Progress'


@admin.register(DocumentTemplate)
class DocumentTemplateAdmin(admin.ModelAdmin):
    list_display = ['name', 'category', 'version', 'requires_signature', 'is_active']
    list_filter = ['category', 'requires_signature', 'is_active']
    search_fields = ['name', 'description']


@admin.register(EmployeeDocument)
class EmployeeDocumentAdmin(admin.ModelAdmin):
    list_display = ['title', 'employee', 'category', 'status', 'requires_signature', 'created_at']
    list_filter = ['category', 'status', 'requires_signature']
    search_fields = ['title', 'employee__user__email']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['employee', 'template', 'uploaded_by']


@admin.register(Offboarding)
class OffboardingAdmin(admin.ModelAdmin):
    list_display = [
        'employee', 'separation_type', 'notice_date',
        'last_working_day', 'completion_status'
    ]
    list_filter = ['separation_type', 'eligible_for_rehire']
    search_fields = ['employee__user__email', 'employee__employee_id']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['employee', 'processed_by']

    def completion_status(self, obj):
        if obj.is_complete:
            return format_html('<span style="color: green;">Complete</span>')
        return format_html('<span style="color: orange;">In Progress</span>')
    completion_status.short_description = 'Status'


@admin.register(PerformanceReview)
class PerformanceReviewAdmin(admin.ModelAdmin):
    list_display = [
        'employee', 'review_type', 'review_period_end',
        'overall_rating', 'status', 'completed_at'
    ]
    list_filter = ['status', 'review_type', 'overall_rating']
    search_fields = ['employee__user__email', 'employee__employee_id']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['employee', 'reviewer']
    date_hierarchy = 'review_period_end'


# ==================== COMPENSATION ADMIN ====================

@admin.register(EmployeeCompensation)
class EmployeeCompensationAdmin(admin.ModelAdmin):
    list_display = [
        'employee', 'effective_date', 'base_salary', 'currency',
        'change_reason', 'salary_change_display', 'approved_at'
    ]
    list_filter = ['change_reason', 'currency', 'effective_date']
    search_fields = ['employee__user__email', 'employee__employee_id']
    readonly_fields = ['uuid', 'created_at', 'updated_at', 'salary_change_percentage']
    raw_id_fields = ['employee', 'approved_by', 'created_by']
    date_hierarchy = 'effective_date'

    fieldsets = (
        ('Employee', {
            'fields': ('employee', 'effective_date', 'end_date')
        }),
        ('Base Compensation', {
            'fields': ('base_salary', 'currency', 'pay_frequency')
        }),
        ('Variable Compensation', {
            'fields': ('bonus_target_percentage', 'bonus_type', 'commission_percentage'),
            'classes': ('collapse',)
        }),
        ('Equity', {
            'fields': ('equity_shares', 'equity_vest_start', 'equity_vest_end', 'equity_cliff_months'),
            'classes': ('collapse',)
        }),
        ('Change Details', {
            'fields': ('change_reason', 'change_notes', 'previous_salary', 'salary_change_percentage')
        }),
        ('Approval', {
            'fields': ('approved_by', 'approved_at'),
            'classes': ('collapse',)
        }),
    )

    def salary_change_display(self, obj):
        pct = obj.salary_change_percentage
        if pct is None:
            return '-'
        if pct > 0:
            return format_html(
                '<span style="color: green;">+{:.1f}%</span>',
                pct
            )
        elif pct < 0:
            return format_html(
                '<span style="color: red;">{:.1f}%</span>',
                pct
            )
        return '0%'
    salary_change_display.short_description = 'Change'


# ==================== TIME OFF BALANCE ADMIN ====================

@admin.register(TimeOffBalance)
class TimeOffBalanceAdmin(admin.ModelAdmin):
    list_display = [
        'employee', 'time_off_type', 'year',
        'balance', 'accrued_this_year', 'used_this_year', 'pending'
    ]
    list_filter = ['time_off_type', 'year']
    search_fields = ['employee__user__email', 'employee__employee_id']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['employee', 'time_off_type']


class TimeOffAccrualLogInline(admin.TabularInline):
    model = TimeOffAccrualLog
    extra = 0
    readonly_fields = ['accrual_date', 'amount', 'balance_after', 'created_at']
    can_delete = False


@admin.register(TimeOffAccrualLog)
class TimeOffAccrualLogAdmin(admin.ModelAdmin):
    list_display = ['balance', 'accrual_date', 'amount', 'balance_after', 'created_at']
    list_filter = ['accrual_date']
    search_fields = ['balance__employee__user__email']
    readonly_fields = ['created_at']
    date_hierarchy = 'accrual_date'


@admin.register(TimeOffBlackoutDate)
class TimeOffBlackoutDateAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'start_date', 'end_date', 'restriction_type',
        'applies_to_all', 'is_active'
    ]
    list_filter = ['restriction_type', 'is_active', 'applies_to_all']
    search_fields = ['name', 'description']
    filter_horizontal = ['departments']
    date_hierarchy = 'start_date'

    fieldsets = (
        ('Blackout Period', {
            'fields': ('name', 'description', 'start_date', 'end_date')
        }),
        ('Scope', {
            'fields': ('applies_to_all', 'departments', 'restriction_type')
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
    )


# ==================== SKILL ADMIN ====================

@admin.register(SkillCategory)
class SkillCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'order', 'skills_count', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'description']
    ordering = ['order', 'name']

    def skills_count(self, obj):
        return obj.skills.count()
    skills_count.short_description = 'Skills'


@admin.register(Skill)
class SkillAdmin(admin.ModelAdmin):
    list_display = ['name', 'category', 'employees_count', 'is_active']
    list_filter = ['category', 'is_active']
    search_fields = ['name', 'description']

    def employees_count(self, obj):
        return obj.employee_skills.count()
    employees_count.short_description = 'Employees'


@admin.register(EmployeeSkill)
class EmployeeSkillAdmin(admin.ModelAdmin):
    list_display = [
        'employee', 'skill', 'proficiency', 'years_of_experience',
        'is_primary', 'verified', 'verified_date'
    ]
    list_filter = ['proficiency', 'is_primary', 'verified', 'skill__category']
    search_fields = ['employee__user__email', 'skill__name']
    raw_id_fields = ['employee', 'skill', 'verified_by']

    def proficiency_badge(self, obj):
        colors = {
            'beginner': '#9ca3af',
            'intermediate': '#3b82f6',
            'advanced': '#10b981',
            'expert': '#8b5cf6',
        }
        color = colors.get(obj.proficiency, '#9ca3af')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_proficiency_display()
        )
    proficiency_badge.short_description = 'Proficiency'


# ==================== CERTIFICATION ADMIN ====================

@admin.register(Certification)
class CertificationAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'employee', 'issuing_organization',
        'issue_date', 'expiry_status', 'is_verified', 'is_active'
    ]
    list_filter = ['is_verified', 'is_active', 'issuing_organization']
    search_fields = ['name', 'employee__user__email', 'credential_id']
    readonly_fields = ['uuid', 'created_at', 'updated_at', 'is_expired', 'days_until_expiry']
    raw_id_fields = ['employee', 'verified_by']
    date_hierarchy = 'issue_date'

    fieldsets = (
        ('Certification', {
            'fields': ('employee', 'name', 'issuing_organization')
        }),
        ('Credentials', {
            'fields': ('credential_id', 'credential_url', 'certificate_file')
        }),
        ('Dates', {
            'fields': ('issue_date', 'expiry_date', 'is_expired', 'days_until_expiry')
        }),
        ('Verification', {
            'fields': ('is_verified', 'verified_by', 'verified_date')
        }),
        ('Status', {
            'fields': ('is_active', 'notes')
        }),
    )

    def expiry_status(self, obj):
        if obj.is_expired:
            return format_html(
                '<span style="color: red; font-weight: bold;">Expired</span>'
            )
        if obj.days_until_expiry is not None and obj.days_until_expiry <= 30:
            return format_html(
                '<span style="color: orange;">Expires in {} days</span>',
                obj.days_until_expiry
            )
        if obj.expiry_date:
            return format_html(
                '<span style="color: green;">Valid</span>'
            )
        return 'No expiry'
    expiry_status.short_description = 'Status'


# ==================== ACTIVITY LOG ADMIN ====================

@admin.register(EmployeeActivityLog)
class EmployeeActivityLogAdmin(admin.ModelAdmin):
    list_display = [
        'employee', 'activity_type', 'description_preview',
        'performed_by', 'created_at'
    ]
    list_filter = ['activity_type', 'created_at']
    search_fields = ['employee__user__email', 'description']
    readonly_fields = [
        'uuid', 'employee', 'activity_type', 'description',
        'old_value', 'new_value', 'metadata', 'performed_by', 'created_at'
    ]
    date_hierarchy = 'created_at'

    def description_preview(self, obj):
        if len(obj.description) > 50:
            return obj.description[:50] + '...'
        return obj.description
    description_preview.short_description = 'Description'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


# ==================== GOAL ADMIN ====================

@admin.register(EmployeeGoal)
class EmployeeGoalAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'employee', 'category', 'priority_badge',
        'progress_bar', 'status', 'target_date', 'is_overdue'
    ]
    list_filter = ['status', 'category', 'priority']
    search_fields = ['title', 'employee__user__email', 'description']
    readonly_fields = ['uuid', 'created_at', 'updated_at', 'is_overdue', 'days_remaining']
    raw_id_fields = ['employee', 'performance_review', 'approved_by']
    date_hierarchy = 'target_date'

    fieldsets = (
        ('Goal Details', {
            'fields': ('employee', 'title', 'description', 'key_results')
        }),
        ('Categorization', {
            'fields': ('category', 'priority', 'weight')
        }),
        ('Timeline', {
            'fields': ('start_date', 'target_date', 'completed_date')
        }),
        ('Progress', {
            'fields': ('status', 'progress_percentage', 'is_overdue', 'days_remaining')
        }),
        ('Approval', {
            'fields': ('approved_by', 'approved_at'),
            'classes': ('collapse',)
        }),
        ('Related', {
            'fields': ('performance_review',),
            'classes': ('collapse',)
        }),
    )

    def priority_badge(self, obj):
        colors = {
            'low': '#6b7280',
            'medium': '#3b82f6',
            'high': '#f59e0b',
            'critical': '#ef4444',
        }
        color = colors.get(obj.priority, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_priority_display()
        )
    priority_badge.short_description = 'Priority'

    def progress_bar(self, obj):
        pct = obj.progress_percentage
        if pct >= 100:
            color = '#10b981'
        elif pct >= 50:
            color = '#f59e0b'
        else:
            color = '#ef4444'
        return format_html(
            '<div style="width: 100px; background: #e5e7eb; border-radius: 4px;">'
            '<div style="width: {}%; background: {}; height: 8px; border-radius: 4px;"></div>'
            '</div> {}%',
            pct, color, pct
        )
    progress_bar.short_description = 'Progress'
