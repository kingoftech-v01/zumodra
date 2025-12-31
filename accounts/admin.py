"""
Accounts Admin - Admin configuration for KYC and user management.
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import (
    TenantUser, UserProfile, KYCVerification,
    ProgressiveConsent, DataAccessLog, LoginHistory,
    TrustScore, EmploymentVerification, EducationVerification,
    Review, CandidateCV, StudentProfile, CoopTerm
)


@admin.register(TenantUser)
class TenantUserAdmin(admin.ModelAdmin):
    list_display = ['user', 'tenant', 'role', 'department', 'is_active', 'joined_at']
    list_filter = ['role', 'is_active', 'tenant']
    search_fields = ['user__email', 'user__first_name', 'user__last_name', 'tenant__name']
    raw_id_fields = ['user', 'tenant', 'department', 'reports_to']
    readonly_fields = ['uuid', 'joined_at', 'last_active_at']


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'profile_type', 'phone', 'city', 'country', 'completion_badge']
    list_filter = ['profile_type', 'country', 'phone_verified']
    search_fields = ['user__email', 'phone', 'city']
    readonly_fields = ['uuid', 'created_at', 'updated_at', 'completion_percentage']

    def completion_badge(self, obj):
        pct = obj.completion_percentage
        if pct >= 80:
            color = 'green'
        elif pct >= 50:
            color = 'orange'
        else:
            color = 'red'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, f"{pct}%"
        )
    completion_badge.short_description = 'Completion'


@admin.register(KYCVerification)
class KYCVerificationAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'verification_type', 'status_badge', 'level',
        'provider', 'confidence_score', 'created_at'
    ]
    list_filter = ['status', 'verification_type', 'level', 'provider']
    search_fields = ['user__email', 'provider_reference_id']
    readonly_fields = [
        'uuid', 'created_at', 'updated_at', 'submitted_at',
        'verified_at', 'provider_response'
    ]
    raw_id_fields = ['user', 'verified_by']

    fieldsets = (
        ('User', {
            'fields': ('user', 'verification_type', 'level')
        }),
        ('Status', {
            'fields': ('status', 'confidence_score', 'rejection_reason')
        }),
        ('Provider', {
            'fields': ('provider', 'provider_reference_id', 'provider_response')
        }),
        ('Document', {
            'fields': (
                'document_type', 'document_number_hash',
                'document_country', 'document_expiry'
            ),
            'classes': ('collapse',)
        }),
        ('Audit', {
            'fields': ('verified_by', 'notes', 'verified_data')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'submitted_at', 'verified_at', 'expires_at'),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'pending': 'orange',
            'in_progress': 'blue',
            'verified': 'green',
            'rejected': 'red',
            'expired': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(ProgressiveConsent)
class ProgressiveConsentAdmin(admin.ModelAdmin):
    list_display = [
        'grantor', 'grantee_display', 'data_category',
        'status', 'requested_at', 'expires_at'
    ]
    list_filter = ['status', 'data_category']
    search_fields = ['grantor__email', 'grantee_user__email', 'grantee_tenant__name']
    readonly_fields = ['uuid', 'requested_at', 'responded_at', 'revoked_at']

    def grantee_display(self, obj):
        if obj.grantee_user:
            return obj.grantee_user.email
        if obj.grantee_tenant:
            return f"[Tenant] {obj.grantee_tenant.name}"
        return "N/A"
    grantee_display.short_description = 'Grantee'


@admin.register(DataAccessLog)
class DataAccessLogAdmin(admin.ModelAdmin):
    list_display = [
        'accessor', 'data_subject', 'data_category',
        'ip_address', 'accessed_at'
    ]
    list_filter = ['data_category', 'accessed_at']
    search_fields = ['accessor__email', 'data_subject__email', 'ip_address']
    readonly_fields = [
        'uuid', 'accessor', 'data_subject', 'data_category',
        'data_fields', 'ip_address', 'user_agent', 'accessed_at'
    ]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    list_display = ['user', 'result', 'ip_address', 'timestamp']
    list_filter = ['result', 'timestamp']
    search_fields = ['user__email', 'ip_address']
    readonly_fields = [
        'user', 'result', 'ip_address', 'user_agent',
        'location', 'device_fingerprint', 'timestamp'
    ]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


# =============================================================================
# TRUST SYSTEM MODELS
# =============================================================================

@admin.register(TrustScore)
class TrustScoreAdmin(admin.ModelAdmin):
    """Admin for TrustScore model - Multi-dimensional trust scoring."""
    list_display = [
        'user', 'entity_type', 'trust_level_badge', 'overall_score_display',
        'is_id_verified', 'is_career_verified', 'total_reviews',
        'completed_jobs', 'updated_at'
    ]
    list_filter = [
        'entity_type', 'trust_level', 'is_id_verified', 'is_career_verified'
    ]
    search_fields = ['user__email', 'user__first_name', 'user__last_name']
    readonly_fields = [
        'uuid', 'created_at', 'updated_at', 'last_calculated_at',
        'overall_score', 'identity_score', 'career_score', 'activity_score',
        'review_score', 'dispute_score', 'payment_score'
    ]
    ordering = ['-overall_score', '-updated_at']

    fieldsets = (
        ('User', {
            'fields': ('user', 'uuid', 'entity_type', 'trust_level')
        }),
        ('Composite Scores', {
            'fields': (
                'overall_score', 'identity_score', 'career_score',
                'activity_score', 'review_score', 'dispute_score', 'payment_score'
            )
        }),
        ('Verification Status', {
            'fields': (
                'is_id_verified', 'is_career_verified',
                'verified_employment_count', 'total_employment_count',
                'verified_education_count', 'total_education_count'
            )
        }),
        ('Activity Metrics', {
            'fields': (
                'completed_jobs', 'total_contracts', 'successful_hires',
                'on_time_deliveries'
            )
        }),
        ('Review Metrics', {
            'fields': (
                'total_reviews', 'positive_reviews', 'negative_reviews',
                'average_rating'
            )
        }),
        ('Dispute Metrics', {
            'fields': (
                'total_disputes', 'disputes_won', 'disputes_lost', 'disputes_pending'
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'last_calculated_at'),
            'classes': ('collapse',)
        }),
    )

    def trust_level_badge(self, obj):
        colors = {
            'new': 'gray',
            'basic': 'blue',
            'verified': 'teal',
            'high': 'green',
            'premium': 'gold',
        }
        color = colors.get(obj.trust_level, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_trust_level_display()
        )
    trust_level_badge.short_description = 'Trust Level'

    def overall_score_display(self, obj):
        score = float(obj.overall_score)
        if score >= 70:
            color = 'green'
        elif score >= 40:
            color = 'orange'
        else:
            color = 'red'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.1f}</span>',
            color, score
        )
    overall_score_display.short_description = 'Score'


@admin.register(EmploymentVerification)
class EmploymentVerificationAdmin(admin.ModelAdmin):
    """Admin for EmploymentVerification model - Employment verification workflow."""
    list_display = [
        'user', 'company_name', 'job_title', 'status_badge',
        'employment_type', 'start_date', 'end_date', 'is_current'
    ]
    list_filter = ['status', 'employment_type', 'is_current', 'created_at']
    search_fields = [
        'user__email', 'company_name', 'job_title', 'hr_contact_email'
    ]
    readonly_fields = [
        'uuid', 'verification_token', 'token_expires_at',
        'created_at', 'updated_at', 'request_sent_at',
        'reminder_sent_at', 'verified_at'
    ]
    raw_id_fields = ['user']
    ordering = ['-start_date']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('User', {
            'fields': ('user', 'uuid')
        }),
        ('Employment Details', {
            'fields': (
                'company_name', 'job_title', 'employment_type',
                'start_date', 'end_date', 'is_current', 'description'
            )
        }),
        ('Verification Contact', {
            'fields': (
                'hr_contact_email', 'hr_contact_name', 'hr_contact_phone',
                'company_domain'
            )
        }),
        ('Status', {
            'fields': ('status', 'verification_token', 'token_expires_at')
        }),
        ('Verification Response', {
            'fields': (
                'verified_by_email', 'verified_by_name', 'verification_response',
                'response_notes', 'dates_confirmed', 'title_confirmed',
                'eligible_for_rehire', 'performance_rating'
            ),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': (
                'created_at', 'updated_at', 'request_sent_at',
                'reminder_sent_at', 'verified_at', 'expires_at'
            ),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'unverified': 'gray',
            'pending': 'orange',
            'in_progress': 'blue',
            'verified': 'green',
            'disputed': 'red',
            'unable': 'darkgray',
            'expired': 'lightgray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(EducationVerification)
class EducationVerificationAdmin(admin.ModelAdmin):
    """Admin for EducationVerification model - Education verification workflow."""
    list_display = [
        'user', 'institution_name', 'degree_type', 'field_of_study',
        'status_badge', 'verification_method', 'graduated'
    ]
    list_filter = [
        'status', 'degree_type', 'institution_type',
        'verification_method', 'graduated'
    ]
    search_fields = [
        'user__email', 'institution_name', 'field_of_study'
    ]
    readonly_fields = [
        'uuid', 'verification_token', 'token_expires_at',
        'created_at', 'updated_at', 'request_sent_at', 'verified_at'
    ]
    raw_id_fields = ['user']
    ordering = ['-end_date', '-start_date']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('User', {
            'fields': ('user', 'uuid')
        }),
        ('Education Details', {
            'fields': (
                'institution_name', 'institution_type', 'degree_type',
                'field_of_study', 'start_date', 'end_date', 'is_current',
                'graduated', 'gpa', 'honors'
            )
        }),
        ('Institution Contact', {
            'fields': (
                'registrar_email', 'institution_domain', 'student_id'
            )
        }),
        ('Verification', {
            'fields': (
                'verification_method', 'status',
                'verification_token', 'token_expires_at'
            )
        }),
        ('Documents', {
            'fields': ('transcript_file', 'diploma_file'),
            'classes': ('collapse',)
        }),
        ('Verification Response', {
            'fields': (
                'verified_by', 'verification_response',
                'degree_confirmed', 'dates_confirmed', 'graduation_confirmed'
            ),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': (
                'created_at', 'updated_at', 'request_sent_at',
                'verified_at', 'expires_at'
            ),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'unverified': 'gray',
            'pending': 'orange',
            'in_progress': 'blue',
            'verified': 'green',
            'disputed': 'red',
            'unable': 'darkgray',
            'expired': 'lightgray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    """Admin for Review model - Review system with AI verification."""
    list_display = [
        'reviewer', 'reviewee', 'review_type', 'overall_rating_display',
        'status_badge', 'is_negative', 'ai_flagged', 'created_at'
    ]
    list_filter = [
        'review_type', 'status', 'overall_rating', 'is_negative',
        'ai_flagged', 'requires_verification'
    ]
    search_fields = [
        'reviewer__email', 'reviewee__email', 'title', 'content'
    ]
    readonly_fields = [
        'uuid', 'created_at', 'updated_at', 'published_at',
        'disputed_at', 'resolved_at', 'is_negative',
        'trust_impact_applied', 'trust_impact_score'
    ]
    raw_id_fields = ['reviewer', 'reviewee']
    ordering = ['-created_at']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Participants', {
            'fields': ('uuid', 'reviewer', 'reviewee', 'review_type')
        }),
        ('Context', {
            'fields': ('context_type', 'context_id')
        }),
        ('Ratings', {
            'fields': (
                'overall_rating', 'communication_rating', 'professionalism_rating',
                'quality_rating', 'timeliness_rating', 'would_recommend',
                'would_work_again'
            )
        }),
        ('Content', {
            'fields': ('title', 'content', 'pros', 'cons')
        }),
        ('Status', {
            'fields': ('status', 'is_negative', 'requires_verification')
        }),
        ('AI Analysis', {
            'fields': ('ai_analysis', 'ai_flagged', 'ai_confidence_score'),
            'classes': ('collapse',)
        }),
        ('Verification/Mediation', {
            'fields': (
                'evidence_submitted', 'reviewee_response', 'reviewee_evidence',
                'mediation_notes', 'mediation_outcome'
            ),
            'classes': ('collapse',)
        }),
        ('Trust Impact', {
            'fields': ('trust_impact_applied', 'trust_impact_score'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': (
                'created_at', 'updated_at', 'published_at',
                'disputed_at', 'resolved_at'
            ),
            'classes': ('collapse',)
        }),
    )

    def overall_rating_display(self, obj):
        rating = obj.overall_rating
        if rating >= 4:
            color = 'green'
        elif rating >= 3:
            color = 'orange'
        else:
            color = 'red'
        stars = '★' * rating + '☆' * (5 - rating)
        return format_html(
            '<span style="color: {};">{}</span>',
            color, stars
        )
    overall_rating_display.short_description = 'Rating'

    def status_badge(self, obj):
        colors = {
            'pending': 'orange',
            'published': 'green',
            'under_review': 'blue',
            'disputed': 'red',
            'validated': 'teal',
            'rejected': 'darkred',
            'hidden': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


# =============================================================================
# MULTI-CV SYSTEM
# =============================================================================

@admin.register(CandidateCV)
class CandidateCVAdmin(admin.ModelAdmin):
    """Admin for CandidateCV model - Multi-CV system."""
    list_display = [
        'user', 'name', 'status_badge', 'is_primary',
        'ai_score_display', 'ats_compatibility_score',
        'times_used', 'applications_count', 'updated_at'
    ]
    list_filter = ['status', 'is_primary', 'created_at']
    search_fields = ['user__email', 'name', 'headline', 'target_job_types']
    readonly_fields = [
        'uuid', 'slug', 'created_at', 'updated_at',
        'times_used', 'applications_count', 'last_used_at',
        'ai_score', 'ai_feedback', 'ats_compatibility_score',
        'interview_rate', 'last_analyzed_at'
    ]
    raw_id_fields = ['user']
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['-is_primary', '-updated_at']

    fieldsets = (
        ('Identity', {
            'fields': ('user', 'uuid', 'name', 'slug', 'is_primary', 'status')
        }),
        ('Target', {
            'fields': ('target_job_types', 'target_industries', 'target_keywords')
        }),
        ('Content', {
            'fields': ('headline', 'summary')
        }),
        ('Skills', {
            'fields': ('skills', 'highlighted_skills')
        }),
        ('Experience & Education', {
            'fields': (
                'included_experiences', 'experience_order', 'included_education'
            ),
            'classes': ('collapse',)
        }),
        ('Projects & Certifications', {
            'fields': ('projects', 'certifications'),
            'classes': ('collapse',)
        }),
        ('File Upload', {
            'fields': ('cv_file', 'cv_file_parsed'),
            'classes': ('collapse',)
        }),
        ('AI Analysis', {
            'fields': (
                'ai_score', 'ai_feedback', 'ats_compatibility_score',
                'last_analyzed_at'
            )
        }),
        ('Usage Statistics', {
            'fields': (
                'times_used', 'last_used_at', 'applications_count',
                'interview_rate'
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'draft': 'gray',
            'active': 'green',
            'archived': 'orange',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def ai_score_display(self, obj):
        if obj.ai_score is None:
            return format_html('<span style="color: gray;">-</span>')
        score = float(obj.ai_score)
        if score >= 80:
            color = 'green'
        elif score >= 60:
            color = 'orange'
        else:
            color = 'red'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.1f}</span>',
            color, score
        )
    ai_score_display.short_description = 'AI Score'


# =============================================================================
# CO-OP / STUDENT ECOSYSTEM
# =============================================================================

@admin.register(StudentProfile)
class StudentProfileAdmin(admin.ModelAdmin):
    """Admin for StudentProfile model - Student profile for co-op ecosystem."""
    list_display = [
        'user', 'institution_name', 'program_name', 'student_type',
        'enrollment_status_badge', 'program_type', 'current_year',
        'work_terms_completed', 'enrollment_verified'
    ]
    list_filter = [
        'student_type', 'program_type', 'enrollment_status',
        'enrollment_verified', 'work_authorization'
    ]
    search_fields = [
        'user__email', 'institution_name', 'program_name',
        'major', 'student_id'
    ]
    readonly_fields = [
        'uuid', 'created_at', 'updated_at', 'enrollment_verified_at'
    ]
    raw_id_fields = ['user']
    ordering = ['-created_at']

    fieldsets = (
        ('User', {
            'fields': ('user', 'uuid')
        }),
        ('Student Type', {
            'fields': ('student_type', 'program_type')
        }),
        ('Institution', {
            'fields': (
                'institution_name', 'institution_type',
                'institution_email_domain', 'student_email', 'student_id'
            )
        }),
        ('Program Details', {
            'fields': (
                'program_name', 'faculty', 'major', 'minor',
                'expected_graduation', 'current_year', 'current_term'
            )
        }),
        ('Enrollment Status', {
            'fields': (
                'enrollment_status', 'enrollment_verified',
                'enrollment_verified_at'
            )
        }),
        ('Co-op Program', {
            'fields': (
                'coop_sequence', 'work_terms_completed', 'work_terms_required',
                'next_work_term_start', 'next_work_term_end'
            )
        }),
        ('GPA', {
            'fields': ('gpa', 'gpa_scale', 'gpa_verified'),
            'classes': ('collapse',)
        }),
        ('Skills & Interests', {
            'fields': (
                'skills', 'interests', 'preferred_industries',
                'preferred_locations', 'remote_preference'
            ),
            'classes': ('collapse',)
        }),
        ('Work Authorization', {
            'fields': ('work_authorization', 'work_permit_expiry'),
            'classes': ('collapse',)
        }),
        ('Co-op Coordinator', {
            'fields': ('coordinator_name', 'coordinator_email'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def enrollment_status_badge(self, obj):
        colors = {
            'active': 'green',
            'on_coop': 'blue',
            'graduated': 'teal',
            'withdrawn': 'gray',
            'suspended': 'red',
        }
        color = colors.get(obj.enrollment_status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_enrollment_status_display()
        )
    enrollment_status_badge.short_description = 'Enrollment'


@admin.register(CoopTerm)
class CoopTermAdmin(admin.ModelAdmin):
    """Admin for CoopTerm model - Individual co-op work term tracking."""
    list_display = [
        'student_display', 'term_number', 'term_name', 'status_badge',
        'employer_name', 'job_title', 'start_date', 'end_date',
        'school_approved'
    ]
    list_filter = [
        'status', 'school_approved', 'is_remote', 'start_date'
    ]
    search_fields = [
        'student__user__email', 'employer_name', 'job_title',
        'term_name'
    ]
    readonly_fields = [
        'uuid', 'created_at', 'updated_at', 'school_approved_at'
    ]
    raw_id_fields = ['student', 'employer_tenant']
    ordering = ['student', 'term_number']
    date_hierarchy = 'start_date'

    fieldsets = (
        ('Student', {
            'fields': ('student', 'uuid')
        }),
        ('Term Details', {
            'fields': (
                'term_number', 'term_name', 'start_date', 'end_date', 'status'
            )
        }),
        ('Employer/Position', {
            'fields': (
                'employer_name', 'employer_tenant', 'job_title',
                'job_description', 'location', 'is_remote'
            )
        }),
        ('Compensation', {
            'fields': ('hourly_rate', 'currency')
        }),
        ('Evaluation', {
            'fields': (
                'employer_evaluation', 'employer_rating',
                'student_evaluation', 'student_rating', 'work_term_report'
            ),
            'classes': ('collapse',)
        }),
        ('School Approval', {
            'fields': (
                'school_approved', 'school_approved_by',
                'school_approved_at', 'school_notes'
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def student_display(self, obj):
        return obj.student.user.email
    student_display.short_description = 'Student'

    def status_badge(self, obj):
        colors = {
            'searching': 'orange',
            'matched': 'blue',
            'confirmed': 'teal',
            'in_progress': 'green',
            'completed': 'darkgreen',
            'cancelled': 'red',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
