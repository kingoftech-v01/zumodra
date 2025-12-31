"""
Django Admin Configuration for AI Matching

This module provides admin interface for managing AI matching models.
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import (
    SkillEmbedding, JobEmbedding, CandidateEmbedding,
    MatchingResult, RecommendationLog, BiasAuditLog, AIServiceStatus,
    RankingProfile, RankingRule, CandidateRanking
)


@admin.register(SkillEmbedding)
class SkillEmbeddingAdmin(admin.ModelAdmin):
    """Admin for SkillEmbedding model."""
    list_display = ['skill', 'embedding_model', 'created_at', 'updated_at']
    list_filter = ['embedding_model', 'created_at']
    search_fields = ['skill__name']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-updated_at']


@admin.register(JobEmbedding)
class JobEmbeddingAdmin(admin.ModelAdmin):
    """Admin for JobEmbedding model."""
    list_display = [
        'job', 'embedding_model', 'skills_count',
        'experience_range', 'is_remote', 'updated_at'
    ]
    list_filter = ['embedding_model', 'is_remote', 'created_at']
    search_fields = ['job__title', 'skills_extracted']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-updated_at']

    def skills_count(self, obj):
        return len(obj.skills_extracted) if obj.skills_extracted else 0
    skills_count.short_description = 'Skills Count'

    def experience_range(self, obj):
        if obj.experience_years_min is not None and obj.experience_years_max is not None:
            return f"{obj.experience_years_min}-{obj.experience_years_max} years"
        return "-"
    experience_range.short_description = 'Experience'


@admin.register(CandidateEmbedding)
class CandidateEmbeddingAdmin(admin.ModelAdmin):
    """Admin for CandidateEmbedding model."""
    list_display = [
        'candidate', 'embedding_model', 'skills_count',
        'total_experience_years', 'updated_at'
    ]
    list_filter = ['embedding_model', 'created_at']
    search_fields = ['candidate__user__email', 'skills_extracted']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-updated_at']

    def skills_count(self, obj):
        return len(obj.skills_extracted) if obj.skills_extracted else 0
    skills_count.short_description = 'Skills Count'


@admin.register(MatchingResult)
class MatchingResultAdmin(admin.ModelAdmin):
    """Admin for MatchingResult model."""
    list_display = [
        'uuid', 'candidate_email', 'job_title', 'overall_score_display',
        'matching_algorithm', 'confidence_level', 'is_stale', 'calculated_at'
    ]
    list_filter = [
        'matching_algorithm', 'confidence_level', 'is_stale', 'calculated_at'
    ]
    search_fields = ['candidate__user__email', 'job__title']
    readonly_fields = [
        'uuid', 'calculated_at', 'overall_score', 'skill_score',
        'experience_score', 'location_score', 'salary_score',
        'culture_score', 'education_score'
    ]
    ordering = ['-overall_score', '-calculated_at']
    date_hierarchy = 'calculated_at'

    fieldsets = (
        ('Match Info', {
            'fields': ('uuid', 'candidate', 'job', 'matching_algorithm', 'confidence_level')
        }),
        ('Scores', {
            'fields': (
                'overall_score', 'skill_score', 'experience_score',
                'location_score', 'salary_score', 'culture_score', 'education_score'
            )
        }),
        ('Skills Analysis', {
            'fields': ('matched_skills', 'missing_skills')
        }),
        ('Status', {
            'fields': ('is_stale', 'expires_at', 'calculated_at')
        }),
        ('Details', {
            'fields': ('explanation',),
            'classes': ('collapse',)
        }),
    )

    def candidate_email(self, obj):
        return obj.candidate.user.email
    candidate_email.short_description = 'Candidate'

    def job_title(self, obj):
        return obj.job.title
    job_title.short_description = 'Job'

    def overall_score_display(self, obj):
        score = float(obj.overall_score)
        if score >= 0.7:
            color = 'green'
        elif score >= 0.4:
            color = 'orange'
        else:
            color = 'red'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.2%}</span>',
            color, score
        )
    overall_score_display.short_description = 'Score'


@admin.register(RecommendationLog)
class RecommendationLogAdmin(admin.ModelAdmin):
    """Admin for RecommendationLog model."""
    list_display = [
        'uuid', 'user', 'recommendation_type', 'items_count',
        'user_rating', 'fallback_used', 'processing_time_ms', 'created_at'
    ]
    list_filter = [
        'recommendation_type', 'fallback_used', 'user_rating', 'created_at'
    ]
    search_fields = ['user__email']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    ordering = ['-created_at']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Request Info', {
            'fields': ('uuid', 'user', 'recommendation_type', 'context')
        }),
        ('Results', {
            'fields': ('recommended_items', 'recommendation_scores')
        }),
        ('User Interaction', {
            'fields': ('items_viewed', 'items_clicked', 'items_applied')
        }),
        ('Feedback', {
            'fields': ('user_rating', 'user_feedback')
        }),
        ('Technical', {
            'fields': (
                'algorithm_version', 'model_used', 'fallback_used',
                'processing_time_ms', 'created_at'
            )
        }),
    )

    def items_count(self, obj):
        return len(obj.recommended_items) if obj.recommended_items else 0
    items_count.short_description = 'Items'


@admin.register(BiasAuditLog)
class BiasAuditLogAdmin(admin.ModelAdmin):
    """Admin for BiasAuditLog model."""
    list_display = [
        'uuid', 'content_type', 'content_id', 'bias_detected_display',
        'bias_score_display', 'action_taken', 'automated', 'created_at'
    ]
    list_filter = [
        'content_type', 'bias_detected', 'action_taken', 'automated', 'created_at'
    ]
    search_fields = ['content_id', 'flagged_phrases']
    readonly_fields = ['uuid', 'created_at']
    ordering = ['-created_at']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Content Info', {
            'fields': ('uuid', 'content_type', 'content_id')
        }),
        ('Bias Analysis', {
            'fields': ('bias_detected', 'bias_types', 'bias_score', 'flagged_phrases')
        }),
        ('Recommendations', {
            'fields': ('suggestions',)
        }),
        ('Action', {
            'fields': ('action_taken', 'action_notes', 'auditor', 'automated')
        }),
        ('Timestamps', {
            'fields': ('created_at',)
        }),
    )

    def bias_detected_display(self, obj):
        if obj.bias_detected:
            return format_html('<span style="color: red;">Yes</span>')
        return format_html('<span style="color: green;">No</span>')
    bias_detected_display.short_description = 'Bias Detected'

    def bias_score_display(self, obj):
        if obj.bias_score is None:
            return "-"
        score = float(obj.bias_score)
        if score >= 0.5:
            color = 'red'
        elif score >= 0.2:
            color = 'orange'
        else:
            color = 'green'
        return format_html(
            '<span style="color: {};">{:.2f}</span>',
            color, score
        )
    bias_score_display.short_description = 'Bias Score'


@admin.register(AIServiceStatus)
class AIServiceStatusAdmin(admin.ModelAdmin):
    """Admin for AIServiceStatus model."""
    list_display = [
        'service_name', 'availability_display', 'failure_count',
        'requests_today', 'daily_limit', 'usage_percent', 'last_check'
    ]
    list_filter = ['is_available', 'service_name']
    readonly_fields = ['last_check', 'last_success', 'last_failure']
    ordering = ['service_name']

    def availability_display(self, obj):
        if obj.is_available:
            return format_html(
                '<span style="color: green; font-weight: bold;">Available</span>'
            )
        return format_html(
            '<span style="color: red; font-weight: bold;">Unavailable</span>'
        )
    availability_display.short_description = 'Status'

    def usage_percent(self, obj):
        if obj.daily_limit == 0:
            return "-"
        percent = (obj.requests_today / obj.daily_limit) * 100
        if percent >= 90:
            color = 'red'
        elif percent >= 70:
            color = 'orange'
        else:
            color = 'green'
        return format_html(
            '<span style="color: {};">{:.1f}%</span>',
            color, percent
        )
    usage_percent.short_description = 'Usage'

    actions = ['reset_failure_count', 'mark_available', 'mark_unavailable']

    def reset_failure_count(self, request, queryset):
        queryset.update(failure_count=0, is_available=True, error_message='')
        self.message_user(request, f"Reset {queryset.count()} service(s)")
    reset_failure_count.short_description = "Reset failure count and mark available"

    def mark_available(self, request, queryset):
        queryset.update(is_available=True)
        self.message_user(request, f"Marked {queryset.count()} service(s) as available")
    mark_available.short_description = "Mark as available"

    def mark_unavailable(self, request, queryset):
        queryset.update(is_available=False)
        self.message_user(request, f"Marked {queryset.count()} service(s) as unavailable")
    mark_unavailable.short_description = "Mark as unavailable"


# =============================================================================
# HYBRID RANKING ENGINE ADMIN CLASSES
# =============================================================================

@admin.register(RankingProfile)
class RankingProfileAdmin(admin.ModelAdmin):
    """
    Admin for RankingProfile model.

    Tenant-configurable ranking profiles with weighted scoring components.
    Implements features.md Section 4.1-4.3 for transparent AI ranking.
    """
    list_display = [
        'name', 'tenant', 'is_default_badge', 'is_active_badge',
        'weights_display', 'minimum_overall_score', 'knockouts_count_display',
        'weights_valid_badge', 'created_at', 'updated_at'
    ]
    list_filter = ['is_default', 'is_active', 'tenant', 'created_at']
    search_fields = ['name', 'description', 'tenant__name']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['tenant', 'created_by', 'updated_by']
    ordering = ['-is_default', 'name']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Identity', {
            'fields': ('tenant', 'uuid', 'name', 'description', 'is_default', 'is_active')
        }),
        ('Main Weights (must sum to 1.0)', {
            'fields': (
                'rule_score_weight', 'ai_score_weight', 'verification_score_weight'
            ),
            'description': 'These weights determine the contribution of each scoring component to the overall score.'
        }),
        ('AI Component Weights (must sum to 1.0)', {
            'fields': (
                'skill_match_weight', 'experience_match_weight',
                'culture_fit_weight', 'location_match_weight', 'salary_match_weight'
            ),
            'classes': ('collapse',)
        }),
        ('Verification Component Weights (must sum to 1.0)', {
            'fields': (
                'identity_verification_weight', 'career_verification_weight',
                'trust_score_weight'
            ),
            'classes': ('collapse',)
        }),
        ('Thresholds', {
            'fields': (
                'minimum_rule_score', 'minimum_ai_score',
                'minimum_verification_score', 'minimum_overall_score'
            )
        }),
        ('Knockout Rules', {
            'fields': (
                'knockout_on_missing_required_skills',
                'knockout_on_experience_mismatch',
                'knockout_on_location_mismatch',
                'knockout_on_salary_mismatch',
                'knockout_on_education_mismatch'
            ),
            'classes': ('collapse',)
        }),
        ('Bonuses', {
            'fields': (
                'bonus_for_verified_career',
                'bonus_for_premium_trust',
                'bonus_for_platform_experience'
            ),
            'classes': ('collapse',)
        }),
        ('Audit', {
            'fields': ('created_by', 'updated_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def is_default_badge(self, obj):
        """Display colored badge for default status."""
        if obj.is_default:
            return format_html(
                '<span style="background-color: #28a745; color: white; padding: 3px 8px; '
                'border-radius: 4px; font-weight: bold;">Default</span>'
            )
        return format_html(
            '<span style="background-color: #6c757d; color: white; padding: 3px 8px; '
            'border-radius: 4px;">Custom</span>'
        )
    is_default_badge.short_description = 'Type'

    def is_active_badge(self, obj):
        """Display colored badge for active status."""
        if obj.is_active:
            return format_html(
                '<span style="color: green; font-weight: bold;">Active</span>'
            )
        return format_html(
            '<span style="color: red; font-weight: bold;">Inactive</span>'
        )
    is_active_badge.short_description = 'Status'

    def weights_display(self, obj):
        """Display weight distribution with visual indicators."""
        return format_html(
            '<span title="Rule | AI | Verification">'
            'R:<b>{:.0%}</b> | A:<b>{:.0%}</b> | V:<b>{:.0%}</b></span>',
            float(obj.rule_score_weight),
            float(obj.ai_score_weight),
            float(obj.verification_score_weight)
        )
    weights_display.short_description = 'Weights (R|A|V)'

    def knockouts_count_display(self, obj):
        """Display count of active knockout rules with color coding."""
        count = sum([
            obj.knockout_on_missing_required_skills,
            obj.knockout_on_experience_mismatch,
            obj.knockout_on_location_mismatch,
            obj.knockout_on_salary_mismatch,
            obj.knockout_on_education_mismatch
        ])
        if count == 0:
            return format_html('<span style="color: #6c757d;">None</span>')
        elif count <= 2:
            color = 'orange'
        else:
            color = 'red'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{} active</span>',
            color, count
        )
    knockouts_count_display.short_description = 'Knockouts'

    def weights_valid_badge(self, obj):
        """Display validation status for weight configuration."""
        if obj.validate_weights():
            return format_html(
                '<span style="background-color: #28a745; color: white; padding: 2px 6px; '
                'border-radius: 3px;">Valid</span>'
            )
        return format_html(
            '<span style="background-color: #dc3545; color: white; padding: 2px 6px; '
            'border-radius: 3px;">Invalid</span>'
        )
    weights_valid_badge.short_description = 'Weights'

    actions = ['set_as_default', 'activate_profiles', 'deactivate_profiles']

    def set_as_default(self, request, queryset):
        """Set selected profile as default for its tenant."""
        if queryset.count() != 1:
            self.message_user(
                request,
                "Please select exactly one profile to set as default.",
                level='error'
            )
            return
        profile = queryset.first()
        RankingProfile.objects.filter(
            tenant=profile.tenant, is_default=True
        ).update(is_default=False)
        profile.is_default = True
        profile.save()
        self.message_user(request, f"'{profile.name}' is now the default profile.")
    set_as_default.short_description = "Set as default profile"

    def activate_profiles(self, request, queryset):
        """Activate selected profiles."""
        count = queryset.update(is_active=True)
        self.message_user(request, f"Activated {count} profile(s).")
    activate_profiles.short_description = "Activate selected profiles"

    def deactivate_profiles(self, request, queryset):
        """Deactivate selected profiles."""
        count = queryset.update(is_active=False)
        self.message_user(request, f"Deactivated {count} profile(s).")
    deactivate_profiles.short_description = "Deactivate selected profiles"


@admin.register(RankingRule)
class RankingRuleAdmin(admin.ModelAdmin):
    """
    Admin for RankingRule model.

    Deterministic ranking rules for ATS filtering with knockout,
    preference, and bonus rule types.
    """
    list_display = [
        'name', 'tenant', 'rule_type_badge', 'field_type_display',
        'operator_display', 'weight_display', 'priority', 'is_active_badge',
        'apply_to_all_jobs', 'updated_at'
    ]
    list_filter = [
        'rule_type', 'field_type', 'operator', 'is_active',
        'apply_to_all_jobs', 'tenant'
    ]
    search_fields = ['name', 'description', 'tenant__name', 'job_categories']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    raw_id_fields = ['tenant']
    ordering = ['priority', 'name']

    fieldsets = (
        ('Identity', {
            'fields': ('tenant', 'uuid', 'name', 'description', 'is_active')
        }),
        ('Rule Configuration', {
            'fields': ('rule_type', 'field_type', 'operator', 'target_value', 'weight')
        }),
        ('Scope', {
            'fields': ('apply_to_all_jobs', 'job_categories', 'priority')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def rule_type_badge(self, obj):
        """Display colored badge for rule type."""
        colors = {
            'knockout': ('#dc3545', 'white'),  # Red for knockout
            'preference': ('#007bff', 'white'),  # Blue for preference
            'bonus': ('#28a745', 'white'),  # Green for bonus
        }
        bg_color, text_color = colors.get(obj.rule_type, ('#6c757d', 'white'))
        return format_html(
            '<span style="background-color: {}; color: {}; padding: 3px 8px; '
            'border-radius: 4px; font-weight: bold;">{}</span>',
            bg_color, text_color, obj.get_rule_type_display()
        )
    rule_type_badge.short_description = 'Type'

    def field_type_display(self, obj):
        """Display field type with icon."""
        return format_html(
            '<code style="background-color: #f8f9fa; padding: 2px 6px; '
            'border-radius: 3px;">{}</code>',
            obj.get_field_type_display()
        )
    field_type_display.short_description = 'Field'

    def operator_display(self, obj):
        """Display operator with styled code formatting."""
        return format_html(
            '<code style="background-color: #e9ecef; padding: 2px 6px; '
            'border-radius: 3px; font-weight: bold;">{}</code>',
            obj.get_operator_display()
        )
    operator_display.short_description = 'Operator'

    def weight_display(self, obj):
        """Display weight with color coding based on value."""
        weight = float(obj.weight)
        if weight >= 5:
            color = 'green'
        elif weight >= 2:
            color = 'orange'
        else:
            color = '#6c757d'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.2f}</span>',
            color, weight
        )
    weight_display.short_description = 'Weight'

    def is_active_badge(self, obj):
        """Display colored badge for active status."""
        if obj.is_active:
            return format_html(
                '<span style="color: green; font-weight: bold;">Active</span>'
            )
        return format_html(
            '<span style="color: red; font-weight: bold;">Inactive</span>'
        )
    is_active_badge.short_description = 'Status'

    actions = [
        'activate_rules', 'deactivate_rules',
        'set_as_knockout', 'set_as_preference', 'set_as_bonus'
    ]

    def activate_rules(self, request, queryset):
        """Activate selected rules."""
        count = queryset.update(is_active=True)
        self.message_user(request, f"Activated {count} rule(s).")
    activate_rules.short_description = "Activate selected rules"

    def deactivate_rules(self, request, queryset):
        """Deactivate selected rules."""
        count = queryset.update(is_active=False)
        self.message_user(request, f"Deactivated {count} rule(s).")
    deactivate_rules.short_description = "Deactivate selected rules"

    def set_as_knockout(self, request, queryset):
        """Set selected rules as knockout type."""
        count = queryset.update(rule_type='knockout')
        self.message_user(request, f"Set {count} rule(s) as knockout.")
    set_as_knockout.short_description = "Set as knockout rule"

    def set_as_preference(self, request, queryset):
        """Set selected rules as preference type."""
        count = queryset.update(rule_type='preference')
        self.message_user(request, f"Set {count} rule(s) as preference.")
    set_as_preference.short_description = "Set as preference rule"

    def set_as_bonus(self, request, queryset):
        """Set selected rules as bonus type."""
        count = queryset.update(rule_type='bonus')
        self.message_user(request, f"Set {count} rule(s) as bonus.")
    set_as_bonus.short_description = "Set as bonus rule"


@admin.register(CandidateRanking)
class CandidateRankingAdmin(admin.ModelAdmin):
    """
    Admin for CandidateRanking model.

    Computed rankings for candidate-job pairs with transparent
    three-score breakdown and explainable ranking factors.
    """
    list_display = [
        'uuid_short', 'job_id', 'candidate_id', 'overall_score_badge',
        'rule_score_badge', 'ai_score_badge', 'verification_score_badge',
        'passed_knockout_badge', 'is_recommended_badge', 'rank_position',
        'calculated_at'
    ]
    list_filter = [
        'passed_knockout', 'is_recommended', 'ranking_profile',
        'tenant', 'calculated_at'
    ]
    search_fields = ['job_id', 'candidate_id', 'tenant__name']
    readonly_fields = [
        'uuid', 'calculated_at', 'recalculated_at',
        'overall_score', 'rule_score', 'ai_score', 'verification_score',
        'skill_match_score', 'experience_match_score', 'culture_fit_score',
        'location_match_score', 'salary_match_score',
        'identity_verification_score', 'career_verification_score', 'trust_score_value',
        'bonus_points', 'bonuses_applied', 'passed_knockout', 'knockout_reasons',
        'rules_evaluated', 'rules_passed', 'rule_details',
        'ranking_explanation', 'top_strengths', 'improvement_areas',
        'is_recommended', 'rank_position'
    ]
    raw_id_fields = ['tenant', 'ranking_profile']
    ordering = ['-overall_score', '-calculated_at']
    date_hierarchy = 'calculated_at'

    fieldsets = (
        ('Identity', {
            'fields': ('tenant', 'uuid', 'job_id', 'candidate_id', 'ranking_profile')
        }),
        ('Overall Scores', {
            'fields': (
                'overall_score', 'rule_score', 'ai_score',
                'verification_score', 'bonus_points'
            )
        }),
        ('AI Component Breakdown', {
            'fields': (
                'skill_match_score', 'experience_match_score', 'culture_fit_score',
                'location_match_score', 'salary_match_score'
            ),
            'classes': ('collapse',)
        }),
        ('Verification Component Breakdown', {
            'fields': (
                'identity_verification_score', 'career_verification_score',
                'trust_score_value'
            ),
            'classes': ('collapse',)
        }),
        ('Knockout Status', {
            'fields': ('passed_knockout', 'knockout_reasons')
        }),
        ('Rule Evaluation', {
            'fields': ('rules_evaluated', 'rules_passed', 'rule_details'),
            'classes': ('collapse',)
        }),
        ('Bonuses', {
            'fields': ('bonuses_applied',),
            'classes': ('collapse',)
        }),
        ('Explanation', {
            'fields': ('ranking_explanation', 'top_strengths', 'improvement_areas'),
            'classes': ('collapse',)
        }),
        ('Status & Position', {
            'fields': ('is_recommended', 'rank_position')
        }),
        ('Timestamps', {
            'fields': ('calculated_at', 'recalculated_at'),
            'classes': ('collapse',)
        }),
    )

    def uuid_short(self, obj):
        """Display shortened UUID for list view."""
        return str(obj.uuid)[:8] + '...'
    uuid_short.short_description = 'UUID'

    def _score_badge(self, score, label=None):
        """Helper method to create colored score badges."""
        score_val = float(score)
        if score_val >= 70:
            color = '#28a745'  # Green
        elif score_val >= 40:
            color = '#fd7e14'  # Orange
        else:
            color = '#dc3545'  # Red
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.1f}</span>',
            color, score_val
        )

    def overall_score_badge(self, obj):
        """Display overall score with colored badge (green/orange/red)."""
        score = float(obj.overall_score)
        if score >= 70:
            bg_color = '#28a745'  # Green
        elif score >= 40:
            bg_color = '#fd7e14'  # Orange
        else:
            bg_color = '#dc3545'  # Red
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 4px; font-weight: bold; font-size: 1.1em;">{:.1f}</span>',
            bg_color, score
        )
    overall_score_badge.short_description = 'Overall'

    def rule_score_badge(self, obj):
        """Display rule score with color coding (green >= 70, orange >= 40, red < 40)."""
        return self._score_badge(obj.rule_score)
    rule_score_badge.short_description = 'Rules'

    def ai_score_badge(self, obj):
        """Display AI score with color coding (green >= 70, orange >= 40, red < 40)."""
        return self._score_badge(obj.ai_score)
    ai_score_badge.short_description = 'AI'

    def verification_score_badge(self, obj):
        """Display verification score with color coding (green >= 70, orange >= 40, red < 40)."""
        return self._score_badge(obj.verification_score)
    verification_score_badge.short_description = 'Verify'

    def passed_knockout_badge(self, obj):
        """Display knockout status with colored badge."""
        if obj.passed_knockout:
            return format_html(
                '<span style="background-color: #28a745; color: white; padding: 2px 6px; '
                'border-radius: 3px;">Passed</span>'
            )
        return format_html(
            '<span style="background-color: #dc3545; color: white; padding: 2px 6px; '
            'border-radius: 3px;">Failed</span>'
        )
    passed_knockout_badge.short_description = 'Knockout'

    def is_recommended_badge(self, obj):
        """Display recommendation status with styled badge."""
        if obj.is_recommended:
            return format_html(
                '<span style="background-color: #28a745; color: white; padding: 3px 10px; '
                'border-radius: 4px; font-weight: bold;">Recommended</span>'
            )
        return format_html(
            '<span style="background-color: #dc3545; color: white; padding: 3px 10px; '
            'border-radius: 4px;">Not Recommended</span>'
        )
    is_recommended_badge.short_description = 'Status'

    actions = [
        'recalculate_rankings', 'mark_as_recommended',
        'mark_as_not_recommended', 'generate_explanations'
    ]

    def recalculate_rankings(self, request, queryset):
        """Recalculate rankings using their associated profiles."""
        count = 0
        for ranking in queryset:
            ranking.calculate_overall()
            count += 1
        self.message_user(request, f"Recalculated {count} ranking(s).")
    recalculate_rankings.short_description = "Recalculate selected rankings"

    def mark_as_recommended(self, request, queryset):
        """Mark selected rankings as recommended."""
        count = queryset.update(is_recommended=True)
        self.message_user(request, f"Marked {count} ranking(s) as recommended.")
    mark_as_recommended.short_description = "Mark as recommended"

    def mark_as_not_recommended(self, request, queryset):
        """Mark selected rankings as not recommended."""
        count = queryset.update(is_recommended=False)
        self.message_user(request, f"Marked {count} ranking(s) as not recommended.")
    mark_as_not_recommended.short_description = "Mark as not recommended"

    def generate_explanations(self, request, queryset):
        """Generate human-readable explanations for rankings."""
        count = 0
        for ranking in queryset:
            ranking.generate_explanation()
            count += 1
        self.message_user(request, f"Generated explanations for {count} ranking(s).")
    generate_explanations.short_description = "Generate explanations"
