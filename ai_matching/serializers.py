"""
Serializers for AI Matching API

This module provides serializers for the AI matching REST API endpoints.
"""

from rest_framework import serializers
from decimal import Decimal

from configurations.models import (
    CandidateProfile, Job, Skill, WorkExperience, Education
)
from .models import (
    SkillEmbedding, JobEmbedding, CandidateEmbedding,
    MatchingResult, RecommendationLog, BiasAuditLog
)


# ============================================================================
# Input Serializers
# ============================================================================

class MatchCandidatesInputSerializer(serializers.Serializer):
    """Input serializer for matching candidates to a job."""
    job_id = serializers.IntegerField(
        help_text="ID of the job to match candidates for"
    )
    limit = serializers.IntegerField(
        default=20,
        min_value=1,
        max_value=100,
        help_text="Maximum number of candidates to return"
    )
    min_score = serializers.FloatField(
        default=0.0,
        min_value=0.0,
        max_value=1.0,
        required=False,
        help_text="Minimum match score threshold"
    )
    use_ai = serializers.BooleanField(
        default=True,
        help_text="Whether to use AI-based matching (falls back to rules if unavailable)"
    )
    filters = serializers.DictField(
        required=False,
        default=dict,
        help_text="Optional filters (e.g., min_experience, location)"
    )


class MatchJobsInputSerializer(serializers.Serializer):
    """Input serializer for matching jobs to a candidate."""
    candidate_id = serializers.IntegerField(
        help_text="ID of the candidate profile to find jobs for"
    )
    limit = serializers.IntegerField(
        default=20,
        min_value=1,
        max_value=100,
        help_text="Maximum number of jobs to return"
    )
    min_score = serializers.FloatField(
        default=0.0,
        min_value=0.0,
        max_value=1.0,
        required=False,
        help_text="Minimum match score threshold"
    )
    use_ai = serializers.BooleanField(
        default=True,
        help_text="Whether to use AI-based matching"
    )
    filters = serializers.DictField(
        required=False,
        default=dict,
        help_text="Optional filters (e.g., location, salary_min, remote_only)"
    )


class ParseResumeInputSerializer(serializers.Serializer):
    """Input serializer for resume parsing."""
    resume_text = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Plain text content of resume"
    )
    resume_file = serializers.FileField(
        required=False,
        help_text="Resume file (PDF, DOCX, TXT supported)"
    )
    candidate_id = serializers.IntegerField(
        required=False,
        help_text="Optional candidate ID to update with parsed data"
    )

    def validate(self, data):
        if not data.get('resume_text') and not data.get('resume_file'):
            raise serializers.ValidationError(
                "Either resume_text or resume_file must be provided"
            )
        return data


class AnalyzeJobDescriptionInputSerializer(serializers.Serializer):
    """Input serializer for job description analysis."""
    job_description = serializers.CharField(
        help_text="Full job description text"
    )
    job_title = serializers.CharField(
        required=False,
        default='',
        help_text="Job title for additional context"
    )
    job_id = serializers.IntegerField(
        required=False,
        help_text="Optional job ID to update with analyzed data"
    )


class BiasCheckInputSerializer(serializers.Serializer):
    """Input serializer for bias detection."""
    text = serializers.CharField(
        help_text="Text to check for bias"
    )
    content_type = serializers.ChoiceField(
        choices=['job_posting', 'resume', 'profile', 'other'],
        default='job_posting',
        help_text="Type of content being analyzed"
    )
    content_id = serializers.IntegerField(
        required=False,
        help_text="Optional ID of content for audit logging"
    )
    log_audit = serializers.BooleanField(
        default=True,
        help_text="Whether to log the bias check for auditing"
    )


# ============================================================================
# Output Serializers
# ============================================================================

class SkillSerializer(serializers.ModelSerializer):
    """Serializer for Skill model."""

    class Meta:
        model = Skill
        fields = ['id', 'name', 'description']


class CandidateMatchSerializer(serializers.Serializer):
    """Serializer for candidate match results."""
    candidate_id = serializers.IntegerField(source='candidate.id')
    candidate_name = serializers.SerializerMethodField()
    candidate_email = serializers.SerializerMethodField()
    overall_score = serializers.FloatField()
    skill_score = serializers.FloatField()
    experience_score = serializers.FloatField()
    location_score = serializers.FloatField()
    salary_score = serializers.FloatField()
    matched_skills = serializers.ListField(child=serializers.CharField())
    missing_skills = serializers.ListField(child=serializers.CharField())
    confidence = serializers.CharField()
    algorithm = serializers.CharField()

    def get_candidate_name(self, obj):
        try:
            user = obj['candidate'].user
            return f"{user.first_name} {user.last_name}".strip() or user.username
        except Exception:
            return "Unknown"

    def get_candidate_email(self, obj):
        try:
            return obj['candidate'].user.email
        except Exception:
            return ""


class JobMatchSerializer(serializers.Serializer):
    """Serializer for job match results."""
    job_id = serializers.IntegerField(source='job.id')
    job_title = serializers.CharField(source='job.title')
    company_name = serializers.SerializerMethodField()
    overall_score = serializers.FloatField()
    skill_score = serializers.FloatField()
    experience_score = serializers.FloatField()
    location_score = serializers.FloatField()
    salary_score = serializers.FloatField()
    matched_skills = serializers.ListField(child=serializers.CharField())
    missing_skills = serializers.ListField(child=serializers.CharField())
    confidence = serializers.CharField()
    algorithm = serializers.CharField()
    is_remote = serializers.BooleanField(required=False)
    salary_range = serializers.SerializerMethodField()

    def get_company_name(self, obj):
        try:
            return obj['job'].company.name
        except Exception:
            return "Unknown"

    def get_salary_range(self, obj):
        try:
            job = obj['job']
            if job.salary_from and job.salary_to:
                return {
                    'min': float(job.salary_from),
                    'max': float(job.salary_to)
                }
        except Exception:
            pass
        return None


class ParsedResumeSerializer(serializers.Serializer):
    """Serializer for parsed resume output."""
    skills = serializers.ListField(child=serializers.CharField())
    experience_years = serializers.FloatField()
    education = serializers.ListField(child=serializers.DictField())
    work_history = serializers.ListField(child=serializers.DictField())
    certifications = serializers.ListField(child=serializers.CharField())
    summary = serializers.CharField()


class JobAnalysisSerializer(serializers.Serializer):
    """Serializer for job description analysis output."""
    required_skills = serializers.ListField(child=serializers.CharField())
    preferred_skills = serializers.ListField(child=serializers.CharField())
    experience_range = serializers.ListField(child=serializers.IntegerField())
    education_level = serializers.CharField()
    is_remote = serializers.BooleanField()
    salary_range = serializers.ListField(
        child=serializers.FloatField(),
        allow_null=True
    )
    key_responsibilities = serializers.ListField(child=serializers.CharField())
    company_values = serializers.ListField(child=serializers.CharField())


class BiasReportSerializer(serializers.Serializer):
    """Serializer for bias detection report."""
    has_bias = serializers.BooleanField()
    bias_score = serializers.FloatField()
    gender_bias = serializers.DictField()
    age_bias = serializers.ListField(child=serializers.CharField())
    other_bias = serializers.ListField(child=serializers.CharField())
    suggestions = serializers.ListField(child=serializers.DictField())


# ============================================================================
# Model Serializers
# ============================================================================

class MatchingResultSerializer(serializers.ModelSerializer):
    """Serializer for MatchingResult model."""
    candidate_email = serializers.SerializerMethodField()
    job_title = serializers.SerializerMethodField()

    class Meta:
        model = MatchingResult
        fields = [
            'uuid', 'candidate', 'job', 'candidate_email', 'job_title',
            'overall_score', 'skill_score', 'experience_score',
            'location_score', 'salary_score', 'culture_score',
            'education_score', 'matching_algorithm', 'confidence_level',
            'matched_skills', 'missing_skills', 'explanation',
            'calculated_at', 'expires_at', 'is_stale'
        ]
        read_only_fields = ['uuid', 'calculated_at']

    def get_candidate_email(self, obj):
        return obj.candidate.user.email

    def get_job_title(self, obj):
        return obj.job.title


class RecommendationLogSerializer(serializers.ModelSerializer):
    """Serializer for RecommendationLog model."""
    user_email = serializers.SerializerMethodField()

    class Meta:
        model = RecommendationLog
        fields = [
            'uuid', 'user', 'user_email', 'recommendation_type',
            'recommended_items', 'recommendation_scores', 'context',
            'items_viewed', 'items_clicked', 'items_applied',
            'user_rating', 'user_feedback', 'algorithm_version',
            'model_used', 'fallback_used', 'processing_time_ms',
            'created_at'
        ]
        read_only_fields = ['uuid', 'created_at']

    def get_user_email(self, obj):
        return obj.user.email


class BiasAuditLogSerializer(serializers.ModelSerializer):
    """Serializer for BiasAuditLog model."""

    class Meta:
        model = BiasAuditLog
        fields = [
            'uuid', 'content_type', 'content_id', 'bias_detected',
            'bias_types', 'bias_score', 'flagged_phrases', 'suggestions',
            'auditor', 'automated', 'action_taken', 'action_notes',
            'created_at'
        ]
        read_only_fields = ['uuid', 'created_at']


# ============================================================================
# Embedding Serializers
# ============================================================================

class SkillEmbeddingSerializer(serializers.ModelSerializer):
    """Serializer for SkillEmbedding model."""
    skill_name = serializers.SerializerMethodField()

    class Meta:
        model = SkillEmbedding
        fields = [
            'id', 'skill', 'skill_name', 'embedding_model',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_skill_name(self, obj):
        return obj.skill.name


class JobEmbeddingSerializer(serializers.ModelSerializer):
    """Serializer for JobEmbedding model."""
    job_title = serializers.SerializerMethodField()

    class Meta:
        model = JobEmbedding
        fields = [
            'id', 'job', 'job_title', 'embedding_model',
            'skills_extracted', 'experience_years_min', 'experience_years_max',
            'is_remote', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_job_title(self, obj):
        return obj.job.title


class CandidateEmbeddingSerializer(serializers.ModelSerializer):
    """Serializer for CandidateEmbedding model."""
    candidate_email = serializers.SerializerMethodField()

    class Meta:
        model = CandidateEmbedding
        fields = [
            'id', 'candidate', 'candidate_email', 'embedding_model',
            'total_experience_years', 'skills_extracted',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_candidate_email(self, obj):
        return obj.candidate.user.email


# ============================================================================
# Feedback Serializers
# ============================================================================

class RecommendationFeedbackSerializer(serializers.Serializer):
    """Serializer for recommendation feedback."""
    recommendation_id = serializers.UUIDField(
        help_text="UUID of the recommendation log"
    )
    items_viewed = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="IDs of items that were viewed"
    )
    items_clicked = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="IDs of items that were clicked"
    )
    items_applied = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="IDs of items that led to application"
    )
    rating = serializers.IntegerField(
        min_value=1,
        max_value=5,
        required=False,
        help_text="User rating of recommendations (1-5)"
    )
    feedback = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="User feedback text"
    )


class MatchingResultListSerializer(serializers.Serializer):
    """Serializer for listing match results with pagination info."""
    count = serializers.IntegerField()
    next = serializers.URLField(allow_null=True)
    previous = serializers.URLField(allow_null=True)
    results = MatchingResultSerializer(many=True)


# ============================================================================
# Bulk Operation Serializers
# ============================================================================

class BulkMatchInputSerializer(serializers.Serializer):
    """Input serializer for bulk matching operations."""
    job_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="List of job IDs to match"
    )
    candidate_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="List of candidate IDs to match"
    )
    recalculate = serializers.BooleanField(
        default=False,
        help_text="Whether to recalculate existing matches"
    )

    def validate(self, data):
        if not data.get('job_ids') and not data.get('candidate_ids'):
            raise serializers.ValidationError(
                "At least one of job_ids or candidate_ids must be provided"
            )
        return data


class BulkMatchResultSerializer(serializers.Serializer):
    """Output serializer for bulk matching operations."""
    total_matches = serializers.IntegerField()
    new_matches = serializers.IntegerField()
    updated_matches = serializers.IntegerField()
    errors = serializers.ListField(child=serializers.DictField())
    processing_time_ms = serializers.IntegerField()


# ============================================================================
# Tenant-Aware Serializers (Cycle 7 Additions)
# ============================================================================

try:
    from api.serializers_base import TenantAwareSerializer
except ImportError:
    # Fallback if TenantAwareSerializer not available
    TenantAwareSerializer = serializers.ModelSerializer


class MatchingProfileSerializer(TenantAwareSerializer):
    """
    Candidate matching profile serializer with tenant awareness.
    Provides full profile details for matching context.
    """
    user_email = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    skills = serializers.SerializerMethodField()
    experience_years = serializers.DecimalField(
        max_digits=4, decimal_places=1, read_only=True
    )
    education_level = serializers.CharField(read_only=True)
    location = serializers.SerializerMethodField()
    availability = serializers.CharField(read_only=True)
    profile_completion = serializers.SerializerMethodField()

    class Meta:
        model = CandidateProfile
        fields = [
            'id', 'uuid', 'user_email', 'full_name', 'skills',
            'experience_years', 'education_level', 'location',
            'availability', 'profile_completion', 'bio',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'uuid', 'created_at', 'updated_at']

    def get_user_email(self, obj):
        try:
            return obj.user.email
        except Exception:
            return ""

    def get_full_name(self, obj):
        try:
            return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username
        except Exception:
            return "Unknown"

    def get_skills(self, obj):
        try:
            return list(obj.skills.values_list('name', flat=True))
        except Exception:
            return []

    def get_location(self, obj):
        try:
            parts = []
            if hasattr(obj, 'city') and obj.city:
                parts.append(obj.city)
            if hasattr(obj, 'country') and obj.country:
                parts.append(obj.country)
            return ', '.join(parts) if parts else None
        except Exception:
            return None

    def get_profile_completion(self, obj):
        """Calculate profile completion percentage."""
        required_fields = ['bio', 'skills']
        completed = 0
        total = len(required_fields)

        if obj.bio:
            completed += 1
        if hasattr(obj, 'skills') and obj.skills.exists():
            completed += 1

        return round((completed / total) * 100) if total > 0 else 0


class CandidateMinimalSerializer(serializers.Serializer):
    """Minimal candidate representation for match results."""
    id = serializers.IntegerField()
    uuid = serializers.UUIDField(required=False)
    email = serializers.EmailField()
    full_name = serializers.CharField()
    avatar_url = serializers.URLField(required=False, allow_null=True)
    title = serializers.CharField(required=False, allow_blank=True)
    location = serializers.CharField(required=False, allow_blank=True)


class JobListSerializer(serializers.Serializer):
    """Minimal job representation for match results."""
    id = serializers.IntegerField()
    uuid = serializers.UUIDField(required=False)
    title = serializers.CharField()
    company_name = serializers.CharField()
    location = serializers.CharField(required=False, allow_blank=True)
    is_remote = serializers.BooleanField(default=False)
    salary_min = serializers.DecimalField(
        max_digits=12, decimal_places=2, required=False, allow_null=True
    )
    salary_max = serializers.DecimalField(
        max_digits=12, decimal_places=2, required=False, allow_null=True
    )
    posted_at = serializers.DateTimeField(required=False)


class MatchResultSerializer(serializers.Serializer):
    """
    Match result with detailed scores and explanation.
    Used for returning candidate matches for a job.
    """
    candidate = CandidateMinimalSerializer()
    overall_score = serializers.FloatField(
        help_text="Overall match score (0-1)"
    )
    skill_match_score = serializers.FloatField(
        help_text="Skill alignment score (0-1)"
    )
    experience_match_score = serializers.FloatField(
        help_text="Experience alignment score (0-1)"
    )
    location_score = serializers.FloatField(
        required=False, default=1.0,
        help_text="Location compatibility score (0-1)"
    )
    salary_score = serializers.FloatField(
        required=False, default=1.0,
        help_text="Salary alignment score (0-1)"
    )
    culture_score = serializers.FloatField(
        required=False, default=1.0,
        help_text="Culture fit score (0-1)"
    )
    explanation = serializers.ListField(
        child=serializers.CharField(),
        help_text="Human-readable explanation of match"
    )
    match_highlights = serializers.SerializerMethodField()
    matched_skills = serializers.ListField(
        child=serializers.CharField(), required=False
    )
    missing_skills = serializers.ListField(
        child=serializers.CharField(), required=False
    )
    confidence = serializers.ChoiceField(
        choices=['high', 'medium', 'low'],
        default='medium'
    )
    algorithm = serializers.CharField(default='hybrid')

    def get_match_highlights(self, obj):
        """Generate highlight summary for UI display."""
        highlights = []

        score = obj.get('overall_score', 0)
        if score >= 0.9:
            highlights.append({'type': 'excellent', 'text': 'Excellent Match'})
        elif score >= 0.75:
            highlights.append({'type': 'good', 'text': 'Good Match'})
        elif score >= 0.6:
            highlights.append({'type': 'moderate', 'text': 'Moderate Match'})

        # Skill highlights
        matched = obj.get('matched_skills', [])
        if len(matched) >= 5:
            highlights.append({
                'type': 'skills',
                'text': f'{len(matched)} skills matched'
            })

        # Experience highlight
        exp_score = obj.get('experience_match_score', 0)
        if exp_score >= 0.9:
            highlights.append({
                'type': 'experience',
                'text': 'Experience level matches'
            })

        return highlights


class JobMatchResultSerializer(serializers.Serializer):
    """
    Job match result for candidate perspective.
    Shows jobs that match a candidate's profile.
    """
    job = JobListSerializer()
    overall_score = serializers.FloatField(
        help_text="Overall match score (0-1)"
    )
    skill_match_score = serializers.FloatField(
        help_text="Skill alignment score (0-1)"
    )
    experience_match_score = serializers.FloatField(
        help_text="Experience alignment score (0-1)"
    )
    why_good_fit = serializers.ListField(
        child=serializers.CharField(),
        help_text="Reasons why this job is a good fit"
    )
    growth_opportunities = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Skills candidate can learn from this role"
    )
    salary_alignment = serializers.DictField(
        required=False,
        help_text="Salary comparison details"
    )
    application_tips = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Tips for applying to this job"
    )


class BiasReportDetailSerializer(serializers.Serializer):
    """
    Detailed bias detection results for job postings or content.
    """
    overall_fairness_score = serializers.FloatField(
        help_text="Overall fairness score (0-1, higher is better)"
    )
    has_bias = serializers.BooleanField(
        help_text="Whether significant bias was detected"
    )
    demographic_analysis = serializers.DictField(
        help_text="Breakdown of bias by demographic category"
    )
    flagged_phrases = serializers.ListField(
        child=serializers.DictField(),
        help_text="Specific phrases flagged for potential bias"
    )
    recommendations = serializers.ListField(
        child=serializers.DictField(),
        help_text="Actionable recommendations to reduce bias"
    )
    severity = serializers.ChoiceField(
        choices=['none', 'low', 'medium', 'high', 'critical'],
        help_text="Overall severity of detected bias"
    )
    compliance_status = serializers.DictField(
        required=False,
        help_text="EEOC and other compliance check results"
    )
    audit_id = serializers.UUIDField(
        required=False,
        help_text="ID for audit trail reference"
    )


class MatchExplanationSerializer(serializers.Serializer):
    """
    Detailed match explanation for transparency.
    """
    match_id = serializers.UUIDField()
    candidate_id = serializers.IntegerField()
    job_id = serializers.IntegerField()
    overall_score = serializers.FloatField()
    score_breakdown = serializers.DictField(
        help_text="Detailed breakdown of all score components"
    )
    skill_analysis = serializers.DictField(
        help_text="Detailed skill matching analysis"
    )
    experience_analysis = serializers.DictField(
        help_text="Experience comparison details"
    )
    location_analysis = serializers.DictField(
        required=False,
        help_text="Location compatibility analysis"
    )
    salary_analysis = serializers.DictField(
        required=False,
        help_text="Salary alignment details"
    )
    human_readable_summary = serializers.CharField(
        help_text="Plain English summary of match"
    )
    improvement_suggestions = serializers.ListField(
        child=serializers.CharField(),
        help_text="What could improve this match"
    )
    algorithm_details = serializers.DictField(
        help_text="Algorithm and model information"
    )


class ResumeParseResultSerializer(serializers.Serializer):
    """
    Result of resume parsing operation.
    """
    success = serializers.BooleanField()
    candidate_id = serializers.IntegerField(required=False, allow_null=True)
    parsed_data = ParsedResumeSerializer()
    confidence_scores = serializers.DictField(
        help_text="Confidence scores for each extracted field"
    )
    warnings = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Any warnings during parsing"
    )
    processing_time_ms = serializers.IntegerField()
    file_info = serializers.DictField(
        required=False,
        help_text="Original file metadata"
    )


# ============================================================================
# Hybrid Ranking Serializers (Step 4 - Three-Score Breakdown)
# ============================================================================

class CandidateRankingSerializer(serializers.Serializer):
    """
    Serializer for CandidateRanking with transparent three-score breakdown.

    Implements features.md Section 4.3:
    - Overall weighted score
    - Rule-based score (knockout + preference + bonus)
    - AI/ML score (skill, experience, culture, location, salary)
    - Verification/Trust score (identity, career, trust level)
    """
    uuid = serializers.UUIDField(read_only=True)
    job_id = serializers.IntegerField()
    candidate_id = serializers.IntegerField()

    # Three-Score Breakdown (main scores)
    rule_score = serializers.DecimalField(
        max_digits=5, decimal_places=2,
        help_text="Deterministic rule-based score (0-100)"
    )
    ai_score = serializers.DecimalField(
        max_digits=5, decimal_places=2,
        help_text="AI/ML matching score (0-100)"
    )
    verification_score = serializers.DecimalField(
        max_digits=5, decimal_places=2,
        help_text="Trust/verification score (0-100)"
    )
    overall_score = serializers.DecimalField(
        max_digits=5, decimal_places=2,
        help_text="Weighted overall score (0-100)"
    )

    # AI Component Breakdown
    skill_match_score = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False
    )
    experience_match_score = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False
    )
    culture_fit_score = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False
    )
    location_match_score = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False
    )
    salary_match_score = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False
    )

    # Verification Component Breakdown
    identity_verification_score = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False
    )
    career_verification_score = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False
    )
    trust_score_value = serializers.DecimalField(
        max_digits=5, decimal_places=2, required=False
    )

    # Knockout Status
    passed_knockout = serializers.BooleanField(default=True)
    knockout_reasons = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )

    # Skills Analysis
    matched_skills = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Skills matching job requirements"
    )
    missing_skills = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Required skills candidate lacks"
    )
    bonus_skills = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Extra relevant skills"
    )

    # Weights Used
    weights_used = serializers.DictField(
        required=False,
        help_text="Weight configuration used for scoring"
    )

    # Explanation
    ranking_explanation = serializers.DictField(
        required=False,
        help_text="Human-readable explanation"
    )
    top_strengths = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    improvement_areas = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )

    # Metadata
    computed_at = serializers.DateTimeField(read_only=True, required=False)
    computation_time_ms = serializers.IntegerField(read_only=True, required=False)


class CandidateRankingListSerializer(serializers.Serializer):
    """
    Lightweight ranking serializer for lists (ATS candidate pipelines).
    """
    candidate_id = serializers.IntegerField()
    candidate_name = serializers.CharField(required=False)
    candidate_email = serializers.EmailField(required=False)
    overall_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    rule_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    ai_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    verification_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    passed_knockout = serializers.BooleanField(default=True)
    match_level = serializers.SerializerMethodField()
    top_matched_skills = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    is_verified = serializers.BooleanField(required=False)

    def get_match_level(self, obj):
        """Convert score to human-readable match level."""
        score = float(obj.get('overall_score', 0))
        if score >= 85:
            return 'excellent'
        elif score >= 70:
            return 'good'
        elif score >= 50:
            return 'moderate'
        elif score >= 30:
            return 'limited'
        return 'poor'


class RankingProfileSerializer(serializers.Serializer):
    """
    Serializer for RankingProfile configuration.
    """
    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(max_length=100)
    description = serializers.CharField(required=False, allow_blank=True)
    is_default = serializers.BooleanField(default=False)
    is_active = serializers.BooleanField(default=True)

    # Main Weights (must sum to 1.0)
    rule_score_weight = serializers.DecimalField(
        max_digits=4, decimal_places=3, default=Decimal('0.300')
    )
    ai_score_weight = serializers.DecimalField(
        max_digits=4, decimal_places=3, default=Decimal('0.500')
    )
    verification_score_weight = serializers.DecimalField(
        max_digits=4, decimal_places=3, default=Decimal('0.200')
    )

    # AI Component Weights
    skill_match_weight = serializers.DecimalField(
        max_digits=4, decimal_places=3, default=Decimal('0.350')
    )
    experience_match_weight = serializers.DecimalField(
        max_digits=4, decimal_places=3, default=Decimal('0.250')
    )
    culture_fit_weight = serializers.DecimalField(
        max_digits=4, decimal_places=3, default=Decimal('0.150')
    )
    location_match_weight = serializers.DecimalField(
        max_digits=4, decimal_places=3, default=Decimal('0.150')
    )
    salary_match_weight = serializers.DecimalField(
        max_digits=4, decimal_places=3, default=Decimal('0.100')
    )

    # Thresholds
    minimum_overall_score = serializers.DecimalField(
        max_digits=5, decimal_places=2, default=Decimal('50.00')
    )

    def validate(self, data):
        """Ensure main weights sum to 1.0."""
        rule_w = float(data.get('rule_score_weight', Decimal('0.30')))
        ai_w = float(data.get('ai_score_weight', Decimal('0.50')))
        ver_w = float(data.get('verification_score_weight', Decimal('0.20')))

        total = rule_w + ai_w + ver_w
        if abs(total - 1.0) > 0.001:
            raise serializers.ValidationError({
                'weights': f"Main weights must sum to 1.0 (current: {total:.3f})"
            })
        return data


class RankCandidatesInputSerializer(serializers.Serializer):
    """
    Input serializer for ranking candidates using HybridRankingEngine.
    """
    job_id = serializers.IntegerField(
        help_text="ID of the job to rank candidates for"
    )
    candidate_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Optional specific candidates to rank (defaults to all)"
    )
    ranking_profile_id = serializers.IntegerField(
        required=False,
        help_text="Optional ranking profile UUID (uses default if not specified)"
    )
    limit = serializers.IntegerField(
        default=50,
        min_value=1,
        max_value=500,
        help_text="Maximum rankings to return"
    )
    min_score = serializers.FloatField(
        default=0.0,
        min_value=0.0,
        max_value=100.0,
        help_text="Minimum overall score threshold"
    )
    include_knocked_out = serializers.BooleanField(
        default=False,
        help_text="Whether to include candidates who failed knockout rules"
    )
    recalculate = serializers.BooleanField(
        default=False,
        help_text="Force recalculation even if cached results exist"
    )


class RankCandidatesOutputSerializer(serializers.Serializer):
    """
    Output serializer for hybrid ranking results.
    """
    job_id = serializers.IntegerField()
    job_title = serializers.CharField()
    total_candidates = serializers.IntegerField()
    ranked_candidates = serializers.IntegerField()
    knocked_out_count = serializers.IntegerField()
    ranking_profile_used = serializers.CharField()
    weights = serializers.DictField()
    rankings = CandidateRankingListSerializer(many=True)
    processing_time_ms = serializers.IntegerField()
    cached = serializers.BooleanField(default=False)
