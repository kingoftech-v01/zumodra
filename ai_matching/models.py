"""
AI Matching Models

This module contains models for caching embeddings, storing match results,
and logging recommendation activity for the AI matching service.

Enhanced for Zumodra Cycle 7 with:
- Tenant-aware models for multi-tenant isolation
- Sentence-transformers embeddings (384 dimensions for all-MiniLM-L6-v2)
- Normalized skill taxonomies with weights
- AI model version tracking for reproducibility
- Enhanced match explanations
"""

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid

from tenants.mixins import TenantAwareModelMixin, TenantBaseModel, TimestampMixin, UUIDMixin
from core.db.models import TenantAwareModel


# ============================================================================
# Constants
# ============================================================================

# Embedding dimensions for different models
EMBEDDING_DIMENSIONS = {
    'text-embedding-ada-002': 1536,  # OpenAI
    'all-MiniLM-L6-v2': 384,  # Sentence Transformers (default)
    'all-mpnet-base-v2': 768,  # Sentence Transformers (higher quality)
    'local_fallback': 384,  # Fallback uses same dimension as MiniLM
}

DEFAULT_EMBEDDING_MODEL = 'all-MiniLM-L6-v2'
DEFAULT_EMBEDDING_DIMENSION = 384


class SkillEmbedding(models.Model):
    """
    Cached skill vector embeddings for efficient similarity calculations.
    Embeddings can be generated via OpenAI API or local models.
    """
    skill = models.OneToOneField(
        'configurations.Skill',
        on_delete=models.CASCADE,
        related_name='embedding'
    )
    embedding_vector = ArrayField(
        models.FloatField(),
        size=1536,  # OpenAI ada-002 embedding dimension
        help_text="Vector representation of the skill"
    )
    embedding_model = models.CharField(
        max_length=100,
        default='text-embedding-ada-002',
        help_text="Model used to generate the embedding"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Skill Embedding"
        verbose_name_plural = "Skill Embeddings"
        indexes = [
            models.Index(fields=['skill']),
            models.Index(fields=['updated_at']),
        ]

    def __str__(self):
        return f"Embedding for {self.skill.name}"


class JobEmbedding(models.Model):
    """
    Cached job requirement vectors for matching against candidates.
    Combines job description, requirements, and required skills into a single vector.
    """
    job = models.OneToOneField(
        'configurations.Job',
        on_delete=models.CASCADE,
        related_name='embedding'
    )
    embedding_vector = ArrayField(
        models.FloatField(),
        size=1536,
        help_text="Vector representation of job requirements"
    )
    # Store individual component vectors for fine-grained matching
    title_vector = ArrayField(
        models.FloatField(),
        size=1536,
        null=True,
        blank=True,
        help_text="Vector for job title only"
    )
    requirements_vector = ArrayField(
        models.FloatField(),
        size=1536,
        null=True,
        blank=True,
        help_text="Vector for job requirements text"
    )
    description_vector = ArrayField(
        models.FloatField(),
        size=1536,
        null=True,
        blank=True,
        help_text="Vector for job description text"
    )
    embedding_model = models.CharField(
        max_length=100,
        default='text-embedding-ada-002'
    )
    skills_extracted = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text="Skills extracted from job description"
    )
    experience_years_min = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Minimum years of experience extracted"
    )
    experience_years_max = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Maximum years of experience extracted"
    )
    is_remote = models.BooleanField(
        null=True,
        blank=True,
        help_text="Whether job allows remote work"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Job Embedding"
        verbose_name_plural = "Job Embeddings"
        indexes = [
            models.Index(fields=['job']),
            models.Index(fields=['updated_at']),
        ]

    def __str__(self):
        return f"Embedding for Job: {self.job.title}"


class CandidateEmbedding(models.Model):
    """
    Cached candidate skill vectors for matching against jobs.
    Combines resume, skills, experience, and education into a single vector.
    """
    candidate = models.OneToOneField(
        'configurations.CandidateProfile',
        on_delete=models.CASCADE,
        related_name='embedding'
    )
    embedding_vector = ArrayField(
        models.FloatField(),
        size=1536,
        help_text="Combined vector representation of candidate profile"
    )
    skills_vector = ArrayField(
        models.FloatField(),
        size=1536,
        null=True,
        blank=True,
        help_text="Vector for skills only"
    )
    experience_vector = ArrayField(
        models.FloatField(),
        size=1536,
        null=True,
        blank=True,
        help_text="Vector for work experience"
    )
    education_vector = ArrayField(
        models.FloatField(),
        size=1536,
        null=True,
        blank=True,
        help_text="Vector for education background"
    )
    bio_vector = ArrayField(
        models.FloatField(),
        size=1536,
        null=True,
        blank=True,
        help_text="Vector for bio/summary text"
    )
    embedding_model = models.CharField(
        max_length=100,
        default='text-embedding-ada-002'
    )
    total_experience_years = models.DecimalField(
        max_digits=4,
        decimal_places=1,
        null=True,
        blank=True,
        help_text="Total years of experience calculated from resume"
    )
    skills_extracted = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text="Skills extracted from resume"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Candidate Embedding"
        verbose_name_plural = "Candidate Embeddings"
        indexes = [
            models.Index(fields=['candidate']),
            models.Index(fields=['updated_at']),
        ]

    def __str__(self):
        return f"Embedding for Candidate: {self.candidate.user.email}"


class MatchingResult(models.Model):
    """
    Cached match scores between candidates and jobs.
    Stores detailed breakdown of match components for transparency.
    """
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    candidate = models.ForeignKey(
        'configurations.CandidateProfile',
        on_delete=models.CASCADE,
        related_name='matching_results'
    )
    job = models.ForeignKey(
        'configurations.Job',
        on_delete=models.CASCADE,
        related_name='matching_results'
    )

    # Overall match score
    overall_score = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        help_text="Overall match score (0-1)"
    )

    # Component scores for transparency
    skill_score = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        null=True,
        blank=True,
        help_text="Skill match score"
    )
    experience_score = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        null=True,
        blank=True,
        help_text="Experience match score"
    )
    location_score = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        null=True,
        blank=True,
        help_text="Location compatibility score"
    )
    salary_score = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        null=True,
        blank=True,
        help_text="Salary alignment score"
    )
    culture_score = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        null=True,
        blank=True,
        help_text="Culture fit score"
    )
    education_score = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        null=True,
        blank=True,
        help_text="Education match score"
    )

    # Match metadata
    matching_algorithm = models.CharField(
        max_length=50,
        choices=[
            ('ai_embedding', 'AI Embedding Based'),
            ('rule_based', 'Rule-Based Fallback'),
            ('hybrid', 'Hybrid AI + Rules'),
        ],
        default='ai_embedding'
    )
    confidence_level = models.CharField(
        max_length=20,
        choices=[
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
        ],
        default='medium'
    )

    # Matched and missing skills for feedback
    matched_skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True
    )
    missing_skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True
    )

    # Match explanation for transparency
    explanation = models.JSONField(
        default=dict,
        blank=True,
        help_text="Detailed explanation of match score components"
    )

    # Timestamps
    calculated_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        help_text="When this cached result should be recalculated"
    )

    # Status tracking
    is_stale = models.BooleanField(
        default=False,
        help_text="Whether this match needs recalculation"
    )

    class Meta:
        verbose_name = "Matching Result"
        verbose_name_plural = "Matching Results"
        unique_together = ('candidate', 'job')
        ordering = ['-overall_score']
        indexes = [
            models.Index(fields=['candidate', 'job']),
            models.Index(fields=['overall_score']),
            models.Index(fields=['calculated_at']),
            models.Index(fields=['is_stale']),
        ]

    def __str__(self):
        return f"Match: {self.candidate.user.email} - {self.job.title} ({self.overall_score})"

    def save(self, *args, **kwargs):
        # Set expiration to 24 hours from calculation if not set
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at


class RecommendationLog(models.Model):
    """
    Logs recommendation activity for analytics, model improvement,
    and audit purposes.
    """
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Who received the recommendation
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='recommendation_logs'
    )

    # Type of recommendation
    recommendation_type = models.CharField(
        max_length=30,
        choices=[
            ('jobs_for_candidate', 'Jobs for Candidate'),
            ('candidates_for_job', 'Candidates for Job'),
            ('similar_jobs', 'Similar Jobs'),
            ('similar_candidates', 'Similar Candidates'),
            ('skills_to_learn', 'Skills to Learn'),
        ]
    )

    # What was recommended (store IDs as JSON array)
    recommended_items = models.JSONField(
        default=list,
        help_text="IDs of recommended items"
    )

    # Ranking and scores
    recommendation_scores = models.JSONField(
        default=dict,
        help_text="Scores for each recommended item"
    )

    # Context of recommendation
    context = models.JSONField(
        default=dict,
        blank=True,
        help_text="Context data used for recommendation"
    )

    # User interaction tracking
    items_viewed = models.JSONField(
        default=list,
        blank=True,
        help_text="Which recommended items were viewed"
    )
    items_clicked = models.JSONField(
        default=list,
        blank=True,
        help_text="Which recommended items were clicked"
    )
    items_applied = models.JSONField(
        default=list,
        blank=True,
        help_text="Which recommended items led to application"
    )

    # Feedback for model improvement
    user_rating = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text="User rating of recommendations (1-5)"
    )
    user_feedback = models.TextField(
        blank=True,
        help_text="User feedback text"
    )

    # Algorithm metadata
    algorithm_version = models.CharField(
        max_length=20,
        default='1.0'
    )
    model_used = models.CharField(
        max_length=100,
        default='text-embedding-ada-002'
    )
    fallback_used = models.BooleanField(
        default=False,
        help_text="Whether rule-based fallback was used"
    )

    # Performance metrics
    processing_time_ms = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Time taken to generate recommendations"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Recommendation Log"
        verbose_name_plural = "Recommendation Logs"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['recommendation_type']),
            models.Index(fields=['created_at']),
            models.Index(fields=['fallback_used']),
        ]

    def __str__(self):
        return f"Recommendation for {self.user.email} - {self.recommendation_type}"


class BiasAuditLog(models.Model):
    """
    Logs bias detection results for job postings and matching algorithms
    for compliance and fairness monitoring.
    """
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # What was audited
    content_type = models.CharField(
        max_length=30,
        choices=[
            ('job_posting', 'Job Posting'),
            ('matching_result', 'Matching Result'),
            ('recommendation', 'Recommendation'),
        ]
    )
    content_id = models.PositiveIntegerField(
        help_text="ID of the audited content"
    )

    # Bias detection results
    bias_detected = models.BooleanField(default=False)
    bias_types = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True,
        help_text="Types of bias detected (gender, age, etc.)"
    )
    bias_score = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        null=True,
        blank=True,
        help_text="Overall bias score (0-1, higher = more bias)"
    )

    # Detailed findings
    flagged_phrases = models.JSONField(
        default=list,
        blank=True,
        help_text="Specific phrases flagged for bias"
    )
    suggestions = models.JSONField(
        default=list,
        blank=True,
        help_text="Suggested neutral alternatives"
    )

    # Audit metadata
    auditor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='bias_audits_performed'
    )
    automated = models.BooleanField(
        default=True,
        help_text="Whether this was an automated check"
    )

    # Action taken
    action_taken = models.CharField(
        max_length=30,
        choices=[
            ('none', 'No Action'),
            ('warned', 'Warning Issued'),
            ('modified', 'Content Modified'),
            ('blocked', 'Content Blocked'),
        ],
        default='none'
    )
    action_notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Bias Audit Log"
        verbose_name_plural = "Bias Audit Logs"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['content_type', 'content_id']),
            models.Index(fields=['bias_detected']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        status = "Bias detected" if self.bias_detected else "No bias"
        return f"{self.content_type} {self.content_id}: {status}"


class AIServiceStatus(models.Model):
    """
    Tracks AI service availability and health for fallback decisions.
    """
    service_name = models.CharField(
        max_length=50,
        unique=True,
        choices=[
            ('openai_embedding', 'OpenAI Embedding'),
            ('openai_chat', 'OpenAI Chat'),
            ('local_embedding', 'Local Embedding Model'),
            ('resume_parser', 'Resume Parser'),
        ]
    )
    is_available = models.BooleanField(default=True)
    last_check = models.DateTimeField(auto_now=True)
    last_success = models.DateTimeField(null=True, blank=True)
    last_failure = models.DateTimeField(null=True, blank=True)
    failure_count = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)

    # Rate limiting tracking
    requests_today = models.PositiveIntegerField(default=0)
    daily_limit = models.PositiveIntegerField(default=10000)

    class Meta:
        verbose_name = "AI Service Status"
        verbose_name_plural = "AI Service Statuses"

    def __str__(self):
        status = "Available" if self.is_available else "Unavailable"
        return f"{self.service_name}: {status}"

    def record_success(self):
        self.is_available = True
        self.last_success = timezone.now()
        self.failure_count = 0
        self.error_message = ''
        self.requests_today += 1
        self.save()

    def record_failure(self, error_message=''):
        self.failure_count += 1
        self.last_failure = timezone.now()
        self.error_message = error_message
        # Mark as unavailable after 3 consecutive failures
        if self.failure_count >= 3:
            self.is_available = False
        self.save()

    def reset_daily_count(self):
        self.requests_today = 0
        self.save()


# ============================================================================
# NEW TENANT-AWARE MODELS FOR CYCLE 7
# ============================================================================

class AIModelVersion(models.Model):
    """
    Track AI model versions for reproducibility.

    Each version captures the configuration used for a specific model type,
    enabling rollback and A/B testing of different model configurations.
    """

    class ModelType(models.TextChoices):
        SKILL_MATCHER = 'skill_matcher', _('Skill Matcher')
        RESUME_PARSER = 'resume_parser', _('Resume Parser')
        EMBEDDING = 'embedding', _('Embedding Generator')
        BIAS_DETECTOR = 'bias_detector', _('Bias Detector')
        JOB_ANALYZER = 'job_analyzer', _('Job Analyzer')
        CANDIDATE_RANKER = 'candidate_ranker', _('Candidate Ranker')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    version = models.CharField(
        max_length=50,
        help_text=_('Semantic version string (e.g., 1.0.0)')
    )
    model_type = models.CharField(
        max_length=30,
        choices=ModelType.choices,
        db_index=True
    )

    # Model configuration
    config = models.JSONField(
        default=dict,
        help_text=_('Model configuration parameters')
    )
    model_name = models.CharField(
        max_length=100,
        default=DEFAULT_EMBEDDING_MODEL,
        help_text=_('Underlying model name (e.g., all-MiniLM-L6-v2)')
    )
    embedding_dimension = models.PositiveIntegerField(
        default=DEFAULT_EMBEDDING_DIMENSION,
        help_text=_('Embedding vector dimension')
    )

    # Deployment status
    deployed_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(
        default=False,
        db_index=True,
        help_text=_('Whether this version is currently active')
    )
    deprecated_at = models.DateTimeField(null=True, blank=True)

    # Performance metrics
    accuracy_score = models.FloatField(
        null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Measured accuracy on test set')
    )
    avg_latency_ms = models.FloatField(
        null=True, blank=True,
        help_text=_('Average inference latency in milliseconds')
    )

    # Changelog
    changelog = models.TextField(
        blank=True,
        help_text=_('Description of changes in this version')
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('AI Model Version')
        verbose_name_plural = _('AI Model Versions')
        unique_together = ['version', 'model_type']
        ordering = ['-deployed_at']
        indexes = [
            models.Index(fields=['model_type', 'is_active']),
            models.Index(fields=['-deployed_at']),
        ]

    def __str__(self):
        status = 'Active' if self.is_active else 'Inactive'
        return f"{self.get_model_type_display()} v{self.version} ({status})"

    def activate(self):
        """Activate this version and deactivate others of same type."""
        AIModelVersion.objects.filter(
            model_type=self.model_type,
            is_active=True
        ).update(is_active=False)
        self.is_active = True
        self.save(update_fields=['is_active'])

    def deprecate(self):
        """Mark this version as deprecated."""
        self.deprecated_at = timezone.now()
        self.is_active = False
        self.save(update_fields=['deprecated_at', 'is_active'])

    @classmethod
    def get_active_version(cls, model_type: str) -> 'AIModelVersion':
        """Get the currently active version for a model type."""
        try:
            return cls.objects.get(model_type=model_type, is_active=True)
        except cls.DoesNotExist:
            return None


class MatchingProfile(TenantAwareModelMixin, models.Model):
    """
    Candidate profile optimized for AI matching.

    Stores pre-computed embeddings and normalized data for efficient
    matching against job postings. Linked to CandidateProfile.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    candidate = models.OneToOneField(
        'ats.Candidate',
        on_delete=models.CASCADE,
        related_name='matching_profile'
    )

    # Vector embedding (384 dims for all-MiniLM-L6-v2)
    embedding = ArrayField(
        models.FloatField(),
        size=DEFAULT_EMBEDDING_DIMENSION,
        null=True,
        blank=True,
        help_text=_('Vector representation of candidate profile')
    )

    # Component embeddings for fine-grained matching
    skills_embedding = ArrayField(
        models.FloatField(),
        size=DEFAULT_EMBEDDING_DIMENSION,
        null=True,
        blank=True,
        help_text=_('Vector for skills only')
    )
    experience_embedding = ArrayField(
        models.FloatField(),
        size=DEFAULT_EMBEDDING_DIMENSION,
        null=True,
        blank=True,
        help_text=_('Vector for work experience')
    )
    education_embedding = ArrayField(
        models.FloatField(),
        size=DEFAULT_EMBEDDING_DIMENSION,
        null=True,
        blank=True,
        help_text=_('Vector for education background')
    )

    # Normalized skills with weights
    skills_normalized = models.JSONField(
        default=dict,
        blank=True,
        help_text=_(
            'Normalized skill list with weights. Format: '
            '{"skill_id": {"name": "Python", "weight": 0.9, "category": "programming"}}'
        )
    )

    # Computed scores
    experience_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Normalized experience score (0-1)')
    )
    education_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Normalized education score (0-1)')
    )
    overall_quality_score = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Overall profile completeness/quality score')
    )

    # Extracted data
    total_experience_years = models.DecimalField(
        max_digits=4,
        decimal_places=1,
        null=True,
        blank=True
    )
    highest_education_level = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('Highest education level (e.g., Masters, Bachelors)')
    )
    primary_skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('Top 10 primary skills')
    )
    industries = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('Industries from work experience')
    )

    # Processing metadata
    last_processed = models.DateTimeField(auto_now=True)
    processing_version = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('AI model version used for processing')
    )
    processing_status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('processing', 'Processing'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
        ],
        default='pending'
    )
    processing_error = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Matching Profile')
        verbose_name_plural = _('Matching Profiles')
        indexes = [
            models.Index(fields=['tenant', 'candidate']),
            models.Index(fields=['processing_status']),
            models.Index(fields=['overall_quality_score']),
            models.Index(fields=['-last_processed']),
        ]

    def __str__(self):
        return f"Matching Profile for {self.candidate}"

    @property
    def is_stale(self):
        """Check if profile needs reprocessing (older than 7 days)."""
        if not self.last_processed:
            return True
        return (timezone.now() - self.last_processed).days > 7

    def mark_for_reprocessing(self):
        """Mark profile for reprocessing."""
        self.processing_status = 'pending'
        self.save(update_fields=['processing_status'])


class JobMatchingProfile(TenantAwareModelMixin, models.Model):
    """
    Job posting profile optimized for AI matching.

    Stores pre-computed embeddings and normalized requirements for
    efficient matching against candidates.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    job = models.OneToOneField(
        'ats.JobPosting',
        on_delete=models.CASCADE,
        related_name='matching_profile'
    )

    # Vector embedding
    embedding = ArrayField(
        models.FloatField(),
        size=DEFAULT_EMBEDDING_DIMENSION,
        null=True,
        blank=True,
        help_text=_('Combined vector representation of job requirements')
    )

    # Component embeddings
    title_embedding = ArrayField(
        models.FloatField(),
        size=DEFAULT_EMBEDDING_DIMENSION,
        null=True,
        blank=True
    )
    requirements_embedding = ArrayField(
        models.FloatField(),
        size=DEFAULT_EMBEDDING_DIMENSION,
        null=True,
        blank=True
    )
    description_embedding = ArrayField(
        models.FloatField(),
        size=DEFAULT_EMBEDDING_DIMENSION,
        null=True,
        blank=True
    )

    # Normalized skills with weights
    required_skills_normalized = models.JSONField(
        default=dict,
        blank=True,
        help_text=_(
            'Required skills with weights. Format: '
            '{"skill_id": {"name": "Python", "weight": 1.0, "required": true}}'
        )
    )
    nice_to_have_normalized = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Nice-to-have skills with weights')
    )

    # Matching weights (customizable per job)
    experience_weight = models.FloatField(
        default=0.20,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Weight for experience matching')
    )
    skills_weight = models.FloatField(
        default=0.35,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Weight for skills matching')
    )
    education_weight = models.FloatField(
        default=0.10,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Weight for education matching')
    )
    cultural_fit_weight = models.FloatField(
        default=0.15,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Weight for cultural fit matching')
    )
    location_weight = models.FloatField(
        default=0.10,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Weight for location matching')
    )
    salary_weight = models.FloatField(
        default=0.10,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Weight for salary matching')
    )

    # Extracted requirements
    min_experience_years = models.PositiveIntegerField(
        null=True, blank=True
    )
    max_experience_years = models.PositiveIntegerField(
        null=True, blank=True
    )
    required_education_level = models.CharField(
        max_length=50,
        blank=True
    )
    is_remote = models.BooleanField(null=True, blank=True)

    # Company values for cultural fit
    company_values = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True
    )

    # Processing metadata
    last_processed = models.DateTimeField(auto_now=True)
    processing_version = models.CharField(max_length=50, blank=True)
    processing_status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('processing', 'Processing'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
        ],
        default='pending'
    )
    processing_error = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Job Matching Profile')
        verbose_name_plural = _('Job Matching Profiles')
        indexes = [
            models.Index(fields=['tenant', 'job']),
            models.Index(fields=['processing_status']),
            models.Index(fields=['-last_processed']),
        ]

    def __str__(self):
        return f"Matching Profile for {self.job}"

    def get_total_weight(self):
        """Calculate total weights (should sum to 1.0)."""
        return (
            self.experience_weight + self.skills_weight +
            self.education_weight + self.cultural_fit_weight +
            self.location_weight + self.salary_weight
        )

    def normalize_weights(self):
        """Normalize weights to sum to 1.0."""
        total = self.get_total_weight()
        if total > 0 and total != 1.0:
            self.experience_weight /= total
            self.skills_weight /= total
            self.education_weight /= total
            self.cultural_fit_weight /= total
            self.location_weight /= total
            self.salary_weight /= total
            self.save()


class MatchResult(TenantAwareModelMixin, models.Model):
    """
    Cached match results with detailed scoring breakdown.

    Stores computed match scores between candidates and jobs with
    full explainability for transparent AI decisions.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    candidate = models.ForeignKey(
        'ats.Candidate',
        on_delete=models.CASCADE,
        related_name='ai_match_results'
    )
    job = models.ForeignKey(
        'ats.JobPosting',
        on_delete=models.CASCADE,
        related_name='ai_match_results'
    )

    # Overall score
    overall_score = models.FloatField(
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Overall match score (0-1)')
    )

    # Component scores
    skill_match_score = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(1)]
    )
    experience_match_score = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(1)]
    )
    education_match_score = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(1)]
    )
    cultural_fit_score = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(1)]
    )
    location_match_score = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(1)]
    )
    salary_match_score = models.FloatField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(1)]
    )

    # Embedding similarity (raw cosine similarity)
    embedding_similarity = models.FloatField(
        null=True, blank=True,
        validators=[MinValueValidator(-1), MaxValueValidator(1)]
    )

    # Skill analysis
    matched_skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True
    )
    missing_skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True
    )
    bonus_skills = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('Extra skills candidate has beyond requirements')
    )

    # Human-readable explanation
    explanation = models.JSONField(
        default=dict,
        blank=True,
        help_text=_(
            'Detailed explanation of match. Format: '
            '{"summary": "...", "strengths": [...], "gaps": [...], "recommendations": [...]}'
        )
    )

    # Match quality indicators
    confidence_level = models.CharField(
        max_length=20,
        choices=[
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
        ],
        default='medium'
    )
    algorithm_used = models.CharField(
        max_length=30,
        choices=[
            ('ai_embedding', 'AI Embedding Based'),
            ('rule_based', 'Rule-Based Fallback'),
            ('hybrid', 'Hybrid AI + Rules'),
        ],
        default='hybrid'
    )

    # Processing metadata
    computed_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        null=True, blank=True,
        help_text=_('When this cached result should be recalculated')
    )
    model_version = models.CharField(
        max_length=50,
        blank=True,
        help_text=_('AI model version used for this match')
    )
    computation_time_ms = models.PositiveIntegerField(
        null=True, blank=True,
        help_text=_('Time taken to compute this match in milliseconds')
    )

    # Status
    is_stale = models.BooleanField(
        default=False,
        help_text=_('Whether this match needs recalculation')
    )

    class Meta:
        verbose_name = _('Match Result')
        verbose_name_plural = _('Match Results')
        unique_together = ['tenant', 'candidate', 'job']
        ordering = ['-overall_score']
        indexes = [
            models.Index(fields=['tenant', 'candidate', 'job']),
            models.Index(fields=['tenant', 'job', '-overall_score']),
            models.Index(fields=['tenant', 'candidate', '-overall_score']),
            models.Index(fields=['overall_score']),
            models.Index(fields=['computed_at']),
            models.Index(fields=['is_stale']),
        ]

    def __str__(self):
        return f"Match: {self.candidate} - {self.job} ({self.overall_score:.2%})"

    def save(self, *args, **kwargs):
        # Set default expiration to 24 hours if not set
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)

    @property
    def is_expired(self):
        """Check if this match result has expired."""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at

    def generate_explanation_text(self) -> str:
        """Generate human-readable explanation from JSON data."""
        if not self.explanation:
            return ""

        parts = []
        if self.explanation.get('summary'):
            parts.append(self.explanation['summary'])

        if self.explanation.get('strengths'):
            parts.append("\nStrengths:")
            for s in self.explanation['strengths']:
                parts.append(f"  - {s}")

        if self.explanation.get('gaps'):
            parts.append("\nAreas for Development:")
            for g in self.explanation['gaps']:
                parts.append(f"  - {g}")

        return "\n".join(parts)


class SkillTaxonomy(models.Model):
    """
    Hierarchical skill taxonomy for normalization.

    Provides standardized skill names, categories, and relationships
    for consistent matching across different terminology.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Skill identification
    canonical_name = models.CharField(
        max_length=100,
        unique=True,
        help_text=_('Standardized skill name')
    )
    display_name = models.CharField(
        max_length=100,
        help_text=_('User-friendly display name')
    )

    # Hierarchy
    category = models.CharField(
        max_length=50,
        db_index=True,
        help_text=_('Skill category (e.g., programming, soft_skills)')
    )
    subcategory = models.CharField(
        max_length=50,
        blank=True
    )
    parent = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='children',
        help_text=_('Parent skill (e.g., Python -> Programming)')
    )

    # Aliases and synonyms
    aliases = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text=_('Alternative names (e.g., ["JS", "JavaScript", "ECMAScript"])')
    )

    # Relationships
    related_skills = models.ManyToManyField(
        'self',
        blank=True,
        symmetrical=True,
        help_text=_('Related skills for similarity matching')
    )

    # Embedding for semantic matching
    embedding = ArrayField(
        models.FloatField(),
        size=DEFAULT_EMBEDDING_DIMENSION,
        null=True,
        blank=True
    )

    # Metadata
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    popularity_score = models.FloatField(
        default=0.5,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('How commonly this skill appears in job postings')
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Skill Taxonomy')
        verbose_name_plural = _('Skill Taxonomies')
        ordering = ['category', 'canonical_name']
        indexes = [
            models.Index(fields=['canonical_name']),
            models.Index(fields=['category']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.display_name} ({self.category})"

    @classmethod
    def normalize_skill(cls, skill_name: str) -> 'SkillTaxonomy':
        """
        Find the canonical skill for a given name.

        Checks canonical_name, display_name, and aliases.
        """
        skill_lower = skill_name.lower().strip()

        # Try exact match
        try:
            return cls.objects.get(
                models.Q(canonical_name__iexact=skill_lower) |
                models.Q(display_name__iexact=skill_lower)
            )
        except cls.DoesNotExist:
            pass

        # Try alias match
        return cls.objects.filter(
            aliases__icontains=skill_lower,
            is_active=True
        ).first()


class BiasMetric(TenantAwareModelMixin, models.Model):
    """
    Track bias metrics across matching operations.

    Monitors for demographic bias in matching results to ensure
    fair and equitable candidate evaluation.
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Period
    period_start = models.DateField(db_index=True)
    period_end = models.DateField(db_index=True)

    # Scope
    job = models.ForeignKey(
        'ats.JobPosting',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='bias_metrics'
    )

    # Sample size
    total_candidates_evaluated = models.PositiveIntegerField(default=0)
    total_matches_computed = models.PositiveIntegerField(default=0)

    # Demographic parity metrics (if demographic data available)
    # Stored as JSON with anonymized aggregate counts
    demographic_distribution = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Distribution of candidates by demographic (anonymized)')
    )

    # Score distribution analysis
    score_distribution = models.JSONField(
        default=dict,
        blank=True,
        help_text=_(
            'Score distribution analysis. Format: '
            '{"mean": 0.65, "std": 0.15, "percentiles": {...}}'
        )
    )

    # Bias indicators
    gender_parity_score = models.FloatField(
        null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
        help_text=_('Gender parity score (1.0 = perfect parity)')
    )
    age_parity_score = models.FloatField(
        null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(1)]
    )

    # Fairness metrics
    disparate_impact_ratio = models.FloatField(
        null=True, blank=True,
        help_text=_('Disparate impact ratio (>0.8 generally acceptable)')
    )
    equal_opportunity_diff = models.FloatField(
        null=True, blank=True,
        help_text=_('Equal opportunity difference (closer to 0 is better)')
    )

    # Flagged issues
    bias_detected = models.BooleanField(default=False)
    bias_types = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True
    )
    recommendations = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Recommended actions to address bias')
    )

    # Audit
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_bias_metrics'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Bias Metric')
        verbose_name_plural = _('Bias Metrics')
        ordering = ['-period_start']
        indexes = [
            models.Index(fields=['tenant', 'period_start']),
            models.Index(fields=['bias_detected']),
        ]

    def __str__(self):
        scope = f"Job {self.job_id}" if self.job else "All Jobs"
        return f"Bias Metrics ({scope}) - {self.period_start}"


# =============================================================================
# HYBRID RANKING ENGINE (features.md Section 4)
# =============================================================================

class RankingProfile(TenantAwareModel):
    """
    Tenant-configurable ranking profile with weighted scoring components.

    Implements features.md Section 4.1-4.3:
    - Rules-based filters (Boolean knockouts)
    - AI scoring with transparent weights
    - Verification score integration
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100, help_text=_('Profile name'))
    description = models.TextField(blank=True)
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    # Weight Configuration (must sum to 1.0)
    rule_score_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.300'),
        help_text=_('Weight for deterministic rule matching (0-1)')
    )
    ai_score_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.500'),
        help_text=_('Weight for AI/ML matching (0-1)')
    )
    verification_score_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.200'),
        help_text=_('Weight for verification/trust score (0-1)')
    )

    # AI Component Weights (within AI score)
    skill_match_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.350'),
        help_text=_('Weight for skill matching')
    )
    experience_match_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.250'),
        help_text=_('Weight for experience level matching')
    )
    culture_fit_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.150'),
        help_text=_('Weight for culture fit prediction')
    )
    location_match_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.150'),
        help_text=_('Weight for location/remote preference')
    )
    salary_match_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.100'),
        help_text=_('Weight for salary expectation alignment')
    )

    # Verification Component Weights (within verification score)
    identity_verification_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.300'),
        help_text=_('Weight for KYC/identity verification')
    )
    career_verification_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.400'),
        help_text=_('Weight for employment/education verification')
    )
    trust_score_weight = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        default=Decimal('0.300'),
        help_text=_('Weight for overall trust score')
    )

    # Thresholds
    minimum_rule_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Minimum rule score to pass (0-100)')
    )
    minimum_ai_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Minimum AI score to pass (0-100)')
    )
    minimum_verification_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Minimum verification score to pass (0-100)')
    )
    minimum_overall_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('50.00'),
        help_text=_('Minimum overall score to recommend (0-100)')
    )

    # Knockout Rules (instant disqualification)
    knockout_on_missing_required_skills = models.BooleanField(
        default=True,
        help_text=_('Disqualify if missing required skills')
    )
    knockout_on_experience_mismatch = models.BooleanField(
        default=False,
        help_text=_('Disqualify if experience below minimum')
    )
    knockout_on_location_mismatch = models.BooleanField(
        default=False,
        help_text=_('Disqualify if location/remote mismatch')
    )
    knockout_on_salary_mismatch = models.BooleanField(
        default=False,
        help_text=_('Disqualify if salary expectation too high')
    )
    knockout_on_education_mismatch = models.BooleanField(
        default=False,
        help_text=_('Disqualify if education below minimum')
    )

    # Bonus Rules
    bonus_for_verified_career = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('5.00'),
        help_text=_('Bonus points for career verification')
    )
    bonus_for_premium_trust = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('3.00'),
        help_text=_('Bonus points for premium trust level')
    )
    bonus_for_platform_experience = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('2.00'),
        help_text=_('Bonus points for successful platform history')
    )

    # Audit
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='ranking_profiles_created'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='ranking_profiles_updated'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Ranking Profile')
        verbose_name_plural = _('Ranking Profiles')
        ordering = ['-is_default', 'name']

    def __str__(self):
        return f"{self.name} ({'Default' if self.is_default else 'Custom'})"

    def save(self, *args, **kwargs):
        # Ensure only one default profile per tenant
        if self.is_default:
            RankingProfile.objects.filter(
                tenant=self.tenant,
                is_default=True
            ).exclude(pk=self.pk).update(is_default=False)
        super().save(*args, **kwargs)

    def validate_weights(self) -> bool:
        """Validate that weights sum to 1.0."""
        main_weights = self.rule_score_weight + self.ai_score_weight + self.verification_score_weight
        ai_weights = (
            self.skill_match_weight + self.experience_match_weight +
            self.culture_fit_weight + self.location_match_weight + self.salary_match_weight
        )
        verification_weights = (
            self.identity_verification_weight + self.career_verification_weight + self.trust_score_weight
        )
        return (
            abs(main_weights - Decimal('1.0')) < Decimal('0.001') and
            abs(ai_weights - Decimal('1.0')) < Decimal('0.001') and
            abs(verification_weights - Decimal('1.0')) < Decimal('0.001')
        )


class RankingRule(TenantAwareModel):
    """
    Deterministic ranking rules for ATS filtering.

    Implements features.md Section 4.1:
    - Boolean knockout filters
    - Requirement matching rules
    - Configurable per job or tenant-wide
    """

    class RuleType(models.TextChoices):
        KNOCKOUT = 'knockout', _('Knockout (Must Pass)')
        PREFERENCE = 'preference', _('Preference (Weighted)')
        BONUS = 'bonus', _('Bonus (Additional Points)')

    class MatchOperator(models.TextChoices):
        EQUALS = 'eq', _('Equals')
        NOT_EQUALS = 'neq', _('Not Equals')
        GREATER_THAN = 'gt', _('Greater Than')
        GREATER_EQUAL = 'gte', _('Greater Than or Equal')
        LESS_THAN = 'lt', _('Less Than')
        LESS_EQUAL = 'lte', _('Less Than or Equal')
        CONTAINS = 'contains', _('Contains')
        NOT_CONTAINS = 'not_contains', _('Not Contains')
        IN_LIST = 'in', _('In List')
        NOT_IN_LIST = 'not_in', _('Not In List')
        MATCHES_ANY = 'any', _('Matches Any')
        MATCHES_ALL = 'all', _('Matches All')

    class FieldType(models.TextChoices):
        SKILL = 'skill', _('Skill')
        EXPERIENCE_YEARS = 'experience_years', _('Years of Experience')
        EDUCATION_LEVEL = 'education', _('Education Level')
        CERTIFICATION = 'certification', _('Certification')
        LOCATION = 'location', _('Location')
        REMOTE_PREFERENCE = 'remote', _('Remote Preference')
        SALARY_EXPECTATION = 'salary', _('Salary Expectation')
        LANGUAGE = 'language', _('Language')
        WORK_AUTHORIZATION = 'work_auth', _('Work Authorization')
        AVAILABILITY = 'availability', _('Availability Date')
        CUSTOM = 'custom', _('Custom Field')

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    # Rule Configuration
    rule_type = models.CharField(
        max_length=20,
        choices=RuleType.choices,
        default=RuleType.PREFERENCE
    )
    field_type = models.CharField(
        max_length=20,
        choices=FieldType.choices
    )
    operator = models.CharField(
        max_length=20,
        choices=MatchOperator.choices,
        default=MatchOperator.EQUALS
    )

    # Value Configuration
    target_value = models.JSONField(
        default=dict,
        help_text=_('Target value(s) for comparison')
    )
    weight = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('1.00'),
        help_text=_('Weight/points for this rule')
    )

    # Scope
    apply_to_all_jobs = models.BooleanField(
        default=True,
        help_text=_('Apply to all jobs in tenant')
    )
    job_categories = ArrayField(
        models.CharField(max_length=50),
        default=list,
        blank=True,
        help_text=_('Specific job categories to apply to')
    )

    # Priority
    priority = models.PositiveIntegerField(
        default=100,
        help_text=_('Evaluation priority (lower = first)')
    )

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Ranking Rule')
        verbose_name_plural = _('Ranking Rules')
        ordering = ['priority', 'name']

    def __str__(self):
        return f"{self.name} ({self.get_rule_type_display()})"

    def evaluate(self, candidate_data: dict) -> tuple:
        """
        Evaluate rule against candidate data.
        Returns (passed: bool, score: Decimal, reason: str)
        """
        field_value = candidate_data.get(self.field_type)

        if field_value is None:
            if self.rule_type == self.RuleType.KNOCKOUT:
                return (False, Decimal('0'), f"Missing required field: {self.field_type}")
            return (True, Decimal('0'), f"Field not provided: {self.field_type}")

        target = self.target_value.get('value') if isinstance(self.target_value, dict) else self.target_value
        passed = False
        reason = ""

        if self.operator == self.MatchOperator.EQUALS:
            passed = field_value == target
            reason = f"{self.field_type} {'equals' if passed else 'does not equal'} {target}"

        elif self.operator == self.MatchOperator.NOT_EQUALS:
            passed = field_value != target
            reason = f"{self.field_type} {'does not equal' if passed else 'equals'} {target}"

        elif self.operator == self.MatchOperator.GREATER_THAN:
            passed = float(field_value) > float(target)
            reason = f"{self.field_type} {'>' if passed else '<='} {target}"

        elif self.operator == self.MatchOperator.GREATER_EQUAL:
            passed = float(field_value) >= float(target)
            reason = f"{self.field_type} {'>=' if passed else '<'} {target}"

        elif self.operator == self.MatchOperator.LESS_THAN:
            passed = float(field_value) < float(target)
            reason = f"{self.field_type} {'<' if passed else '>='} {target}"

        elif self.operator == self.MatchOperator.LESS_EQUAL:
            passed = float(field_value) <= float(target)
            reason = f"{self.field_type} {'<=' if passed else '>'} {target}"

        elif self.operator == self.MatchOperator.CONTAINS:
            passed = target.lower() in str(field_value).lower()
            reason = f"{self.field_type} {'contains' if passed else 'does not contain'} {target}"

        elif self.operator == self.MatchOperator.IN_LIST:
            target_list = target if isinstance(target, list) else [target]
            passed = field_value in target_list
            reason = f"{self.field_type} {'in' if passed else 'not in'} list"

        elif self.operator == self.MatchOperator.MATCHES_ANY:
            target_list = target if isinstance(target, list) else [target]
            if isinstance(field_value, list):
                passed = bool(set(field_value) & set(target_list))
            else:
                passed = field_value in target_list
            reason = f"{self.field_type} {'matches' if passed else 'does not match'} any"

        elif self.operator == self.MatchOperator.MATCHES_ALL:
            target_list = target if isinstance(target, list) else [target]
            if isinstance(field_value, list):
                passed = set(target_list).issubset(set(field_value))
            else:
                passed = len(target_list) == 1 and field_value == target_list[0]
            reason = f"{self.field_type} {'matches' if passed else 'does not match'} all required"

        else:
            passed = True
            reason = "Unknown operator"

        score = self.weight if passed else Decimal('0')
        return (passed, score, reason)


class CandidateRanking(TenantAwareModel):
    """
    Stores computed ranking for a candidate-job pair.

    Implements features.md Section 4.3:
    - Transparent three-score breakdown
    - Explainable ranking factors
    """

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # Foreign Keys (using string references for flexibility)
    job_id = models.PositiveIntegerField(help_text=_('Reference to Job model'))
    candidate_id = models.PositiveIntegerField(help_text=_('Reference to Candidate/User model'))

    # Ranking Profile Used
    ranking_profile = models.ForeignKey(
        RankingProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='rankings'
    )

    # Three-Score Breakdown
    rule_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Deterministic rule-based score (0-100)')
    )
    ai_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('AI/ML matching score (0-100)')
    )
    verification_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Trust/verification score (0-100)')
    )
    overall_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Weighted overall score (0-100)')
    )

    # AI Component Breakdown
    skill_match_score = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))
    experience_match_score = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))
    culture_fit_score = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))
    location_match_score = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))
    salary_match_score = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))

    # Verification Component Breakdown
    identity_verification_score = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))
    career_verification_score = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))
    trust_score_value = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('0.00'))

    # Bonuses Applied
    bonus_points = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal('0.00')
    )
    bonuses_applied = models.JSONField(
        default=list,
        blank=True,
        help_text=_('List of bonuses applied')
    )

    # Knockout Status
    passed_knockout = models.BooleanField(default=True)
    knockout_reasons = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Reasons for knockout if failed')
    )

    # Rule Evaluation Details
    rules_evaluated = models.PositiveIntegerField(default=0)
    rules_passed = models.PositiveIntegerField(default=0)
    rule_details = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Detailed results per rule')
    )

    # Explanation (for transparency)
    ranking_explanation = models.JSONField(
        default=dict,
        blank=True,
        help_text=_('Human-readable explanation of ranking')
    )
    top_strengths = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Top 5 matching strengths')
    )
    improvement_areas = models.JSONField(
        default=list,
        blank=True,
        help_text=_('Areas where candidate could improve match')
    )

    # Status
    is_recommended = models.BooleanField(
        default=False,
        help_text=_('Passes minimum threshold')
    )
    rank_position = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text=_('Position in ranked list for this job')
    )

    # Timestamps
    calculated_at = models.DateTimeField(auto_now_add=True)
    recalculated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Candidate Ranking')
        verbose_name_plural = _('Candidate Rankings')
        ordering = ['-overall_score']
        unique_together = ['tenant', 'job_id', 'candidate_id']
        indexes = [
            models.Index(fields=['tenant', 'job_id', '-overall_score']),
            models.Index(fields=['tenant', 'candidate_id']),
            models.Index(fields=['is_recommended', '-overall_score']),
        ]

    def __str__(self):
        return f"Job {self.job_id} - Candidate {self.candidate_id}: {self.overall_score}"

    def calculate_overall(self, profile: RankingProfile = None):
        """Calculate overall score using ranking profile weights."""
        if not profile:
            profile = self.ranking_profile

        if not profile:
            # Use equal weights if no profile
            self.overall_score = (self.rule_score + self.ai_score + self.verification_score) / 3
        else:
            weighted_score = (
                self.rule_score * profile.rule_score_weight +
                self.ai_score * profile.ai_score_weight +
                self.verification_score * profile.verification_score_weight
            )
            self.overall_score = weighted_score + self.bonus_points

        # Determine recommendation
        if profile:
            self.is_recommended = (
                self.passed_knockout and
                self.overall_score >= profile.minimum_overall_score
            )
        else:
            self.is_recommended = self.passed_knockout and self.overall_score >= 50

        self.save()

    def generate_explanation(self) -> dict:
        """Generate human-readable explanation of the ranking."""
        explanation = {
            'summary': f"Overall match score: {self.overall_score}/100",
            'breakdown': {
                'rules': {
                    'score': float(self.rule_score),
                    'description': f"Passed {self.rules_passed}/{self.rules_evaluated} requirements"
                },
                'ai_match': {
                    'score': float(self.ai_score),
                    'components': {
                        'skills': float(self.skill_match_score),
                        'experience': float(self.experience_match_score),
                        'culture_fit': float(self.culture_fit_score),
                        'location': float(self.location_match_score),
                        'salary': float(self.salary_match_score),
                    }
                },
                'verification': {
                    'score': float(self.verification_score),
                    'components': {
                        'identity': float(self.identity_verification_score),
                        'career': float(self.career_verification_score),
                        'trust': float(self.trust_score_value),
                    }
                }
            },
            'bonuses': self.bonuses_applied,
            'knockout_passed': self.passed_knockout,
            'knockout_reasons': self.knockout_reasons,
            'recommended': self.is_recommended,
        }

        self.ranking_explanation = explanation
        self.save()
        return explanation
