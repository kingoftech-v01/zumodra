"""
ATS Serializers - REST API serialization for Applicant Tracking System

This module provides DRF serializers for:
- Job Categories and Pipelines
- Job Postings (list/detail/create variants)
- Candidates (with resume upload)
- Applications (with stage transitions)
- Interviews and Feedback
- Offers (with e-sign tracking)
- Saved Searches

Enhanced with:
- Nested serializers for related objects
- Validation methods for business rules
- Computed fields (match_score, applicant_count, etc.)
"""

import logging
from decimal import Decimal
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import connection, transaction
from django.db.models import Avg, Count

from .models import (
    JobCategory, Pipeline, PipelineStage, JobPosting,
    Candidate, Application, ApplicationActivity, ApplicationNote,
    Interview, InterviewFeedback, Offer, SavedSearch,
    InterviewSlot, InterviewTemplate, OfferTemplate, OfferApproval,
    InterviewType, MeetingProvider,
    BackgroundCheck, BackgroundCheckDocument
)
from .validators import (
    ApplicationValidator,
    JobPostingValidator,
    CandidateValidator,
    PipelineValidator,
)

User = get_user_model()
logger = logging.getLogger(__name__)


def get_current_tenant():
    """
    Get the current tenant from the database connection.

    Returns:
        The current tenant or None if not available.
    """
    return getattr(connection, 'tenant', None)


# ==================== TENANT-FILTERED RELATED FIELD ====================

class TenantFilteredPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    """
    PrimaryKeyRelatedField that automatically filters queryset by tenant.

    This field ensures tenant isolation by filtering the queryset to only
    include objects belonging to the current tenant. The tenant is obtained
    from the request context or the database connection.

    Usage:
        category_id = TenantFilteredPrimaryKeyRelatedField(
            queryset=JobCategory.objects.all(),
            source='category',
            required=False,
            allow_null=True
        )
    """

    def get_queryset(self):
        """
        Filter queryset by current tenant.

        Returns:
            Filtered queryset scoped to the current tenant.
        """
        queryset = super().get_queryset()
        if queryset is None:
            return queryset

        # Try to get tenant from request context
        request = self.context.get('request')
        tenant = None

        if request and hasattr(request, 'tenant'):
            tenant = request.tenant
        else:
            # Fallback to connection tenant
            tenant = get_current_tenant()

        if tenant is not None:
            # Check if the model has a tenant field
            model = queryset.model
            if hasattr(model, 'tenant'):
                queryset = queryset.filter(tenant=tenant)

        return queryset


class TenantFilteredUserRelatedField(serializers.PrimaryKeyRelatedField):
    """
    PrimaryKeyRelatedField for User model with tenant filtering.

    Filters users to only those associated with the current tenant.
    This handles the case where User model doesn't have a direct tenant
    field but is related through a TenantUser or similar model.
    """

    def get_queryset(self):
        """
        Filter user queryset by current tenant context.

        For now, returns the base queryset since User filtering
        depends on the specific tenant-user relationship model.
        Override in subclass if needed for specific tenant-user models.
        """
        queryset = super().get_queryset()
        if queryset is None:
            return queryset

        # Get tenant from request context
        request = self.context.get('request')
        tenant = None

        if request and hasattr(request, 'tenant'):
            tenant = request.tenant
        else:
            tenant = get_current_tenant()

        # If the User model has a tenant relationship, filter by it
        # This depends on your specific User-Tenant relationship
        # Common patterns:
        # 1. User has a direct tenant field
        # 2. User has a profile with tenant field
        # 3. TenantUser intermediate model

        if tenant is not None:
            model = queryset.model
            if hasattr(model, 'tenant'):
                queryset = queryset.filter(tenant=tenant)
            elif hasattr(model, 'tenants'):
                # Many-to-many relationship
                queryset = queryset.filter(tenants=tenant)
            elif hasattr(model, 'profile') and hasattr(model.profile.field.related_model, 'tenant'):
                # User has profile with tenant
                queryset = queryset.filter(profile__tenant=tenant)

        return queryset


# ==================== USER SERIALIZERS ====================

class UserMinimalSerializer(serializers.ModelSerializer):
    """Minimal user representation for nested serializers."""
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name']
        read_only_fields = fields

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.email


# ==================== JOB CATEGORY SERIALIZERS ====================

class JobCategorySerializer(serializers.ModelSerializer):
    """Job category serializer with nested children and computed fields."""
    children = serializers.SerializerMethodField()
    jobs_count = serializers.SerializerMethodField()
    open_jobs_count = serializers.SerializerMethodField()
    full_path = serializers.ReadOnlyField()
    depth = serializers.ReadOnlyField()
    parent_name = serializers.CharField(source='parent.name', read_only=True, allow_null=True)

    class Meta:
        model = JobCategory
        fields = [
            'id', 'name', 'slug', 'description', 'parent', 'parent_name',
            'icon', 'color', 'sort_order', 'is_active',
            'children', 'jobs_count', 'open_jobs_count', 'full_path', 'depth'
        ]
        read_only_fields = ['id', 'full_path', 'depth']

    def get_children(self, obj):
        children = obj.children.filter(is_active=True)
        return JobCategorySerializer(children, many=True).data

    def get_jobs_count(self, obj):
        return obj.jobs.count()

    def get_open_jobs_count(self, obj):
        return obj.jobs.filter(status='open').count()

    def validate_parent(self, value):
        """Prevent circular parent references."""
        if value and self.instance:
            if value.pk == self.instance.pk:
                raise serializers.ValidationError(
                    "A category cannot be its own parent."
                )
            # Check for circular reference
            ancestor = value
            while ancestor:
                if ancestor.pk == self.instance.pk:
                    raise serializers.ValidationError(
                        "Circular parent reference detected."
                    )
                ancestor = ancestor.parent
        return value


class JobCategoryListSerializer(serializers.ModelSerializer):
    """Lightweight category serializer for lists."""

    class Meta:
        model = JobCategory
        fields = ['id', 'name', 'slug', 'icon', 'color']


# ==================== PIPELINE SERIALIZERS ====================

class PipelineStageSerializer(serializers.ModelSerializer):
    """Pipeline stage serializer with computed properties."""
    applications_count = serializers.SerializerMethodField()
    is_terminal = serializers.ReadOnlyField()
    is_first_stage = serializers.ReadOnlyField()
    is_last_stage = serializers.ReadOnlyField()
    average_time_in_stage_days = serializers.SerializerMethodField()
    next_stage_name = serializers.SerializerMethodField()

    class Meta:
        model = PipelineStage
        fields = [
            'id', 'uuid', 'pipeline', 'name', 'stage_type', 'description',
            'color', 'order', 'is_active', 'auto_reject_after_days',
            'send_email_on_enter', 'email_template_id', 'average_time_in_stage',
            'average_time_in_stage_days', 'applications_count',
            'is_terminal', 'is_first_stage', 'is_last_stage', 'next_stage_name'
        ]
        read_only_fields = ['id', 'uuid', 'average_time_in_stage', 'is_terminal',
                          'is_first_stage', 'is_last_stage']

    def get_applications_count(self, obj):
        return obj.applications.count()

    def get_average_time_in_stage_days(self, obj):
        if obj.average_time_in_stage:
            return obj.average_time_in_stage.days
        return None

    def get_next_stage_name(self, obj):
        next_stage = obj.get_next_stage()
        return next_stage.name if next_stage else None

    def validate_order(self, value):
        """Ensure order is non-negative."""
        if value < 0:
            raise serializers.ValidationError("Order must be non-negative.")
        return value


class PipelineStageCreateSerializer(serializers.ModelSerializer):
    """Pipeline stage creation serializer."""

    class Meta:
        model = PipelineStage
        fields = [
            'name', 'stage_type', 'description', 'color', 'order',
            'is_active', 'auto_reject_after_days', 'send_email_on_enter',
            'email_template_id'
        ]


class PipelineSerializer(serializers.ModelSerializer):
    """Pipeline serializer with nested stages and metrics - COMPANY ONLY."""
    stages = PipelineStageSerializer(many=True, read_only=True)
    created_by = UserMinimalSerializer(read_only=True)
    jobs_count = serializers.SerializerMethodField()
    stages_count = serializers.ReadOnlyField()
    total_applications = serializers.ReadOnlyField()
    average_time_to_hire_days = serializers.SerializerMethodField()
    conversion_rate = serializers.ReadOnlyField()
    tenant_type = serializers.CharField(source='tenant.tenant_type', read_only=True)

    class Meta:
        model = Pipeline
        fields = [
            'id', 'uuid', 'name', 'description', 'is_default', 'is_active',
            'created_by', 'created_at', 'updated_at', 'stages', 'jobs_count',
            'stages_count', 'total_applications', 'average_time_to_hire_days',
            'conversion_rate', 'tenant_type'
        ]
        read_only_fields = ['id', 'uuid', 'created_at', 'updated_at', 'stages_count',
                          'total_applications', 'conversion_rate']

    def get_jobs_count(self, obj):
        return obj.jobs.count()

    def get_average_time_to_hire_days(self, obj):
        avg_time = obj.average_time_to_hire
        if avg_time:
            return avg_time.days
        return None

    def validate_name(self, value):
        """Ensure name is unique within tenant."""
        request = self.context.get('request')
        if request and hasattr(request, 'tenant'):
            qs = Pipeline.objects.filter(tenant=request.tenant, name=value)
            if self.instance:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise serializers.ValidationError(
                    "A pipeline with this name already exists."
                )
        return value


class PipelineListSerializer(serializers.ModelSerializer):
    """Lightweight pipeline serializer for lists."""
    stages_count = serializers.SerializerMethodField()

    class Meta:
        model = Pipeline
        fields = ['id', 'uuid', 'name', 'is_default', 'is_active', 'stages_count']

    def get_stages_count(self, obj):
        return obj.stages.filter(is_active=True).count()


class PipelineCreateSerializer(serializers.ModelSerializer):
    """Pipeline creation serializer."""
    stages = PipelineStageCreateSerializer(many=True, required=False)

    class Meta:
        model = Pipeline
        fields = ['name', 'description', 'is_default', 'is_active', 'stages']

    @transaction.atomic
    def create(self, validated_data):
        stages_data = validated_data.pop('stages', [])
        pipeline = Pipeline.objects.create(**validated_data)

        for order, stage_data in enumerate(stages_data):
            stage_data['order'] = order
            PipelineStage.objects.create(pipeline=pipeline, **stage_data)

        return pipeline


# ==================== JOB POSTING SERIALIZERS ====================

class JobPostingListSerializer(serializers.ModelSerializer):
    """Lightweight job posting serializer for lists with computed fields."""
    category_name = serializers.CharField(source='category.name', read_only=True)
    pipeline_name = serializers.CharField(source='pipeline.name', read_only=True)
    applications_count = serializers.ReadOnlyField()
    active_applications_count = serializers.ReadOnlyField()
    location_display = serializers.ReadOnlyField()
    salary_range_display = serializers.ReadOnlyField()
    hiring_manager_name = serializers.SerializerMethodField()
    is_open = serializers.ReadOnlyField()
    is_closed = serializers.ReadOnlyField()
    is_publishable = serializers.ReadOnlyField()
    can_accept_applications = serializers.ReadOnlyField()
    days_open = serializers.ReadOnlyField()
    positions_remaining = serializers.ReadOnlyField()

    class Meta:
        model = JobPosting
        fields = [
            'id', 'uuid', 'title', 'slug', 'reference_code', 'status',
            'job_type', 'experience_level', 'remote_policy',
            'category_name', 'pipeline_name', 'location_display',
            'salary_min', 'salary_max', 'salary_currency', 'show_salary',
            'salary_range_display',
            'positions_count', 'positions_remaining', 'hiring_manager_name',
            'applications_count', 'active_applications_count',
            'is_featured', 'is_internal_only', 'application_deadline',
            'is_open', 'is_closed', 'is_publishable', 'can_accept_applications',
            'days_open', 'created_at', 'published_at'
        ]

    def get_hiring_manager_name(self, obj):
        if obj.hiring_manager:
            return f"{obj.hiring_manager.first_name} {obj.hiring_manager.last_name}".strip()
        return None


class JobPostingDetailSerializer(serializers.ModelSerializer):
    """Detailed job posting serializer - COMPANY ONLY."""
    category = JobCategoryListSerializer(read_only=True)
    pipeline = PipelineListSerializer(read_only=True)
    hiring_manager = UserMinimalSerializer(read_only=True)
    recruiter = UserMinimalSerializer(read_only=True)
    created_by = UserMinimalSerializer(read_only=True)
    applications_count = serializers.SerializerMethodField()
    applications_by_stage = serializers.SerializerMethodField()
    salary_range_display = serializers.ReadOnlyField()
    tenant_type = serializers.CharField(source='tenant.tenant_type', read_only=True)
    can_create_jobs = serializers.SerializerMethodField()

    class Meta:
        model = JobPosting
        fields = [
            'id', 'uuid', 'title', 'slug', 'reference_code',
            'category', 'status', 'pipeline',
            'description', 'responsibilities', 'requirements',
            'nice_to_have', 'benefits',
            'job_type', 'experience_level', 'remote_policy',
            'location_city', 'location_state', 'location_country',
            'location_coordinates',
            'salary_min', 'salary_max', 'salary_currency', 'salary_period',
            'show_salary', 'salary_range_display', 'equity_offered', 'equity_range',
            'required_skills', 'preferred_skills', 'education_requirements',
            'certifications_required', 'languages_required',
            'positions_count', 'hiring_manager', 'recruiter', 'team', 'reports_to',
            'application_deadline', 'require_cover_letter', 'require_resume',
            'custom_questions', 'application_email', 'external_apply_url',
            'is_internal_only', 'is_featured', 'published_on_career_page',
            'published_on_job_boards',
            'meta_title', 'meta_description',
            'created_at', 'updated_at', 'published_at', 'closed_at',
            'created_by', 'applications_count', 'applications_by_stage',
            'tenant_type', 'can_create_jobs'
        ]

    def get_can_create_jobs(self, obj):
        """Check if tenant can create jobs (COMPANY only)."""
        return obj.tenant.can_create_jobs() if hasattr(obj, 'tenant') and obj.tenant else False

    def get_applications_count(self, obj):
        return obj.applications.count()

    def get_applications_by_stage(self, obj):
        """Get application counts grouped by pipeline stage."""
        if not obj.pipeline:
            return {}

        stages = obj.pipeline.stages.filter(is_active=True)
        result = {}
        for stage in stages:
            result[stage.name] = obj.applications.filter(current_stage=stage).count()
        return result


class JobPostingCreateSerializer(serializers.ModelSerializer):
    """Job posting creation/update serializer with enhanced validation."""
    # Use tenant-filtered fields to ensure tenant isolation
    category_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=JobCategory.objects.all(),
        source='category',
        required=False,
        allow_null=True
    )
    pipeline_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=Pipeline.objects.all(),
        source='pipeline',
        required=False,
        allow_null=True
    )
    hiring_manager_id = TenantFilteredUserRelatedField(
        queryset=User.objects.all(),
        source='hiring_manager',
        required=False,
        allow_null=True
    )
    recruiter_id = TenantFilteredUserRelatedField(
        queryset=User.objects.all(),
        source='recruiter',
        required=False,
        allow_null=True
    )

    class Meta:
        model = JobPosting
        fields = [
            'title', 'slug', 'reference_code', 'category_id', 'pipeline_id',
            'description', 'responsibilities', 'requirements',
            'nice_to_have', 'benefits',
            'job_type', 'experience_level', 'remote_policy',
            'location_city', 'location_state', 'location_country',
            'salary_min', 'salary_max', 'salary_currency', 'salary_period',
            'show_salary', 'equity_offered', 'equity_range',
            'required_skills', 'preferred_skills', 'education_requirements',
            'certifications_required', 'languages_required',
            'positions_count', 'hiring_manager_id', 'recruiter_id',
            'team', 'reports_to',
            'application_deadline', 'require_cover_letter', 'require_resume',
            'custom_questions', 'application_email', 'external_apply_url',
            'is_internal_only', 'is_featured', 'published_on_career_page',
            'published_on_job_boards',
            'meta_title', 'meta_description'
        ]

    def validate_reference_code(self, value):
        """Ensure reference code is unique within tenant."""
        instance = self.instance
        request = self.context.get('request')
        qs = JobPosting.objects.filter(reference_code=value)
        if request and hasattr(request, 'tenant'):
            qs = qs.filter(tenant=request.tenant)
        if instance:
            qs = qs.exclude(pk=instance.pk)
        if qs.exists():
            raise serializers.ValidationError("This reference code already exists.")
        return value

    def validate_positions_count(self, value):
        """Ensure at least 1 position."""
        if value < 1:
            raise serializers.ValidationError("At least 1 position is required.")
        return value

    def validate(self, data):
        """Cross-field validation using JobPostingValidator."""
        errors = {}

        # Salary validation
        salary_min = data.get('salary_min')
        salary_max = data.get('salary_max')
        if salary_min and salary_max and salary_min > salary_max:
            errors['salary_min'] = "Minimum salary cannot exceed maximum salary."

        # Deadline validation
        deadline = data.get('application_deadline')
        if deadline and deadline <= timezone.now():
            errors['application_deadline'] = "Application deadline must be in the future."

        if errors:
            raise serializers.ValidationError(errors)

        return data


class JobPostingCloneSerializer(serializers.Serializer):
    """Serializer for cloning a job posting."""
    new_title = serializers.CharField(max_length=200, required=False)
    new_reference_code = serializers.CharField(max_length=50)

    def validate_new_reference_code(self, value):
        """Ensure reference code is unique within the current tenant."""
        # Get tenant from request context
        request = self.context.get('request')
        tenant = None

        if request and hasattr(request, 'tenant'):
            tenant = request.tenant
        else:
            tenant = get_current_tenant()

        # Filter by tenant for proper isolation
        qs = JobPosting.objects.filter(reference_code=value)
        if tenant is not None:
            qs = qs.filter(tenant=tenant)

        if qs.exists():
            raise serializers.ValidationError("This reference code already exists.")
        return value


# ==================== CANDIDATE SERIALIZERS ====================

class CandidateListSerializer(serializers.ModelSerializer):
    """Lightweight candidate serializer for lists with computed fields."""
    full_name = serializers.ReadOnlyField()
    initials = serializers.ReadOnlyField()
    location_display = serializers.ReadOnlyField()
    applications_count = serializers.ReadOnlyField()
    active_applications_count = serializers.ReadOnlyField()
    is_currently_employed = serializers.ReadOnlyField()
    has_valid_consent = serializers.ReadOnlyField()
    days_since_last_activity = serializers.ReadOnlyField()
    latest_application = serializers.SerializerMethodField()

    class Meta:
        model = Candidate
        fields = [
            'id', 'uuid', 'first_name', 'last_name', 'full_name', 'initials',
            'email', 'phone', 'headline', 'current_company', 'current_title',
            'city', 'country', 'location_display', 'source', 'tags', 'skills',
            'applications_count', 'active_applications_count',
            'is_currently_employed', 'has_valid_consent', 'days_since_last_activity',
            'latest_application', 'created_at', 'last_activity_at'
        ]

    def get_latest_application(self, obj):
        latest = obj.applications.order_by('-applied_at').first()
        if latest:
            return {
                'id': str(latest.id),
                'job_id': str(latest.job.id),
                'job_title': latest.job.title,
                'status': latest.status,
                'stage_name': latest.current_stage.name if latest.current_stage else None,
                'applied_at': latest.applied_at.isoformat()
            }
        return None


class CandidateDetailSerializer(serializers.ModelSerializer):
    """Detailed candidate serializer with computed fields - COMPANY ONLY."""
    user = UserMinimalSerializer(read_only=True)
    referred_by = UserMinimalSerializer(read_only=True)
    full_name = serializers.ReadOnlyField()
    initials = serializers.ReadOnlyField()
    location_display = serializers.ReadOnlyField()
    applications_count = serializers.ReadOnlyField()
    active_applications_count = serializers.ReadOnlyField()
    is_currently_employed = serializers.ReadOnlyField()
    has_valid_consent = serializers.ReadOnlyField()
    days_since_last_activity = serializers.ReadOnlyField()
    applications = serializers.SerializerMethodField()
    skill_summary = serializers.SerializerMethodField()
    tenant_type = serializers.CharField(source='tenant.tenant_type', read_only=True)

    class Meta:
        model = Candidate
        fields = [
            'id', 'uuid', 'user',
            'first_name', 'last_name', 'full_name', 'initials', 'email', 'phone',
            'headline', 'summary', 'current_company', 'current_title',
            'years_experience', 'location_display',
            'city', 'state', 'country', 'willing_to_relocate',
            'resume', 'resume_text', 'cover_letter', 'portfolio_url',
            'skills', 'skill_summary', 'education', 'certifications',
            'work_experience', 'languages',
            'linkedin_url', 'github_url', 'twitter_url', 'website_url',
            'desired_salary_min', 'desired_salary_max', 'notice_period_days',
            'work_authorization',
            'source', 'source_detail', 'referred_by',
            'tags', 'consent_to_store', 'consent_date', 'data_retention_until',
            'has_valid_consent', 'is_currently_employed',
            'applications_count', 'active_applications_count',
            'days_since_last_activity',
            'created_at', 'updated_at', 'last_activity_at',
            'applications', 'tenant_type'
        ]

    def get_applications(self, obj):
        applications = obj.applications.select_related('job', 'current_stage').order_by('-applied_at')[:10]
        return ApplicationListSerializer(applications, many=True).data

    def get_skill_summary(self, obj):
        """Return skills summary with counts."""
        return {
            'total_count': len(obj.skills),
            'skills': obj.skills[:10],  # Top 10 skills
            'has_more': len(obj.skills) > 10
        }


class CandidateCreateSerializer(serializers.ModelSerializer):
    """Candidate creation serializer with enhanced validation."""
    resume = serializers.FileField(required=False, allow_null=True)
    referred_by_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source='referred_by',
        required=False,
        allow_null=True
    )

    class Meta:
        model = Candidate
        fields = [
            'first_name', 'last_name', 'email', 'phone',
            'headline', 'summary', 'current_company', 'current_title',
            'years_experience',
            'city', 'state', 'country', 'willing_to_relocate',
            'resume', 'cover_letter', 'portfolio_url',
            'skills', 'education', 'certifications', 'work_experience', 'languages',
            'linkedin_url', 'github_url', 'twitter_url', 'website_url',
            'desired_salary_min', 'desired_salary_max', 'notice_period_days',
            'work_authorization',
            'source', 'source_detail', 'referred_by_id',
            'tags', 'consent_to_store'
        ]

    def validate_email(self, value):
        """Check for duplicate email within tenant when creating new candidate."""
        instance = self.instance
        request = self.context.get('request')
        qs = Candidate.objects.filter(email__iexact=value)
        if request and hasattr(request, 'tenant'):
            qs = qs.filter(tenant=request.tenant)
        if instance:
            qs = qs.exclude(pk=instance.pk)
        if qs.exists():
            raise serializers.ValidationError(
                "A candidate with this email already exists."
            )
        return value.lower()

    def validate(self, data):
        """Cross-field validation using CandidateValidator."""
        result = CandidateValidator.validate_candidate_data(data)

        if not result.is_valid:
            errors = {}
            for field, messages in result.errors.items():
                errors[field] = messages[0] if messages else "Validation failed."
            raise serializers.ValidationError(errors)

        return data

    @transaction.atomic
    def create(self, validated_data):
        request = self.context.get('request')
        tenant = getattr(request, 'tenant', None) if request else None

        # Set tenant if available
        if tenant:
            validated_data['tenant'] = tenant

        if validated_data.get('consent_to_store'):
            validated_data['consent_date'] = timezone.now()

        return super().create(validated_data)


class CandidateBulkImportSerializer(serializers.Serializer):
    """Serializer for bulk importing candidates."""
    candidates = CandidateCreateSerializer(many=True)
    skip_duplicates = serializers.BooleanField(default=True)
    source = serializers.CharField(default='imported')

    @transaction.atomic
    def create(self, validated_data):
        candidates_data = validated_data['candidates']
        skip_duplicates = validated_data.get('skip_duplicates', True)
        source = validated_data.get('source', 'imported')

        # Get tenant from request context for proper isolation
        request = self.context.get('request')
        tenant = None
        if request and hasattr(request, 'tenant'):
            tenant = request.tenant
        else:
            tenant = get_current_tenant()

        created = []
        skipped = []

        for candidate_data in candidates_data:
            candidate_data['source'] = source
            email = candidate_data.get('email')

            # Filter by tenant for proper isolation - CRITICAL FIX
            qs = Candidate.objects.filter(email__iexact=email)
            if tenant is not None:
                qs = qs.filter(tenant=tenant)

            if qs.exists():
                if skip_duplicates:
                    skipped.append(email)
                    continue
                else:
                    raise serializers.ValidationError(
                        f"Candidate with email {email} already exists."
                    )

            # Set tenant on the candidate data
            if tenant is not None:
                candidate_data['tenant'] = tenant

            candidate = Candidate.objects.create(**candidate_data)
            created.append(candidate)

        return {'created': created, 'skipped': skipped}


class CandidateMergeSerializer(serializers.Serializer):
    """Serializer for merging duplicate candidates."""
    source_candidate_ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=1
    )
    target_candidate_id = serializers.IntegerField()
    delete_source = serializers.BooleanField(default=True)


# ==================== APPLICATION SERIALIZERS ====================

class ApplicationListSerializer(serializers.ModelSerializer):
    """Lightweight application serializer for lists with computed fields."""
    candidate_name = serializers.CharField(source='candidate.full_name', read_only=True)
    candidate_email = serializers.CharField(source='candidate.email', read_only=True)
    candidate_initials = serializers.CharField(source='candidate.initials', read_only=True)
    job_title = serializers.CharField(source='job.title', read_only=True)
    job_reference = serializers.CharField(source='job.reference_code', read_only=True)
    stage_name = serializers.CharField(source='current_stage.name', read_only=True)
    stage_color = serializers.CharField(source='current_stage.color', read_only=True)
    stage_type = serializers.CharField(source='current_stage.stage_type', read_only=True)

    # Computed fields
    is_active = serializers.ReadOnlyField()
    is_terminal = serializers.ReadOnlyField()
    can_advance = serializers.ReadOnlyField()
    can_reject = serializers.ReadOnlyField()
    days_in_pipeline = serializers.ReadOnlyField()
    days_in_current_stage = serializers.ReadOnlyField()
    interviews_count = serializers.ReadOnlyField()
    has_pending_interviews = serializers.ReadOnlyField()

    # Hybrid Match Score (lightweight for lists)
    match_score_summary = serializers.SerializerMethodField()

    class Meta:
        model = Application
        fields = [
            'id', 'uuid', 'candidate', 'job',
            'candidate_name', 'candidate_email', 'candidate_initials',
            'job_title', 'job_reference',
            'status', 'current_stage', 'stage_name', 'stage_color', 'stage_type',
            'overall_rating', 'ai_match_score', 'match_score_summary',
            'is_active', 'is_terminal', 'can_advance', 'can_reject',
            'days_in_pipeline', 'days_in_current_stage',
            'interviews_count', 'has_pending_interviews',
            'applied_at', 'last_stage_change_at'
        ]

    def get_match_score_summary(self, obj):
        """
        Get lightweight match score summary for list views.

        Returns overall score and match level only (no full breakdown).
        """
        try:
            from ai_matching.models import CandidateRanking

            ranking = CandidateRanking.objects.filter(
                job_id=obj.job.id,
                candidate_id=obj.candidate.id,
                is_stale=False
            ).first()

            if ranking:
                score = float(ranking.overall_score)
                return {
                    'overall': score,
                    'level': self._get_match_level(score),
                    'passed_knockout': ranking.passed_knockout,
                    'is_verified': ranking.trust_score_value and float(ranking.trust_score_value) > 50
                }
            return None
        except Exception:
            return None

    def _get_match_level(self, score):
        """Convert numeric score to match level."""
        if score >= 85:
            return 'excellent'
        elif score >= 70:
            return 'good'
        elif score >= 50:
            return 'moderate'
        elif score >= 30:
            return 'limited'
        return 'poor'


class ApplicationDetailSerializer(serializers.ModelSerializer):
    """Detailed application serializer with computed fields and nested relations - COMPANY ONLY."""
    candidate = CandidateListSerializer(read_only=True)
    job = JobPostingListSerializer(read_only=True)
    current_stage = PipelineStageSerializer(read_only=True)
    assigned_to = UserMinimalSerializer(read_only=True)
    interviews = serializers.SerializerMethodField()
    offers = serializers.SerializerMethodField()
    activities = serializers.SerializerMethodField()
    notes_count = serializers.SerializerMethodField()

    # Computed fields
    is_active = serializers.ReadOnlyField()
    is_terminal = serializers.ReadOnlyField()
    can_advance = serializers.ReadOnlyField()
    can_reject = serializers.ReadOnlyField()
    can_withdraw = serializers.ReadOnlyField()
    days_in_pipeline = serializers.ReadOnlyField()
    days_in_current_stage = serializers.ReadOnlyField()
    time_to_hire_days = serializers.SerializerMethodField()
    interviews_count = serializers.ReadOnlyField()
    has_pending_interviews = serializers.ReadOnlyField()
    average_interview_rating = serializers.ReadOnlyField()
    skill_match_score = serializers.SerializerMethodField()

    # Hybrid Match Score (Step 4 - Three-Score Breakdown)
    match_score = serializers.SerializerMethodField()

    # Tenant type
    tenant_type = serializers.CharField(source='job.tenant.tenant_type', read_only=True)

    class Meta:
        model = Application
        fields = [
            'id', 'uuid', 'candidate', 'job',
            'status', 'current_stage',
            'cover_letter', 'custom_answers', 'additional_documents',
            'overall_rating', 'ai_match_score',
            'assigned_to',
            'rejection_reason', 'rejection_feedback', 'send_rejection_email',
            'utm_source', 'utm_medium', 'utm_campaign', 'referrer_url',
            'applied_at', 'updated_at', 'last_stage_change_at',
            'reviewed_at', 'hired_at', 'rejected_at',
            # Computed fields
            'is_active', 'is_terminal', 'can_advance', 'can_reject', 'can_withdraw',
            'days_in_pipeline', 'days_in_current_stage', 'time_to_hire_days',
            'interviews_count', 'has_pending_interviews', 'average_interview_rating',
            'skill_match_score', 'match_score',
            # Related
            'interviews', 'offers', 'activities', 'notes_count',
            'tenant_type'
        ]

    def get_interviews(self, obj):
        interviews = obj.interviews.all().order_by('-scheduled_start')[:5]
        return InterviewListSerializer(interviews, many=True).data

    def get_offers(self, obj):
        offers = obj.offers.all().order_by('-created_at')[:3]
        return OfferListSerializer(offers, many=True).data

    def get_activities(self, obj):
        activities = obj.activities.all().order_by('-created_at')[:20]
        return ApplicationActivitySerializer(activities, many=True).data

    def get_notes_count(self, obj):
        return obj.notes.count()

    def get_time_to_hire_days(self, obj):
        time_to_hire = obj.time_to_hire
        if time_to_hire:
            return time_to_hire.days
        return None

    def get_skill_match_score(self, obj):
        """Calculate skill match between candidate and job."""
        return obj.candidate.get_skill_match_score(obj.job)

    def get_match_score(self, obj):
        """
        Get hybrid match score with three-score breakdown.

        Returns the combined MatchScore from HybridRankingEngine:
        - rule_score: Deterministic rules (skills, experience, location)
        - ai_score: AI/ML semantic matching
        - verification_score: Trust/verification level
        - overall_score: Weighted combination
        """
        try:
            from ai_matching.models import CandidateRanking

            # Try to get cached ranking
            ranking = CandidateRanking.objects.filter(
                job_id=obj.job.id,
                candidate_id=obj.candidate.id,
                is_stale=False
            ).first()

            if ranking:
                return {
                    'overall_score': float(ranking.overall_score),
                    'rule_score': float(ranking.rule_score),
                    'ai_score': float(ranking.ai_score),
                    'verification_score': float(ranking.verification_score),
                    'passed_knockout': ranking.passed_knockout,
                    'match_level': self._get_match_level(float(ranking.overall_score)),
                    'breakdown': {
                        'skill_match': float(ranking.skill_match_score or 0),
                        'experience_match': float(ranking.experience_match_score or 0),
                        'culture_fit': float(ranking.culture_fit_score or 0),
                        'location_match': float(ranking.location_match_score or 0),
                        'salary_match': float(ranking.salary_match_score or 0),
                    },
                    'verification': {
                        'identity': float(ranking.identity_verification_score or 0),
                        'career': float(ranking.career_verification_score or 0),
                        'trust': float(ranking.trust_score_value or 0),
                    },
                    'skills': {
                        'matched': ranking.matched_skills or [],
                        'missing': ranking.missing_skills or [],
                    }
                }

            # Return null if no ranking exists
            return None

        except Exception:
            return None

    def _get_match_level(self, score):
        """Convert numeric score to human-readable match level."""
        if score >= 85:
            return 'excellent'
        elif score >= 70:
            return 'good'
        elif score >= 50:
            return 'moderate'
        elif score >= 30:
            return 'limited'
        return 'poor'


class ApplicationCreateSerializer(serializers.ModelSerializer):
    """Application creation serializer with enhanced validation."""
    # Use tenant-filtered fields to ensure tenant isolation
    candidate_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=Candidate.objects.all(),
        source='candidate'
    )
    job_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=JobPosting.objects.all(),
        source='job'
    )
    assigned_to_id = TenantFilteredUserRelatedField(
        queryset=User.objects.all(),
        source='assigned_to',
        required=False,
        allow_null=True
    )

    class Meta:
        model = Application
        fields = [
            'candidate_id', 'job_id', 'cover_letter', 'custom_answers',
            'assigned_to_id', 'utm_source', 'utm_medium', 'utm_campaign',
            'referrer_url'
        ]

    def validate(self, data):
        """Validate using ApplicationValidator."""
        candidate = data.get('candidate')
        job = data.get('job')
        request = self.context.get('request')
        tenant = getattr(request, 'tenant', None) if request else None

        # Use ApplicationValidator for comprehensive validation
        result = ApplicationValidator.can_apply(candidate, job, tenant)

        if not result.is_valid:
            # Convert validation errors to serializer errors
            errors = {}
            for field, messages in result.errors.items():
                errors[field] = messages[0] if messages else "Validation failed."
            raise serializers.ValidationError(errors)

        return data

    @transaction.atomic
    def create(self, validated_data):
        job = validated_data['job']
        candidate = validated_data['candidate']
        request = self.context.get('request')
        tenant = getattr(request, 'tenant', None) if request else None

        # Set tenant if available
        if tenant:
            validated_data['tenant'] = tenant

        # Set initial stage from job's pipeline
        if job.pipeline:
            initial_stage = job.pipeline.stages.filter(
                is_active=True
            ).order_by('order').first()
            validated_data['current_stage'] = initial_stage

        application = super().create(validated_data)

        # Calculate AI match score
        if candidate.skills and job.required_skills:
            match_score = candidate.get_skill_match_score(job)
            application.ai_match_score = Decimal(str(match_score))
            application.save(update_fields=['ai_match_score'])

        # Create initial activity
        ApplicationActivity.objects.create(
            application=application,
            activity_type=ApplicationActivity.ActivityType.APPLIED,
            performed_by=request.user if request and request.user.is_authenticated else None,
            notes=f"Applied via API"
        )

        # Update candidate last activity
        candidate.update_last_activity()

        return application


class ApplicationStageChangeSerializer(serializers.Serializer):
    """Serializer for moving application to a different stage."""
    stage_id = serializers.PrimaryKeyRelatedField(
        queryset=PipelineStage.objects.all()
    )
    notes = serializers.CharField(required=False, allow_blank=True)


class ApplicationRejectSerializer(serializers.Serializer):
    """Serializer for rejecting an application."""
    reason = serializers.CharField(max_length=200, required=False, allow_blank=True)
    feedback = serializers.CharField(required=False, allow_blank=True)
    send_email = serializers.BooleanField(default=True)


class ApplicationBulkActionSerializer(serializers.Serializer):
    """Serializer for bulk application actions."""
    application_ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=1
    )
    action = serializers.ChoiceField(choices=[
        'move_stage', 'reject', 'assign', 'delete'
    ])
    stage_id = serializers.IntegerField(required=False)
    assigned_to_id = serializers.IntegerField(required=False)
    rejection_reason = serializers.CharField(required=False, allow_blank=True)


# ==================== APPLICATION ACTIVITY SERIALIZERS ====================

class ApplicationActivitySerializer(serializers.ModelSerializer):
    """Application activity/timeline serializer (read-only)."""
    performed_by = UserMinimalSerializer(read_only=True)
    activity_type_display = serializers.CharField(
        source='get_activity_type_display',
        read_only=True
    )

    class Meta:
        model = ApplicationActivity
        fields = [
            'id', 'uuid', 'application', 'activity_type', 'activity_type_display',
            'performed_by', 'old_value', 'new_value', 'notes', 'metadata',
            'created_at'
        ]
        read_only_fields = fields


# ==================== APPLICATION NOTE SERIALIZERS ====================

class ApplicationNoteSerializer(serializers.ModelSerializer):
    """Application note serializer."""
    author = UserMinimalSerializer(read_only=True)
    mentions = UserMinimalSerializer(many=True, read_only=True)
    mention_ids = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        many=True,
        write_only=True,
        required=False,
        source='mentions'
    )

    class Meta:
        model = ApplicationNote
        fields = [
            'id', 'uuid', 'application', 'author', 'content',
            'is_private', 'mentions', 'mention_ids',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'uuid', 'author', 'created_at', 'updated_at']

    def create(self, validated_data):
        mentions = validated_data.pop('mentions', [])
        note = ApplicationNote.objects.create(**validated_data)
        if mentions:
            note.mentions.set(mentions)

        # Log activity
        ApplicationActivity.objects.create(
            application=note.application,
            activity_type=ApplicationActivity.ActivityType.NOTE_ADDED,
            performed_by=note.author,
            notes=f"Note added: {note.content[:100]}..."
        )

        return note


# ==================== INTERVIEW SERIALIZERS ====================

class InterviewListSerializer(serializers.ModelSerializer):
    """Lightweight interview serializer for lists."""
    candidate_name = serializers.CharField(
        source='application.candidate.full_name',
        read_only=True
    )
    job_title = serializers.CharField(
        source='application.job.title',
        read_only=True
    )
    interviewers_count = serializers.SerializerMethodField()
    feedback_count = serializers.SerializerMethodField()
    duration_minutes = serializers.ReadOnlyField()

    class Meta:
        model = Interview
        fields = [
            'id', 'uuid', 'application', 'candidate_name', 'job_title',
            'interview_type', 'status', 'title',
            'scheduled_start', 'scheduled_end', 'duration_minutes',
            'location', 'meeting_url',
            'interviewers_count', 'feedback_count',
            'created_at'
        ]

    def get_interviewers_count(self, obj):
        return obj.interviewers.count()

    def get_feedback_count(self, obj):
        return obj.feedback.count()


class InterviewDetailSerializer(serializers.ModelSerializer):
    """Detailed interview serializer - COMPANY ONLY."""
    application = ApplicationListSerializer(read_only=True)
    interviewers = UserMinimalSerializer(many=True, read_only=True)
    organizer = UserMinimalSerializer(read_only=True)
    feedback = serializers.SerializerMethodField()
    duration_minutes = serializers.ReadOnlyField()
    tenant_type = serializers.CharField(source='application.job.tenant.tenant_type', read_only=True)

    class Meta:
        model = Interview
        fields = [
            'id', 'uuid', 'application',
            'interview_type', 'status', 'title', 'description',
            'scheduled_start', 'scheduled_end', 'timezone',
            'actual_start', 'actual_end', 'duration_minutes',
            'location', 'meeting_url', 'meeting_id', 'meeting_password',
            'interviewers', 'organizer',
            'calendar_event_id', 'candidate_notified', 'interviewers_notified',
            'preparation_notes', 'interview_guide',
            'created_at', 'updated_at', 'feedback', 'tenant_type'
        ]

    def get_feedback(self, obj):
        feedback_list = obj.feedback.all()
        return InterviewFeedbackSerializer(feedback_list, many=True).data


class InterviewCreateSerializer(serializers.ModelSerializer):
    """Interview creation serializer."""
    # Use tenant-filtered fields to ensure tenant isolation
    application_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=Application.objects.all(),
        source='application'
    )
    interviewer_ids = TenantFilteredUserRelatedField(
        queryset=User.objects.all(),
        many=True,
        write_only=True
    )
    organizer_id = TenantFilteredUserRelatedField(
        queryset=User.objects.all(),
        source='organizer',
        required=False,
        allow_null=True
    )

    class Meta:
        model = Interview
        fields = [
            'application_id', 'interview_type', 'title', 'description',
            'scheduled_start', 'scheduled_end', 'timezone',
            'location', 'meeting_url', 'meeting_id', 'meeting_password',
            'interviewer_ids', 'organizer_id',
            'preparation_notes', 'interview_guide'
        ]

    def validate(self, data):
        if data['scheduled_end'] <= data['scheduled_start']:
            raise serializers.ValidationError(
                "End time must be after start time."
            )
        return data

    def create(self, validated_data):
        interviewer_ids = validated_data.pop('interviewer_ids', [])
        interview = Interview.objects.create(**validated_data)
        interview.interviewers.set(interviewer_ids)

        # Log activity
        ApplicationActivity.objects.create(
            application=interview.application,
            activity_type=ApplicationActivity.ActivityType.INTERVIEW_SCHEDULED,
            performed_by=interview.organizer,
            new_value=interview.title,
            metadata={
                'interview_id': interview.id,
                'interview_type': interview.interview_type,
                'scheduled_start': interview.scheduled_start.isoformat()
            }
        )

        return interview


class InterviewRescheduleSerializer(serializers.Serializer):
    """Serializer for rescheduling an interview."""
    scheduled_start = serializers.DateTimeField()
    scheduled_end = serializers.DateTimeField()
    reason = serializers.CharField(required=False, allow_blank=True)
    notify_participants = serializers.BooleanField(default=True)


# ==================== INTERVIEW FEEDBACK SERIALIZERS ====================

class InterviewFeedbackSerializer(serializers.ModelSerializer):
    """Interview feedback serializer."""
    interviewer = UserMinimalSerializer(read_only=True)
    recommendation_display = serializers.CharField(
        source='get_recommendation_display',
        read_only=True
    )

    class Meta:
        model = InterviewFeedback
        fields = [
            'id', 'uuid', 'interview', 'interviewer',
            'overall_rating', 'technical_skills', 'communication',
            'cultural_fit', 'problem_solving',
            'recommendation', 'recommendation_display',
            'strengths', 'weaknesses', 'notes', 'private_notes',
            'custom_ratings',
            'created_at', 'updated_at', 'submitted_at'
        ]
        read_only_fields = ['id', 'uuid', 'interviewer', 'created_at', 'updated_at']


class InterviewFeedbackCreateSerializer(serializers.ModelSerializer):
    """Interview feedback creation serializer."""
    interview_id = serializers.PrimaryKeyRelatedField(
        queryset=Interview.objects.all(),
        source='interview'
    )

    class Meta:
        model = InterviewFeedback
        fields = [
            'interview_id',
            'overall_rating', 'technical_skills', 'communication',
            'cultural_fit', 'problem_solving',
            'recommendation',
            'strengths', 'weaknesses', 'notes', 'private_notes',
            'custom_ratings'
        ]

    def validate(self, data):
        interview = data.get('interview')
        user = self.context['request'].user

        # Check if user is an interviewer for this interview
        if not interview.interviewers.filter(id=user.id).exists():
            raise serializers.ValidationError(
                "You are not an interviewer for this interview."
            )

        # Check for existing feedback
        if InterviewFeedback.objects.filter(
            interview=interview,
            interviewer=user
        ).exists():
            raise serializers.ValidationError(
                "You have already submitted feedback for this interview."
            )

        return data

    def create(self, validated_data):
        validated_data['interviewer'] = self.context['request'].user
        validated_data['submitted_at'] = timezone.now()
        feedback = super().create(validated_data)

        # Log activity
        ApplicationActivity.objects.create(
            application=feedback.interview.application,
            activity_type=ApplicationActivity.ActivityType.FEEDBACK_SUBMITTED,
            performed_by=feedback.interviewer,
            new_value=f"{feedback.recommendation} - {feedback.overall_rating}/5",
            metadata={
                'interview_id': feedback.interview.id,
                'feedback_id': feedback.id,
                'recommendation': feedback.recommendation
            }
        )

        return feedback


# ==================== OFFER SERIALIZERS ====================

class OfferListSerializer(serializers.ModelSerializer):
    """Lightweight offer serializer for lists."""
    candidate_name = serializers.CharField(
        source='application.candidate.full_name',
        read_only=True
    )
    job_reference = serializers.CharField(
        source='application.job.reference_code',
        read_only=True
    )
    status_display = serializers.CharField(
        source='get_status_display',
        read_only=True
    )

    class Meta:
        model = Offer
        fields = [
            'id', 'uuid', 'application', 'candidate_name', 'job_reference',
            'status', 'status_display', 'job_title',
            'base_salary', 'salary_currency', 'start_date',
            'expiration_date', 'requires_signature', 'signed_at',
            'created_at', 'sent_at', 'responded_at'
        ]


class OfferDetailSerializer(serializers.ModelSerializer):
    """Detailed offer serializer - COMPANY ONLY."""
    application = ApplicationListSerializer(read_only=True)
    approved_by = UserMinimalSerializer(read_only=True)
    created_by = UserMinimalSerializer(read_only=True)
    status_display = serializers.CharField(
        source='get_status_display',
        read_only=True
    )
    tenant_type = serializers.CharField(source='application.job.tenant.tenant_type', read_only=True)

    class Meta:
        model = Offer
        fields = [
            'id', 'uuid', 'application',
            'status', 'status_display',
            'job_title', 'department', 'reports_to', 'start_date',
            'employment_type',
            'base_salary', 'salary_currency', 'salary_period',
            'signing_bonus', 'annual_bonus_target', 'equity',
            'other_compensation',
            'benefits_summary', 'pto_days', 'remote_policy',
            'offer_letter_content', 'terms_and_conditions', 'expiration_date',
            'requires_signature', 'signature_document_id', 'signed_at',
            'approved_by', 'approved_at',
            'response_notes', 'decline_reason',
            'created_at', 'updated_at', 'sent_at', 'responded_at',
            'created_by', 'tenant_type'
        ]


class OfferCreateSerializer(serializers.ModelSerializer):
    """Offer creation serializer."""
    application_id = serializers.PrimaryKeyRelatedField(
        queryset=Application.objects.all(),
        source='application'
    )

    class Meta:
        model = Offer
        fields = [
            'application_id',
            'job_title', 'department', 'reports_to', 'start_date',
            'employment_type',
            'base_salary', 'salary_currency', 'salary_period',
            'signing_bonus', 'annual_bonus_target', 'equity',
            'other_compensation',
            'benefits_summary', 'pto_days', 'remote_policy',
            'offer_letter_content', 'terms_and_conditions', 'expiration_date',
            'requires_signature'
        ]

    def create(self, validated_data):
        offer = super().create(validated_data)

        # Log activity
        ApplicationActivity.objects.create(
            application=offer.application,
            activity_type=ApplicationActivity.ActivityType.OFFER_CREATED,
            performed_by=offer.created_by,
            new_value=f"{offer.job_title} - {offer.salary_currency} {offer.base_salary}",
            metadata={
                'offer_id': offer.id,
                'base_salary': str(offer.base_salary),
                'start_date': offer.start_date.isoformat() if offer.start_date else None
            }
        )

        return offer


class OfferSendSerializer(serializers.Serializer):
    """Serializer for sending an offer to candidate."""
    send_email = serializers.BooleanField(default=True)
    custom_message = serializers.CharField(required=False, allow_blank=True)


class OfferResponseSerializer(serializers.Serializer):
    """Serializer for candidate offer response."""
    action = serializers.ChoiceField(choices=['accept', 'decline'])
    response_notes = serializers.CharField(required=False, allow_blank=True)
    decline_reason = serializers.CharField(required=False, allow_blank=True)
    signature_data = serializers.CharField(required=False, allow_blank=True)


# ==================== SAVED SEARCH SERIALIZERS ====================

class SavedSearchSerializer(serializers.ModelSerializer):
    """Saved search serializer."""
    user = UserMinimalSerializer(read_only=True)
    results_count = serializers.SerializerMethodField()

    class Meta:
        model = SavedSearch
        fields = [
            'id', 'uuid', 'user', 'name', 'filters',
            'is_alert_enabled', 'alert_frequency',
            'last_run_at', 'created_at', 'updated_at',
            'results_count'
        ]
        read_only_fields = ['id', 'uuid', 'user', 'last_run_at', 'created_at', 'updated_at']

    def get_results_count(self, obj):
        """Get count of candidates matching the saved search filters."""
        # This would need to implement the actual filter logic
        # For now, return None to indicate it needs to be calculated
        return None


class SavedSearchCreateSerializer(serializers.ModelSerializer):
    """Saved search creation serializer."""

    class Meta:
        model = SavedSearch
        fields = ['name', 'filters', 'is_alert_enabled', 'alert_frequency']


# ==================== DASHBOARD/METRICS SERIALIZERS ====================

class PipelineMetricsSerializer(serializers.Serializer):
    """Serializer for pipeline metrics/stats."""
    pipeline_id = serializers.IntegerField()
    pipeline_name = serializers.CharField()
    total_applications = serializers.IntegerField()
    stages = serializers.ListField(child=serializers.DictField())
    average_time_to_hire = serializers.DurationField(allow_null=True)
    conversion_rate = serializers.FloatField()


class DashboardStatsSerializer(serializers.Serializer):
    """Serializer for ATS dashboard statistics."""
    total_open_jobs = serializers.IntegerField()
    total_applications = serializers.IntegerField()
    new_applications_today = serializers.IntegerField()
    new_applications_this_week = serializers.IntegerField()
    interviews_scheduled = serializers.IntegerField()
    offers_pending = serializers.IntegerField()
    hires_this_month = serializers.IntegerField()
    applications_by_status = serializers.DictField()
    applications_by_source = serializers.DictField()
    top_jobs_by_applications = serializers.ListField(child=serializers.DictField())
    pipeline_metrics = PipelineMetricsSerializer(many=True)


class KanbanBoardSerializer(serializers.Serializer):
    """Serializer for Kanban board data."""
    job_id = serializers.IntegerField()
    job_title = serializers.CharField()
    pipeline_id = serializers.IntegerField()
    pipeline_name = serializers.CharField()
    columns = serializers.ListField(child=serializers.DictField())


class AIMatchScoreSerializer(serializers.Serializer):
    """Serializer for AI match score results."""
    application_id = serializers.IntegerField()
    candidate_id = serializers.IntegerField()
    job_id = serializers.IntegerField()
    match_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    skill_match = serializers.DictField()
    experience_match = serializers.DictField()
    location_match = serializers.DictField()
    recommendations = serializers.ListField(child=serializers.CharField())
    calculated_at = serializers.DateTimeField()


# ==================== INTERVIEW SLOT SERIALIZERS ====================

class InterviewSlotSerializer(serializers.ModelSerializer):
    """Interview slot serializer with computed fields."""
    interviewer = UserMinimalSerializer(read_only=True)
    duration_minutes = serializers.ReadOnlyField()
    is_booked = serializers.ReadOnlyField()
    can_book = serializers.ReadOnlyField()
    booked_interview_title = serializers.CharField(
        source='booked_interview.title',
        read_only=True,
        allow_null=True
    )

    class Meta:
        model = InterviewSlot
        fields = [
            'id', 'uuid', 'interviewer', 'start_time', 'end_time', 'timezone',
            'is_available', 'recurring', 'recurrence_rule', 'recurrence_end_date',
            'slot_type', 'booked_by_interview',
            'booked_interview_title', 'notes', 'duration_minutes', 'is_booked',
            'can_book', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'uuid', 'created_at', 'updated_at']


class InterviewSlotCreateSerializer(serializers.ModelSerializer):
    """Interview slot creation serializer."""
    interviewer_id = TenantFilteredUserRelatedField(
        queryset=User.objects.all(),
        source='interviewer',
        required=False
    )

    class Meta:
        model = InterviewSlot
        fields = [
            'interviewer_id', 'start_time', 'end_time', 'timezone',
            'is_available', 'recurring', 'recurrence_rule', 'recurrence_end_date',
            'slot_type', 'notes'
        ]

    def validate(self, data):
        """Validate slot times."""
        if data.get('end_time') and data.get('start_time'):
            if data['end_time'] <= data['start_time']:
                raise serializers.ValidationError({
                    'end_time': 'End time must be after start time.'
                })
        return data

    def create(self, validated_data):
        # Default to current user if no interviewer specified
        request = self.context.get('request')
        if 'interviewer' not in validated_data and request:
            validated_data['interviewer'] = request.user
        return super().create(validated_data)


class InterviewSlotBulkCreateSerializer(serializers.Serializer):
    """Serializer for bulk creating interview slots."""
    interviewer_id = serializers.IntegerField(required=False)
    start_date = serializers.DateField()
    end_date = serializers.DateField()
    start_time = serializers.TimeField()
    end_time = serializers.TimeField()
    days_of_week = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=6),
        help_text='List of weekday numbers (0=Monday, 6=Sunday)'
    )
    slot_duration_minutes = serializers.IntegerField(default=60)
    slot_type = serializers.ChoiceField(
        choices=['phone', 'video', 'in_person', 'technical', 'panel', 'any'],
        default='any'
    )
    timezone = serializers.CharField(default='America/Toronto')

    def validate(self, data):
        if data['end_date'] < data['start_date']:
            raise serializers.ValidationError({
                'end_date': 'End date must be after start date.'
            })
        if data['end_time'] <= data['start_time']:
            raise serializers.ValidationError({
                'end_time': 'End time must be after start time.'
            })
        return data


class InterviewSlotAvailableSerializer(serializers.Serializer):
    """Serializer for querying available slots."""
    start_date = serializers.DateField()
    end_date = serializers.DateField()
    slot_type = serializers.ChoiceField(
        choices=['phone', 'video', 'in_person', 'technical', 'panel', 'any'],
        required=False
    )
    interviewer_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False
    )
    duration_minutes = serializers.IntegerField(required=False)


class InterviewSlotFindCommonSerializer(serializers.Serializer):
    """Serializer for finding common available slots for panel interviews."""
    interviewer_ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=2
    )
    start_date = serializers.DateField()
    end_date = serializers.DateField()
    duration_minutes = serializers.IntegerField(default=60)


# ==================== OFFER TEMPLATE SERIALIZERS ====================

class OfferTemplateSerializer(serializers.ModelSerializer):
    """Offer template serializer."""
    created_by = UserMinimalSerializer(read_only=True)
    job_type_display = serializers.CharField(source='get_job_type_display', read_only=True)
    experience_level_display = serializers.CharField(
        source='get_job_level_display',
        read_only=True
    )

    class Meta:
        model = OfferTemplate
        fields = [
            'id', 'uuid', 'name',
            'job_type', 'job_type_display', 'department',
            'job_level', 'experience_level_display',
            'letter_template', 'terms_template', 'benefits_package',
            'default_pto_days', 'bonus_percentage', 'equity_shares',
            'requires_approval',
            'created_by', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'uuid', 'created_by', 'created_at', 'updated_at']


class OfferTemplateCreateSerializer(serializers.ModelSerializer):
    """Offer template creation serializer."""

    class Meta:
        model = OfferTemplate
        fields = [
            'name', 'job_type', 'department', 'job_level',
            'letter_template', 'terms_template', 'benefits_package',
            'default_pto_days', 'bonus_percentage', 'equity_shares',
            'requires_approval'
        ]

    def validate_name(self, value):
        """Ensure unique name within tenant."""
        request = self.context.get('request')
        tenant = getattr(request, 'tenant', None) if request else get_current_tenant()
        qs = OfferTemplate.objects.filter(name=value)
        if tenant:
            qs = qs.filter(tenant=tenant)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError('A template with this name already exists.')
        return value


class OfferTemplateApplySerializer(serializers.Serializer):
    """Serializer for applying a template to an offer."""
    offer_id = serializers.IntegerField()
    context = serializers.DictField(required=False, default=dict)


# ==================== OFFER APPROVAL SERIALIZERS ====================

class OfferApprovalSerializer(serializers.ModelSerializer):
    """Offer approval serializer."""
    approver = UserMinimalSerializer(read_only=True)
    requested_by = UserMinimalSerializer(read_only=True)
    is_pending = serializers.ReadOnlyField()
    is_overdue = serializers.ReadOnlyField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = OfferApproval
        fields = [
            'id', 'uuid', 'offer', 'approver', 'level', 'status',
            'status_display', 'comments', 'requested_by',
            'requested_at', 'decided_at', 'due_date', 'reminder_sent',
            'is_pending', 'is_overdue'
        ]
        read_only_fields = [
            'id', 'uuid', 'requested_at', 'decided_at',
            'reminder_sent'
        ]


class OfferApprovalCreateSerializer(serializers.Serializer):
    """Serializer for requesting offer approval."""
    approver_ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=1
    )
    due_date = serializers.DateTimeField(required=False, allow_null=True)
    message = serializers.CharField(required=False, allow_blank=True)


class OfferApprovalResponseSerializer(serializers.Serializer):
    """Serializer for approval response (approve/reject)."""
    comments = serializers.CharField(required=False, allow_blank=True)
    rejection_reason = serializers.CharField(required=False, allow_blank=True)


# ==================== OFFER WORKFLOW SERIALIZERS ====================

class OfferGenerateLetterSerializer(serializers.Serializer):
    """Serializer for generating offer letter."""
    template_id = serializers.IntegerField(required=False)
    context = serializers.DictField(required=False, default=dict)


class OfferSignatureSerializer(serializers.Serializer):
    """Serializer for e-signature operations."""
    provider = serializers.ChoiceField(
        choices=['docusign', 'hellosign', 'adobe_sign'],
        default='docusign'
    )
    callback_url = serializers.URLField(required=False)
    expiration_days = serializers.IntegerField(default=7, min_value=1, max_value=30)


class OfferCounterSerializer(serializers.Serializer):
    """Serializer for counter-offer creation."""
    base_salary = serializers.DecimalField(max_digits=12, decimal_places=2)
    signing_bonus = serializers.DecimalField(
        max_digits=12, decimal_places=2, required=False, allow_null=True
    )
    start_date = serializers.DateField(required=False)
    pto_days = serializers.IntegerField(required=False)
    equity = serializers.CharField(required=False, allow_blank=True)
    other_terms = serializers.CharField(required=False, allow_blank=True)
    notes = serializers.CharField(required=False, allow_blank=True)


# ==================== PIPELINE ANALYTICS SERIALIZERS ====================

class StageConversionRateSerializer(serializers.Serializer):
    """Stage conversion rate data."""
    stage_id = serializers.IntegerField()
    stage_name = serializers.CharField()
    stage_order = serializers.IntegerField()
    applications_entered = serializers.IntegerField()
    applications_advanced = serializers.IntegerField()
    conversion_rate = serializers.FloatField()
    average_time_in_stage_days = serializers.FloatField(allow_null=True)


class PipelineBottleneckSerializer(serializers.Serializer):
    """Pipeline bottleneck data."""
    stage_id = serializers.IntegerField()
    stage_name = serializers.CharField()
    applications_stuck = serializers.IntegerField()
    average_days_stuck = serializers.FloatField()
    recommended_action = serializers.CharField()


class SLAStatusSerializer(serializers.Serializer):
    """SLA compliance status data."""
    stage_id = serializers.IntegerField()
    stage_name = serializers.CharField()
    sla_days = serializers.IntegerField()
    applications_within_sla = serializers.IntegerField()
    applications_breaching_sla = serializers.IntegerField()
    compliance_rate = serializers.FloatField()


class PipelineComparisonSerializer(serializers.Serializer):
    """Pipeline comparison for A/B testing."""
    pipeline_a_id = serializers.IntegerField()
    pipeline_a_name = serializers.CharField()
    pipeline_b_id = serializers.IntegerField()
    pipeline_b_name = serializers.CharField()
    comparison_period_days = serializers.IntegerField()
    metrics = serializers.DictField()


class PipelineAnalyticsSerializer(serializers.Serializer):
    """Full pipeline analytics."""
    pipeline_id = serializers.IntegerField()
    pipeline_name = serializers.CharField()
    period_start = serializers.DateTimeField()
    period_end = serializers.DateTimeField()
    total_applications = serializers.IntegerField()
    total_hires = serializers.IntegerField()
    total_rejections = serializers.IntegerField()
    total_withdrawals = serializers.IntegerField()
    overall_conversion_rate = serializers.FloatField()
    average_time_to_hire_days = serializers.FloatField(allow_null=True)
    stage_metrics = StageConversionRateSerializer(many=True)


# ==================== ADVANCED REPORTS SERIALIZERS ====================

class RecruitingFunnelSerializer(serializers.Serializer):
    """Recruiting funnel report data."""
    period_start = serializers.DateTimeField()
    period_end = serializers.DateTimeField()
    total_applications = serializers.IntegerField()
    funnel_stages = serializers.ListField(child=serializers.DictField())
    conversion_rates = serializers.DictField()
    drop_off_points = serializers.ListField(child=serializers.DictField())


class DEIMetricsSerializer(serializers.Serializer):
    """DEI (Diversity, Equity, Inclusion) metrics."""
    period_start = serializers.DateTimeField()
    period_end = serializers.DateTimeField()
    total_applications = serializers.IntegerField()
    source_diversity = serializers.DictField()
    stage_progression_equity = serializers.DictField()
    hiring_rate_by_source = serializers.DictField()
    recommendations = serializers.ListField(child=serializers.CharField())


class CostPerHireSerializer(serializers.Serializer):
    """Cost per hire analysis."""
    period_start = serializers.DateTimeField()
    period_end = serializers.DateTimeField()
    total_hires = serializers.IntegerField()
    total_cost = serializers.DecimalField(max_digits=12, decimal_places=2)
    average_cost_per_hire = serializers.DecimalField(max_digits=12, decimal_places=2)
    cost_breakdown = serializers.DictField()
    cost_by_source = serializers.DictField()
    cost_by_department = serializers.DictField()


class TimeToFillSerializer(serializers.Serializer):
    """Time to fill metrics."""
    period_start = serializers.DateTimeField()
    period_end = serializers.DateTimeField()
    average_time_to_fill_days = serializers.FloatField()
    median_time_to_fill_days = serializers.FloatField()
    time_by_department = serializers.DictField()
    time_by_job_type = serializers.DictField()
    time_by_experience_level = serializers.DictField()
    time_trend = serializers.ListField(child=serializers.DictField())


class SourceQualitySerializer(serializers.Serializer):
    """Source effectiveness analysis."""
    period_start = serializers.DateTimeField()
    period_end = serializers.DateTimeField()
    sources = serializers.ListField(child=serializers.DictField())
    top_performing_source = serializers.CharField()
    recommendations = serializers.ListField(child=serializers.CharField())


class RecruiterPerformanceSerializer(serializers.Serializer):
    """Recruiter performance metrics."""
    period_start = serializers.DateTimeField()
    period_end = serializers.DateTimeField()
    recruiters = serializers.ListField(child=serializers.DictField())
    team_averages = serializers.DictField()
    rankings = serializers.ListField(child=serializers.DictField())


# ==================== INTERVIEW TEMPLATE SERIALIZERS ====================

class InterviewTemplateSerializer(serializers.ModelSerializer):
    """
    Interview template serializer.

    Templates define reusable interview configurations including questions,
    scoring criteria, and required interviewers.
    """
    created_by = UserMinimalSerializer(read_only=True)
    interview_type_display = serializers.CharField(
        source='get_interview_type_display',
        read_only=True
    )
    questions_count = serializers.ReadOnlyField()
    criteria_count = serializers.ReadOnlyField()
    default_duration_minutes = serializers.SerializerMethodField()

    class Meta:
        model = InterviewTemplate
        fields = [
            'id', 'uuid', 'name', 'interview_type', 'interview_type_display',
            'default_duration', 'default_duration_minutes', 'required_interviewers',
            'questions', 'scorecard_criteria', 'instructions', 'preparation_guide',
            'candidate_instructions', 'is_active', 'allow_multiple_interviewers',
            'requires_feedback_before_discussion', 'department', 'job_level',
            'skills_assessed', 'questions_count', 'criteria_count',
            'created_by', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'uuid', 'created_by', 'created_at', 'updated_at']

    def get_default_duration_minutes(self, obj):
        """Return default duration in minutes."""
        if obj.default_duration:
            return int(obj.default_duration.total_seconds() / 60)
        return 60


class InterviewTemplateCreateSerializer(serializers.ModelSerializer):
    """
    Create/update interview templates with validation.
    """
    default_duration_minutes = serializers.IntegerField(
        write_only=True,
        required=False,
        help_text='Duration in minutes (converted to timedelta)'
    )

    class Meta:
        model = InterviewTemplate
        fields = [
            'name', 'interview_type', 'default_duration', 'default_duration_minutes',
            'required_interviewers', 'questions', 'scorecard_criteria',
            'instructions', 'preparation_guide', 'candidate_instructions',
            'is_active', 'allow_multiple_interviewers',
            'requires_feedback_before_discussion', 'department', 'job_level',
            'skills_assessed'
        ]

    def validate_questions(self, value):
        """Validate questions format."""
        if value:
            if not isinstance(value, list):
                raise serializers.ValidationError("Questions must be a list.")
            for i, q in enumerate(value):
                if not isinstance(q, dict):
                    raise serializers.ValidationError(
                        f"Question {i + 1} must be a dictionary."
                    )
                if 'question' not in q:
                    raise serializers.ValidationError(
                        f"Question {i + 1} must have a 'question' field."
                    )
        return value

    def validate_scorecard_criteria(self, value):
        """Validate scorecard criteria format."""
        if value:
            if not isinstance(value, list):
                raise serializers.ValidationError("Scorecard criteria must be a list.")
            for i, c in enumerate(value):
                if not isinstance(c, dict):
                    raise serializers.ValidationError(
                        f"Criterion {i + 1} must be a dictionary."
                    )
                if 'name' not in c:
                    raise serializers.ValidationError(
                        f"Criterion {i + 1} must have a 'name' field."
                    )
        return value

    def validate_required_interviewers(self, value):
        """Validate required interviewers count."""
        if value is not None and value < 1:
            raise serializers.ValidationError(
                "At least 1 interviewer is required."
            )
        return value

    def validate_name(self, value):
        """Ensure unique name within tenant."""
        request = self.context.get('request')
        tenant = getattr(request, 'tenant', None) if request else get_current_tenant()
        qs = InterviewTemplate.objects.filter(name=value)
        if tenant:
            qs = qs.filter(tenant=tenant)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError('A template with this name already exists.')
        return value

    def validate(self, data):
        """Handle duration conversion."""
        duration_minutes = data.pop('default_duration_minutes', None)
        if duration_minutes is not None:
            from datetime import timedelta
            data['default_duration'] = timedelta(minutes=duration_minutes)
        return data


class InterviewTemplateListSerializer(serializers.ModelSerializer):
    """Lightweight interview template serializer for lists."""
    interview_type_display = serializers.CharField(
        source='get_interview_type_display',
        read_only=True
    )
    questions_count = serializers.ReadOnlyField()

    class Meta:
        model = InterviewTemplate
        fields = [
            'id', 'uuid', 'name', 'interview_type', 'interview_type_display',
            'default_duration', 'required_interviewers', 'is_active',
            'department', 'job_level', 'questions_count'
        ]


class InterviewScheduleSerializer(serializers.Serializer):
    """
    Schedule an interview from a slot and optional template.

    Used to create an interview by combining an available slot with an
    optional template configuration.
    """
    application_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=Application.objects.all(),
        help_text="The application this interview is for"
    )
    slot_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=InterviewSlot.objects.all(),
        help_text="The interview slot to use"
    )
    interview_type = serializers.ChoiceField(
        choices=InterviewType.choices,
        help_text="Type of interview"
    )
    template_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=InterviewTemplate.objects.all(),
        required=False,
        allow_null=True,
        help_text="Optional interview template to use"
    )
    additional_interviewers = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        default=list,
        help_text="Additional interviewer UUIDs beyond the slot owner"
    )
    candidate_timezone = serializers.CharField(
        default='America/Toronto',
        help_text="Candidate's timezone for notifications"
    )
    meeting_provider = serializers.ChoiceField(
        choices=[
            ('zoom', 'Zoom'),
            ('teams', 'Microsoft Teams'),
            ('meet', 'Google Meet'),
            ('webex', 'Cisco Webex'),
            ('none', 'No Video - In Person or Phone')
        ],
        default='none',
        help_text="Video conferencing provider to use"
    )
    title = serializers.CharField(
        max_length=200,
        required=False,
        allow_blank=True,
        help_text="Custom interview title (optional)"
    )
    notes = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Notes for interviewers"
    )
    send_notifications = serializers.BooleanField(
        default=True,
        help_text="Send email notifications to participants"
    )

    def validate(self, data):
        """Validate interview scheduling data."""
        errors = {}

        # Validate candidate timezone
        tz = data.get('candidate_timezone', 'America/Toronto')
        try:
            import pytz
            pytz.timezone(tz)
        except Exception:
            errors['candidate_timezone'] = f"Invalid timezone: {tz}"

        # Validate application can have interviews scheduled
        application = data.get('application_id')
        if application:
            if application.is_terminal:
                errors['application_id'] = (
                    "Cannot schedule interview for a terminal application."
                )

        # Validate slot is available
        slot = data.get('slot_id')
        if slot:
            if hasattr(slot, 'is_available') and not slot.is_available:
                errors['slot_id'] = "This slot is not available."
            if hasattr(slot, 'is_booked') and slot.is_booked:
                errors['slot_id'] = "This slot is already booked."

        if errors:
            raise serializers.ValidationError(errors)

        return data


class AvailableSlotQuerySerializer(serializers.Serializer):
    """
    Query parameters for finding available interview slots.

    Used to search for open slots based on date range, interviewers, and duration.
    """
    date_from = serializers.DateTimeField(
        help_text="Start of the date range to search"
    )
    date_to = serializers.DateTimeField(
        help_text="End of the date range to search"
    )
    interviewer_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        help_text="Optional list of specific interviewer UUIDs to filter by"
    )
    duration_minutes = serializers.IntegerField(
        default=60,
        min_value=15,
        max_value=480,
        help_text="Required duration in minutes (default: 60)"
    )
    slot_type = serializers.ChoiceField(
        choices=['phone', 'video', 'in_person', 'technical', 'panel', 'any'],
        required=False,
        help_text="Filter by slot type"
    )
    timezone = serializers.CharField(
        default='America/Toronto',
        help_text="Timezone for the returned slots"
    )

    def validate(self, data):
        """Validate query parameters."""
        errors = {}

        date_from = data.get('date_from')
        date_to = data.get('date_to')

        if date_from and date_to:
            if date_to <= date_from:
                errors['date_to'] = "End date must be after start date."

            # Maximum search range of 30 days
            date_range = (date_to - date_from).days
            if date_range > 30:
                errors['date_to'] = "Search range cannot exceed 30 days."

        # Timezone validation
        tz = data.get('timezone', 'America/Toronto')
        try:
            import pytz
            pytz.timezone(tz)
        except Exception:
            errors['timezone'] = f"Invalid timezone: {tz}"

        if errors:
            raise serializers.ValidationError(errors)

        return data


# ==================== OFFER LETTER AND COUNTER OFFER SERIALIZERS ====================

class OfferLetterGenerateSerializer(serializers.Serializer):
    """
    Generate offer letter from template.

    Combines a template with application/candidate data to produce
    a customized offer letter.
    """
    template_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=OfferTemplate.objects.all(),
        help_text="OfferTemplate to use for generation"
    )
    application_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=Application.objects.all(),
        required=False,
        allow_null=True,
        help_text="Optional application to pre-fill candidate data"
    )
    offer_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=Offer.objects.all(),
        required=False,
        allow_null=True,
        help_text="Optional existing offer to update"
    )
    custom_fields = serializers.DictField(
        required=False,
        default=dict,
        help_text="Custom field values to merge into the template"
    )
    base_salary = serializers.DecimalField(
        max_digits=12,
        decimal_places=2,
        required=False,
        help_text="Override template salary (optional)"
    )
    signing_bonus = serializers.DecimalField(
        max_digits=12,
        decimal_places=2,
        required=False,
        allow_null=True,
        help_text="Override signing bonus (optional)"
    )
    start_date = serializers.DateField(
        required=False,
        help_text="Proposed start date"
    )
    output_format = serializers.ChoiceField(
        choices=[
            ('html', 'HTML'),
            ('pdf', 'PDF'),
            ('docx', 'Word Document'),
            ('json', 'JSON Data')
        ],
        default='html',
        help_text="Output format for the generated letter"
    )

    def validate(self, data):
        """Validate letter generation parameters."""
        errors = {}

        # Validate custom fields don't override protected fields
        custom_fields = data.get('custom_fields', {})
        protected_fields = {'candidate_signature', 'company_signature', 'legal_disclaimer'}
        for field in protected_fields:
            if field in custom_fields:
                errors['custom_fields'] = (
                    f"Cannot override protected field: {field}"
                )
                break

        # Must have either application_id or custom candidate data
        application = data.get('application_id')
        if not application and 'candidate_name' not in custom_fields:
            errors['application_id'] = (
                "Either application_id or custom_fields.candidate_name is required."
            )

        if errors:
            raise serializers.ValidationError(errors)

        return data


class CounterOfferSerializer(serializers.Serializer):
    """
    Create counter offer from candidate.

    Records candidate's counter proposal on compensation terms.
    """
    offer_id = TenantFilteredPrimaryKeyRelatedField(
        queryset=Offer.objects.all(),
        help_text="The original offer being countered"
    )
    base_salary = serializers.DecimalField(
        max_digits=12,
        decimal_places=2,
        help_text="Requested base salary"
    )
    bonus = serializers.DecimalField(
        max_digits=12,
        decimal_places=2,
        required=False,
        allow_null=True,
        help_text="Requested signing or annual bonus"
    )
    equity_shares = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=0,
        help_text="Requested equity shares"
    )
    start_date = serializers.DateField(
        required=False,
        allow_null=True,
        help_text="Requested start date"
    )
    pto_days = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=0,
        help_text="Requested PTO days"
    )
    remote_policy = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Requested remote work arrangement"
    )
    additional_requests = serializers.DictField(
        required=False,
        default=dict,
        help_text="Additional requests (equipment, benefits, etc.)"
    )
    notes = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Candidate's explanation or notes"
    )

    def validate(self, data):
        """Validate counter offer data."""
        errors = {}

        offer = data.get('offer_id')
        if offer:
            # Check offer status allows counter offers
            valid_statuses = {'sent', 'pending_approval', 'approved'}
            if hasattr(offer, 'status'):
                from .models import Offer
                if offer.status not in [
                    Offer.OfferStatus.SENT,
                    Offer.OfferStatus.APPROVED
                ]:
                    errors['offer_id'] = (
                        f"Cannot counter an offer with status: {offer.get_status_display()}"
                    )

            # Validate salary is reasonable (warn if more than 50% increase)
            base_salary = data.get('base_salary')
            if base_salary and hasattr(offer, 'base_salary') and offer.base_salary:
                increase_pct = ((base_salary - offer.base_salary) / offer.base_salary) * 100
                if increase_pct > 50:
                    # This is a warning, not an error - add to data for upstream handling
                    data['_salary_increase_warning'] = (
                        f"Counter offer is {increase_pct:.1f}% higher than original offer."
                    )

        if errors:
            raise serializers.ValidationError(errors)

        return data


class OfferNegotiationHistorySerializer(serializers.Serializer):
    """
    Serializer for offer negotiation history.

    Tracks all counter offers and responses for an offer.
    """
    offer_id = serializers.IntegerField()
    original_offer = serializers.DictField()
    negotiations = serializers.ListField(
        child=serializers.DictField(),
        help_text="List of negotiation rounds with counter offers and responses"
    )
    current_terms = serializers.DictField(
        help_text="Current terms after all negotiations"
    )
    total_rounds = serializers.IntegerField()
    days_in_negotiation = serializers.IntegerField()
    status = serializers.CharField()


# ==================== TENANT-AWARE BASE SERIALIZER ====================

class TenantAwareSerializer(serializers.ModelSerializer):
    """
    Base serializer that provides tenant-aware functionality.

    Automatically handles tenant context for create operations and
    provides helper methods for tenant-filtered queries.
    """

    def get_tenant(self):
        """
        Get the current tenant from request context or database connection.

        Returns:
            The current tenant or None if not available.
        """
        request = self.context.get('request')
        if request and hasattr(request, 'tenant'):
            return request.tenant
        return get_current_tenant()

    def create(self, validated_data):
        """
        Create a new instance with tenant automatically set.
        """
        tenant = self.get_tenant()
        if tenant and 'tenant' not in validated_data:
            model = self.Meta.model
            if hasattr(model, 'tenant'):
                validated_data['tenant'] = tenant
        return super().create(validated_data)


# ==================== BACKGROUND CHECKS ====================

class BackgroundCheckDocumentSerializer(serializers.ModelSerializer):
    """
    Serializer for individual background check documents.
    """

    class Meta:
        model = BackgroundCheckDocument
        fields = [
            'id',
            'document_type',
            'status',
            'result',
            'completed_at',
            'findings_summary',
            'document_data',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class BackgroundCheckSerializer(serializers.ModelSerializer):
    """
    Serializer for background check records.
    """
    documents = BackgroundCheckDocumentSerializer(many=True, read_only=True)
    initiated_by_name = serializers.SerializerMethodField()
    application_info = serializers.SerializerMethodField()

    class Meta:
        model = BackgroundCheck
        fields = [
            'id',
            'application',
            'application_info',
            'provider',
            'package',
            'status',
            'result',
            'external_candidate_id',
            'external_report_id',
            'initiated_by',
            'initiated_by_name',
            'initiated_at',
            'completed_at',
            'report_url',
            'report_data',
            'consent_given',
            'consent_ip_address',
            'consent_timestamp',
            'notes',
            'documents',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'external_candidate_id',
            'external_report_id',
            'status',
            'result',
            'initiated_at',
            'completed_at',
            'report_url',
            'report_data',
            'created_at',
            'updated_at',
        ]

    def get_initiated_by_name(self, obj):
        """Get name of user who initiated the check."""
        if obj.initiated_by:
            return f"{obj.initiated_by.first_name} {obj.initiated_by.last_name}".strip() or obj.initiated_by.email
        return None

    def get_application_info(self, obj):
        """Get basic application information."""
        return {
            'id': obj.application.id,
            'uuid': str(obj.application.uuid),
            'candidate_name': str(obj.application.candidate),
            'job_title': obj.application.job.title,
            'status': obj.application.status,
        }


class InitiateBackgroundCheckSerializer(serializers.Serializer):
    """
    Serializer for initiating a background check.
    """
    package = serializers.ChoiceField(
        choices=['basic', 'standard', 'pro', 'comprehensive'],
        default='standard',
        help_text="Background check package level"
    )
    consent_given = serializers.BooleanField(
        required=True,
        help_text="Candidate must provide consent before background check can be initiated"
    )
    provider_name = serializers.ChoiceField(
        choices=['checkr', 'sterling', 'hireright'],
        required=False,
        help_text="Specific provider to use (optional, defaults to tenant's configured provider)"
    )

    def validate_consent_given(self, value):
        """Ensure consent is given."""
        if not value:
            raise serializers.ValidationError(
                "Candidate consent is required to initiate a background check."
            )
        return value
