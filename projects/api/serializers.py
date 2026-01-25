"""
Projects Serializers - DRF serializers for API endpoints.

This module provides serializers for:
- Projects (CRUD)
- Project Categories
- Project Providers
- Proposals
- Milestones
- Contracts
- Deliverables
- Reviews

All serializers follow DRF best practices with validation and nested representations.
"""

from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from ..models import (
    ProjectCategory,
    ProjectProvider,
    Project,
    ProjectProposal,
    ProjectContract,
    ProjectMilestone,
    ProjectDeliverable,
    ProjectReview
)


# ============================================================================
# PROJECT CATEGORY SERIALIZERS
# ============================================================================

class ProjectCategorySerializer(serializers.ModelSerializer):
    """Serializer for project categories."""

    subcategories = serializers.SerializerMethodField()
    full_path = serializers.CharField(source='get_full_path', read_only=True)

    class Meta:
        model = ProjectCategory
        fields = [
            'id',
            'uuid',
            'name',
            'slug',
            'description',
            'parent',
            'subcategories',
            'full_path',
            'icon',
            'color',
            'project_count',
            'display_order',
        ]
        read_only_fields = ['uuid', 'project_count', 'full_path']

    def get_subcategories(self, obj):
        """Get immediate subcategories."""
        subcats = obj.subcategories.all()[:10]
        return ProjectCategorySerializer(subcats, many=True).data


# ============================================================================
# PROJECT PROVIDER SERIALIZERS
# ============================================================================

class ProjectProviderSerializer(serializers.ModelSerializer):
    """Serializer for project providers."""

    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    categories_display = ProjectCategorySerializer(
        source='categories',
        many=True,
        read_only=True
    )
    active_projects_count = serializers.IntegerField(read_only=True)
    can_accept_new_project = serializers.BooleanField(read_only=True)

    class Meta:
        model = ProjectProvider
        fields = [
            'id',
            'uuid',
            'tenant',
            'tenant_name',
            'name',
            'description',
            'tagline',
            'categories',
            'categories_display',
            'skills',
            'portfolio_url',
            'portfolio_images',
            'city',
            'country',
            'remote_only',
            'is_active',
            'is_accepting_projects',
            'max_concurrent_projects',
            'active_projects_count',
            'can_accept_new_project',
            'completed_projects',
            'total_earnings',
            'average_rating',
            'total_reviews',
            'is_verified',
            'verification_date',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'tenant',
            'completed_projects',
            'total_earnings',
            'average_rating',
            'total_reviews',
            'verification_date',
            'created_at',
            'updated_at',
        ]


# ============================================================================
# PROJECT SERIALIZERS
# ============================================================================

class ProjectListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for project listings."""

    category_name = serializers.CharField(source='category.name', read_only=True)
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    is_open_for_proposals = serializers.BooleanField(read_only=True)
    proposal_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Project
        fields = [
            'id',
            'uuid',
            'title',
            'short_description',
            'category',
            'category_name',
            'tenant_name',
            'required_skills',
            'experience_level',
            'budget_type',
            'budget_min',
            'budget_max',
            'budget_currency',
            'location_type',
            'location_city',
            'location_country',
            'status',
            'is_published',
            'published_at',
            'deadline',
            'is_open_for_proposals',
            'proposal_count',
            'created_at',
        ]


class ProjectSerializer(serializers.ModelSerializer):
    """Full serializer for project detail."""

    category_detail = ProjectCategorySerializer(source='category', read_only=True)
    assigned_provider_detail = ProjectProviderSerializer(
        source='assigned_provider',
        read_only=True
    )
    is_open_for_proposals = serializers.BooleanField(read_only=True)
    proposal_count = serializers.IntegerField(read_only=True)
    accepted_proposal_id = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = [
            'id',
            'uuid',
            'tenant',
            'title',
            'description',
            'short_description',
            'category',
            'category_detail',
            'required_skills',
            'experience_level',
            'start_date',
            'end_date',
            'estimated_duration_weeks',
            'deadline',
            'budget_type',
            'budget_min',
            'budget_max',
            'budget_currency',
            'deliverables',
            'location_type',
            'location_city',
            'location_country',
            'status',
            'is_published',
            'published_at',
            'published_to_catalog',
            'assigned_provider',
            'assigned_provider_detail',
            'assigned_at',
            'contract',
            'contact_email',
            'contact_person',
            'max_proposals',
            'proposal_deadline',
            'is_open_for_proposals',
            'proposal_count',
            'accepted_proposal_id',
            'completed_at',
            'cancelled_at',
            'cancellation_reason',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'tenant',
            'published_to_catalog',
            'assigned_at',
            'completed_at',
            'created_at',
            'updated_at',
        ]

    def get_accepted_proposal_id(self, obj):
        """Get ID of accepted proposal if any."""
        accepted = obj.accepted_proposal
        return accepted.id if accepted else None


class ProjectCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating projects."""

    class Meta:
        model = Project
        fields = [
            'title',
            'description',
            'short_description',
            'category',
            'required_skills',
            'experience_level',
            'start_date',
            'end_date',
            'estimated_duration_weeks',
            'deadline',
            'budget_type',
            'budget_min',
            'budget_max',
            'budget_currency',
            'deliverables',
            'location_type',
            'location_city',
            'location_country',
            'contact_email',
            'contact_person',
            'max_proposals',
            'proposal_deadline',
        ]

    def validate(self, data):
        """Cross-field validation."""
        # Validate dates
        if data.get('start_date') and data.get('end_date'):
            if data['end_date'] <= data['start_date']:
                raise serializers.ValidationError({
                    'end_date': _('End date must be after start date')
                })

        # Validate budget
        if data.get('budget_min') and data.get('budget_max'):
            if data['budget_max'] < data['budget_min']:
                raise serializers.ValidationError({
                    'budget_max': _('Maximum budget must be greater than minimum')
                })

        return data


# ============================================================================
# PROPOSAL SERIALIZERS
# ============================================================================

class ProjectProposalListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for proposal listings."""

    project_title = serializers.CharField(source='project.title', read_only=True)
    provider_name = serializers.CharField(source='provider.name', read_only=True)

    class Meta:
        model = ProjectProposal
        fields = [
            'id',
            'uuid',
            'project',
            'project_title',
            'provider',
            'provider_name',
            'status',
            'proposed_budget',
            'budget_currency',
            'proposed_duration_weeks',
            'submitted_at',
            'created_at',
        ]


class ProjectProposalSerializer(serializers.ModelSerializer):
    """Full serializer for proposal detail."""

    project_detail = ProjectListSerializer(source='project', read_only=True)
    provider_detail = ProjectProviderSerializer(source='provider', read_only=True)

    class Meta:
        model = ProjectProposal
        fields = [
            'id',
            'uuid',
            'project',
            'project_detail',
            'provider',
            'provider_detail',
            'freelancer_profile',
            'cover_letter',
            'approach',
            'proposed_budget',
            'budget_currency',
            'proposed_duration_weeks',
            'proposed_start_date',
            'proposed_completion_date',
            'proposed_milestones',
            'portfolio_links',
            'attachments',
            'status',
            'submitted_at',
            'reviewed_at',
            'accepted_at',
            'rejected_at',
            'rejection_reason',
            'questionnaire_responses',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'submitted_at',
            'reviewed_at',
            'accepted_at',
            'rejected_at',
            'created_at',
            'updated_at',
        ]


class ProjectProposalCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating proposals."""

    class Meta:
        model = ProjectProposal
        fields = [
            'project',
            'provider',
            'freelancer_profile',
            'cover_letter',
            'approach',
            'proposed_budget',
            'budget_currency',
            'proposed_duration_weeks',
            'proposed_start_date',
            'proposed_completion_date',
            'proposed_milestones',
            'portfolio_links',
            'attachments',
            'questionnaire_responses',
        ]

    def validate(self, data):
        """Validate proposal."""
        # Check if project is open
        project = data.get('project')
        if project and not project.is_open_for_proposals:
            raise serializers.ValidationError({
                'project': _('This project is not accepting proposals')
            })

        # Validate dates
        if data.get('proposed_start_date') and data.get('proposed_completion_date'):
            if data['proposed_completion_date'] <= data['proposed_start_date']:
                raise serializers.ValidationError({
                    'proposed_completion_date': _('Completion date must be after start date')
                })

        return data


# ============================================================================
# MILESTONE SERIALIZERS
# ============================================================================

class ProjectMilestoneSerializer(serializers.ModelSerializer):
    """Serializer for project milestones."""

    project_title = serializers.CharField(source='project.title', read_only=True)

    class Meta:
        model = ProjectMilestone
        fields = [
            'id',
            'uuid',
            'project',
            'project_title',
            'contract',
            'title',
            'description',
            'order',
            'deliverables',
            'amount',
            'currency',
            'due_date',
            'status',
            'submitted_at',
            'approved_at',
            'paid_at',
            'reviewer_notes',
            'rejection_reason',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'submitted_at',
            'approved_at',
            'paid_at',
            'created_at',
            'updated_at',
        ]


# ============================================================================
# CONTRACT SERIALIZERS
# ============================================================================

class ProjectContractSerializer(serializers.ModelSerializer):
    """Serializer for project contracts."""

    project_title = serializers.CharField(source='project.title', read_only=True)
    provider_name = serializers.CharField(source='provider.name', read_only=True)
    is_fully_executed = serializers.BooleanField(read_only=True)
    milestones = ProjectMilestoneSerializer(many=True, read_only=True)

    class Meta:
        model = ProjectContract
        fields = [
            'id',
            'uuid',
            'project',
            'project_title',
            'proposal',
            'provider',
            'provider_name',
            'total_amount',
            'currency',
            'payment_terms',
            'start_date',
            'end_date',
            'terms_and_conditions',
            'scope_of_work',
            'deliverables',
            'status',
            'client_signed_at',
            'provider_signed_at',
            'fully_executed_at',
            'is_fully_executed',
            'terminated_at',
            'termination_reason',
            'milestones',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'client_signed_at',
            'provider_signed_at',
            'fully_executed_at',
            'created_at',
            'updated_at',
        ]


# ============================================================================
# DELIVERABLE SERIALIZERS
# ============================================================================

class ProjectDeliverableSerializer(serializers.ModelSerializer):
    """Serializer for project deliverables."""

    project_title = serializers.CharField(source='project.title', read_only=True)
    submitted_by_name = serializers.CharField(
        source='submitted_by.get_full_name',
        read_only=True
    )

    class Meta:
        model = ProjectDeliverable
        fields = [
            'id',
            'uuid',
            'project',
            'project_title',
            'milestone',
            'title',
            'description',
            'file_url',
            'file_name',
            'file_size',
            'file_type',
            'submitted_by',
            'submitted_by_name',
            'submitted_at',
            'is_approved',
            'approved_at',
            'reviewer_notes',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'submitted_by',
            'submitted_at',
            'approved_at',
            'created_at',
            'updated_at',
        ]


# ============================================================================
# REVIEW SERIALIZERS
# ============================================================================

class ProjectReviewSerializer(serializers.ModelSerializer):
    """Serializer for project reviews."""

    project_title = serializers.CharField(source='project.title', read_only=True)
    reviewer_name = serializers.CharField(
        source='reviewer.get_full_name',
        read_only=True
    )
    average_detailed_rating = serializers.FloatField(read_only=True)

    class Meta:
        model = ProjectReview
        fields = [
            'id',
            'uuid',
            'project',
            'project_title',
            'reviewer',
            'reviewer_name',
            'reviewer_type',
            'rating',
            'communication_rating',
            'quality_rating',
            'timeliness_rating',
            'professionalism_rating',
            'average_detailed_rating',
            'title',
            'review',
            'is_public',
            'is_featured',
            'response',
            'responded_at',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'responded_at',
            'created_at',
            'updated_at',
        ]

    def validate_rating(self, value):
        """Validate rating is between 1 and 5."""
        if value < 1 or value > 5:
            raise serializers.ValidationError(_('Rating must be between 1 and 5'))
        return value
