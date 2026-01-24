"""
Projects Admin - Django admin configuration.

Provides admin interface for:
- Projects
- Project Categories
- Project Providers
- Proposals
- Milestones
- Contracts
- Deliverables
- Reviews
"""

from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse

from .models import (
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
# PROJECT CATEGORIES
# ============================================================================

@admin.register(ProjectCategory)
class ProjectCategoryAdmin(admin.ModelAdmin):
    """Admin for project categories."""

    list_display = ['name', 'parent', 'project_count', 'icon_display', 'display_order']
    list_filter = ['parent']
    search_fields = ['name', 'description']
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['display_order', 'name']

    fieldsets = (
        (_('Basic Info'), {
            'fields': ('name', 'slug', 'description', 'parent')
        }),
        (_('Visual'), {
            'fields': ('icon', 'color', 'display_order')
        }),
        (_('Stats'), {
            'fields': ('project_count',),
            'classes': ('collapse',)
        }),
    )

    def icon_display(self, obj):
        """Display icon with color."""
        if obj.icon:
            return format_html(
                '<i class="{}" style="color: {}; font-size: 24px;"></i>',
                obj.icon,
                obj.color
            )
        return '-'
    icon_display.short_description = _('Icon')


# ============================================================================
# PROJECT PROVIDERS
# ============================================================================

@admin.register(ProjectProvider)
class ProjectProviderAdmin(admin.ModelAdmin):
    """Admin for project providers."""

    list_display = [
        'name',
        'tenant',
        'is_active',
        'is_accepting_projects',
        'completed_projects',
        'average_rating',
        'verified_badge'
    ]
    list_filter = [
        'is_active',
        'is_accepting_projects',
        'is_verified',
        'remote_only',
        'country'
    ]
    search_fields = ['name', 'description', 'skills']
    readonly_fields = [
        'uuid',
        'completed_projects',
        'total_earnings',
        'average_rating',
        'total_reviews',
        'created_at',
        'updated_at'
    ]

    fieldsets = (
        (_('Basic Info'), {
            'fields': ('uuid', 'tenant', 'name', 'description', 'tagline')
        }),
        (_('Skills & Categories'), {
            'fields': ('categories', 'skills')
        }),
        (_('Portfolio'), {
            'fields': ('portfolio_url', 'portfolio_images')
        }),
        (_('Location'), {
            'fields': ('city', 'country', 'remote_only')
        }),
        (_('Availability'), {
            'fields': (
                'is_active',
                'is_accepting_projects',
                'max_concurrent_projects'
            )
        }),
        (_('Stats'), {
            'fields': (
                'completed_projects',
                'total_earnings',
                'average_rating',
                'total_reviews'
            ),
            'classes': ('collapse',)
        }),
        (_('Verification'), {
            'fields': ('is_verified', 'verification_date')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def verified_badge(self, obj):
        """Display verification badge."""
        if obj.is_verified:
            return format_html(
                '<span style="color: green;">✓ Verified</span>'
            )
        return format_html('<span style="color: gray;">Not Verified</span>')
    verified_badge.short_description = _('Verified')


# ============================================================================
# PROJECTS
# ============================================================================

class ProjectMilestoneInline(admin.TabularInline):
    """Inline admin for project milestones."""
    model = ProjectMilestone
    extra = 0
    fields = ['title', 'order', 'amount', 'due_date', 'status']
    readonly_fields = ['submitted_at', 'approved_at', 'paid_at']


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    """Admin for projects."""

    list_display = [
        'title',
        'tenant',
        'category',
        'status',
        'budget_display',
        'proposal_count',
        'published_badge',
        'created_at'
    ]
    list_filter = [
        'status',
        'budget_type',
        'experience_level',
        'location_type',
        'is_published',
        'published_to_catalog',
        'category'
    ]
    search_fields = ['title', 'description', 'required_skills']
    readonly_fields = [
        'uuid',
        'proposal_count',
        'published_to_catalog',
        'created_at',
        'updated_at'
    ]
    date_hierarchy = 'created_at'
    inlines = [ProjectMilestoneInline]

    fieldsets = (
        (_('Basic Info'), {
            'fields': (
                'uuid',
                'tenant',
                'title',
                'description',
                'short_description',
                'category'
            )
        }),
        (_('Requirements'), {
            'fields': (
                'required_skills',
                'experience_level',
                'deliverables'
            )
        }),
        (_('Timeline'), {
            'fields': (
                'start_date',
                'end_date',
                'estimated_duration_weeks',
                'deadline'
            )
        }),
        (_('Budget'), {
            'fields': (
                'budget_type',
                'budget_min',
                'budget_max',
                'budget_currency'
            )
        }),
        (_('Location'), {
            'fields': (
                'location_type',
                'location_city',
                'location_country'
            )
        }),
        (_('Status'), {
            'fields': (
                'status',
                'is_published',
                'published_at',
                'published_to_catalog'
            )
        }),
        (_('Assignment'), {
            'fields': (
                'assigned_provider',
                'assigned_at',
                'contract'
            )
        }),
        (_('Application Settings'), {
            'fields': (
                'max_proposals',
                'proposal_deadline',
                'proposal_count'
            ),
            'classes': ('collapse',)
        }),
        (_('Contact'), {
            'fields': ('contact_email', 'contact_person'),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def budget_display(self, obj):
        """Display budget range."""
        if obj.budget_min and obj.budget_max:
            return f"{obj.budget_currency} {obj.budget_min:,.0f} - {obj.budget_max:,.0f}"
        elif obj.budget_min:
            return f"{obj.budget_currency} {obj.budget_min:,.0f}+"
        return _('Negotiable')
    budget_display.short_description = _('Budget')

    def published_badge(self, obj):
        """Display publication status."""
        if obj.is_published:
            color = 'green' if obj.published_to_catalog else 'orange'
            text = 'Published & Synced' if obj.published_to_catalog else 'Published'
            return format_html(
                '<span style="color: {};">● {}</span>',
                color,
                text
            )
        return format_html('<span style="color: gray;">○ Draft</span>')
    published_badge.short_description = _('Published')


# ============================================================================
# PROPOSALS
# ============================================================================

@admin.register(ProjectProposal)
class ProjectProposalAdmin(admin.ModelAdmin):
    """Admin for project proposals."""

    list_display = [
        'project',
        'provider',
        'status',
        'proposed_budget',
        'proposed_duration_weeks',
        'submitted_at'
    ]
    list_filter = ['status', 'submitted_at']
    search_fields = ['project__title', 'provider__name', 'cover_letter']
    readonly_fields = [
        'uuid',
        'submitted_at',
        'reviewed_at',
        'accepted_at',
        'rejected_at',
        'created_at',
        'updated_at'
    ]
    date_hierarchy = 'submitted_at'

    fieldsets = (
        (_('Basic Info'), {
            'fields': (
                'uuid',
                'project',
                'provider',
                'freelancer_profile',
                'status'
            )
        }),
        (_('Proposal Content'), {
            'fields': (
                'cover_letter',
                'approach',
                'portfolio_links',
                'attachments'
            )
        }),
        (_('Pricing & Timeline'), {
            'fields': (
                'proposed_budget',
                'budget_currency',
                'proposed_duration_weeks',
                'proposed_start_date',
                'proposed_completion_date',
                'proposed_milestones'
            )
        }),
        (_('Review'), {
            'fields': (
                'submitted_at',
                'reviewed_at',
                'accepted_at',
                'rejected_at',
                'rejection_reason'
            ),
            'classes': ('collapse',)
        }),
    )


# ============================================================================
# CONTRACTS
# ============================================================================

@admin.register(ProjectContract)
class ProjectContractAdmin(admin.ModelAdmin):
    """Admin for project contracts."""

    list_display = [
        'project',
        'provider',
        'total_amount',
        'status',
        'signature_status',
        'start_date',
        'end_date'
    ]
    list_filter = ['status', 'start_date']
    search_fields = ['project__title', 'provider__name']
    readonly_fields = [
        'uuid',
        'client_signed_at',
        'provider_signed_at',
        'fully_executed_at',
        'created_at',
        'updated_at'
    ]

    def signature_status(self, obj):
        """Display signature status."""
        if obj.is_fully_executed:
            return format_html('<span style="color: green;">✓ Fully Executed</span>')
        elif obj.client_signed_at:
            return format_html('<span style="color: orange;">Client Signed</span>')
        elif obj.provider_signed_at:
            return format_html('<span style="color: orange;">Provider Signed</span>')
        return format_html('<span style="color: gray;">Pending Signatures</span>')
    signature_status.short_description = _('Signatures')


# ============================================================================
# MILESTONES
# ============================================================================

@admin.register(ProjectMilestone)
class ProjectMilestoneAdmin(admin.ModelAdmin):
    """Admin for project milestones."""

    list_display = [
        'project',
        'title',
        'order',
        'amount',
        'due_date',
        'status',
        'payment_status'
    ]
    list_filter = ['status', 'due_date']
    search_fields = ['project__title', 'title', 'description']
    readonly_fields = [
        'uuid',
        'submitted_at',
        'approved_at',
        'paid_at',
        'created_at',
        'updated_at'
    ]
    date_hierarchy = 'due_date'

    def payment_status(self, obj):
        """Display payment status."""
        if obj.status == 'PAID':
            return format_html('<span style="color: green;">✓ Paid</span>')
        elif obj.status == 'APPROVED':
            return format_html('<span style="color: orange;">Approved, Pending Payment</span>')
        return '-'
    payment_status.short_description = _('Payment')


# ============================================================================
# DELIVERABLES
# ============================================================================

@admin.register(ProjectDeliverable)
class ProjectDeliverableAdmin(admin.ModelAdmin):
    """Admin for project deliverables."""

    list_display = [
        'project',
        'title',
        'file_name',
        'file_size_display',
        'submitted_at',
        'approval_status'
    ]
    list_filter = ['is_approved', 'submitted_at']
    search_fields = ['project__title', 'title', 'file_name']
    readonly_fields = [
        'uuid',
        'submitted_at',
        'approved_at',
        'created_at',
        'updated_at'
    ]

    def file_size_display(self, obj):
        """Display file size in human-readable format."""
        size_mb = obj.file_size / (1024 * 1024)
        return f"{size_mb:.2f} MB"
    file_size_display.short_description = _('File Size')

    def approval_status(self, obj):
        """Display approval status."""
        if obj.is_approved:
            return format_html('<span style="color: green;">✓ Approved</span>')
        return format_html('<span style="color: gray;">Pending Review</span>')
    approval_status.short_description = _('Status')


# ============================================================================
# REVIEWS
# ============================================================================

@admin.register(ProjectReview)
class ProjectReviewAdmin(admin.ModelAdmin):
    """Admin for project reviews."""

    list_display = [
        'project',
        'reviewer',
        'reviewer_type',
        'rating_display',
        'is_public',
        'created_at'
    ]
    list_filter = ['reviewer_type', 'rating', 'is_public', 'is_featured']
    search_fields = ['project__title', 'title', 'review']
    readonly_fields = [
        'uuid',
        'responded_at',
        'created_at',
        'updated_at'
    ]

    def rating_display(self, obj):
        """Display rating with stars."""
        stars = '★' * obj.rating + '☆' * (5 - obj.rating)
        return format_html(
            '<span style="color: #F59E0B; font-size: 16px;">{}</span>',
            stars
        )
    rating_display.short_description = _('Rating')
