"""
Services Admin - Zumodra Freelance Marketplace

Admin interface for managing marketplace services, providers, contracts, and reviews.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.urls import reverse

from .models import (
    ServiceCategory,
    ServiceTag,
    ServiceImage,
    ProviderSkill,
    ServiceProvider,
    Service,
    ServiceLike,
    ClientRequest,
    ProviderMatch,
    ServiceProposal,
    ServiceContract,
    ServiceReview,
    ContractMessage,
)


# =============================================================================
# INLINE ADMINS
# =============================================================================

class ProviderSkillInline(admin.TabularInline):
    model = ProviderSkill
    extra = 1
    autocomplete_fields = ['skill']


class ServiceInline(admin.TabularInline):
    model = Service
    extra = 0
    fields = ['name', 'category', 'price', 'is_active']
    readonly_fields = ['name']
    show_change_link = True


class ServiceImageInline(admin.TabularInline):
    model = Service.images.through
    extra = 1


class ContractMessageInline(admin.TabularInline):
    model = ContractMessage
    extra = 0
    readonly_fields = ['sender', 'content', 'created_at', 'read_at']
    can_delete = False


# =============================================================================
# CATEGORY & TAXONOMY
# =============================================================================

@admin.register(ServiceCategory)
class ServiceCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'parent', 'slug', 'sort_order', 'service_count', 'created_at']
    list_filter = ['parent', 'created_at']
    search_fields = ['name', 'description']
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['sort_order', 'name']

    def service_count(self, obj):
        return obj.services.count()
    service_count.short_description = _('Services')


@admin.register(ServiceTag)
class ServiceTagAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'created_at']
    search_fields = ['name']
    prepopulated_fields = {'slug': ('name',)}


@admin.register(ServiceImage)
class ServiceImageAdmin(admin.ModelAdmin):
    list_display = ['id', 'description', 'sort_order', 'created_at']
    list_filter = ['created_at']
    search_fields = ['description', 'alt_text']


# =============================================================================
# PROVIDER
# =============================================================================

@admin.register(ServiceProvider)
class ServiceProviderAdmin(admin.ModelAdmin):
    list_display = [
        'display_name', 'user_email', 'provider_type', 'rating_display',
        'completed_jobs_count', 'availability_status', 'is_verified', 'created_at'
    ]
    list_filter = [
        'provider_type', 'availability_status', 'is_verified',
        'is_featured', 'stripe_payouts_enabled', 'created_at'
    ]
    search_fields = ['display_name', 'user__email', 'user__first_name', 'user__last_name', 'bio']
    readonly_fields = [
        'uuid', 'rating_avg', 'total_reviews', 'completed_jobs_count',
        'total_earnings', 'created_at', 'updated_at'
    ]
    autocomplete_fields = ['user', 'company']
    inlines = [ProviderSkillInline, ServiceInline]

    fieldsets = (
        (None, {
            'fields': ('uuid', 'user', 'company', 'provider_type', 'display_name')
        }),
        (_('Profile'), {
            'fields': ('bio', 'tagline', 'avatar', 'cover_image')
        }),
        (_('Location'), {
            'fields': ('address', 'city', 'state', 'postal_code', 'country', 'location_lat', 'location_lng')
        }),
        (_('Pricing'), {
            'fields': ('hourly_rate', 'minimum_budget', 'currency')
        }),
        (_('Stats'), {
            'fields': ('rating_avg', 'total_reviews', 'completed_jobs_count', 'total_earnings', 'response_rate')
        }),
        (_('Status'), {
            'fields': ('availability_status', 'is_verified', 'is_featured', 'is_private', 'is_accepting_projects')
        }),
        (_('Stripe Connect'), {
            'fields': ('stripe_account_id', 'stripe_onboarding_complete', 'stripe_payouts_enabled'),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('last_active_at', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = _('Email')

    def rating_display(self, obj):
        stars = '★' * int(obj.rating_avg) + '☆' * (5 - int(obj.rating_avg))
        return f"{stars} ({obj.rating_avg})"
    rating_display.short_description = _('Rating')


@admin.register(ProviderSkill)
class ProviderSkillAdmin(admin.ModelAdmin):
    list_display = ['provider', 'skill', 'level', 'years_experience', 'is_verified']
    list_filter = ['level', 'is_verified']
    search_fields = ['provider__display_name', 'skill__name']
    autocomplete_fields = ['provider', 'skill']


# =============================================================================
# SERVICE
# =============================================================================

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'provider_link', 'category', 'price_display',
        'is_active', 'is_featured', 'order_count', 'created_at'
    ]
    list_filter = ['category', 'service_type', 'delivery_type', 'is_active', 'is_featured', 'created_at']
    search_fields = ['name', 'description', 'provider__display_name']
    readonly_fields = ['uuid', 'view_count', 'order_count', 'created_at', 'updated_at']
    autocomplete_fields = ['provider', 'category']
    filter_horizontal = ['tags', 'images']
    prepopulated_fields = {'slug': ('name',)}

    fieldsets = (
        (None, {
            'fields': ('uuid', 'provider', 'category', 'name', 'slug')
        }),
        (_('Details'), {
            'fields': ('description', 'short_description')
        }),
        (_('Pricing'), {
            'fields': ('service_type', 'price', 'price_min', 'price_max', 'currency')
        }),
        (_('Delivery'), {
            'fields': ('delivery_type', 'duration_days', 'revisions_included')
        }),
        (_('Media'), {
            'fields': ('thumbnail', 'video_url', 'tags')
        }),
        (_('Status'), {
            'fields': ('is_active', 'is_featured')
        }),
        (_('Stats'), {
            'fields': ('view_count', 'order_count'),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def provider_link(self, obj):
        url = reverse('admin:services_serviceprovider_change', args=[obj.provider.pk])
        return format_html('<a href="{}">{}</a>', url, obj.provider.display_name)
    provider_link.short_description = _('Provider')

    def price_display(self, obj):
        if obj.service_type == 'fixed' and obj.price:
            return f"${obj.price}"
        elif obj.price_min and obj.price_max:
            return f"${obj.price_min} - ${obj.price_max}"
        return "-"
    price_display.short_description = _('Price')


@admin.register(ServiceLike)
class ServiceLikeAdmin(admin.ModelAdmin):
    list_display = ['user', 'service', 'created_at']
    list_filter = ['created_at']
    search_fields = ['user__email', 'service__name']
    autocomplete_fields = ['user', 'service']


# =============================================================================
# CLIENT REQUESTS & MATCHING
# =============================================================================

@admin.register(ClientRequest)
class ClientRequestAdmin(admin.ModelAdmin):
    list_display = ['title', 'client', 'category', 'budget_display', 'status', 'proposal_count', 'created_at']
    list_filter = ['status', 'category', 'remote_allowed', 'created_at']
    search_fields = ['title', 'description', 'client__email']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    autocomplete_fields = ['client', 'category']
    filter_horizontal = ['required_skills']

    def budget_display(self, obj):
        if obj.budget_min and obj.budget_max:
            return f"${obj.budget_min} - ${obj.budget_max}"
        return "-"
    budget_display.short_description = _('Budget')

    def proposal_count(self, obj):
        return obj.proposals.count()
    proposal_count.short_description = _('Proposals')


@admin.register(ProviderMatch)
class ProviderMatchAdmin(admin.ModelAdmin):
    list_display = ['client_request', 'provider', 'score', 'viewed_by_client', 'accepted_by_client', 'created_at']
    list_filter = ['viewed_by_client', 'accepted_by_client', 'rejected_by_client']
    search_fields = ['client_request__title', 'provider__display_name']
    autocomplete_fields = ['client_request', 'provider']


# =============================================================================
# PROPOSALS & CONTRACTS
# =============================================================================

@admin.register(ServiceProposal)
class ServiceProposalAdmin(admin.ModelAdmin):
    list_display = ['client_request', 'provider', 'proposed_rate', 'rate_type', 'status', 'created_at']
    list_filter = ['status', 'rate_type', 'created_at']
    search_fields = ['client_request__title', 'provider__display_name', 'cover_letter']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    autocomplete_fields = ['client_request', 'provider']


@admin.register(ServiceContract)
class ServiceContractAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'client_email', 'provider_name', 'agreed_rate',
        'status', 'escrow_status', 'created_at'
    ]
    list_filter = ['status', 'rate_type', 'created_at']
    search_fields = ['title', 'client__email', 'provider__display_name']
    readonly_fields = [
        'uuid', 'provider_payout_amount',
        'started_at', 'delivered_at', 'completed_at', 'cancelled_at',
        'created_at', 'updated_at'
    ]
    autocomplete_fields = ['client', 'provider', 'proposal', 'service', 'client_request', 'escrow_transaction']
    inlines = [ContractMessageInline]
    date_hierarchy = 'created_at'

    fieldsets = (
        (None, {
            'fields': ('uuid', 'title', 'description')
        }),
        (_('Parties'), {
            'fields': ('client', 'provider')
        }),
        (_('Origin'), {
            'fields': ('proposal', 'service', 'client_request'),
            'classes': ('collapse',)
        }),
        (_('Terms'), {
            'fields': ('agreed_rate', 'rate_type', 'currency', 'agreed_deadline', 'revisions_allowed', 'revisions_used')
        }),
        (_('Escrow'), {
            'fields': ('escrow_transaction', 'platform_fee_percent', 'provider_payout_amount')
        }),
        (_('Status'), {
            'fields': ('status', 'cancellation_reason')
        }),
        (_('Timeline'), {
            'fields': ('started_at', 'delivered_at', 'completed_at', 'cancelled_at'),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def client_email(self, obj):
        return obj.client.email
    client_email.short_description = _('Client')

    def provider_name(self, obj):
        return obj.provider.display_name
    provider_name.short_description = _('Provider')

    def escrow_status(self, obj):
        if obj.escrow_transaction:
            return obj.escrow_transaction.status
        return "-"
    escrow_status.short_description = _('Escrow')


# =============================================================================
# REVIEWS & MESSAGES
# =============================================================================

@admin.register(ServiceReview)
class ServiceReviewAdmin(admin.ModelAdmin):
    list_display = ['contract', 'reviewer', 'provider', 'rating_stars', 'has_response', 'created_at']
    list_filter = ['rating', 'created_at']
    search_fields = ['contract__title', 'reviewer__email', 'provider__display_name', 'content']
    readonly_fields = ['created_at', 'updated_at']
    autocomplete_fields = ['contract', 'reviewer', 'provider']

    def rating_stars(self, obj):
        return '★' * obj.rating + '☆' * (5 - obj.rating)
    rating_stars.short_description = _('Rating')

    def has_response(self, obj):
        return bool(obj.provider_response)
    has_response.boolean = True
    has_response.short_description = _('Responded')


@admin.register(ContractMessage)
class ContractMessageAdmin(admin.ModelAdmin):
    list_display = ['contract', 'sender', 'content_preview', 'is_system_message', 'created_at', 'read_at']
    list_filter = ['is_system_message', 'created_at']
    search_fields = ['contract__title', 'sender__email', 'content']
    readonly_fields = ['created_at']
    autocomplete_fields = ['contract', 'sender']

    def content_preview(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    content_preview.short_description = _('Message')
