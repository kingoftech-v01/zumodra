from django.contrib import admin
from .models import (
    ServiceCategory, ServicesTag, ServicesPicture,
    ProviderSkill, ServiceProviderProfile, Service,
    ServiceLike, ClientRequest, Match,
    ServiceRequest, ServiceProposal, ServiceContract,
    ServiceComment, ServiceMessage
)

# Register your models here.

# --- Inline Admins ---
class ServicesPictureInline(admin.TabularInline):
    model = Service.images.through
    extra = 1

class ProviderSkillInline(admin.TabularInline):
    model = ProviderSkill
    extra = 1

class ServiceInline(admin.TabularInline):
    model = Service
    extra = 1


# --- MAIN MODELS ADMIN ---
@admin.register(ServiceCategory)
class ServiceCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'parent', 'created_at', 'updated_at')
    list_filter = ('parent',)
    search_fields = ('name',)
    ordering = ('name',)
    prepopulated_fields = {"name": ("name",)}


@admin.register(ServicesTag)
class ServicesTagAdmin(admin.ModelAdmin):
    list_display = ('tag',)
    search_fields = ('tag',)


@admin.register(ServicesPicture)
class ServicesPictureAdmin(admin.ModelAdmin):
    list_display = ('id', 'description', 'uploaded_at')
    list_filter = ('uploaded_at',)
    search_fields = ('description',)


@admin.register(ServiceProviderProfile)
class ServiceProviderProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'company', 'hourly_rate', 'rating_avg', 'availability_status', 'created_at')
    list_filter = ('availability_status', 'company')
    search_fields = ('user__email', 'company__name', 'bio')
    # inlines = [ProviderSkillInline, ServiceInline]


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ('name', 'serviceCategory', 'price', 'duration_minutes', 'created_at')
    list_filter = ('serviceCategory', 'created_at')
    search_fields = ('name', 'description')
    inlines = [ServicesPictureInline]

# , 'provider'


@admin.register(ServiceLike)
class ServiceLikeAdmin(admin.ModelAdmin):
    list_display = ('user', 'service', 'liked_at')
    list_filter = ('liked_at',)
    search_fields = ('user__email', 'service__name')


@admin.register(ClientRequest)
class ClientRequestAdmin(admin.ModelAdmin):
    list_display = ('client', 'service_category', 'budget_min', 'budget_max', 'remote_allowed', 'created_at')
    list_filter = ('remote_allowed', 'service_category', 'created_at')
    search_fields = ('client__email', 'description')


@admin.register(Match)
class MatchAdmin(admin.ModelAdmin):
    list_display = ('client_request', 'provider_profile', 'score', 'matched_at', 'accepted_by_client')
    list_filter = ('accepted_by_client',)
    search_fields = ('client_request__client__email', 'provider_profile__user__email')


@admin.register(ServiceRequest)
class ServiceRequestAdmin(admin.ModelAdmin):
    list_display = ('client', 'company', 'title', 'budget_min', 'budget_max', 'deadline', 'is_open')
    list_filter = ('is_open', 'deadline')
    search_fields = ('title', 'client__email', 'company__name')


@admin.register(ServiceProposal)
class ServiceProposalAdmin(admin.ModelAdmin):
    list_display = ('request', 'provider', 'proposed_rate', 'is_accepted', 'submitted_at')
    list_filter = ('is_accepted',)
    search_fields = ('provider__user__email', 'request__title')


@admin.register(ServiceContract)
class ServiceContractAdmin(admin.ModelAdmin):
    list_display = ('request', 'provider', 'client', 'status', 'agreed_rate', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('client__email', 'provider__user__email')
    date_hierarchy = 'created_at'


@admin.register(ServiceComment)
class ServiceCommentAdmin(admin.ModelAdmin):
    list_display = ('service', 'provider', 'reviewer', 'rating', 'created_at')
    list_filter = ('rating', 'created_at')
    search_fields = ('service__name', 'reviewer__email', 'content')


@admin.register(ServiceMessage)
class ServiceMessageAdmin(admin.ModelAdmin):
    list_display = ('contract', 'sender', 'sent_at')
    list_filter = ('sent_at',)
    search_fields = ('sender__email', 'message')
