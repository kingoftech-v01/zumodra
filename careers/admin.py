"""
Careers Admin - Admin for public career pages.
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import (
    CareerPage, CareerPageSection, JobListing,
    PublicApplication, TalentPool, TalentPoolMember
)


class CareerPageSectionInline(admin.TabularInline):
    model = CareerPageSection
    extra = 0
    ordering = ['order']


@admin.register(CareerPage)
class CareerPageAdmin(admin.ModelAdmin):
    list_display = ['title', 'is_active', 'show_salary_range', 'require_account', 'updated_at']
    list_filter = ['is_active', 'show_salary_range', 'require_account']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    inlines = [CareerPageSectionInline]

    fieldsets = (
        ('Basic Info', {
            'fields': ('title', 'tagline', 'description')
        }),
        ('Branding', {
            'fields': ('logo', 'cover_image', 'favicon')
        }),
        ('Colors', {
            'fields': (
                'primary_color', 'secondary_color', 'accent_color',
                'text_color', 'background_color'
            )
        }),
        ('Content', {
            'fields': (
                'show_company_info', 'company_description',
                'show_benefits', 'benefits_content',
                'show_culture', 'culture_content',
                'show_values', 'values_content'
            )
        }),
        ('Social Links', {
            'fields': (
                'linkedin_url', 'twitter_url', 'facebook_url',
                'instagram_url', 'glassdoor_url'
            ),
            'classes': ('collapse',)
        }),
        ('SEO', {
            'fields': (
                'meta_title', 'meta_description', 'meta_keywords', 'og_image'
            ),
            'classes': ('collapse',)
        }),
        ('Settings', {
            'fields': (
                'is_active', 'require_account', 'show_salary_range',
                'allow_general_applications', 'gdpr_consent_text'
            )
        }),
        ('Analytics', {
            'fields': ('google_analytics_id', 'facebook_pixel_id'),
            'classes': ('collapse',)
        }),
    )


@admin.register(JobListing)
class JobListingAdmin(admin.ModelAdmin):
    list_display = [
        'job', 'is_featured', 'view_count',
        'apply_click_count', 'published_at'
    ]
    list_filter = ['is_featured', 'published_at']
    search_fields = ['job__title']
    readonly_fields = ['view_count', 'apply_click_count']
    raw_id_fields = ['job']


@admin.register(PublicApplication)
class PublicApplicationAdmin(admin.ModelAdmin):
    list_display = [
        'full_name', 'email', 'job_display',
        'status_badge', 'submitted_at'
    ]
    list_filter = ['status', 'submitted_at']
    search_fields = ['first_name', 'last_name', 'email']
    readonly_fields = [
        'uuid', 'submitted_at', 'processed_at',
        'ats_candidate', 'ats_application'
    ]
    raw_id_fields = ['job_listing']

    def full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"
    full_name.short_description = 'Name'

    def job_display(self, obj):
        if obj.job_listing:
            return obj.job_listing.job.title
        return 'General Application'
    job_display.short_description = 'Job'

    def status_badge(self, obj):
        colors = {
            'pending': 'orange',
            'processed': 'green',
            'duplicate': 'blue',
            'spam': 'red',
            'error': 'red',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


class TalentPoolMemberInline(admin.TabularInline):
    model = TalentPoolMember
    extra = 0
    raw_id_fields = ['candidate', 'added_by']


@admin.register(TalentPool)
class TalentPoolAdmin(admin.ModelAdmin):
    list_display = ['name', 'is_public', 'member_count', 'created_at']
    list_filter = ['is_public', 'created_at']
    search_fields = ['name', 'description']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
    inlines = [TalentPoolMemberInline]

    def member_count(self, obj):
        return obj.members.count()
    member_count.short_description = 'Members'
