"""
Careers Serializers - REST API serializers for public career pages.

This module provides serializers for:
- Career page configuration (public/admin)
- Job listings (public/admin with analytics)
- Public applications (no auth required)
- Talent pools and members
- Job alert subscriptions

Public serializers expose no sensitive data and are optimized for SEO.
"""

from rest_framework import serializers
from rest_framework.fields import (
    CharField, EmailField, FileField, BooleanField,
    UUIDField, SlugField, DateField, URLField,
    ListField, DictField, SerializerMethodField
)
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import FileExtensionValidator
from django.conf import settings

from .models import (
    CareerPage, CareerPageSection, JobListing,
    PublicApplication, TalentPool, TalentPoolMember
)
from ats.models import JobPosting, JobCategory, Candidate
from tenants.models import PublicJobCatalog


# ==================== PUBLIC CAREER SITE SERIALIZERS ====================

class PublicCareerSiteSerializer(serializers.Serializer):
    """
    Career site public configuration.
    Exposes only public-safe branding and content information.
    No sensitive tenant data exposed.
    """
    subdomain = CharField(read_only=True)
    company_name = CharField(source='title', read_only=True)
    logo_url = SerializerMethodField()
    favicon_url = SerializerMethodField()
    cover_image_url = SerializerMethodField()
    primary_color = CharField(read_only=True)
    secondary_color = CharField(read_only=True)
    accent_color = CharField(read_only=True)
    text_color = CharField(read_only=True)
    background_color = CharField(read_only=True)
    hero_title = CharField(source='title', read_only=True)
    hero_subtitle = CharField(source='tagline', read_only=True)
    about_company = CharField(source='company_description', read_only=True)
    benefits_sections = SerializerMethodField()
    culture_content = CharField(read_only=True)
    values = SerializerMethodField()
    social_links = SerializerMethodField()
    custom_css = CharField(read_only=True)
    # SEO fields
    meta_title = CharField(read_only=True)
    meta_description = CharField(read_only=True)
    meta_keywords = CharField(read_only=True)
    og_image_url = SerializerMethodField()
    # Settings
    show_salary_range = BooleanField(read_only=True)
    require_account = BooleanField(read_only=True)
    allow_general_applications = BooleanField(read_only=True)
    gdpr_consent_text = CharField(read_only=True)
    # Analytics (client-side tracking)
    google_analytics_id = CharField(read_only=True)
    facebook_pixel_id = CharField(read_only=True)

    def get_logo_url(self, obj):
        """Return absolute URL for logo."""
        if obj.logo:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.logo.url)
            return obj.logo.url
        return None

    def get_favicon_url(self, obj):
        """Return absolute URL for favicon."""
        if obj.favicon:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.favicon.url)
            return obj.favicon.url
        return None

    def get_cover_image_url(self, obj):
        """Return absolute URL for cover image."""
        if obj.cover_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.cover_image.url)
            return obj.cover_image.url
        return None

    def get_og_image_url(self, obj):
        """Return absolute URL for Open Graph image."""
        if obj.og_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.og_image.url)
            return obj.og_image.url
        return None

    def get_benefits_sections(self, obj):
        """Parse and return benefits content sections."""
        if obj.show_benefits and obj.benefits_content:
            return [
                {'title': 'Benefits', 'content': obj.benefits_content}
            ]
        return []

    def get_values(self, obj):
        """Return company values if enabled."""
        if obj.show_values:
            return obj.values_content or []
        return []

    def get_social_links(self, obj):
        """Return social media links as structured data."""
        links = []
        if obj.linkedin_url:
            links.append({'platform': 'linkedin', 'url': obj.linkedin_url, 'icon': 'mdi-linkedin'})
        if obj.twitter_url:
            links.append({'platform': 'twitter', 'url': obj.twitter_url, 'icon': 'mdi-twitter'})
        if obj.facebook_url:
            links.append({'platform': 'facebook', 'url': obj.facebook_url, 'icon': 'mdi-facebook'})
        if obj.instagram_url:
            links.append({'platform': 'instagram', 'url': obj.instagram_url, 'icon': 'mdi-instagram'})
        if obj.glassdoor_url:
            links.append({'platform': 'glassdoor', 'url': obj.glassdoor_url, 'icon': 'mdi-briefcase'})
        return links


class PublicJobListSerializer(serializers.Serializer):
    """
    Job listing for public career site.
    Optimized for list views with minimal data transfer.
    """
    id = UUIDField(source='job.uuid', read_only=True)
    slug = SlugField(source='custom_slug', read_only=True)
    title = CharField(source='job.title', read_only=True)
    department = SerializerMethodField()
    location_city = CharField(source='job.location_city', read_only=True)
    location_country = CharField(source='job.location_country', read_only=True)
    location_display = SerializerMethodField()
    employment_type = CharField(source='job.job_type', read_only=True)
    employment_type_display = SerializerMethodField()
    experience_level = CharField(source='job.experience_level', read_only=True)
    experience_level_display = SerializerMethodField()
    remote_policy = CharField(source='job.remote_policy', read_only=True)
    remote_policy_display = SerializerMethodField()
    salary_range = SerializerMethodField()
    posted_date = DateField(source='published_at', read_only=True)
    is_featured = BooleanField(read_only=True)
    is_new = SerializerMethodField()
    days_remaining = SerializerMethodField()
    application_count_display = SerializerMethodField()
    category_name = SerializerMethodField()
    category_color = SerializerMethodField()

    def get_department(self, obj):
        """Return department/category name."""
        if obj.job.category:
            return obj.job.category.name
        return None

    def get_location_display(self, obj):
        """Format location for display."""
        parts = [
            p for p in [obj.job.location_city, obj.job.location_state, obj.job.location_country]
            if p
        ]
        if not parts and obj.job.remote_policy == 'remote':
            return _('Remote')
        return ', '.join(parts) if parts else _('Location flexible')

    def get_employment_type_display(self, obj):
        """Return human-readable employment type."""
        return obj.job.get_job_type_display() if hasattr(obj.job, 'get_job_type_display') else obj.job.job_type

    def get_experience_level_display(self, obj):
        """Return human-readable experience level."""
        return obj.job.get_experience_level_display() if hasattr(obj.job, 'get_experience_level_display') else obj.job.experience_level

    def get_remote_policy_display(self, obj):
        """Return human-readable remote policy."""
        return obj.job.get_remote_policy_display() if hasattr(obj.job, 'get_remote_policy_display') else obj.job.remote_policy

    def get_salary_range(self, obj):
        """Return salary range only if show_salary_ranges is enabled."""
        # Check career page settings
        career_page = CareerPage.objects.filter(is_active=True).first()
        if career_page and career_page.show_salary_range and obj.job.show_salary:
            if obj.job.salary_min and obj.job.salary_max:
                currency = obj.job.salary_currency or 'CAD'
                period = obj.job.salary_period or 'yearly'
                return {
                    'min': float(obj.job.salary_min),
                    'max': float(obj.job.salary_max),
                    'currency': currency,
                    'period': period,
                    'display': f"{currency} {obj.job.salary_min:,.0f} - {obj.job.salary_max:,.0f} / {period}"
                }
        return None

    def get_is_new(self, obj):
        """Check if job was posted within the last 7 days."""
        if not obj.published_at:
            return False
        return (timezone.now() - obj.published_at).days <= 7

    def get_days_remaining(self, obj):
        """Days until job expires."""
        if not obj.expires_at:
            return None
        delta = obj.expires_at - timezone.now()
        return max(0, delta.days)

    def get_application_count_display(self, obj):
        """Return application count if enabled."""
        if not obj.show_application_count:
            return None
        count = obj.public_applications.filter(
            status__in=['pending', 'processed']
        ).count()
        if count >= obj.application_count_threshold:
            return f"{obj.application_count_threshold}+ applicants"
        return f"{count} applicant{'s' if count != 1 else ''}"

    def get_category_name(self, obj):
        """Return category name."""
        return obj.job.category.name if obj.job.category else None

    def get_category_color(self, obj):
        """Return category color for UI."""
        return obj.job.category.color if obj.job.category else '#3B82F6'


class PublicJobDetailSerializer(PublicJobListSerializer):
    """
    Full job detail for public view.
    Includes all information needed for job detail page and application form.
    """
    description = CharField(source='job.description', read_only=True)
    responsibilities = CharField(source='job.responsibilities', read_only=True)
    requirements = CharField(source='job.requirements', read_only=True)
    nice_to_have = CharField(source='job.nice_to_have', read_only=True)
    benefits = CharField(source='job.benefits', read_only=True)
    education_requirements = CharField(source='job.education_requirements', read_only=True)
    required_skills = SerializerMethodField()
    preferred_skills = SerializerMethodField()
    languages_required = SerializerMethodField()
    custom_questions = SerializerMethodField()
    require_cover_letter = BooleanField(source='job.require_cover_letter', read_only=True)
    require_resume = BooleanField(source='job.require_resume', read_only=True)
    application_deadline = SerializerMethodField()
    reference_code = CharField(source='job.reference_code', read_only=True)
    team = CharField(source='job.team', read_only=True)
    reports_to = CharField(source='job.reports_to', read_only=True)
    # Structured data for Google Jobs
    structured_data = SerializerMethodField()
    related_jobs = SerializerMethodField()

    def get_required_skills(self, obj):
        """Return required skills as list."""
        return obj.job.required_skills or []

    def get_preferred_skills(self, obj):
        """Return preferred skills as list."""
        return obj.job.preferred_skills or []

    def get_languages_required(self, obj):
        """Return required languages as list."""
        return obj.job.languages_required or []

    def get_custom_questions(self, obj):
        """Return custom questions applicant must answer."""
        # Combine job-level and listing-level custom questions
        questions = []
        if obj.job.custom_questions:
            questions.extend(obj.job.custom_questions)
        if obj.custom_application_form:
            form_fields = obj.custom_application_form.get('fields', [])
            questions.extend(form_fields)
        return questions

    def get_application_deadline(self, obj):
        """Return formatted application deadline."""
        if obj.job.application_deadline:
            return obj.job.application_deadline.isoformat()
        if obj.expires_at:
            return obj.expires_at.isoformat()
        return None

    def get_structured_data(self, obj):
        """
        Return JSON-LD structured data for Google Jobs.
        https://developers.google.com/search/docs/data-types/job-posting
        """
        request = self.context.get('request')
        base_url = request.build_absolute_uri('/') if request else ''

        structured = {
            "@context": "https://schema.org/",
            "@type": "JobPosting",
            "title": obj.job.title,
            "description": obj.job.description,
            "datePosted": obj.published_at.isoformat() if obj.published_at else None,
            "employmentType": self._map_employment_type(obj.job.job_type),
            "jobLocation": {
                "@type": "Place",
                "address": {
                    "@type": "PostalAddress",
                    "addressLocality": obj.job.location_city,
                    "addressRegion": obj.job.location_state,
                    "addressCountry": obj.job.location_country,
                }
            },
            "identifier": {
                "@type": "PropertyValue",
                "name": "Reference Code",
                "value": obj.job.reference_code
            }
        }

        # Add remote work type
        if obj.job.remote_policy in ['remote', 'hybrid', 'flexible']:
            structured["jobLocationType"] = "TELECOMMUTE"

        # Add salary if visible
        salary_range = self.get_salary_range(obj)
        if salary_range:
            structured["baseSalary"] = {
                "@type": "MonetaryAmount",
                "currency": salary_range['currency'],
                "value": {
                    "@type": "QuantitativeValue",
                    "minValue": salary_range['min'],
                    "maxValue": salary_range['max'],
                    "unitText": salary_range['period'].upper()
                }
            }

        # Add valid through date
        if obj.expires_at:
            structured["validThrough"] = obj.expires_at.isoformat()
        elif obj.job.application_deadline:
            structured["validThrough"] = obj.job.application_deadline.isoformat()

        # Add experience requirements
        if obj.job.experience_level:
            structured["experienceRequirements"] = obj.job.get_experience_level_display()

        # Add education requirements
        if obj.job.education_requirements:
            structured["educationRequirements"] = obj.job.education_requirements

        # Add skills
        if obj.job.required_skills:
            structured["skills"] = ", ".join(obj.job.required_skills)

        return structured

    def _map_employment_type(self, job_type):
        """Map job type to Google Jobs employment type."""
        mapping = {
            'full_time': 'FULL_TIME',
            'part_time': 'PART_TIME',
            'contract': 'CONTRACTOR',
            'internship': 'INTERN',
            'temporary': 'TEMPORARY',
            'freelance': 'CONTRACTOR',
        }
        return mapping.get(job_type, 'OTHER')

    def get_related_jobs(self, obj):
        """Return up to 3 related jobs in the same category."""
        if not obj.job.category:
            return []

        related = JobListing.objects.filter(
            job__category=obj.job.category,
            job__status='open',
            published_at__isnull=False
        ).exclude(
            id=obj.id
        ).exclude(
            expires_at__lt=timezone.now()
        ).select_related('job', 'job__category').order_by('-is_featured', '-published_at')[:3]

        return PublicJobListSerializer(
            related, many=True, context=self.context
        ).data


class PublicApplicationSubmitSerializer(serializers.Serializer):
    """
    Submit application data.
    Validates all application fields including consent and honeypot spam detection.
    """
    first_name = CharField(max_length=100)
    last_name = CharField(max_length=100)
    email = EmailField()
    phone = CharField(max_length=30, required=False, allow_blank=True)
    resume = FileField(
        validators=[FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx'])]
    )
    cover_letter = CharField(required=False, allow_blank=True)
    linkedin_url = URLField(required=False, allow_blank=True)
    portfolio_url = URLField(required=False, allow_blank=True)
    custom_answers = DictField(required=False)
    consent_to_store = BooleanField()
    consent_to_process = BooleanField()
    marketing_consent = BooleanField(required=False, default=False)
    # Honeypot field for spam detection - should always be empty
    website = CharField(required=False, allow_blank=True)
    # Job listing ID (optional for general applications)
    job_listing_id = serializers.IntegerField(required=False, allow_null=True)

    def validate_consent_to_store(self, value):
        """Validate that consent to store data is given."""
        if not value:
            raise serializers.ValidationError(
                _("You must consent to storing your personal data to submit an application.")
            )
        return value

    def validate_consent_to_process(self, value):
        """Validate that consent to process data is given."""
        if not value:
            raise serializers.ValidationError(
                _("You must consent to processing your application to submit.")
            )
        return value

    def validate_website(self, value):
        """Honeypot validation - this field should always be empty."""
        if value:
            raise serializers.ValidationError(_("Invalid submission detected."))
        return value

    def validate_resume(self, value):
        """Validate resume file size and type."""
        if value:
            # Max 10MB
            if value.size > 10 * 1024 * 1024:
                raise serializers.ValidationError(
                    _("Resume file size must be under 10MB.")
                )
        return value

    def validate(self, data):
        """Cross-field validation."""
        job_listing_id = data.get('job_listing_id')

        if job_listing_id:
            try:
                job_listing = JobListing.objects.select_related('job').get(pk=job_listing_id)
            except JobListing.DoesNotExist:
                raise serializers.ValidationError({
                    'job_listing_id': _("Job listing not found.")
                })

            # Check if job is still accepting applications
            if job_listing.is_expired:
                raise serializers.ValidationError({
                    'job_listing_id': _("This job posting has expired.")
                })

            if job_listing.job.status != 'open':
                raise serializers.ValidationError({
                    'job_listing_id': _("This job is not currently accepting applications.")
                })

            # Validate required fields based on job settings
            if job_listing.job.require_cover_letter and not data.get('cover_letter'):
                raise serializers.ValidationError({
                    'cover_letter': _("A cover letter is required for this position.")
                })

            # Validate custom questions
            if job_listing.job.custom_questions:
                custom_answers = data.get('custom_answers', {})
                for question in job_listing.job.custom_questions:
                    if question.get('required', False):
                        field_id = question.get('id') or question.get('name')
                        if field_id and field_id not in custom_answers:
                            raise serializers.ValidationError({
                                'custom_answers': _(f"Please answer: {question.get('label', field_id)}")
                            })

        return data

    def create(self, validated_data):
        """Create the public application."""
        request = self.context.get('request')

        # Remove honeypot field
        validated_data.pop('website', None)

        # Get job listing
        job_listing_id = validated_data.pop('job_listing_id', None)
        job_listing = None
        if job_listing_id:
            job_listing = JobListing.objects.get(pk=job_listing_id)

        # Map consent fields
        validated_data['privacy_consent'] = validated_data.pop('consent_to_store', False)
        validated_data.pop('consent_to_process', None)  # Implicit in privacy_consent

        # Capture tracking data
        if request:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                validated_data['ip_address'] = x_forwarded_for.split(',')[0].strip()
            else:
                validated_data['ip_address'] = request.META.get('REMOTE_ADDR')

            validated_data['user_agent'] = request.META.get('HTTP_USER_AGENT', '')
            validated_data['consent_timestamp'] = timezone.now()
            validated_data['consent_ip'] = validated_data['ip_address']
            validated_data['referrer'] = request.META.get('HTTP_REFERER', '')

            # UTM tracking
            validated_data['utm_source'] = request.GET.get('utm_source', '')
            validated_data['utm_medium'] = request.GET.get('utm_medium', '')
            validated_data['utm_campaign'] = request.GET.get('utm_campaign', '')

        # Create application
        application = PublicApplication.objects.create(
            job_listing=job_listing,
            **validated_data
        )

        # Update apply click count
        if job_listing:
            job_listing.apply_click_count += 1
            job_listing.save(update_fields=['apply_click_count'])

        return application


class JobAlertSubscriptionSerializer(serializers.Serializer):
    """
    Job alert subscription.
    Allows candidates to subscribe to email alerts for new job postings.
    """
    email = EmailField()
    departments = ListField(child=CharField(max_length=100), required=False, default=list)
    job_types = ListField(child=CharField(max_length=50), required=False, default=list)
    locations = ListField(child=CharField(max_length=100), required=False, default=list)
    keywords = ListField(child=CharField(max_length=100), required=False, default=list)
    remote_only = BooleanField(required=False, default=False)
    frequency = CharField(max_length=20, default='weekly')  # daily, weekly, monthly

    def validate_email(self, value):
        """Validate email format."""
        return value.lower().strip()

    def validate_frequency(self, value):
        """Validate frequency is valid."""
        valid_frequencies = ['daily', 'weekly', 'monthly']
        if value not in valid_frequencies:
            raise serializers.ValidationError(
                _("Frequency must be one of: daily, weekly, monthly")
            )
        return value


# ==================== CAREER PAGE SERIALIZERS ====================

class CareerPageSectionSerializer(serializers.ModelSerializer):
    """Serializer for custom career page sections."""

    class Meta:
        model = CareerPageSection
        fields = [
            'id', 'title', 'section_type', 'content',
            'order', 'is_visible'
        ]
        read_only_fields = ['id']


class CareerPagePublicSerializer(serializers.ModelSerializer):
    """
    Public career page serializer.
    Exposes only public-facing information for job seekers.
    """
    sections = serializers.SerializerMethodField()
    job_count = serializers.SerializerMethodField()
    logo_url = serializers.SerializerMethodField()
    cover_image_url = serializers.SerializerMethodField()
    favicon_url = serializers.SerializerMethodField()
    og_image_url = serializers.SerializerMethodField()

    class Meta:
        model = CareerPage
        fields = [
            'uuid', 'title', 'tagline', 'description',
            # Branding
            'logo_url', 'cover_image_url', 'favicon_url',
            # Colors
            'primary_color', 'secondary_color', 'accent_color',
            'text_color', 'background_color',
            # Custom CSS
            'custom_css',
            # Content toggles
            'show_company_info', 'company_description',
            'show_benefits', 'benefits_content',
            'show_culture', 'culture_content',
            'show_values', 'values_content',
            'show_team', 'team_members',
            # Social Links
            'linkedin_url', 'twitter_url', 'facebook_url',
            'instagram_url', 'glassdoor_url',
            # SEO
            'meta_title', 'meta_description', 'meta_keywords', 'og_image_url',
            # Settings
            'require_account', 'show_salary_range',
            'allow_general_applications', 'gdpr_consent_text',
            # Analytics
            'google_analytics_id', 'facebook_pixel_id',
            # Computed
            'sections', 'job_count',
        ]
        read_only_fields = fields

    def get_sections(self, obj):
        """Return only visible sections, ordered."""
        visible_sections = obj.sections.filter(is_visible=True).order_by('order')
        return CareerPageSectionSerializer(visible_sections, many=True).data

    def get_job_count(self, obj):
        """Count of active public job listings."""
        return JobListing.objects.filter(
            job__status='open',
            job__published_on_career_page=True,
            published_at__isnull=False
        ).exclude(
            expires_at__lt=timezone.now()
        ).count()

    def get_logo_url(self, obj):
        if obj.logo:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.logo.url)
            return obj.logo.url
        return None

    def get_cover_image_url(self, obj):
        if obj.cover_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.cover_image.url)
            return obj.cover_image.url
        return None

    def get_favicon_url(self, obj):
        if obj.favicon:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.favicon.url)
            return obj.favicon.url
        return None

    def get_og_image_url(self, obj):
        if obj.og_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.og_image.url)
            return obj.og_image.url
        return None


class CareerPageAdminSerializer(serializers.ModelSerializer):
    """
    Admin career page serializer.
    Full CRUD access for tenant administrators.
    """
    sections = CareerPageSectionSerializer(many=True, read_only=True)
    analytics = serializers.SerializerMethodField()

    class Meta:
        model = CareerPage
        fields = [
            'id', 'uuid', 'title', 'tagline', 'description',
            # Branding
            'logo', 'cover_image', 'favicon',
            # Colors
            'primary_color', 'secondary_color', 'accent_color',
            'text_color', 'background_color',
            # Custom CSS
            'custom_css',
            # Content
            'show_company_info', 'company_description',
            'show_benefits', 'benefits_content',
            'show_culture', 'culture_content',
            'show_values', 'values_content',
            'show_team', 'team_members',
            # Social Links
            'linkedin_url', 'twitter_url', 'facebook_url',
            'instagram_url', 'glassdoor_url',
            # SEO
            'meta_title', 'meta_description', 'meta_keywords', 'og_image',
            # Settings
            'is_active', 'require_account', 'show_salary_range',
            'allow_general_applications', 'gdpr_consent_text',
            # Analytics
            'google_analytics_id', 'facebook_pixel_id',
            # Timestamps
            'created_at', 'updated_at',
            # Related
            'sections', 'analytics',
        ]
        read_only_fields = ['id', 'uuid', 'created_at', 'updated_at', 'analytics']

    def get_analytics(self, obj):
        """Return career page analytics summary."""
        now = timezone.now()
        thirty_days_ago = now - timezone.timedelta(days=30)

        # Get all job listings for this career page
        listings = JobListing.objects.filter(
            job__published_on_career_page=True
        )

        # Get applications in the last 30 days
        recent_applications = PublicApplication.objects.filter(
            submitted_at__gte=thirty_days_ago
        )

        return {
            'total_jobs': listings.count(),
            'active_jobs': listings.filter(
                job__status='open',
                published_at__isnull=False
            ).exclude(expires_at__lt=now).count(),
            'total_views': sum(l.view_count for l in listings),
            'total_applications': PublicApplication.objects.count(),
            'applications_last_30_days': recent_applications.count(),
            'conversion_rate': self._calculate_conversion_rate(listings),
        }

    def _calculate_conversion_rate(self, listings):
        """Calculate view to application conversion rate."""
        total_views = sum(l.view_count for l in listings) or 1
        total_applies = sum(l.apply_click_count for l in listings)
        return round((total_applies / total_views) * 100, 2)


# ==================== JOB LISTING SERIALIZERS ====================

class JobCategorySerializer(serializers.ModelSerializer):
    """Nested serializer for job categories."""

    class Meta:
        model = JobCategory
        fields = ['id', 'name', 'slug', 'icon', 'color']


class JobPostingPublicSerializer(serializers.ModelSerializer):
    """
    Public job posting info (nested in JobListing).
    Only exposes public-safe fields.
    """
    category = JobCategorySerializer(read_only=True)
    salary_range = serializers.SerializerMethodField()
    location_display = serializers.SerializerMethodField()

    class Meta:
        model = JobPosting
        fields = [
            'uuid', 'title', 'slug', 'reference_code',
            'category', 'description', 'responsibilities',
            'requirements', 'nice_to_have', 'benefits',
            'job_type', 'experience_level', 'remote_policy',
            'location_display', 'salary_range',
            'required_skills', 'preferred_skills',
            'education_requirements', 'languages_required',
            'require_cover_letter', 'require_resume',
            'custom_questions', 'application_deadline',
            'published_at',
        ]

    def get_salary_range(self, obj):
        """Return salary range if show_salary is enabled."""
        career_page = CareerPage.objects.first()
        if career_page and career_page.show_salary_range and obj.show_salary:
            return obj.salary_range_display
        return None

    def get_location_display(self, obj):
        """Format location for display."""
        parts = [
            p for p in [obj.location_city, obj.location_state, obj.location_country]
            if p
        ]
        if not parts and obj.remote_policy == 'remote':
            return 'Remote'
        return ', '.join(parts) if parts else None


class JobListingPublicSerializer(serializers.ModelSerializer):
    """
    Public job listing serializer.
    For job seekers viewing available positions.
    """
    job = JobPostingPublicSerializer(read_only=True)
    application_count_display = serializers.SerializerMethodField()
    is_new = serializers.SerializerMethodField()
    days_remaining = serializers.SerializerMethodField()

    class Meta:
        model = JobListing
        fields = [
            'id', 'job', 'custom_slug',
            'show_company_name', 'show_department',
            'is_featured', 'application_count_display',
            'published_at', 'expires_at',
            'is_new', 'days_remaining', 'is_expired',
        ]

    def get_application_count_display(self, obj):
        """Return application count if enabled."""
        if not obj.show_application_count:
            return None
        count = obj.public_applications.filter(
            status__in=['pending', 'processed']
        ).count()
        if count >= obj.application_count_threshold:
            return f"{obj.application_count_threshold}+ applicants"
        return f"{count} applicant{'s' if count != 1 else ''}"

    def get_is_new(self, obj):
        """Check if job was posted within the last 7 days."""
        if not obj.published_at:
            return False
        return (timezone.now() - obj.published_at).days <= 7

    def get_days_remaining(self, obj):
        """Days until job expires."""
        if not obj.expires_at:
            return None
        delta = obj.expires_at - timezone.now()
        return max(0, delta.days)


class JobListingDetailPublicSerializer(JobListingPublicSerializer):
    """
    Detailed public job listing with custom form configuration.
    Used for job detail pages with application form.
    """
    custom_form_fields = serializers.SerializerMethodField()
    related_jobs = serializers.SerializerMethodField()

    class Meta(JobListingPublicSerializer.Meta):
        fields = JobListingPublicSerializer.Meta.fields + [
            'custom_application_form', 'custom_form_fields',
            'related_jobs', 'view_count',
        ]

    def get_custom_form_fields(self, obj):
        """Parse custom form configuration for frontend rendering."""
        form_config = obj.custom_application_form or {}
        return form_config.get('fields', [])

    def get_related_jobs(self, obj):
        """Return up to 3 related jobs in the same category."""
        if not obj.job.category:
            return []

        related = JobListing.objects.filter(
            job__category=obj.job.category,
            job__status='open',
            published_at__isnull=False
        ).exclude(
            id=obj.id
        ).exclude(
            expires_at__lt=timezone.now()
        ).order_by('-is_featured', '-published_at')[:3]

        return JobListingPublicSerializer(
            related, many=True, context=self.context
        ).data


class JobListingAdminSerializer(serializers.ModelSerializer):
    """
    Admin job listing serializer with full analytics.
    For tenant administrators managing listings.
    """
    job_title = serializers.CharField(source='job.title', read_only=True)
    job_status = serializers.CharField(source='job.status', read_only=True)
    job_reference = serializers.CharField(source='job.reference_code', read_only=True)
    analytics = serializers.SerializerMethodField()
    funnel_metrics = serializers.SerializerMethodField()

    class Meta:
        model = JobListing
        fields = [
            'id', 'job', 'job_title', 'job_status', 'job_reference',
            'custom_slug',
            'show_company_name', 'show_department', 'show_team_size',
            'show_application_count', 'application_count_threshold',
            'custom_application_form',
            'is_featured', 'feature_priority',
            'view_count', 'apply_click_count',
            'published_at', 'expires_at',
            'analytics', 'funnel_metrics',
        ]
        read_only_fields = ['view_count', 'apply_click_count', 'analytics', 'funnel_metrics']

    def get_analytics(self, obj):
        """Detailed analytics for the job listing."""
        applications = obj.public_applications.all()
        now = timezone.now()
        seven_days_ago = now - timezone.timedelta(days=7)
        thirty_days_ago = now - timezone.timedelta(days=30)

        return {
            'total_views': obj.view_count,
            'total_clicks': obj.apply_click_count,
            'total_applications': applications.count(),
            'applications_last_7_days': applications.filter(
                submitted_at__gte=seven_days_ago
            ).count(),
            'applications_last_30_days': applications.filter(
                submitted_at__gte=thirty_days_ago
            ).count(),
            'pending_applications': applications.filter(status='pending').count(),
            'processed_applications': applications.filter(status='processed').count(),
            'click_through_rate': self._calculate_ctr(obj),
            'application_rate': self._calculate_application_rate(obj),
        }

    def get_funnel_metrics(self, obj):
        """Conversion funnel metrics."""
        views = obj.view_count or 1
        clicks = obj.apply_click_count
        applications = obj.public_applications.filter(
            status__in=['pending', 'processed']
        ).count()

        return {
            'views': views,
            'clicks': clicks,
            'applications': applications,
            'view_to_click_rate': round((clicks / views) * 100, 2),
            'click_to_apply_rate': round((applications / max(clicks, 1)) * 100, 2),
            'view_to_apply_rate': round((applications / views) * 100, 2),
        }

    def _calculate_ctr(self, obj):
        """Calculate click-through rate."""
        if not obj.view_count:
            return 0
        return round((obj.apply_click_count / obj.view_count) * 100, 2)

    def _calculate_application_rate(self, obj):
        """Calculate application rate from clicks."""
        if not obj.apply_click_count:
            return 0
        applications = obj.public_applications.filter(
            status__in=['pending', 'processed']
        ).count()
        return round((applications / obj.apply_click_count) * 100, 2)


# ==================== APPLICATION SERIALIZERS ====================

class PublicApplicationSerializer(serializers.ModelSerializer):
    """
    Public application serializer for job seekers.
    Handles application submission without authentication.
    """
    # UTM tracking fields (write-only, captured from request)
    utm_source = serializers.CharField(max_length=100, required=False, write_only=True)
    utm_medium = serializers.CharField(max_length=100, required=False, write_only=True)
    utm_campaign = serializers.CharField(max_length=100, required=False, write_only=True)
    referrer = serializers.URLField(required=False, write_only=True)

    class Meta:
        model = PublicApplication
        fields = [
            'uuid', 'job_listing',
            'first_name', 'last_name', 'email', 'phone',
            'resume', 'cover_letter', 'custom_answers',
            'linkedin_url', 'portfolio_url',
            'privacy_consent', 'marketing_consent',
            'utm_source', 'utm_medium', 'utm_campaign', 'referrer',
            'submitted_at',
        ]
        read_only_fields = ['uuid', 'submitted_at']
        extra_kwargs = {
            'resume': {'required': True},
            'privacy_consent': {'required': True},
        }

    def validate_privacy_consent(self, value):
        """Ensure privacy consent is given."""
        if not value:
            raise serializers.ValidationError(
                _("You must agree to the privacy policy to submit your application.")
            )
        return value

    def validate_job_listing(self, value):
        """Validate job listing is active and accepting applications."""
        if value:
            if value.is_expired:
                raise serializers.ValidationError(
                    _("This job posting has expired and is no longer accepting applications.")
                )
            if value.job.status != 'open':
                raise serializers.ValidationError(
                    _("This job is not currently accepting applications.")
                )
        return value

    def validate(self, attrs):
        """Cross-field validation."""
        job_listing = attrs.get('job_listing')

        # Check if resume is required
        if job_listing and job_listing.job.require_resume:
            if not attrs.get('resume'):
                raise serializers.ValidationError({
                    'resume': _("A resume is required for this position.")
                })

        # Check if cover letter is required
        if job_listing and job_listing.job.require_cover_letter:
            if not attrs.get('cover_letter'):
                raise serializers.ValidationError({
                    'cover_letter': _("A cover letter is required for this position.")
                })

        # Validate custom questions if defined
        if job_listing and job_listing.custom_application_form:
            required_fields = job_listing.custom_application_form.get('required_fields', [])
            custom_answers = attrs.get('custom_answers', {})
            for field in required_fields:
                if field not in custom_answers or not custom_answers[field]:
                    raise serializers.ValidationError({
                        'custom_answers': _(f"Please answer the required question: {field}")
                    })

        return attrs

    def create(self, validated_data):
        """Create application with tracking data."""
        request = self.context.get('request')

        # Capture IP address
        if request:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                validated_data['ip_address'] = x_forwarded_for.split(',')[0].strip()
            else:
                validated_data['ip_address'] = request.META.get('REMOTE_ADDR')

            # Capture user agent
            validated_data['user_agent'] = request.META.get('HTTP_USER_AGENT', '')

            # Capture consent timestamp and IP
            validated_data['consent_timestamp'] = timezone.now()
            validated_data['consent_ip'] = validated_data['ip_address']

        # Increment apply click count on job listing
        job_listing = validated_data.get('job_listing')
        if job_listing:
            job_listing.apply_click_count += 1
            job_listing.save(update_fields=['apply_click_count'])

        return super().create(validated_data)


class PublicApplicationStatusSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for application status tracking.
    Allows candidates to check their application status.
    """
    job_title = serializers.SerializerMethodField()
    company_name = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display')

    class Meta:
        model = PublicApplication
        fields = [
            'uuid', 'job_title', 'company_name',
            'status', 'status_display',
            'submitted_at', 'processed_at',
        ]
        read_only_fields = fields

    def get_job_title(self, obj):
        if obj.job_listing:
            return obj.job_listing.job.title
        return 'General Application'

    def get_company_name(self, obj):
        # Return company name if available
        return None  # Extend based on tenant/company model


# ==================== TALENT POOL SERIALIZERS ====================

class CandidateMinimalSerializer(serializers.ModelSerializer):
    """Minimal candidate info for talent pool display."""
    full_name = serializers.CharField(read_only=True)

    class Meta:
        model = Candidate
        fields = [
            'uuid', 'full_name', 'email', 'headline',
            'current_company', 'current_title',
            'city', 'country', 'skills',
        ]


class TalentPoolMemberSerializer(serializers.ModelSerializer):
    """Talent pool member serializer."""
    candidate = CandidateMinimalSerializer(read_only=True)
    candidate_id = serializers.PrimaryKeyRelatedField(
        queryset=Candidate.objects.all(),
        source='candidate',
        write_only=True
    )
    added_by_name = serializers.SerializerMethodField()

    class Meta:
        model = TalentPoolMember
        fields = [
            'id', 'pool', 'candidate', 'candidate_id',
            'added_by', 'added_by_name', 'added_at', 'notes',
        ]
        read_only_fields = ['id', 'added_at', 'added_by', 'added_by_name']

    def get_added_by_name(self, obj):
        if obj.added_by:
            return obj.added_by.get_full_name() or obj.added_by.email
        return None

    def create(self, validated_data):
        """Set added_by from request user."""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['added_by'] = request.user
        return super().create(validated_data)


class TalentPoolSerializer(serializers.ModelSerializer):
    """Talent pool serializer for admin management."""
    member_count = serializers.SerializerMethodField()
    created_by_name = serializers.SerializerMethodField()

    class Meta:
        model = TalentPool
        fields = [
            'id', 'uuid', 'name', 'description',
            'is_public', 'auto_add_criteria',
            'created_by', 'created_by_name',
            'member_count',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'uuid', 'created_by', 'created_at', 'updated_at']

    def get_member_count(self, obj):
        return obj.members.count()

    def get_created_by_name(self, obj):
        if obj.created_by:
            return obj.created_by.get_full_name() or obj.created_by.email
        return None

    def create(self, validated_data):
        """Set created_by from request user."""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['created_by'] = request.user
        return super().create(validated_data)


class TalentPoolDetailSerializer(TalentPoolSerializer):
    """Detailed talent pool with members list."""
    members = TalentPoolMemberSerializer(many=True, read_only=True)

    class Meta(TalentPoolSerializer.Meta):
        fields = TalentPoolSerializer.Meta.fields + ['members']


# =============================================================================
# PUBLIC JOB CATALOG SERIALIZERS
# =============================================================================

class PublicJobCatalogListSerializer(serializers.ModelSerializer):
    """
    Serializer for public job catalog list view.
    Lightweight for browse/search performance.
    """
    
    tenant_url = serializers.SerializerMethodField()
    public_url = serializers.SerializerMethodField()
    
    class Meta:
        model = PublicJobCatalog
        fields = [
            'job_id',
            'title',
            'company_name',
            'location',
            'job_type',
            'is_remote',
            'salary_min',
            'salary_max',
            'salary_currency',
            'show_salary',
            'category_name',
            'category_slug',
            'is_featured',
            'published_at',
            'expires_at',
            'view_count',
            'application_count',
            'tenant_url',
            'public_url',
        ]
        
    def get_tenant_url(self, obj):
        """Get URL to view job on tenant subdomain"""
        return obj.get_tenant_job_url()
    
    def get_public_url(self, obj):
        """Get public URL to view job"""
        return obj.get_public_url()


class PublicJobCatalogDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for public job catalog detail view.
    Includes full description and all details.
    """
    
    tenant_url = serializers.SerializerMethodField()
    public_url = serializers.SerializerMethodField()
    tenant_name = serializers.CharField(source='tenant.name', read_only=True)
    tenant_schema = serializers.CharField(source='tenant_schema_name', read_only=True)
    
    class Meta:
        model = PublicJobCatalog
        fields = [
            'job_id',
            'tenant_schema',
            'tenant_name',
            'title',
            'description',
            'company_name',
            'company_logo',
            'location',
            'job_type',
            'is_remote',
            'salary_min',
            'salary_max',
            'salary_currency',
            'show_salary',
            'category_name',
            'category_slug',
            'is_featured',
            'is_active',
            'published_at',
            'expires_at',
            'view_count',
            'application_count',
            'created_at',
            'updated_at',
            'tenant_url',
            'public_url',
        ]
        
    def get_tenant_url(self, obj):
        """Get URL to view job on tenant subdomain"""
        return obj.get_tenant_job_url()
    
    def get_public_url(self, obj):
        """Get public URL to view job"""
        return obj.get_public_url()
