"""
Jobs Public Catalog API Serializers.

Serializers for PublicJobCatalog model with all fields for API responses.
"""

from rest_framework import serializers
from jobs_public.models import PublicJobCatalog


class PublicJobCatalogListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for job list views.

    Includes only essential fields for performance.
    """

    location = serializers.SerializerMethodField()
    salary = serializers.SerializerMethodField()
    days_until_expiration = serializers.SerializerMethodField()

    class Meta:
        model = PublicJobCatalog
        fields = [
            'id',
            'jobposting_uuid',
            'title',
            'company_name',
            'company_logo_url',
            'employment_type',
            'location',
            'is_remote',
            'salary',
            'experience_level',
            'is_featured',
            'published_at',
            'days_until_expiration',
            'view_count',
            'application_count',
        ]

    def get_location(self, obj):
        """Get formatted location data."""
        return {
            'city': obj.location_city,
            'state': obj.location_state,
            'country': obj.location_country,
            'display': obj.location_display,
            'is_remote': obj.is_remote,
        }

    def get_salary(self, obj):
        """Get formatted salary data."""
        return {
            'min': float(obj.salary_min) if obj.salary_min else None,
            'max': float(obj.salary_max) if obj.salary_max else None,
            'currency': obj.salary_currency,
            'period': obj.salary_period,
            'display': obj.salary_display,
        }

    def get_days_until_expiration(self, obj):
        """Calculate days until job expires."""
        if not obj.expiration_date:
            return None

        from django.utils import timezone
        delta = obj.expiration_date - timezone.now()
        return delta.days if delta.days >= 0 else 0


class PublicJobCatalogDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for job detail views.

    Includes all fields including rich content, company info, and media.
    """

    location = serializers.SerializerMethodField()
    salary = serializers.SerializerMethodField()
    company_info = serializers.SerializerMethodField()
    job_overview = serializers.SerializerMethodField()
    rich_content = serializers.SerializerMethodField()
    media = serializers.SerializerMethodField()
    days_until_expiration = serializers.SerializerMethodField()

    class Meta:
        model = PublicJobCatalog
        fields = [
            'id',
            'jobposting_uuid',
            'title',
            'description_html',
            'company_name',
            'company_logo_url',
            'employment_type',
            'location',
            'salary',
            'company_info',
            'job_overview',
            'rich_content',
            'media',
            'category_names',
            'category_slugs',
            'required_skills',
            'is_featured',
            'is_active',
            'is_expired',
            'published_at',
            'expiration_date',
            'days_until_expiration',
            'view_count',
            'application_count',
            'application_url',
        ]

    def get_location(self, obj):
        """Get formatted location data with geocoding."""
        return {
            'city': obj.location_city,
            'state': obj.location_state,
            'country': obj.location_country,
            'display': obj.location_display,
            'is_remote': obj.is_remote,
            'coordinates': {
                'lat': obj.latitude,
                'lng': obj.longitude,
            } if obj.latitude and obj.longitude else None,
        }

    def get_salary(self, obj):
        """Get formatted salary data."""
        return {
            'min': float(obj.salary_min) if obj.salary_min else None,
            'max': float(obj.salary_max) if obj.salary_max else None,
            'currency': obj.salary_currency,
            'period': obj.salary_period,
            'show_salary': obj.show_salary,
            'display': obj.salary_display,
        }

    def get_company_info(self, obj):
        """Get company information."""
        return {
            'name': obj.company_name,
            'logo_url': obj.company_logo_url,
            'rating': float(obj.company_rating) if obj.company_rating else None,
            'established_date': obj.company_established_date,
            'industry': obj.company_industry,
            'size': obj.company_size,
            'social_links': {
                'website': obj.company_website,
                'linkedin': obj.company_linkedin,
                'twitter': obj.company_twitter,
                'facebook': obj.company_facebook,
                'instagram': obj.company_instagram,
                'pinterest': obj.company_pinterest,
            },
        }

    def get_job_overview(self, obj):
        """Get job overview details."""
        return {
            'experience_level': obj.experience_level,
            'hours_per_week': obj.hours_per_week,
            'years_of_experience': obj.years_of_experience,
            'english_level': obj.english_level,
        }

    def get_rich_content(self, obj):
        """Get rich content lists."""
        return {
            'responsibilities': obj.responsibilities_list,
            'requirements': obj.requirements_list,
            'qualifications': obj.qualifications_list,
            'benefits': obj.benefits_list,
        }

    def get_media(self, obj):
        """Get media content."""
        return {
            'image_gallery': obj.image_gallery,
            'video_url': obj.video_url,
        }

    def get_days_until_expiration(self, obj):
        """Calculate days until job expires."""
        if not obj.expiration_date:
            return None

        from django.utils import timezone
        delta = obj.expiration_date - timezone.now()
        return delta.days if delta.days >= 0 else 0


class PublicJobCatalogMapSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for map markers.

    Includes only fields needed for map display (location, basic info).
    Optimized for performance when loading many markers.
    """

    location = serializers.SerializerMethodField()
    salary_display = serializers.CharField(read_only=True)

    class Meta:
        model = PublicJobCatalog
        fields = [
            'id',
            'jobposting_uuid',
            'title',
            'company_name',
            'employment_type',
            'location',
            'salary_display',
            'is_remote',
        ]

    def get_location(self, obj):
        """Get location with coordinates for map markers."""
        return {
            'lat': obj.latitude,
            'lng': obj.longitude,
            'display': obj.location_display,
        }
