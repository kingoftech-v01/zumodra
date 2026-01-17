"""
Provider Public Sync Service

Handles synchronization of ServiceProvider instances to PublicProviderCatalog.

This module implements bidirectional sync:
- When provider.marketplace_enabled = True → sync to public catalog
- When provider.marketplace_enabled = False → remove from catalog
- On provider update → re-sync if conditions met
- On provider delete → remove from catalog

Security:
- Never syncs: user emails, phone numbers, bank accounts, Stripe data
- Conditional sync: only if marketplace_enabled=True and is_active=True
- Sanitizes HTML in bio and other text fields
- Denormalizes categories and skills as JSON for efficient querying

Usage:
    from core.sync.provider_sync import ProviderPublicSyncService

    sync_service = ProviderPublicSyncService()

    # Sync a provider
    if sync_service.should_sync(provider):
        catalog_entry = sync_service.sync_to_public(provider)

    # Remove from catalog
    removed_count = sync_service.remove_from_public(provider)
"""

from typing import Dict, Any, List, Optional
import logging

from core.sync.base import PublicSyncService

logger = logging.getLogger(__name__)


class ProviderPublicSyncService(PublicSyncService):
    """
    Sync service for ServiceProvider → PublicProviderCatalog.

    Handles mapping of provider data to public catalog, including:
    - Profile information (name, bio, tagline)
    - Media URLs (avatar, cover image)
    - Location data
    - Categories and skills (denormalized as JSON)
    - Statistics (ratings, reviews, completed jobs)
    - Availability and verification status

    Attributes:
        public_model: PublicProviderCatalog model class
        tenant_model: ServiceProvider model class
        field_mapping: Dict mapping catalog fields to provider fields/callables
        sync_conditions: List of condition callables that must all return True
    """

    def __init__(self):
        """Initialize provider sync service with models and field mapping."""
        from tenants.models import PublicProviderCatalog
        from services.models import ServiceProvider

        self.public_model = PublicProviderCatalog
        self.tenant_model = ServiceProvider

        # Field mapping: {catalog_field: provider_field_or_callable}
        self.field_mapping = {
            # Identity
            'uuid': 'uuid',
            'provider_uuid': 'uuid',

            # Profile
            'display_name': lambda p: p.display_name or p.user.get_full_name() or p.user.email.split('@')[0],
            'provider_type': 'provider_type',
            'bio': lambda p: self.sanitize_html(p.bio) if p.bio else '',
            'tagline': 'tagline',

            # Media URLs (safe - public accessible)
            'avatar_url': lambda p: self._get_avatar_url(p),
            'cover_image_url': lambda p: self._get_cover_image_url(p),

            # Location
            'city': lambda p: getattr(p, 'city', ''),
            'state': lambda p: getattr(p, 'state', ''),
            'country': lambda p: getattr(p, 'country', ''),
            'location': lambda p: self._get_location_data(p),

            # Categories & Skills (denormalized as JSON)
            'category_names': lambda p: self._get_category_names(p),
            'category_slugs': lambda p: self._get_category_slugs(p),
            'skills_data': lambda p: self._get_skills_data(p),

            # Pricing
            'hourly_rate': lambda p: p.hourly_rate if hasattr(p, 'hourly_rate') and p.hourly_rate else None,
            'minimum_budget': lambda p: p.minimum_budget if hasattr(p, 'minimum_budget') and p.minimum_budget else None,
            'currency': lambda p: getattr(p, 'currency', 'USD'),

            # Statistics
            'rating_avg': lambda p: self._get_rating_avg(p),
            'total_reviews': lambda p: self._get_total_reviews(p),
            'completed_jobs_count': lambda p: self._get_completed_jobs_count(p),
            'response_rate': lambda p: self._get_response_rate(p),
            'avg_response_time_hours': lambda p: self._get_avg_response_time(p),

            # Availability & Status
            'availability_status': lambda p: getattr(p, 'availability_status', 'available'),
            'is_verified': lambda p: getattr(p.user, 'is_verified', False) if hasattr(p, 'user') else False,
            'is_featured': lambda p: getattr(p, 'is_featured', False),
            'is_accepting_projects': lambda p: getattr(p, 'is_accepting_projects', True),

            # Work Preferences
            'can_work_remotely': lambda p: getattr(p, 'can_work_remotely', True),
            'can_work_onsite': lambda p: getattr(p, 'can_work_onsite', False),

            # Sync Metadata
            'published_at': lambda p: p.created_at if hasattr(p, 'created_at') else None,
        }

        # Sync conditions - ALL must be True for sync to occur
        self.sync_conditions = [
            lambda p: getattr(p, 'marketplace_enabled', False) == True,
            lambda p: getattr(p, 'is_active', False) == True,
            lambda p: hasattr(p, 'user') and p.user.is_active == True,
        ]

    # =====================================================================
    # Helper Methods - Extract Complex Data
    # =====================================================================

    def _get_avatar_url(self, provider) -> str:
        """Get provider's avatar URL (from profile or default)."""
        try:
            if hasattr(provider, 'user') and hasattr(provider.user, 'profile'):
                profile = provider.user.profile
                if hasattr(profile, 'avatar') and profile.avatar:
                    return profile.avatar.url
        except Exception as e:
            logger.debug(f"Could not get avatar URL for provider {provider.uuid}: {e}")
        return ''

    def _get_cover_image_url(self, provider) -> str:
        """Get provider's cover image URL."""
        try:
            if hasattr(provider, 'cover_image') and provider.cover_image:
                return provider.cover_image.url
        except Exception as e:
            logger.debug(f"Could not get cover image URL for provider {provider.uuid}: {e}")
        return ''

    def _get_location_data(self, provider) -> Optional[Dict[str, Any]]:
        """Get full location data as GeoJSON Point or None for PostGIS field."""
        try:
            # For PostGIS PointField, return the Point object directly (not dict)
            # PublicProviderCatalog.location expects a Point, not a dict
            if hasattr(provider, 'location') and provider.location:
                return provider.location
            # Fallback: try to construct Point from lat/lng if available
            elif hasattr(provider, 'location_lat') and hasattr(provider, 'location_lng'):
                if provider.location_lat and provider.location_lng:
                    from django.contrib.gis.geos import Point
                    return Point(provider.location_lng, provider.location_lat, srid=4326)
            return None
        except Exception as e:
            logger.debug(f"Could not get location data for provider {provider.uuid}: {e}")
            return None

    def _get_category_names(self, provider) -> List[str]:
        """Get list of category names the provider operates in."""
        try:
            categories = []
            if hasattr(provider, 'categories') and provider.categories:
                # If it's a ManyToMany relationship
                if hasattr(provider.categories, 'all'):
                    categories = [cat.name for cat in provider.categories.all()]
                # If it's already a list
                elif isinstance(provider.categories, list):
                    categories = [cat.name for cat in provider.categories]
            return categories
        except Exception as e:
            logger.debug(f"Could not get category names for provider {provider.uuid}: {e}")
            return []

    def _get_category_slugs(self, provider) -> List[str]:
        """Get list of category slugs for filtering."""
        try:
            slugs = []
            if hasattr(provider, 'categories') and provider.categories:
                if hasattr(provider.categories, 'all'):
                    slugs = [cat.slug for cat in provider.categories.all()]
                elif isinstance(provider.categories, list):
                    slugs = [cat.slug for cat in provider.categories]
            return slugs
        except Exception as e:
            logger.debug(f"Could not get category slugs for provider {provider.uuid}: {e}")
            return []

    def _get_skills_data(self, provider) -> List[Dict[str, Any]]:
        """
        Get skills data as array of objects: [{name, level, years_experience}].

        Returns:
            List of skill dicts with name, proficiency level, and years of experience
        """
        try:
            skills_data = []

            # Check if provider has skills relationship
            if hasattr(provider, 'skills') and provider.skills:
                if hasattr(provider.skills, 'all'):
                    for skill in provider.skills.all():
                        skill_dict = {'name': skill.name}

                        # Check for proficiency level
                        if hasattr(skill, 'level'):
                            skill_dict['level'] = skill.level

                        # Check for years of experience
                        if hasattr(skill, 'years_experience'):
                            skill_dict['years_experience'] = skill.years_experience

                        skills_data.append(skill_dict)

            # Fallback: check for simple skills array/list
            elif hasattr(provider, 'skills_list'):
                if isinstance(provider.skills_list, list):
                    skills_data = [{'name': skill} for skill in provider.skills_list]

            return skills_data
        except Exception as e:
            logger.debug(f"Could not get skills data for provider {provider.uuid}: {e}")
            return []

    def _get_rating_avg(self, provider) -> Optional[float]:
        """Get average rating from reviews."""
        try:
            if hasattr(provider, 'rating_avg') and provider.rating_avg:
                return float(provider.rating_avg)

            # Calculate from reviews if not cached
            if hasattr(provider, 'reviews'):
                from django.db.models import Avg
                result = provider.reviews.aggregate(avg=Avg('rating'))
                return float(result['avg']) if result['avg'] else None
        except Exception as e:
            logger.debug(f"Could not get rating avg for provider {provider.uuid}: {e}")
        return None

    def _get_total_reviews(self, provider) -> int:
        """Get total number of reviews."""
        try:
            if hasattr(provider, 'total_reviews'):
                return int(provider.total_reviews)

            if hasattr(provider, 'reviews'):
                return provider.reviews.count()
        except Exception as e:
            logger.debug(f"Could not get total reviews for provider {provider.uuid}: {e}")
        return 0

    def _get_completed_jobs_count(self, provider) -> int:
        """Get number of completed jobs/contracts."""
        try:
            if hasattr(provider, 'completed_jobs_count'):
                return int(provider.completed_jobs_count)

            # Calculate from contracts if available
            if hasattr(provider, 'contracts'):
                return provider.contracts.filter(status='completed').count()
        except Exception as e:
            logger.debug(f"Could not get completed jobs count for provider {provider.uuid}: {e}")
        return 0

    def _get_response_rate(self, provider) -> Optional[float]:
        """Get response rate percentage."""
        try:
            if hasattr(provider, 'response_rate') and provider.response_rate:
                return float(provider.response_rate)
        except Exception as e:
            logger.debug(f"Could not get response rate for provider {provider.uuid}: {e}")
        return None

    def _get_avg_response_time(self, provider) -> Optional[int]:
        """Get average response time in hours."""
        try:
            if hasattr(provider, 'avg_response_time_hours') and provider.avg_response_time_hours:
                return int(provider.avg_response_time_hours)
        except Exception as e:
            logger.debug(f"Could not get avg response time for provider {provider.uuid}: {e}")
        return None
