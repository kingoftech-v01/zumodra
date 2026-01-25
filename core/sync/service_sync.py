"""
Service Public Sync Service.

Handles synchronization of Service instances to PublicService catalog.

This module implements bidirectional sync:
- When service.is_public = True and is_active = True → sync to public catalog
- When service.is_public = False or is_active = False → remove from catalog
- On service update → re-sync if conditions met
- On service delete → remove from catalog
- On related data change (images, pricing tiers) → re-sync parent service

Security:
    - Never syncs: sensitive user data, payment information
    - Conditional sync: only if is_public=True, is_active=True, provider.marketplace_enabled=True
    - Sanitizes HTML in description and other text fields
    - Denormalizes provider data, categories, tags as JSON for efficient querying

Usage:
    from core.sync.service_sync import ServicePublicSyncService

    sync_service = ServicePublicSyncService()

    # Sync a service
    if sync_service.should_sync(service):
        catalog_entry = sync_service.sync_to_public(service)

    # Remove from catalog
    removed_count = sync_service.remove_from_public(service)
"""

from typing import Dict, Any, List, Optional
import logging
from decimal import Decimal

from django.db import connection
from django.utils import timezone

from core.sync.base import PublicSyncService

logger = logging.getLogger(__name__)


class ServicePublicSyncService(PublicSyncService):
    """
    Sync service for Service → PublicService catalog.

    Handles mapping of service data to public catalog, including:
    - Service information (name, description, pricing)
    - Provider information (denormalized)
    - Category and tags (denormalized as JSON)
    - Location data (from provider)
    - Statistics (ratings, reviews, view count)
    - Related data (images, pricing tiers, portfolio)

    Attributes:
        public_model: PublicService model class
        tenant_model: Service model class
        field_mapping: Dict mapping catalog fields to service fields/callables
        sync_conditions: List of condition callables that must all return True
    """

    def __init__(self):
        """Initialize service sync service with models and field mapping."""
        from services_public.models import PublicService
        from services.models import Service

        self.public_model = PublicService
        self.tenant_model = Service

        # Field mapping: {catalog_field: service_field_or_callable}
        self.field_mapping = {
            # ===== Identity =====
            'service_uuid': 'uuid',

            # ===== Source Tenant Info =====
            'tenant_id': lambda s: self._get_tenant_id(),
            'tenant_schema_name': lambda s: connection.schema_name,

            # ===== Service Core Data =====
            'name': 'name',
            'slug': 'slug',
            'description': lambda s: self.sanitize_html(s.description) if s.description else '',
            'short_description': lambda s: s.short_description or '',

            # ===== Provider Info (Denormalized) =====
            'provider_uuid': lambda s: s.provider.uuid,
            'provider_name': lambda s: self._get_provider_name(s),
            'provider_avatar_url': lambda s: self._get_provider_avatar(s),
            'provider_type': lambda s: getattr(s.provider, 'provider_type', ''),
            'provider_rating_avg': lambda s: self._get_provider_rating_avg(s),
            'provider_total_reviews': lambda s: getattr(s.provider, 'total_reviews', 0),
            'provider_completed_jobs_count': lambda s: getattr(s.provider, 'completed_jobs_count', 0),

            # ===== Category =====
            'category_name': lambda s: s.category.name if s.category else '',
            'category_slug': lambda s: s.category.slug if s.category else '',
            'category_full_path': lambda s: self._get_category_full_path(s),

            # ===== Pricing =====
            'service_type': 'service_type',
            'price': lambda s: s.price if s.price else None,
            'price_min': lambda s: s.price_min if s.price_min else None,
            'price_max': lambda s: s.price_max if s.price_max else None,
            'currency': lambda s: s.currency or 'CAD',

            # ===== Delivery =====
            'delivery_type': 'delivery_type',
            'duration_days': lambda s: s.duration_days if hasattr(s, 'duration_days') else None,
            'revisions_included': lambda s: s.revisions_included if hasattr(s, 'revisions_included') else 1,

            # ===== Media =====
            'thumbnail_url': lambda s: self._get_thumbnail_url(s),
            'video_url': lambda s: s.video_url if hasattr(s, 'video_url') and s.video_url else '',

            # ===== Tags (Denormalized) =====
            'tags_list': lambda s: self._get_tags_list(s),

            # ===== Services Offered List =====
            'services_list': lambda s: self._get_services_list(s),

            # ===== Location (from Provider) =====
            'location_city': lambda s: getattr(s.provider, 'city', ''),
            'location_state': lambda s: getattr(s.provider, 'state', ''),
            'location_country': lambda s: getattr(s.provider, 'country', ''),
            'location': lambda s: self._get_location(s),

            # ===== Rating Stats =====
            'rating_avg': lambda s: self._calculate_service_rating_avg(s),
            'total_reviews': lambda s: self._calculate_service_total_reviews(s),
            'rating_breakdown': lambda s: self._calculate_rating_breakdown(s),

            # ===== Status =====
            'is_active': lambda s: s.is_active if hasattr(s, 'is_active') else True,
            'is_featured': lambda s: s.is_featured if hasattr(s, 'is_featured') else False,
            'provider_is_verified': lambda s: getattr(s.provider, 'is_verified', False),
            'provider_availability_status': lambda s: getattr(s.provider, 'availability_status', 'available'),

            # ===== Stats =====
            'view_count': lambda s: s.view_count if hasattr(s, 'view_count') else 0,
            'order_count': lambda s: s.order_count if hasattr(s, 'order_count') else 0,

            # ===== Metadata =====
            'published_at': lambda s: self._get_published_at(s),

            # ===== Booking URLs =====
            'booking_url': lambda s: self._generate_booking_url(s),
            'detail_url': lambda s: self._generate_detail_url(s),
        }

        # ALL conditions must be True for sync to proceed
        self.sync_conditions = [
            lambda s: getattr(s, 'is_public', False) is True,
            lambda s: getattr(s, 'is_active', False) is True,
            lambda s: hasattr(s, 'provider') and s.provider is not None,
            lambda s: getattr(s.provider, 'marketplace_enabled', False) is True,
            lambda s: getattr(s.provider, 'is_active', False) is True,
            lambda s: s.provider.user.is_active is True,
        ]

        super().__init__()

    # =========================================================================
    # HELPER METHODS FOR COMPLEX FIELD EXTRACTION
    # =========================================================================

    def _get_tenant_id(self) -> int:
        """Get current tenant ID from connection."""
        from tenants.models import Tenant
        try:
            tenant = Tenant.objects.get(schema_name=connection.schema_name)
            return tenant.id
        except Tenant.DoesNotExist:
            logger.error(f"Tenant not found for schema: {connection.schema_name}")
            return 0

    def _get_provider_name(self, service) -> str:
        """Extract provider display name safely."""
        try:
            if hasattr(service.provider, 'display_name') and service.provider.display_name:
                return service.provider.display_name
            elif hasattr(service.provider.user, 'get_full_name'):
                return service.provider.user.get_full_name()
            elif hasattr(service.provider.user, 'email'):
                return service.provider.user.email.split('@')[0]
        except Exception as e:
            logger.debug(f"Could not get provider name: {e}")
        return "Provider"

    def _get_provider_avatar(self, service) -> str:
        """Extract provider avatar URL safely."""
        try:
            if hasattr(service.provider, 'avatar') and service.provider.avatar:
                return service.provider.avatar.url
        except Exception as e:
            logger.debug(f"Could not get provider avatar: {e}")
        return ''

    def _get_provider_rating_avg(self, service) -> Optional[Decimal]:
        """Extract provider's average rating."""
        try:
            if hasattr(service.provider, 'rating_avg') and service.provider.rating_avg:
                return Decimal(str(service.provider.rating_avg))
        except Exception as e:
            logger.debug(f"Could not get provider rating: {e}")
        return None

    def _get_category_full_path(self, service) -> str:
        """Get full category hierarchy path."""
        try:
            if service.category and hasattr(service.category, 'full_path'):
                return service.category.full_path
            elif service.category:
                return service.category.name
        except Exception as e:
            logger.debug(f"Could not get category path: {e}")
        return ''

    def _get_thumbnail_url(self, service) -> str:
        """Extract service thumbnail URL safely."""
        try:
            if hasattr(service, 'thumbnail') and service.thumbnail:
                return service.thumbnail.url
        except Exception as e:
            logger.debug(f"Could not get thumbnail: {e}")
        return ''

    def _get_tags_list(self, service) -> List[str]:
        """
        Extract tags as list of strings.

        Returns:
            ['Python', 'Django', 'React', ...]
        """
        try:
            if hasattr(service, 'tags') and service.tags:
                return [tag.name for tag in service.tags.all()]
        except Exception as e:
            logger.debug(f"Could not get tags: {e}")
        return []

    def _get_services_list(self, service) -> List[str]:
        """
        Extract list of services offered.

        This could come from a specific field or be parsed from description.
        For now, returns empty list - can be enhanced based on data structure.
        """
        # TODO: Implement based on how services_list is stored in tenant
        # Options:
        # 1. Parse from description
        # 2. Use a dedicated JSONField
        # 3. Use a related model
        return []

    def _get_location(self, service):
        """
        Get PostGIS Point from provider location.

        Returns:
            Point object or None
        """
        try:
            if hasattr(service.provider, 'location') and service.provider.location:
                return service.provider.location
            # Fallback: construct from lat/lng if available
            if hasattr(service.provider, 'location_lat') and hasattr(service.provider, 'location_lng'):
                if service.provider.location_lat and service.provider.location_lng:
                    from django.contrib.gis.geos import Point
                    return Point(
                        float(service.provider.location_lng),
                        float(service.provider.location_lat),
                        srid=4326
                    )
        except Exception as e:
            logger.debug(f"Could not get location: {e}")
        return None

    def _calculate_service_rating_avg(self, service) -> Optional[Decimal]:
        """
        Calculate average rating from SERVICE reviews.

        This aggregates reviews for this specific service, not provider-wide.
        """
        try:
            from django.db.models import Avg
            # Assuming reviews are linked via contracts
            # Adjust query based on actual review model structure
            if hasattr(service, 'contracts'):
                from services.models import ServiceReview
                reviews = ServiceReview.objects.filter(
                    contract__service=service,
                    contract__status='completed'
                )
                result = reviews.aggregate(avg=Avg('rating'))
                if result['avg']:
                    return Decimal(str(result['avg']))
        except Exception as e:
            logger.debug(f"Could not calculate service rating: {e}")
        return None

    def _calculate_service_total_reviews(self, service) -> int:
        """Calculate total number of reviews for this service."""
        try:
            if hasattr(service, 'contracts'):
                from services.models import ServiceReview
                return ServiceReview.objects.filter(
                    contract__service=service,
                    contract__status='completed'
                ).count()
        except Exception as e:
            logger.debug(f"Could not count service reviews: {e}")
        return 0

    def _calculate_rating_breakdown(self, service) -> Dict[str, int]:
        """
        Calculate 5-star rating breakdown as percentages.

        Returns:
            {'5': 70, '4': 20, '3': 10, '2': 0, '1': 0}
        """
        try:
            from django.db.models import Count
            from services.models import ServiceReview

            reviews = ServiceReview.objects.filter(
                contract__service=service,
                contract__status='completed'
            )

            total = reviews.count()
            if total == 0:
                return {'5': 0, '4': 0, '3': 0, '2': 0, '1': 0}

            breakdown_counts = reviews.values('rating').annotate(count=Count('rating'))

            percentages = {}
            for rating in range(1, 6):
                count = next((b['count'] for b in breakdown_counts if b['rating'] == rating), 0)
                percentages[str(rating)] = round((count / total) * 100)

            return percentages

        except Exception as e:
            logger.debug(f"Could not calculate rating breakdown: {e}")
            return {'5': 0, '4': 0, '3': 0, '2': 0, '1': 0}

    def _get_published_at(self, service):
        """Get publication timestamp."""
        try:
            if hasattr(service, 'catalog_synced_at') and service.catalog_synced_at:
                return service.catalog_synced_at
            elif hasattr(service, 'created_at'):
                return service.created_at
        except Exception as e:
            logger.debug(f"Could not get published_at: {e}")
        return timezone.now()

    def _generate_booking_url(self, service) -> str:
        """
        Generate booking URL that redirects to tenant domain.

        Format: https://{tenant_domain}/services/{service_uuid}/book/

        This ensures users are authenticated in tenant context before booking.
        """
        try:
            from tenants.models import Tenant
            tenant = Tenant.objects.get(schema_name=connection.schema_name)

            # Use custom domain if configured, otherwise use tenant subdomain
            if hasattr(tenant, 'domain_url') and tenant.domain_url:
                domain = tenant.domain_url
            else:
                # Fallback to subdomain pattern
                domain = f"{tenant.schema_name}.zumodra.com"

            return f"https://{domain}/services/{service.uuid}/book/"

        except Exception as e:
            logger.warning(f"Could not generate booking URL: {e}")
            return ''

    def _generate_detail_url(self, service) -> str:
        """
        Generate detail URL in tenant domain.

        Format: https://{tenant_domain}/services/{service_uuid}/
        """
        try:
            from tenants.models import Tenant
            tenant = Tenant.objects.get(schema_name=connection.schema_name)

            if hasattr(tenant, 'domain_url') and tenant.domain_url:
                domain = tenant.domain_url
            else:
                domain = f"{tenant.schema_name}.zumodra.com"

            return f"https://{domain}/services/{service.uuid}/"

        except Exception as e:
            logger.warning(f"Could not generate detail URL: {e}")
            return ''

    # =========================================================================
    # SYNC LIFECYCLE HOOKS
    # =========================================================================

    def after_sync(self, instance, catalog_entry, created: bool):
        """
        Post-sync hook to sync related models.

        Called after main PublicService entry is created/updated.
        Syncs related data:
        - Service images
        - Pricing tiers
        - Provider portfolio

        Args:
            instance: Source Service instance (in tenant schema)
            catalog_entry: PublicService instance (in public schema)
            created: Whether catalog_entry was newly created
        """
        try:
            # Sync related models
            self._sync_service_images(instance, catalog_entry)
            self._sync_pricing_tiers(instance, catalog_entry)
            self._sync_portfolio(instance, catalog_entry)

            logger.info(
                f"Synced related data for service {instance.uuid} "
                f"(created={created})"
            )

        except Exception as e:
            logger.error(f"Error syncing related data for service {instance.uuid}: {e}")
            # Don't raise - main sync succeeded, related data can be retried

    def _sync_service_images(self, service, catalog_entry):
        """Sync service gallery images to public catalog."""
        from services_public.models import PublicServiceImage

        try:
            # Delete existing images (full replacement strategy)
            catalog_entry.images.all().delete()

            # Create new images
            if hasattr(service, 'images'):
                for image in service.images.all():
                    PublicServiceImage.objects.create(
                        service=catalog_entry,
                        image_url=image.image.url if image.image else '',
                        alt_text=getattr(image, 'alt_text', ''),
                        description=getattr(image, 'description', ''),
                        sort_order=getattr(image, 'sort_order', 0)
                    )

        except Exception as e:
            logger.error(f"Error syncing images for service {service.uuid}: {e}")

    def _sync_pricing_tiers(self, service, catalog_entry):
        """Sync pricing tiers to public catalog."""
        from services_public.models import PublicServicePricingTier

        try:
            # Delete existing tiers
            catalog_entry.pricing_tiers.all().delete()

            # Create new tiers
            if hasattr(service, 'pricing_tiers'):
                for tier in service.pricing_tiers.all():
                    PublicServicePricingTier.objects.create(
                        service=catalog_entry,
                        name=tier.name,
                        price=tier.price,
                        currency=service.currency,
                        delivery_time_days=tier.delivery_time_days,
                        revisions=tier.revisions,
                        features=tier.features or {},
                        sort_order=tier.sort_order,
                        is_recommended=getattr(tier, 'is_recommended', False)
                    )

        except Exception as e:
            logger.error(f"Error syncing pricing tiers for service {service.uuid}: {e}")

    def _sync_portfolio(self, service, catalog_entry):
        """Sync provider portfolio images to service catalog entry."""
        from services_public.models import PublicServicePortfolio

        try:
            # Delete existing portfolio items
            catalog_entry.portfolio_images.all().delete()

            # Create new portfolio items from provider's portfolio
            if hasattr(service.provider, 'portfolio'):
                for portfolio_item in service.provider.portfolio.all():
                    PublicServicePortfolio.objects.create(
                        service=catalog_entry,
                        image_url=portfolio_item.image.url if portfolio_item.image else '',
                        title=getattr(portfolio_item, 'title', ''),
                        description=getattr(portfolio_item, 'description', ''),
                        sort_order=getattr(portfolio_item, 'sort_order', 0),
                        grid_col_span=getattr(portfolio_item, 'grid_col_span', 1),
                        grid_row_span=getattr(portfolio_item, 'grid_row_span', 1)
                    )

        except Exception as e:
            logger.error(f"Error syncing portfolio for service {service.uuid}: {e}")
