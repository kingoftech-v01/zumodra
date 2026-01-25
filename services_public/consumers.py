"""
Services Public WebSocket Consumers

Real-time WebSocket consumers for the public service catalog:
- ServiceCatalogConsumer: Real-time filtering and search
- ServiceMapConsumer: Interactive map marker updates

These consumers enable real-time interactions without page reloads.
"""

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django.core.paginator import Paginator

from services_public.models import PublicService
from services_public.utils import apply_filters, apply_sorting, build_geojson

logger = logging.getLogger(__name__)


class ServiceCatalogConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time service catalog filtering.

    Allows clients to:
    - Send filter parameters via WebSocket
    - Receive filtered results in real-time without page reload
    - Subscribe to catalog update notifications

    Message Format (Client -> Server):
        {
            "action": "filter",
            "filters": {
                "q": "search query",
                "category": "category_slug",
                "city": "city_name",
                "min_price": 50,
                "max_price": 500,
                "min_rating": 4.0,
                "verified": true,
                "remote": true,
                "service_type": "fixed",
                "sort": "rating"
            },
            "page": 1,
            "per_page": 20
        }

    Response Format (Server -> Client):
        {
            "type": "filter_results",
            "services": [...],
            "total_count": 150,
            "page": 1,
            "total_pages": 8,
            "has_next": true,
            "has_previous": false
        }
    """

    async def connect(self):
        """Accept WebSocket connection and join catalog updates group."""
        self.group_name = 'services_catalog_updates'

        # Join broadcast group for catalog updates
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()
        logger.info(f"ServiceCatalogConsumer connected: {self.channel_name}")

    async def disconnect(self, close_code):
        """Leave the catalog updates group on disconnect."""
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
        logger.info(f"ServiceCatalogConsumer disconnected: {self.channel_name} (code: {close_code})")

    async def receive(self, text_data):
        """
        Handle incoming filter requests from client.

        Expected actions:
        - "filter": Apply filters and return paginated results
        - "subscribe": Subscribe to specific category/location updates
        """
        try:
            data = json.loads(text_data)
            action = data.get('action', 'filter')

            if action == 'filter':
                await self.handle_filter_request(data)
            elif action == 'subscribe':
                await self.handle_subscribe_request(data)
            else:
                await self.send_error(f"Unknown action: {action}")

        except json.JSONDecodeError:
            await self.send_error("Invalid JSON format")
        except Exception as e:
            logger.error(f"Error in ServiceCatalogConsumer.receive: {e}", exc_info=True)
            await self.send_error("Server error processing request")

    async def handle_filter_request(self, data):
        """
        Apply filters and return paginated service results.

        Args:
            data: Dict with 'filters', 'page', and 'per_page' keys
        """
        filters = data.get('filters', {})
        page_num = int(data.get('page', 1))
        per_page = min(int(data.get('per_page', 20)), 100)  # Max 100 items per page

        try:
            # Execute database query asynchronously
            results = await self.get_filtered_services(filters, page_num, per_page)

            await self.send(text_data=json.dumps({
                'type': 'filter_results',
                'services': results['services'],
                'total_count': results['total_count'],
                'page': results['page'],
                'total_pages': results['total_pages'],
                'has_next': results['has_next'],
                'has_previous': results['has_previous'],
            }))

        except Exception as e:
            logger.error(f"Error filtering services: {e}", exc_info=True)
            await self.send_error("Error filtering services")

    async def handle_subscribe_request(self, data):
        """
        Subscribe to specific catalog update notifications.

        Clients can subscribe to updates for:
        - Specific categories
        - Specific locations
        - All updates (default)
        """
        subscription_type = data.get('subscription_type', 'all')

        # In a real implementation, this would track subscriptions
        # and send targeted updates. For now, just acknowledge.
        await self.send(text_data=json.dumps({
            'type': 'subscribed',
            'subscription_type': subscription_type,
            'message': f'Subscribed to {subscription_type} updates'
        }))

    @database_sync_to_async
    def get_filtered_services(self, filters, page_num, per_page):
        """
        Query database with filters and return paginated results.

        Args:
            filters: Dict of filter parameters
            page_num: Page number (1-indexed)
            per_page: Items per page

        Returns:
            Dict with services list and pagination info
        """
        # Build queryset
        queryset = PublicService.objects.filter(is_active=True)

        # Apply filters (simulating request object)
        class FakeRequest:
            GET = filters

        fake_request = FakeRequest()
        queryset = apply_filters(queryset, fake_request)
        queryset = apply_sorting(queryset, fake_request)

        # Get total count
        total_count = queryset.count()

        # Optimize query for list view
        queryset = queryset.only(
            'service_uuid', 'name', 'slug', 'short_description',
            'provider_name', 'provider_avatar_url', 'category_name',
            'category_slug', 'thumbnail_url', 'price', 'currency',
            'rating_avg', 'total_reviews', 'is_featured',
            'provider_is_verified', 'detail_url'
        )

        # Paginate
        paginator = Paginator(queryset, per_page)

        try:
            page_obj = paginator.page(page_num)
        except:
            page_obj = paginator.page(1)
            page_num = 1

        # Serialize services
        services = [
            {
                'service_uuid': str(s.service_uuid),
                'name': s.name,
                'slug': s.slug,
                'short_description': s.short_description,
                'provider_name': s.provider_name,
                'provider_avatar_url': s.provider_avatar_url or '',
                'category_name': s.category_name,
                'category_slug': s.category_slug,
                'thumbnail_url': s.thumbnail_url or '',
                'price': float(s.price) if s.price else None,
                'currency': s.currency,
                'rating_avg': float(s.rating_avg) if s.rating_avg else None,
                'total_reviews': s.total_reviews,
                'is_featured': s.is_featured,
                'provider_is_verified': s.provider_is_verified,
                'detail_url': s.detail_url,
            }
            for s in page_obj
        ]

        return {
            'services': services,
            'total_count': total_count,
            'page': page_num,
            'total_pages': paginator.num_pages,
            'has_next': page_obj.has_next(),
            'has_previous': page_obj.has_previous(),
        }

    async def send_error(self, message):
        """Send error message to client."""
        await self.send(text_data=json.dumps({
            'type': 'error',
            'message': message
        }))

    async def catalog_update(self, event):
        """
        Handle broadcast catalog update notifications.

        Called when new services are published or updated.
        """
        await self.send(text_data=json.dumps({
            'type': 'catalog_update',
            'action': event.get('action'),  # 'new_service', 'update', 'remove'
            'service_uuid': event.get('service_uuid'),
            'category': event.get('category'),
        }))


class ServiceMapConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for interactive service map updates.

    Provides real-time map marker updates based on:
    - Viewport changes (pan/zoom)
    - Filter changes
    - New services published in visible area

    Message Format (Client -> Server):
        {
            "action": "update_viewport",
            "bounds": {
                "north": 45.6,
                "south": 45.4,
                "east": -73.5,
                "west": -73.7
            },
            "filters": {
                "category": "web-design",
                "min_rating": 4.0
            }
        }

    Response Format (Server -> Client):
        {
            "type": "map_update",
            "geojson": {
                "type": "FeatureCollection",
                "features": [...]
            },
            "total_count": 45
        }
    """

    async def connect(self):
        """Accept WebSocket connection for map updates."""
        self.group_name = 'services_map_updates'

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()
        logger.info(f"ServiceMapConsumer connected: {self.channel_name}")

    async def disconnect(self, close_code):
        """Leave map updates group on disconnect."""
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
        logger.info(f"ServiceMapConsumer disconnected: {self.channel_name} (code: {close_code})")

    async def receive(self, text_data):
        """
        Handle incoming map viewport updates.

        Actions:
        - "update_viewport": Send services within new viewport bounds
        - "filter": Apply filters to map markers
        """
        try:
            data = json.loads(text_data)
            action = data.get('action', 'update_viewport')

            if action == 'update_viewport':
                await self.handle_viewport_update(data)
            elif action == 'filter':
                await self.handle_map_filter(data)
            else:
                await self.send_error(f"Unknown action: {action}")

        except json.JSONDecodeError:
            await self.send_error("Invalid JSON format")
        except Exception as e:
            logger.error(f"Error in ServiceMapConsumer.receive: {e}", exc_info=True)
            await self.send_error("Server error processing request")

    async def handle_viewport_update(self, data):
        """
        Send services within viewport bounds.

        Args:
            data: Dict with 'bounds' and optional 'filters'
        """
        bounds = data.get('bounds', {})
        filters = data.get('filters', {})

        try:
            results = await self.get_services_in_viewport(bounds, filters)

            await self.send(text_data=json.dumps({
                'type': 'map_update',
                'geojson': results['geojson'],
                'total_count': results['total_count'],
            }))

        except Exception as e:
            logger.error(f"Error updating map viewport: {e}", exc_info=True)
            await self.send_error("Error updating map")

    async def handle_map_filter(self, data):
        """Apply filters to map markers (same as viewport update with filters)."""
        await self.handle_viewport_update(data)

    @database_sync_to_async
    def get_services_in_viewport(self, bounds, filters):
        """
        Query services within map viewport bounds.

        Args:
            bounds: Dict with north, south, east, west coordinates
            filters: Additional filter parameters

        Returns:
            Dict with GeoJSON and count
        """
        # Base queryset: active services with location
        queryset = PublicService.objects.filter(
            is_active=True,
            location__isnull=False
        )

        # Apply viewport bounds if provided
        if all(k in bounds for k in ['north', 'south', 'east', 'west']):
            try:
                north = float(bounds['north'])
                south = float(bounds['south'])
                east = float(bounds['east'])
                west = float(bounds['west'])

                # Filter by bounding box
                queryset = queryset.filter(
                    location__latitude__gte=south,
                    location__latitude__lte=north,
                    location__longitude__gte=west,
                    location__longitude__lte=east
                )
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid bounds: {e}")

        # Apply additional filters
        if filters:
            class FakeRequest:
                GET = filters

            fake_request = FakeRequest()
            queryset = apply_filters(queryset, fake_request)

        # Limit to 200 services for performance (map clustering will handle this)
        services = queryset[:200]
        total_count = queryset.count()

        # Build GeoJSON
        geojson = build_geojson(services)

        return {
            'geojson': geojson,
            'total_count': total_count,
        }

    async def send_error(self, message):
        """Send error message to client."""
        await self.send(text_data=json.dumps({
            'type': 'error',
            'message': message
        }))

    async def map_marker_update(self, event):
        """
        Handle broadcast map marker updates.

        Called when services are added/removed in the map area.
        """
        await self.send(text_data=json.dumps({
            'type': 'marker_update',
            'action': event.get('action'),
            'service_uuid': event.get('service_uuid'),
            'location': event.get('location'),
        }))
