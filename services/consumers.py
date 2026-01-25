"""
Services WebSocket Consumers - Zumodra Freelance Marketplace

WebSocket consumers for real-time service provider location updates
and nearby provider discovery.

Consolidated from dashboard_service/consumers.py
"""

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django.contrib.gis.db.models.functions import Distance

from .models import ServiceProvider

logger = logging.getLogger(__name__)


class LocationConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time provider location updates.

    Clients can send their location and receive nearby providers
    with optional filtering by skill, category, and hourly rate.

    Usage:
        ws = new WebSocket('ws://example.com/ws/location/')
        ws.send(JSON.stringify({
            lat: 45.5017,
            lng: -73.5673,
            radius: 10,  // km
            skill: 'Python',  // optional
            category: 'Web Development',  // optional
            min_hourly: 50,  // optional
            max_hourly: 150  // optional
        }))
    """

    async def connect(self):
        """Accept WebSocket connection and join location updates group."""
        self.group_name = 'location_updates'
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.info(f"WebSocket connected: {self.channel_name}")

    async def disconnect(self, close_code):
        """Leave the location updates group on disconnect."""
        await self.channel_layer.group_discard(self.group_name, self.channel_name)
        logger.info(f"WebSocket disconnected: {self.channel_name} (code: {close_code})")

    async def receive(self, text_data):
        """
        Handle incoming location queries.

        Expected JSON format:
        {
            "lat": float,
            "lng": float,
            "radius": int (km, default 10),
            "skill": string (optional),
            "category": string (optional),
            "min_hourly": float (optional),
            "max_hourly": float (optional)
        }
        """
        try:
            data = json.loads(text_data)

            lat = float(data.get('lat', 0))
            lng = float(data.get('lng', 0))
            radius = int(data.get('radius', 10))

            # Optional filters
            skill = data.get('skill')
            category = data.get('category')
            min_hourly = data.get('min_hourly')
            max_hourly = data.get('max_hourly')
            availability = data.get('availability')

            providers = await self.get_filtered_providers(
                lat, lng, radius, skill, category, min_hourly, max_hourly, availability
            )

            await self.send(text_data=json.dumps({
                'type': 'nearby_providers',
                'providers': providers,
                'query': {
                    'lat': lat,
                    'lng': lng,
                    'radius': radius
                }
            }))

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except ValueError as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Invalid parameter value: {str(e)}'
            }))
        except Exception as e:
            logger.error(f"Error in LocationConsumer.receive: {e}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Server error processing request'
            }))

    @database_sync_to_async
    def get_filtered_providers(
        self, lat, lng, radius, skill=None, category=None,
        min_hourly=None, max_hourly=None, availability=None
    ):
        """
        Query providers within radius with optional filters.

        Returns up to 20 providers sorted by distance.
        """
        if lat == 0 and lng == 0:
            return []

        user_location = Point(lng, lat, srid=4326)

        # Base query: providers within radius
        qs = ServiceProvider.objects.filter(
            location__distance_lte=(user_location, D(km=radius)),
            is_private=False,
            is_accepting_work=True
        ).annotate(
            distance=Distance('location', user_location)
        ).order_by('distance')

        # Apply optional filters
        if skill:
            qs = qs.filter(provider_skills__skill__name__iexact=skill).distinct()

        if category:
            qs = qs.filter(categories__name__iexact=category).distinct()

        if min_hourly:
            qs = qs.filter(hourly_rate__gte=float(min_hourly))

        if max_hourly:
            qs = qs.filter(hourly_rate__lte=float(max_hourly))

        if availability:
            qs = qs.filter(availability_status=availability)

        # Limit results and serialize
        return [
            {
                'id': str(p.uuid),
                'name': p.display_name,
                'lat': p.location_lat,
                'lng': p.location_lng,
                'distance_km': round(p.distance.km, 2) if hasattr(p, 'distance') and p.distance else None,
                'rating': float(p.rating_avg),
                'total_reviews': p.total_reviews,
                'address': p.address,
                'city': p.city,
                'hourly_rate': float(p.hourly_rate) if p.hourly_rate else None,
                'currency': p.currency,
                'availability': p.availability_status,
                'is_verified': p.is_verified,
                'avatar_url': p.avatar.url if p.avatar else None,
            }
            for p in qs[:20]
        ]

    async def provider_location_update(self, event):
        """
        Handle broadcast of provider location updates.

        Called when a provider updates their location.
        """
        await self.send(text_data=json.dumps({
            'type': 'provider_update',
            'provider': event['provider']
        }))


class ProviderStatusConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for provider status updates.

    Allows clients to subscribe to status changes for specific providers
    (availability, online/offline, etc.)
    """

    async def connect(self):
        """Accept connection and optionally join provider-specific groups."""
        self.provider_groups = set()
        await self.accept()

    async def disconnect(self, close_code):
        """Leave all subscribed provider groups."""
        for group in self.provider_groups:
            await self.channel_layer.group_discard(group, self.channel_name)

    async def receive(self, text_data):
        """
        Handle subscription requests.

        Expected format:
        {
            "action": "subscribe" | "unsubscribe",
            "provider_id": "uuid"
        }
        """
        try:
            data = json.loads(text_data)
            action = data.get('action')
            provider_id = data.get('provider_id')

            if not provider_id:
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': 'provider_id is required'
                }))
                return

            group_name = f'provider_{provider_id}'

            if action == 'subscribe':
                await self.channel_layer.group_add(group_name, self.channel_name)
                self.provider_groups.add(group_name)
                await self.send(text_data=json.dumps({
                    'type': 'subscribed',
                    'provider_id': provider_id
                }))

            elif action == 'unsubscribe':
                await self.channel_layer.group_discard(group_name, self.channel_name)
                self.provider_groups.discard(group_name)
                await self.send(text_data=json.dumps({
                    'type': 'unsubscribed',
                    'provider_id': provider_id
                }))

        except Exception as e:
            logger.error(f"Error in ProviderStatusConsumer: {e}")

    async def provider_status_change(self, event):
        """Handle provider status change broadcasts."""
        await self.send(text_data=json.dumps({
            'type': 'status_change',
            'provider_id': event['provider_id'],
            'status': event['status']
        }))
