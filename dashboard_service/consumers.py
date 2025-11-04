import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django.contrib.gis.db.models.functions import Distance
from .models import ServiceProviderProfile

class LocationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.group_name = 'location_updates'
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        lat = float(data.get('lat'))
        lng = float(data.get('lng'))
        radius = int(data.get('radius', 10))
        nearby = await self.get_nearby_providers(lat, lng, radius)

        await self.send(text_data=json.dumps({
            'providers': nearby
        }))

    @database_sync_to_async
    def get_nearby_providers(self, lat, lng, radius):
        user_location = Point(lng, lat, srid=4326)
        qs = ServiceProviderProfile.objects.filter(
            location__distance_lte=(user_location, D(km=radius))
        ).annotate(distance=Distance('location', user_location)).order_by('distance')[:20]

        return [
            {
                'id': str(p.uuid),
                'name': p.entity_name,
                'lat': p.location_lat,
                'lng': p.location_lng,
                'distance': p.distance.km,
                'rating': float(p.rating_avg),
                'address': p.address,
            } for p in qs
        ]


import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
from django.contrib.gis.db.models.functions import Distance
from .models import ServiceProviderProfile

class LocationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        lat = float(data.get('lat', 0))
        lng = float(data.get('lng', 0))
        radius = int(data.get('radius', 10))  # Optional

        # Additional filters
        skill = data.get('skill')
        category = data.get('category')
        min_hourly = data.get('min_hourly')
        max_hourly = data.get('max_hourly')

        providers = await self.get_filtered_providers(lat, lng, radius, skill, category, min_hourly, max_hourly)

        await self.send(text_data=json.dumps({
            'providers': providers
        }))

    @database_sync_to_async
    def get_filtered_providers(self, lat, lng, radius, skill, category, min_hourly, max_hourly):
        user_location = Point(lng, lat, srid=4326)
        qs = ServiceProviderProfile.objects.filter(
            location__distance_lte=(user_location, D(km=radius))
        ).annotate(distance=Distance('location', user_location)).order_by('distance')

        # Example: add further filtering here as needed
        if skill:
            qs = qs.filter(skills__name=skill).distinct()
        if category:
            qs = qs.filter(categories__name=category).distinct()
        if min_hourly:
            qs = qs.filter(hourly_rate__gte=float(min_hourly))
        if max_hourly:
            qs = qs.filter(hourly_rate__lte=float(max_hourly))

        # Only return first 20 by distance to minimize load
        return [
            {
                'id': str(p.uuid),
                'name': p.entity_name,
                'lat': p.location_lat,
                'lng': p.location_lng,
                'distance': round(p.distance.km, 2) if hasattr(p, 'distance') else None,
                'rating': float(p.rating_avg),
                'address': p.address,
            } for p in qs[:20]
        ]
