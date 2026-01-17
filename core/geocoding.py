"""
Geocoding service using Nominatim (OpenStreetMap).
"""

import requests
import time
from django.contrib.gis.geos import Point
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)


class GeocodingService:
    """
    Geocoding service using Nominatim API.

    Rate limit: 1 request per second (Nominatim usage policy).
    """

    BASE_URL = 'https://nominatim.openstreetmap.org'
    USER_AGENT = 'Zumodra/1.0'
    CACHE_TTL = 86400 * 30  # 30 days

    @classmethod
    def geocode_address(cls, address_parts):
        """
        Geocode an address to coordinates.

        Args:
            address_parts: dict with keys: street, city, state, country

        Returns:
            Point or None
        """
        # Build full address string
        parts = [
            address_parts.get('street'),
            address_parts.get('city'),
            address_parts.get('state'),
            address_parts.get('country'),
        ]
        full_address = ', '.join([p for p in parts if p])

        if not full_address:
            return None

        # Check cache
        cache_key = f'geocode:{full_address}'
        cached = cache.get(cache_key)
        if cached:
            return Point(cached['lng'], cached['lat'], srid=4326)

        # Make API request
        try:
            params = {
                'q': full_address,
                'format': 'json',
                'limit': 1,
            }

            headers = {
                'User-Agent': cls.USER_AGENT
            }

            response = requests.get(
                f'{cls.BASE_URL}/search',
                params=params,
                headers=headers,
                timeout=10
            )

            response.raise_for_status()
            results = response.json()

            if results:
                result = results[0]
                lat = float(result['lat'])
                lng = float(result['lon'])

                # Cache result
                cache.set(cache_key, {'lat': lat, 'lng': lng}, cls.CACHE_TTL)

                # Respect rate limit
                time.sleep(1)

                return Point(lng, lat, srid=4326)

            return None

        except Exception as e:
            logger.error(f'Geocoding failed for {full_address}: {e}')
            return None

    @classmethod
    def geocode_tenant(cls, tenant):
        """
        Geocode a tenant's address.

        Updates tenant.location PointField in-place.
        See TODO-CAREERS-001 in careers/TODO.md for implementation details.
        """
        # Skip if already geocoded
        if tenant.location:
            return

        # Skip if no address information
        if not tenant.city or not tenant.country:
            logger.warning(f'Tenant {tenant.name} has insufficient address info for geocoding')
            return

        address = {
            'street': tenant.address_line1 or None,
            'city': tenant.city,
            'state': tenant.state,
            'country': tenant.country,
        }

        try:
            coords = cls.geocode_address(address)

            if coords:
                tenant.location = coords
                tenant.save(update_fields=['location'])
                logger.info(f'Successfully geocoded tenant {tenant.name}: {coords}')
            else:
                logger.warning(f'Geocoding failed for tenant {tenant.name}: No results found')

        except Exception as e:
            logger.error(f'Geocoding error for tenant {tenant.name}: {e}')

    @classmethod
    def geocode_job(cls, job):
        """Geocode a job's location."""
        if job.location_coordinates or job.geocode_attempted:
            return

        address = {
            'city': getattr(job, 'location_city', None),
            'country': getattr(job, 'location_country', None),
        }

        coords = cls.geocode_address(address)

        job.location_coordinates = coords
        job.geocode_attempted = True
        job.save(update_fields=['location_coordinates', 'geocode_attempted'])

        logger.info(f'Geocoded job {job.title}: {coords}')

    @classmethod
    def geocode_service(cls, service):
        """
        Geocode a service provider's location.

        Args:
            service: Service model instance

        Returns:
            Point or None
        """
        if not hasattr(service, 'provider') or not service.provider:
            logger.warning(f"Service {service.pk} has no provider")
            return None

        provider = service.provider

        # Build address from provider fields
        address = {
            'city': getattr(provider, 'city', None),
            'state': getattr(provider, 'state', None),
            'country': getattr(provider, 'country', None),
        }

        coords = cls.geocode_address(address)

        if coords:
            # Save to provider location fields if available
            if hasattr(provider, 'location'):
                provider.location = coords
                provider.save(update_fields=['location'])
                logger.info(f"Successfully geocoded service {service.pk} provider")
            elif hasattr(provider, 'location_lat'):
                provider.location_lat = coords.y
                provider.location_lng = coords.x
                provider.save(update_fields=['location_lat', 'location_lng'])
                logger.info(f"Successfully geocoded service {service.pk} provider")

        return coords

    @staticmethod
    def calculate_distance(point1, point2):
        """
        Calculate the distance between two points using the Haversine formula.

        Args:
            point1: Point object (SRID 4326)
            point2: Point object (SRID 4326)

        Returns:
            Distance in kilometers
        """
        from math import radians, sin, cos, sqrt, atan2

        # Earth's radius in kilometers
        R = 6371.0

        # Extract coordinates (Point is (x, y) = (lng, lat))
        lat1, lng1 = radians(point1.y), radians(point1.x)
        lat2, lng2 = radians(point2.y), radians(point2.x)

        # Haversine formula
        dlat = lat2 - lat1
        dlng = lng2 - lng1

        a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlng / 2)**2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))

        distance = R * c
        return distance
