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

        Updates tenant.location_coordinates in-place.
        """
        if tenant.location_coordinates or tenant.geocode_attempted:
            return  # Already geocoded or attempted

        address = {
            'street': getattr(tenant, 'address', None),
            'city': getattr(tenant, 'city', None),
            'state': getattr(tenant, 'state', None),
            'country': getattr(tenant, 'country', None),
        }

        coords = cls.geocode_address(address)

        tenant.location_coordinates = coords
        tenant.geocode_attempted = True

        if not coords:
            tenant.geocode_error = 'Unable to geocode address'

        tenant.save(update_fields=['location_coordinates', 'geocode_attempted', 'geocode_error'])

        logger.info(f'Geocoded tenant {tenant.name}: {coords}')

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
