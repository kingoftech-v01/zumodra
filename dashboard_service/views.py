from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from .models import *
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404
from django.contrib.gis.geos import Point
from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.measure import D
from django.db.models import Q
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderUnavailable, GeocoderTimedOut

geolocator = Nominatim(user_agent="zumodra_geocoder")

# Create your views here.
def browse_service(request):
    service_categories = ServiceCategory.objects.all()
    services_list_query = Service.objects.all()
    service_providers = ServiceProviderProfile.objects.all()
    service_tags = ServicesTag.objects.all()

    paginator = Paginator(services_list_query, 1)
    page_number = request.GET.get('page')
    services = paginator.get_page(page_number)

    request = request.GET.get('request')

    if request:
        service_categories = ServiceCategory.objects.filter(name__icontains=request)

    context = {
        'service_categories': service_categories,
        'services': services,
        'service_providers': service_providers,
        'service_tags': service_tags,
    }
    return render(request, 'services-default.html', context)


def browse_service_detail(request, service_uuid):
    service = get_object_or_404(Service, uuid=service_uuid)
    context = {
        'service': service,
    }
    return render(request, 'services-detail1.html', context)

def browse_nearby_services(request):
    lat = request.GET.get('lat')
    lng = request.GET.get('lng')

    if lat is None or lng is None:
        # Handle the missing parameter case, e.g. return an error response or default values
        return redirect('browse_service')

    try:
        user_lat = float(lat)
        user_lng = float(lng)
    except ValueError:
        return HttpResponseBadRequest("Invalid latitude or longitude value")

    user_location = Point(user_lng, user_lat, srid=4326)

    within_area = request.GET.get('within_area')

    within_area_offset = int(within_area) if within_area else 10

    nearby_providers = (
        ServiceProviderProfile.objects
        .filter(location__distance_lte=(user_location, D(km=within_area_offset)))  # within 10km
        .annotate(distance=Distance('location', user_location))
        .order_by('distance')
    )

    return render(request, 'services-nearby.html', {'providers': nearby_providers})

def address_to_coords(address):
    """Convert a text address into geographic (lat, lon) coordinates."""
    try:
        location = geolocator.geocode(address)
        if location:
            return (location.latitude, location.longitude)
    except (GeocoderUnavailable, GeocoderTimedOut):
        return None
    return None


def coords_to_address(latitude, longitude):
    """Convert (lat, lon) coordinates back into a readable address."""
    try:
        location = geolocator.reverse((latitude, longitude))
        if location:
            return location.address
    except (GeocoderUnavailable, GeocoderTimedOut):
        return None
    return None
