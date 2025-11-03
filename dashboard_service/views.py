from django.shortcuts import render
from .models import *
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404
# from django.contrib.gis.geos import Point
# from django.contrib.gis.db.models.functions import Distance
# from django.contrib.gis.measure import D
from django.db.models import Q

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

# def nearby_services(request):
#     user_lat = float(request.GET.get('lat'))
#     user_lon = float(request.GET.get('lon'))
#     user_location = Point(user_lon, user_lat, srid=4326)

#     nearby_providers = (
#         ServiceProviderProfile.objects
#         .filter(location__distance_lte=(user_location, D(km=10)))  # within 10km
#         .annotate(distance=Distance('location', user_location))
#         .order_by('distance')
#     )

#     return render(request, 'services-nearby.html', {'providers': nearby_providers})
