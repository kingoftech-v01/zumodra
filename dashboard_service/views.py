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
def service_view(request):
    return render(request, 'services.html')

def add_service_view(request):
    return render(request, 'add-service.html')

def service_detail_view(request, pk):
    return render(request, 'service-detail.html')

def update_service_view(request, pk):
    return render(request, 'update-service.html')

def delete_service_view(request, pk):
    return render(request, 'delete-service.html')

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

from django.shortcuts import render, redirect, get_object_or_404
from .forms import ServiceForm, ServiceProviderProfileForm, ServiceCategoryForm  # importe les forms nécessaires


# Ajout d'un service
def add_service_view(request):
    if request.method == 'POST':
        form = ServiceForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('browse_service')  # redirige vers la liste ou détail
    else:
        form = ServiceForm()
    return render(request, 'add-service.html', {'form': form})


# Modification d'un service
def update_service_view(request, pk):
    service = get_object_or_404(Service, pk=pk)
    if request.method == 'POST':
        form = ServiceForm(request.POST, request.FILES, instance=service)
        if form.is_valid():
            form.save()
            return redirect('browse_service_detail', service_uuid=service.uuid)
    else:
        form = ServiceForm(instance=service)
    return render(request, 'update-service.html', {'form': form, 'service': service})


# Détail d'un service (affichage)
def service_detail_view(request, pk):
    service = get_object_or_404(Service, pk=pk)
    return render(request, 'service-detail.html', {'service': service})


# Suppression d'un service (confirmation)
def delete_service_view(request, pk):
    service = get_object_or_404(Service, pk=pk)
    if request.method == 'POST':
        service.delete()
        return redirect('browse_service')
    return render(request, 'delete-service.html', {'service': service})
