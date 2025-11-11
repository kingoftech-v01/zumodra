from django.urls import path
from .views import *

app_name = 'services'

urlpatterns = [
    path('browse-service/', browse_service, name='browse_service'),
    path('browse-service/detail/<str:service_uuid>', browse_service_detail, name='browse_service_detail'),
    path('browse-nearby-service/', browse_nearby_services, name='browse_nearby_services'),
]