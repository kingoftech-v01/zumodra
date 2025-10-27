from django.urls import path
from .views import *

urlpatterns = [
    path('browse-service/', browse_service, name='browse_service'),
    path('browse-service/<str:service_uuid>', browse_service_detail, name='browse_service_detail'),
]
