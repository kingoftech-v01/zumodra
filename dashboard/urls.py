from django.urls import path
from .views import *

urlpatterns = [
    path('browse-project/', browse_project, name='browse_project'),
    path('browse-project/<str:project_uuid>', browse_project_detail, name='browse_project_detail'),
    path('browse-service/', browse_service, name='browse_service'),
    path('browse-service/<str:service_uuid>', browse_service_detail, name='browse_service_detail'),
]