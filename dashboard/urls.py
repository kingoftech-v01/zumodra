from django.urls import path, include
from .views import *

urlpatterns = [
    path('', dashboard_view, name='dashboard'),
    path('my-bookmarks/', my_bookmarks_view, name='my_bookmarks'),
    path('alert/', include('dashboard_alert.urls')),
    path('service/', include('dashboard_service.urls')),
    path('project/', include('dashboard_project.urls')),
    path('allert/', include('dashboard_alert.urls')),
    path('account/', include('custom_account_u.urls')),
]