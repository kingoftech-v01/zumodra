from django.urls import path
from . import views

app_name = 'analytics'

urlpatterns = [
    path('dashboard/', views.analytics_dashboard, name='dashboard'),
    path('provider/', views.provider_analytics, name='provider_analytics'),
    path('client/', views.client_analytics, name='client_analytics'),
]
