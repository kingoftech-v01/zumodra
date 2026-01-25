from django.urls import path
from . import views

app_name = 'services'

urlpatterns = [
    path('', views.ServiceListView.as_view(), name='list'),
    path('map/', views.ServiceMapView.as_view(), name='map'),
    path('<int:pk>/', views.ServiceDetailView.as_view(), name='detail'),
    path('<int:pk>/v2/', views.ServiceDetailView2.as_view(), name='detail_v2'),
]
