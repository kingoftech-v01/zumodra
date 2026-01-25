from django.urls import path
from . import views

app_name = 'employers'

urlpatterns = [
    path('', views.EmployerListView.as_view(), name='list'),
    path('map/', views.EmployerMapView.as_view(), name='map'),
    path('<int:pk>/', views.EmployerDetailView.as_view(), name='detail'),
    path('<int:pk>/v2/', views.EmployerDetailView2.as_view(), name='detail_v2'),
]
