from django.urls import path
from . import views

app_name = 'projects'

urlpatterns = [
    path('', views.ProjectListView.as_view(), name='list'),
    path('map/', views.ProjectMapView.as_view(), name='map'),
    path('<int:pk>/', views.ProjectDetailView.as_view(), name='detail'),
    path('<int:pk>/v2/', views.ProjectDetailView2.as_view(), name='detail_v2'),
    path('<int:pk>/v3/', views.ProjectDetailView3.as_view(), name='detail_v3'),
]
