from django.urls import path
from . import views

app_name = 'jobs'

urlpatterns = [
    path('', views.JobListView.as_view(), name='list'),
    path('list/', views.JobListView2.as_view(), name='list_view'),
    path('grid/', views.JobGridView.as_view(), name='grid'),
    path('map-grid/', views.JobMapGridView.as_view(), name='map_grid'),
    path('map-grid-2/', views.JobMapGridView2.as_view(), name='map_grid2'),
    path('<int:pk>/', views.JobDetailView.as_view(), name='detail'),
    path('<int:pk>/v2/', views.JobDetailView2.as_view(), name='detail_v2'),
]
