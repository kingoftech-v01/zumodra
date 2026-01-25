from django.urls import path
from . import views

app_name = 'candidates'

urlpatterns = [
    path('', views.CandidateListView.as_view(), name='list'),
    path('map/', views.CandidateMapView.as_view(), name='map'),
    path('<int:pk>/', views.CandidateDetailView.as_view(), name='detail'),
    path('<int:pk>/v2/', views.CandidateDetailView2.as_view(), name='detail_v2'),
]
