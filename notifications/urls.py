from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    path('', views.notification_list, name='notification_list'),
    path('<int:notification_id>/read/', views.notification_mark_read, name='mark_read'),
    path('mark-all-read/', views.notification_mark_all_read, name='mark_all_read'),
    path('<int:notification_id>/delete/', views.notification_delete, name='delete'),
    path('preferences/', views.notification_preferences, name='notification_preferences'),
    path('api/count/', views.notification_count_api, name='count_api'),
]
