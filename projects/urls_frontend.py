"""
Projects Frontend URLs
"""

from django.urls import path
from . import template_views

app_name = 'projects'

urlpatterns = [
    # Dashboard
    path('dashboard/', template_views.project_dashboard, name='dashboard'),

    # Project list view
    path('', template_views.project_list, name='project_list'),

    # Project detail view
    path('<uuid:uuid>/', template_views.project_detail, name='project_detail'),

    # Project create view
    path('create/', template_views.project_create, name='project_create'),

    # Project update view
    path('<uuid:uuid>/edit/', template_views.project_update, name='project_update'),

    # Project delete view
    path('<uuid:uuid>/delete/', template_views.project_delete, name='project_delete'),

    # Project action views
    path('<uuid:uuid>/publish/', template_views.project_publish, name='project_publish'),
    path('<uuid:uuid>/unpublish/', template_views.project_unpublish, name='project_unpublish'),

    # Proposal views
    path('proposals/', template_views.proposal_list, name='proposal_list'),
    path('proposals/<uuid:uuid>/', template_views.proposal_detail, name='proposal_detail'),
    path('proposals/<uuid:uuid>/accept/', template_views.proposal_accept, name='proposal_accept'),
    path('proposals/<uuid:uuid>/reject/', template_views.proposal_reject, name='proposal_reject'),

    # Milestone views
    path('<uuid:project_uuid>/milestones/', template_views.milestone_list, name='milestone_list'),
    path('milestones/<uuid:uuid>/', template_views.milestone_detail, name='milestone_detail'),
]
