"""
Projects API URLs
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .viewsets import (
    ProjectCategoryViewSet,
    ProjectProviderViewSet,
    ProjectViewSet,
    ProjectProposalViewSet,
    ProjectContractViewSet,
    ProjectMilestoneViewSet,
    ProjectDeliverableViewSet,
    ProjectReviewViewSet,
)

app_name = 'projects'

router = DefaultRouter()

# Register all ViewSets
router.register(r'categories', ProjectCategoryViewSet, basename='category')
router.register(r'providers', ProjectProviderViewSet, basename='provider')
router.register(r'projects', ProjectViewSet, basename='project')
router.register(r'proposals', ProjectProposalViewSet, basename='proposal')
router.register(r'contracts', ProjectContractViewSet, basename='contract')
router.register(r'milestones', ProjectMilestoneViewSet, basename='milestone')
router.register(r'deliverables', ProjectDeliverableViewSet, basename='deliverable')
router.register(r'reviews', ProjectReviewViewSet, basename='review')

urlpatterns = router.urls
