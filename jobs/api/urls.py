"""
Jobs (ATS) API URLs
"""

from rest_framework.routers import DefaultRouter
from .viewsets import (
    JobCategoryViewSet,
    PipelineViewSet,
    PipelineStageViewSet,
    JobPostingViewSet,
    CandidateViewSet,
    ApplicationViewSet,
    InterviewViewSet,
    InterviewFeedbackViewSet,
    OfferViewSet,
    SavedSearchViewSet,
    InterviewSlotViewSet,
    OfferTemplateViewSet,
    OfferApprovalViewSet,
)

app_name = 'jobs'

router = DefaultRouter()
router.register(r'categories', JobCategoryViewSet, basename='category')
router.register(r'pipelines', PipelineViewSet, basename='pipeline')
router.register(r'pipeline-stages', PipelineStageViewSet, basename='pipeline-stage')
router.register(r'job-postings', JobPostingViewSet, basename='job-posting')
router.register(r'candidates', CandidateViewSet, basename='candidate')
router.register(r'applications', ApplicationViewSet, basename='application')
router.register(r'interviews', InterviewViewSet, basename='interview')
router.register(r'interview-feedback', InterviewFeedbackViewSet, basename='interview-feedback')
router.register(r'offers', OfferViewSet, basename='offer')
router.register(r'saved-searches', SavedSearchViewSet, basename='saved-search')
router.register(r'interview-slots', InterviewSlotViewSet, basename='interview-slot')
router.register(r'offer-templates', OfferTemplateViewSet, basename='offer-template')
router.register(r'offer-approvals', OfferApprovalViewSet, basename='offer-approval')

urlpatterns = router.urls
