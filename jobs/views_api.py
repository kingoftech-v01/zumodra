"""
ATS (Jobs) API Views - REST API endpoints.

This module provides REST API views using Django Rest Framework.
Imports ViewSets from api.viewsets for organizational purposes.

All views return JSON responses.
API URL namespace: api:v1:jobs:resource-name

ViewSets:
---------
Core ViewSets:
    - JobPostingViewSet: Job posting CRUD and management
    - JobCategoryViewSet: Job categories (read-only)
    - CandidateViewSet: Candidate profile management
    - ApplicationViewSet: Application tracking and management
    - InterviewViewSet: Interview scheduling and management
    - InterviewFeedbackViewSet: Interview feedback and evaluations
    - OfferViewSet: Job offer management
    - PipelineViewSet: Hiring pipeline management
    - PipelineStageViewSet: Pipeline stage configuration
    - SavedSearchViewSet: Saved candidate searches
    - InterviewSlotViewSet: Interview time slot management
    - OfferTemplateViewSet: Offer letter templates
    - OfferApprovalViewSet: Offer approval workflows

APIViews (Non-ViewSet Endpoints):
----------------------------------
    - DashboardStatsView: Dashboard statistics and metrics
    - AIMatchScoreView: AI-powered candidate matching
    - BulkOperationsView: Bulk operations on applications/candidates
    - InterviewSchedulingView: Automated interview scheduling
    - OfferWorkflowView: Offer workflow management
    - PipelineAnalyticsView: Pipeline analytics and reporting
    - AdvancedReportsView: Advanced HR reports generation
"""

# Import all ViewSets and APIViews from api package
from .api.viewsets import *  # noqa

# Explicit exports for clarity (convention recommends explicit __all__)
__all__ = [
    # Core ViewSets
    'JobPostingViewSet',
    'JobCategoryViewSet',
    'CandidateViewSet',
    'ApplicationViewSet',
    'InterviewViewSet',
    'InterviewFeedbackViewSet',
    'OfferViewSet',
    'PipelineViewSet',
    'PipelineStageViewSet',
    'SavedSearchViewSet',
    'InterviewSlotViewSet',
    'OfferTemplateViewSet',
    'OfferApprovalViewSet',

    # APIViews (non-ViewSet endpoints)
    'DashboardStatsView',
    'AIMatchScoreView',
    'BulkOperationsView',
    'InterviewSchedulingView',
    'OfferWorkflowView',
    'PipelineAnalyticsView',
    'AdvancedReportsView',
]
