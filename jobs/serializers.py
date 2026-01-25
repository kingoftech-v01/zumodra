"""
ATS (Jobs) Serializers - DRF Serializers.

This module provides DRF serializers for JSON API responses.
Imports from api.serializers for organizational purposes.

Serializers:
-----------
User Serializers:
    - UserMinimalSerializer: Minimal user data for references

Job Posting Serializers:
    - JobCategorySerializer: Job category data
    - JobCategoryListSerializer: Job category list view
    - JobPostingListSerializer: Job posting list view
    - JobPostingDetailSerializer: Job posting detail view
    - JobPostingCreateSerializer: Job posting creation
    - JobPostingCloneSerializer: Job posting cloning

Pipeline Serializers:
    - PipelineSerializer: Pipeline data
    - PipelineListSerializer: Pipeline list view
    - PipelineCreateSerializer: Pipeline creation
    - PipelineStageSerializer: Pipeline stage data
    - PipelineStageCreateSerializer: Pipeline stage creation
    - PipelineMetricsSerializer: Pipeline metrics

Candidate Serializers:
    - CandidateListSerializer: Candidate list view
    - CandidateDetailSerializer: Candidate detail view
    - CandidateCreateSerializer: Candidate creation
    - CandidateBulkImportSerializer: Bulk import candidates
    - CandidateMergeSerializer: Merge duplicate candidates

Application Serializers:
    - ApplicationListSerializer: Application list view
    - ApplicationDetailSerializer: Application detail view
    - ApplicationCreateSerializer: Application creation
    - ApplicationStageChangeSerializer: Move application to different stage
    - ApplicationRejectSerializer: Reject application
    - ApplicationBulkActionSerializer: Bulk operations
    - ApplicationActivitySerializer: Application activity log
    - ApplicationNoteSerializer: Application notes

Interview Serializers:
    - InterviewListSerializer: Interview list view
    - InterviewDetailSerializer: Interview detail view
    - InterviewCreateSerializer: Interview creation
    - InterviewRescheduleSerializer: Reschedule interview
    - InterviewFeedbackSerializer: Interview feedback
    - InterviewFeedbackCreateSerializer: Create feedback

Interview Slot Serializers:
    - InterviewSlotSerializer: Interview time slot
    - InterviewSlotCreateSerializer: Create time slot
    - InterviewSlotBulkCreateSerializer: Bulk create slots
    - InterviewSlotAvailableSerializer: Check availability
    - InterviewSlotFindCommonSerializer: Find common availability

Offer Serializers:
    - OfferListSerializer: Offer list view
    - OfferDetailSerializer: Offer detail view
    - OfferCreateSerializer: Offer creation
    - OfferSendSerializer: Send offer to candidate
    - OfferResponseSerializer: Candidate offer response
    - OfferTemplateSerializer: Offer template
    - OfferTemplateCreateSerializer: Create offer template
    - OfferTemplateApplySerializer: Apply template to offer

Saved Search Serializers:
    - SavedSearchSerializer: Saved search query
    - SavedSearchCreateSerializer: Create saved search

Analytics Serializers:
    - DashboardStatsSerializer: Dashboard statistics
    - KanbanBoardSerializer: Kanban board data
    - AIMatchScoreSerializer: AI matching scores
"""

# Import all serializers from api package
from .api.serializers import *  # noqa

# Explicit exports (convention recommends explicit __all__)
__all__ = [
    # User Serializers
    'UserMinimalSerializer',

    # Job Category Serializers
    'JobCategorySerializer',
    'JobCategoryListSerializer',

    # Pipeline Serializers
    'PipelineSerializer',
    'PipelineListSerializer',
    'PipelineCreateSerializer',
    'PipelineStageSerializer',
    'PipelineStageCreateSerializer',
    'PipelineMetricsSerializer',

    # Job Posting Serializers
    'JobPostingListSerializer',
    'JobPostingDetailSerializer',
    'JobPostingCreateSerializer',
    'JobPostingCloneSerializer',

    # Candidate Serializers
    'CandidateListSerializer',
    'CandidateDetailSerializer',
    'CandidateCreateSerializer',
    'CandidateBulkImportSerializer',
    'CandidateMergeSerializer',

    # Application Serializers
    'ApplicationListSerializer',
    'ApplicationDetailSerializer',
    'ApplicationCreateSerializer',
    'ApplicationStageChangeSerializer',
    'ApplicationRejectSerializer',
    'ApplicationBulkActionSerializer',
    'ApplicationActivitySerializer',
    'ApplicationNoteSerializer',

    # Interview Serializers
    'InterviewListSerializer',
    'InterviewDetailSerializer',
    'InterviewCreateSerializer',
    'InterviewRescheduleSerializer',
    'InterviewFeedbackSerializer',
    'InterviewFeedbackCreateSerializer',

    # Interview Slot Serializers
    'InterviewSlotSerializer',
    'InterviewSlotCreateSerializer',
    'InterviewSlotBulkCreateSerializer',
    'InterviewSlotAvailableSerializer',
    'InterviewSlotFindCommonSerializer',

    # Offer Serializers
    'OfferListSerializer',
    'OfferDetailSerializer',
    'OfferCreateSerializer',
    'OfferSendSerializer',
    'OfferResponseSerializer',

    # Offer Template Serializers
    'OfferTemplateSerializer',
    'OfferTemplateCreateSerializer',
    'OfferTemplateApplySerializer',

    # Saved Search Serializers
    'SavedSearchSerializer',
    'SavedSearchCreateSerializer',

    # Analytics Serializers
    'DashboardStatsSerializer',
    'KanbanBoardSerializer',
    'AIMatchScoreSerializer',
]
