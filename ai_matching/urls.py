"""
URL Configuration for AI Matching API

This module defines the URL patterns for the AI matching service endpoints.

Cycle 7 additions:
- Enhanced candidate matching with caching
- Job matching for candidates
- Match explanation endpoint
- Enhanced bias detection
- Resume parsing with profile updates
"""

from django.urls import path
from .views import (
    MatchCandidatesView,
    MatchJobsView,
    ParseResumeView,
    AnalyzeJobDescriptionView,
    BiasCheckView,
    RecommendationFeedbackView,
    BulkMatchView,
    MatchResultsHistoryView,
    AIServiceHealthView,
    # Cycle 7 additions
    CandidateMatchingView,
    JobMatchingView,
    MatchExplanationView,
    BiasDetectionView,
    ResumeParsingView,
)

app_name = 'ai_matching'

urlpatterns = [
    # ==================== ORIGINAL ENDPOINTS ====================
    # Matching endpoints
    path(
        'match-candidates/',
        MatchCandidatesView.as_view(),
        name='match-candidates'
    ),
    path(
        'match-jobs/',
        MatchJobsView.as_view(),
        name='match-jobs'
    ),

    # Analysis endpoints
    path(
        'parse-resume/',
        ParseResumeView.as_view(),
        name='parse-resume'
    ),
    path(
        'analyze-job/',
        AnalyzeJobDescriptionView.as_view(),
        name='analyze-job'
    ),
    path(
        'bias-check/',
        BiasCheckView.as_view(),
        name='bias-check'
    ),

    # Feedback and history
    path(
        'recommendation-feedback/',
        RecommendationFeedbackView.as_view(),
        name='recommendation-feedback'
    ),
    path(
        'match-results/',
        MatchResultsHistoryView.as_view(),
        name='match-results'
    ),

    # Admin endpoints
    path(
        'bulk-match/',
        BulkMatchView.as_view(),
        name='bulk-match'
    ),

    # Health check
    path(
        'health/',
        AIServiceHealthView.as_view(),
        name='health'
    ),

    # ==================== CYCLE 7 - ENHANCED API ====================
    # Candidate Matching (with caching)
    # GET: Get top matches for a job
    # POST: Compute fresh matches
    path(
        'candidates/match/',
        CandidateMatchingView.as_view(),
        name='candidate-matching'
    ),

    # Job Matching (for candidates)
    # GET: Get matching jobs for a candidate
    path(
        'jobs/match/',
        JobMatchingView.as_view(),
        name='job-matching'
    ),

    # Match Explanation
    # GET: Get detailed explanation of a specific match
    path(
        'match/<uuid:match_id>/explain/',
        MatchExplanationView.as_view(),
        name='match-explain'
    ),

    # Bias Report (enhanced)
    # GET: Get bias report for a job
    # POST: Run bias detection on text/job
    path(
        'bias-report/',
        BiasDetectionView.as_view(),
        name='bias-report'
    ),

    # Resume Parsing (enhanced with profile updates)
    # POST: Parse resume and optionally update/create profile
    path(
        'resume/parse/',
        ResumeParsingView.as_view(),
        name='resume-parse'
    ),
]
