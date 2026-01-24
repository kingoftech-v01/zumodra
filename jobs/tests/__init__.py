"""
ATS Tests Package - Comprehensive test suite for Applicant Tracking System

This package contains comprehensive tests for the ATS module:

Test Modules:
- test_models.py: Unit tests for ATS models (JobCategory, Pipeline, PipelineStage,
  JobPosting, Candidate, Application, Interview, Offer, SavedSearch)
- test_api.py: Integration tests for ATS API endpoints (all ViewSets and actions)
- test_workflows.py: End-to-end workflow tests covering complete hiring flows
- test_permissions.py: Permission and access control tests for role-based security
- test_services.py: Service layer tests for business logic (ApplicationService,
  CandidateService, JobPostingService, PipelineService)

Test Markers:
- @pytest.mark.unit: Fast unit tests with minimal dependencies
- @pytest.mark.integration: API integration tests requiring database
- @pytest.mark.workflow: End-to-end workflow tests
- @pytest.mark.permissions: Permission and access control tests
- @pytest.mark.services: Service layer tests for business logic
- @pytest.mark.slow: Tests that take longer to run

Running Tests:
    # Run all ATS tests
    pytest ats/tests/ -v

    # Run only unit tests
    pytest ats/tests/ -v -m unit

    # Run only integration tests
    pytest ats/tests/ -v -m integration

    # Run only workflow tests
    pytest ats/tests/ -v -m workflow

    # Run only service tests
    pytest ats/tests/ -v -m services

    # Run with coverage
    pytest ats/tests/ --cov=ats --cov-report=html
"""

# Import test classes for convenient access
from .test_models import (
    TestJobCategoryModel,
    TestPipelineModel,
    TestPipelineStageModel,
    TestJobPostingModel,
    TestCandidateModel,
    TestApplicationModel,
    TestApplicationActivityModel,
    TestApplicationNoteModel,
    TestInterviewModel,
    TestInterviewFeedbackModel,
    TestOfferModel,
    TestSavedSearchModel,
)

from .test_api import (
    TestJobCategoryAPI,
    TestPipelineAPI,
    TestJobPostingAPI,
    TestCandidateAPI,
    TestApplicationAPI,
    TestInterviewAPI,
    TestOfferAPI,
    TestDashboardAPI,
    TestSavedSearchAPI,
    TestAPIPaginationOrdering,
    TestAPIErrorHandling,
)

from .test_workflows import (
    TestCompleteHiringWorkflow,
    TestRejectionWorkflow,
    TestWithdrawalWorkflow,
    TestBulkOperationsWorkflow,
    TestPipelineProgressionWorkflow,
    TestMultipleApplicationsWorkflow,
    TestOfferNegotiationWorkflow,
)

from .test_permissions import (
    TestRecruiterPermissions,
    TestHiringManagerPermissions,
    TestInterviewerPermissions,
    TestCrossTenantIsolation,
    TestOwnerOrReadOnlyPermission,
    TestRoleBasedAccess,
    TestApplicationAssignmentPermissions,
)

from .test_services import (
    TestApplicationService,
    TestCandidateService,
    TestJobPostingService,
    TestPipelineService,
    TestServiceResult,
    TestServiceEdgeCases,
)

__all__ = [
    # Model tests
    'TestJobCategoryModel',
    'TestPipelineModel',
    'TestPipelineStageModel',
    'TestJobPostingModel',
    'TestCandidateModel',
    'TestApplicationModel',
    'TestApplicationActivityModel',
    'TestApplicationNoteModel',
    'TestInterviewModel',
    'TestInterviewFeedbackModel',
    'TestOfferModel',
    'TestSavedSearchModel',
    # API tests
    'TestJobCategoryAPI',
    'TestPipelineAPI',
    'TestJobPostingAPI',
    'TestCandidateAPI',
    'TestApplicationAPI',
    'TestInterviewAPI',
    'TestOfferAPI',
    'TestDashboardAPI',
    'TestSavedSearchAPI',
    'TestAPIPaginationOrdering',
    'TestAPIErrorHandling',
    # Workflow tests
    'TestCompleteHiringWorkflow',
    'TestRejectionWorkflow',
    'TestWithdrawalWorkflow',
    'TestBulkOperationsWorkflow',
    'TestPipelineProgressionWorkflow',
    'TestMultipleApplicationsWorkflow',
    'TestOfferNegotiationWorkflow',
    # Permission tests
    'TestRecruiterPermissions',
    'TestHiringManagerPermissions',
    'TestInterviewerPermissions',
    'TestCrossTenantIsolation',
    'TestOwnerOrReadOnlyPermission',
    'TestRoleBasedAccess',
    'TestApplicationAssignmentPermissions',
    # Service tests
    'TestApplicationService',
    'TestCandidateService',
    'TestJobPostingService',
    'TestPipelineService',
    'TestServiceResult',
    'TestServiceEdgeCases',
]
