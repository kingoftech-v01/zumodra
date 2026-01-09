"""
Configurations API URLs.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    SkillViewSet,
    CompanyViewSet,
    SiteViewSet,
    DepartmentViewSet,
    RoleViewSet,
    MembershipViewSet,
    JobViewSet,
    JobApplicationViewSet,
    FAQViewSet,
    TestimonialViewSet,
    PartnershipViewSet,
    TrustedCompanyViewSet,
    CandidateProfileViewSet,
    LeaveRequestViewSet,
    InternalNotificationViewSet,
)

app_name = 'configurations-api'

router = DefaultRouter()

# Skill taxonomy
router.register(r'skills', SkillViewSet, basename='skill')

# Company/Organization structure
router.register(r'companies', CompanyViewSet, basename='company')
router.register(r'sites', SiteViewSet, basename='site')
router.register(r'departments', DepartmentViewSet, basename='department')
router.register(r'roles', RoleViewSet, basename='role')
router.register(r'memberships', MembershipViewSet, basename='membership')

# Job board
router.register(r'jobs', JobViewSet, basename='job')
router.register(r'job-applications', JobApplicationViewSet, basename='job-application')
router.register(r'candidates', CandidateProfileViewSet, basename='candidate-profile')

# HR operations
router.register(r'leave-requests', LeaveRequestViewSet, basename='leave-request')
router.register(r'notifications', InternalNotificationViewSet, basename='internal-notification')

# Website content
router.register(r'faqs', FAQViewSet, basename='faq')
router.register(r'testimonials', TestimonialViewSet, basename='testimonial')
router.register(r'partnerships', PartnershipViewSet, basename='partnership')
router.register(r'trusted-companies', TrustedCompanyViewSet, basename='trusted-company')

urlpatterns = [
    path('', include(router.urls)),
]
