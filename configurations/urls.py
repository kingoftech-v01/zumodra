"""
Configurations App URL Configuration.

Template views for:
- Dashboard
- Skills management
- Company management
- FAQ management
- Testimonials management
"""

from django.urls import path

from .views import (
    ConfigurationsDashboardView,
    SkillsListView,
    CompanyListView,
    FAQListView,
    TestimonialsListView,
)

app_name = 'configurations'

urlpatterns = [
    path('', ConfigurationsDashboardView.as_view(), name='dashboard'),
    path('skills/', SkillsListView.as_view(), name='skills-list'),
    path('companies/', CompanyListView.as_view(), name='company-list'),
    path('faqs/', FAQListView.as_view(), name='faq-list'),
    path('testimonials/', TestimonialsListView.as_view(), name='testimonials-list'),
]
