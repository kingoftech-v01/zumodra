"""
Main App Views - Public landing pages and utility views.

This module provides views that work on the public schema (no tenant context):
- Public careers landing page (for when careers tables don't exist)
"""

from django.shortcuts import render
from django.utils.translation import gettext_lazy as _


def public_careers_landing(request):
    """
    Public careers landing page.

    This view is shown when accessing /careers/ on the public schema
    where the careers app tables don't exist.

    It explains the careers feature and directs users to:
    - Sign up as an employer to create a career page
    - Browse available company career pages
    """
    context = {
        'page_title': _('Career Opportunities'),
        'meta_description': _('Explore career opportunities with verified companies on Zumodra. Find your next job with companies that value trust and transparency.'),
    }
    return render(request, 'careers/public_landing.html', context)
