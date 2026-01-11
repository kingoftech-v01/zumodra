#!/usr/bin/env python3
"""Convert Accounts and Student templates to FreelanHub design system"""

templates = {
    'templates/accounts/cv/cv_list.html': open('templates/accounts/cv/cv_list.html').read().replace(
        'extends "base/dashboard_base.html"',
        'extends "base/freelanhub_dashboard_base.html"'
    ).replace(
        '{% block breadcrumb %}',
        '{% block dashboard_content %}\n<!-- Breadcrumb -->\n<div class="breadcrumb flex items-center gap-2 mb-6">'
    )
}

print("Template conversion script created")
