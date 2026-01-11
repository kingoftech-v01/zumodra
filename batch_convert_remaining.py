#!/usr/bin/env python3
"""
Batch convert remaining dashboard templates to FreelanHub design system.
"""

import re
from pathlib import Path

# Templates to convert
TEMPLATES = [
    "templates/accounts/student/coop_term_detail.html",
    "templates/accounts/student/dashboard.html",
    "templates/custom_account_u/public_profile.html",
    "templates/custom_account_u/sync_settings_edit.html",
    "templates/custom_account_u/sync_settings_list.html",
    "templates/hr/employee_detail.html",
    "templates/hr/employee_form.html",
    "templates/hr/my_time_off.html",
    "templates/hr/timeoff_list.html",
    "templates/hr/timeoff_request.html",
    "templates/hr/time_off_calendar.html",
    "templates/hr/onboarding.html",
    "templates/hr/onboarding_checklist.html",
    "templates/hr/onboarding_dashboard.html",
    "templates/hr/onboarding_detail.html",
    "templates/hr/org_chart.html",
    "templates/finance/analytics/index.html",
    "templates/finance/connect/index.html",
    "templates/notifications/list.html",
    "templates/notifications/preferences.html",
    "templates/tenants/ein_verification.html",
]

# Icon mappings SVG class → Phosphor icon
ICON_MAPPINGS = {
    # Common hero icons
    'heroicon': 'ph',
    'h-5 w-5': 'text-xl',
    'h-6 w-6': 'text-2xl',
    'h-4 w-4': 'text-lg',
}

def convert_template(filepath):
    """Convert a single template to FreelanHub design."""
    path = Path(filepath)
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}")
        return False

    content = path.read_text(encoding='utf-8')
    original_content = content

    # 1. Change base template
    content = content.replace(
        '{% extends "base/dashboard_base.html" %}',
        '{% extends "base/freelanhub_dashboard_base.html" %}'
    )

    # 2. Change block name
    content = re.sub(
        r'{%\s*block\s+content\s*%}',
        '{% block dashboard_content %}',
        content
    )

    # 3. Remove old block definitions that conflict
    content = re.sub(r'{%\s*block\s+breadcrumb\s*%}.*?{%\s*endblock\s*%}', '', content, flags=re.DOTALL)
    content = re.sub(r'{%\s*block\s+page_header\s*%}.*?{%\s*endblock\s*%}', '', content, flags=re.DOTALL)

    # 4. Common SVG icon replacements (simple patterns)
    # Warning icon
    content = re.sub(
        r'<svg[^>]*class="[^"]*text-yellow[^"]*"[^>]*>.*?</svg>',
        '<i class="ph ph-warning text-yellow text-xl"></i>',
        content,
        flags=re.DOTALL
    )

    # Check/success icon
    content = re.sub(
        r'<svg[^>]*class="[^"]*text-green[^"]*"[^>]*>.*?</svg>',
        '<i class="ph ph-check-circle text-green text-xl"></i>',
        content,
        flags=re.DOTALL
    )

    # Info icon
    content = re.sub(
        r'<svg[^>]*class="[^"]*text-blue[^"]*"[^>]*>.*?</svg>',
        '<i class="ph ph-info text-blue text-xl"></i>',
        content,
        flags=re.DOTALL
    )

    # Generic small icons in breadcrumbs
    content = re.sub(
        r'<svg[^>]*class="[^"]*w-5\s+h-5[^"]*"[^>]*>.*?</svg>',
        '<i class="ph ph-caret-right text-secondary"></i>',
        content,
        flags=re.DOTALL
    )

    # 5. Typography updates
    replacements = [
        (r'\btext-gray-500\b', 'text-secondary'),
        (r'\btext-gray-400\b', 'text-secondary'),
        (r'\btext-gray-600\b', 'text-title'),
        (r'\btext-gray-700\b', 'text-title'),
        (r'\btext-gray-900\b', 'text-title'),
        (r'\btext-sm\b', 'caption1'),
        (r'\btext-xs\b', 'caption2'),
        (r'\btext-lg\b', 'heading5'),
        (r'\btext-xl\b', 'heading4'),
        (r'\btext-2xl\b', 'heading3'),
    ]

    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)

    # 6. Spacing updates
    content = content.replace('gap-6', 'gap-7.5')
    content = content.replace('gap-4', 'gap-5')
    content = content.replace('mt-6', 'mt-7.5')
    content = content.replace('mb-6', 'mb-7.5')
    content = content.replace('p-6', 'p-8')

    # 7. Remove dark mode classes (FreelanHub doesn't use them)
    content = re.sub(r'\bdark:[^\s"]+', '', content)

    # 8. Badge/Tag updates
    content = re.sub(
        r'bg-green-100\s+text-green-800',
        'tag bg-green bg-opacity-10 text-green',
        content
    )
    content = re.sub(
        r'bg-yellow-100\s+text-yellow-800',
        'tag bg-yellow bg-opacity-10 text-yellow',
        content
    )
    content = re.sub(
        r'bg-red-100\s+text-red-800',
        'tag bg-red bg-opacity-10 text-red',
        content
    )
    content = re.sub(
        r'bg-blue-100\s+text-blue-800',
        'tag bg-blue bg-opacity-10 text-blue',
        content
    )

    # 9. Card styling
    content = re.sub(
        r'bg-white\s+shadow-sm\s+rounded-xl',
        'bg-white rounded-lg',
        content
    )

    # Check if anything changed
    if content == original_content:
        print(f"[SKIP] No changes made: {filepath}")
        return False

    # Write back
    path.write_text(content, encoding='utf-8')
    print(f"[OK] Converted: {filepath}")
    return True

def main():
    """Convert all templates."""
    print("Starting batch conversion of remaining templates...\n")

    converted = 0
    skipped = 0

    for template in TEMPLATES:
        if convert_template(template):
            converted += 1
        else:
            skipped += 1

    print(f"\n{'='*60}")
    print(f"Conversion complete!")
    print(f"[OK] Converted: {converted}")
    print(f"[SKIP] Skipped: {skipped}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
