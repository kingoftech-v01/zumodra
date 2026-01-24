"""
ATS Template Filters

Custom template filters for the Applicant Tracking System (ATS) app.
"""

from django import template
import bleach

register = template.Library()

# Allowed HTML tags for rich text content
ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'a', 'blockquote', 'code', 'pre', 'span', 'div'
]

# Allowed HTML attributes for tags
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'target'],
    'span': ['class'],
    'div': ['class'],
}


@register.filter(name='sanitize_html')
def sanitize_html(value):
    """
    Sanitize HTML content to prevent XSS attacks while allowing basic formatting.

    This filter uses bleach to clean HTML content, allowing only safe tags
    and attributes defined in ALLOWED_TAGS and ALLOWED_ATTRIBUTES.

    Usage in templates:
        {{ job.description|sanitize_html|safe }}

    Args:
        value: The HTML content to sanitize

    Returns:
        Sanitized HTML string with only allowed tags and attributes
    """
    if not value:
        return ''

    return bleach.clean(
        value,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True  # Strip disallowed tags instead of escaping them
    )
