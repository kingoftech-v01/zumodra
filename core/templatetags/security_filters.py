"""
Security Template Filters - XSS Prevention

Provides safe HTML rendering filters that sanitize user input before marking it safe.
Uses nh3 (Rust-based HTML sanitizer, successor to bleach) for efficient sanitization.

Usage in templates:
    {% load security_filters %}
    {{ user_content|sanitize_html }}
    {{ rich_text|sanitize_rich_html }}

SECURITY NOTES:
- NEVER use |safe directly on user-controlled content
- Always use these filters instead of |safe for user content
- Static/admin-controlled content can use |safe directly
"""

from django import template
from django.utils.safestring import mark_safe
from django.utils.html import escape
import json
import re

register = template.Library()


# Try to import nh3 (preferred) or bleach (fallback)
try:
    import nh3
    HAS_NH3 = True
except ImportError:
    HAS_NH3 = False

try:
    import bleach
    HAS_BLEACH = True
except ImportError:
    HAS_BLEACH = False


# Allowed HTML tags for basic content
BASIC_TAGS = [
    'p', 'br', 'strong', 'em', 'b', 'i', 'u', 's',
    'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
]

# Allowed HTML tags for rich content (job descriptions, profiles, etc.)
RICH_TAGS = BASIC_TAGS + [
    'ul', 'ol', 'li', 'a', 'img', 'blockquote', 'pre', 'code',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'hr', 'sub', 'sup', 'abbr',
]

# Allowed attributes per tag
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    'span': ['class', 'style'],
    'div': ['class', 'style'],
    'p': ['class', 'style'],
    'table': ['class', 'border', 'cellpadding', 'cellspacing'],
    'th': ['colspan', 'rowspan', 'class'],
    'td': ['colspan', 'rowspan', 'class'],
    'abbr': ['title'],
}

# Allowed CSS properties for style attribute
ALLOWED_STYLES = [
    'color', 'background-color', 'font-size', 'font-weight', 'font-style',
    'text-align', 'text-decoration', 'margin', 'padding', 'border',
]

# URL schemes allowed in href/src attributes
ALLOWED_URL_SCHEMES = ['http', 'https', 'mailto', 'tel']


def _sanitize_with_nh3(html: str, tags: list) -> str:
    """Sanitize HTML using nh3 (Rust-based, fast and secure)."""
    if not HAS_NH3:
        return escape(html)

    # nh3 uses a different API
    allowed_tags = set(tags)

    # Build attribute filter
    attrs = {}
    for tag in tags:
        if tag in ALLOWED_ATTRIBUTES:
            attrs[tag] = set(ALLOWED_ATTRIBUTES[tag])

    return nh3.clean(
        html,
        tags=allowed_tags,
        attributes=attrs,
        url_schemes=set(ALLOWED_URL_SCHEMES),
        link_rel='noopener noreferrer',
        strip_comments=True,
    )


def _sanitize_with_bleach(html: str, tags: list) -> str:
    """Sanitize HTML using bleach (Python-based fallback)."""
    if not HAS_BLEACH:
        return escape(html)

    return bleach.clean(
        html,
        tags=tags,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_URL_SCHEMES,
        strip=True,
        strip_comments=True,
    )


def _sanitize_html(html: str, tags: list) -> str:
    """Sanitize HTML using best available library."""
    if not html:
        return ''

    html = str(html)

    if HAS_NH3:
        return _sanitize_with_nh3(html, tags)
    elif HAS_BLEACH:
        return _sanitize_with_bleach(html, tags)
    else:
        # No sanitizer available - escape everything
        return escape(html)


@register.filter(name='sanitize_html')
def sanitize_html(value):
    """
    Sanitize HTML content, allowing only basic formatting tags.

    Use for: Comments, short descriptions, bios

    Example:
        {{ comment.content|sanitize_html }}
    """
    if not value:
        return ''
    return mark_safe(_sanitize_html(str(value), BASIC_TAGS))


@register.filter(name='sanitize_rich_html')
def sanitize_rich_html(value):
    """
    Sanitize rich HTML content, allowing more tags for formatted content.

    Use for: Job descriptions, profiles, articles, experience sections

    Example:
        {{ job.description|sanitize_rich_html }}
    """
    if not value:
        return ''
    return mark_safe(_sanitize_html(str(value), RICH_TAGS))


@register.filter(name='safe_json')
def safe_json(value):
    """
    Safely serialize a value to JSON for use in JavaScript context.

    Escapes special characters that could break out of script tags.

    Example:
        <script>
            var data = {{ chart_data|safe_json }};
        </script>
    """
    if value is None:
        return 'null'

    # Serialize to JSON
    json_str = json.dumps(value, ensure_ascii=False)

    # Escape characters that could break out of <script> tags
    # This prevents XSS via JSON injection
    json_str = json_str.replace('<', '\\u003c')
    json_str = json_str.replace('>', '\\u003e')
    json_str = json_str.replace('&', '\\u0026')
    json_str = json_str.replace("'", '\\u0027')

    return mark_safe(json_str)


@register.filter(name='strip_html')
def strip_html(value):
    """
    Remove all HTML tags, returning plain text only.

    Use for: Preview text, meta descriptions, notifications

    Example:
        {{ article.content|strip_html|truncatewords:50 }}
    """
    if not value:
        return ''

    # Remove HTML tags using regex
    return re.sub(r'<[^>]+>', '', str(value))


@register.filter(name='safe_attribute')
def safe_attribute(value):
    """
    Escape a value for use in an HTML attribute.

    Example:
        <div data-name="{{ user.name|safe_attribute }}">
    """
    if not value:
        return ''

    # Escape for HTML attribute context
    value = str(value)
    value = value.replace('&', '&amp;')
    value = value.replace('"', '&quot;')
    value = value.replace("'", '&#x27;')
    value = value.replace('<', '&lt;')
    value = value.replace('>', '&gt;')

    return mark_safe(value)
