"""
Centralized Domain Configuration

This module provides a single source of truth for domain configuration across
the entire application. All domain-related settings should be accessed through
this module rather than using hard-coded values.

Environment Variables:
    PRIMARY_DOMAIN: The main domain for the application (e.g., zumodra.com)
    SITE_URL: Full URL including protocol (e.g., https://zumodra.com)
    TENANT_BASE_DOMAIN: Base domain for tenant subdomains (e.g., zumodra.com)
    API_BASE_URL: Base URL for API endpoints (defaults to SITE_URL + /api)
    CAREERS_BASE_DOMAIN: Domain for public career pages (optional)
    ANONYMIZED_EMAIL_DOMAIN: Domain for anonymized emails (privacy compliance)

Usage:
    from core.domain import get_site_url, get_tenant_domain, get_api_url

    # Get the main site URL
    site_url = get_site_url()  # https://zumodra.com

    # Get a tenant-specific domain
    tenant_domain = get_tenant_domain('acme')  # acme.zumodra.com

    # Build an absolute URL
    full_url = build_absolute_url('/api/v1/jobs/')  # https://zumodra.com/api/v1/jobs/
"""

import os
import logging
from functools import lru_cache
from typing import Optional
from urllib.parse import urljoin, urlparse

from django.conf import settings

logger = logging.getLogger(__name__)


# =============================================================================
# DOMAIN CONFIGURATION CONSTANTS
# =============================================================================

# Development-only domains (used only when DEBUG=True and no env vars set)
_DEV_DOMAINS = frozenset({
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '::1',
})

# Default development port
_DEV_PORT = '8000'


# =============================================================================
# CORE DOMAIN GETTERS
# =============================================================================

@lru_cache(maxsize=1)
def get_primary_domain() -> str:
    """
    Get the primary domain for the application.

    This is the canonical domain used for the main site, emails, and
    any context where a single authoritative domain is needed.

    Returns:
        str: The primary domain (e.g., 'zumodra.com' or 'localhost' for dev)

    Environment Variable: PRIMARY_DOMAIN
    Fallback: BASE_DOMAIN, then 'localhost' if DEBUG=True
    """
    domain = getattr(settings, 'PRIMARY_DOMAIN', None)
    if domain:
        return domain

    # Fall back to BASE_DOMAIN
    domain = getattr(settings, 'BASE_DOMAIN', None)
    if domain:
        return domain

    # Environment variable fallback
    domain = os.environ.get('PRIMARY_DOMAIN') or os.environ.get('BASE_DOMAIN')
    if domain:
        return domain

    # Development fallback
    if getattr(settings, 'DEBUG', False):
        logger.debug("Using 'localhost' as PRIMARY_DOMAIN (DEBUG=True)")
        return 'localhost'

    raise ValueError(
        "PRIMARY_DOMAIN or BASE_DOMAIN must be set in environment variables "
        "for production deployments. Set DEBUG=True for development."
    )


@lru_cache(maxsize=1)
def get_site_url() -> str:
    """
    Get the full site URL including protocol.

    Returns:
        str: Full URL (e.g., 'https://zumodra.com' or 'http://localhost:8000')

    Environment Variable: SITE_URL
    Fallback: Constructed from PRIMARY_DOMAIN with appropriate protocol
    """
    site_url = getattr(settings, 'SITE_URL', None)
    if site_url:
        return site_url.rstrip('/')

    # Environment variable fallback
    site_url = os.environ.get('SITE_URL')
    if site_url:
        return site_url.rstrip('/')

    # Construct from domain
    domain = get_primary_domain()
    is_dev = domain in _DEV_DOMAINS or getattr(settings, 'DEBUG', False)

    if is_dev:
        port = os.environ.get('WEB_PORT', _DEV_PORT)
        return f"http://{domain}:{port}"
    else:
        # Production always uses HTTPS
        return f"https://{domain}"


@lru_cache(maxsize=1)
def get_tenant_base_domain() -> str:
    """
    Get the base domain for tenant subdomains.

    Tenants are accessed via subdomains like: tenant-slug.zumodra.com

    Returns:
        str: Base domain for tenants (e.g., 'zumodra.com')

    Environment Variable: TENANT_BASE_DOMAIN
    Fallback: PRIMARY_DOMAIN
    """
    domain = getattr(settings, 'TENANT_BASE_DOMAIN', None)
    if domain:
        return domain

    domain = os.environ.get('TENANT_BASE_DOMAIN')
    if domain:
        return domain

    return get_primary_domain()


@lru_cache(maxsize=1)
def get_api_base_url() -> str:
    """
    Get the base URL for API endpoints.

    Returns:
        str: API base URL (e.g., 'https://zumodra.com/api')

    Environment Variable: API_BASE_URL
    Fallback: SITE_URL + '/api'
    """
    api_url = getattr(settings, 'API_BASE_URL', None)
    if api_url:
        return api_url.rstrip('/')

    api_url = os.environ.get('API_BASE_URL')
    if api_url:
        return api_url.rstrip('/')

    return f"{get_site_url()}/api"


@lru_cache(maxsize=1)
def get_careers_base_domain() -> str:
    """
    Get the base domain for public career pages.

    Returns:
        str: Careers domain (e.g., 'careers.zumodra.com')

    Environment Variable: CAREERS_BASE_DOMAIN
    Fallback: 'careers.' + PRIMARY_DOMAIN
    """
    domain = getattr(settings, 'CAREERS_BASE_DOMAIN', None)
    if domain:
        return domain

    domain = os.environ.get('CAREERS_BASE_DOMAIN')
    if domain:
        return domain

    return f"careers.{get_primary_domain()}"


@lru_cache(maxsize=1)
def get_anonymized_email_domain() -> str:
    """
    Get the domain used for anonymized email addresses (GDPR compliance).

    Returns:
        str: Domain for anonymized emails (e.g., 'anonymized.zumodra.com')

    Environment Variable: ANONYMIZED_EMAIL_DOMAIN
    Fallback: 'anonymized.' + PRIMARY_DOMAIN
    """
    domain = getattr(settings, 'ANONYMIZED_EMAIL_DOMAIN', None)
    if domain:
        return domain

    domain = os.environ.get('ANONYMIZED_EMAIL_DOMAIN')
    if domain:
        return domain

    return f"anonymized.{get_primary_domain()}"


# =============================================================================
# URL BUILDERS
# =============================================================================

def get_tenant_domain(tenant_slug: str) -> str:
    """
    Get the full domain for a specific tenant.

    Args:
        tenant_slug: The tenant's URL slug (e.g., 'acme-corp')

    Returns:
        str: Full tenant domain (e.g., 'acme-corp.zumodra.com')
    """
    return f"{tenant_slug}.{get_tenant_base_domain()}"


def get_tenant_url(tenant_slug: str, path: str = '') -> str:
    """
    Get the full URL for a tenant-specific page.

    Args:
        tenant_slug: The tenant's URL slug
        path: Optional path to append (e.g., '/dashboard/')

    Returns:
        str: Full tenant URL (e.g., 'https://acme-corp.zumodra.com/dashboard/')
    """
    domain = get_tenant_domain(tenant_slug)
    is_dev = get_primary_domain() in _DEV_DOMAINS
    protocol = 'http' if is_dev else 'https'

    if is_dev:
        port = os.environ.get('WEB_PORT', _DEV_PORT)
        base = f"{protocol}://{domain}:{port}"
    else:
        base = f"{protocol}://{domain}"

    if path:
        return urljoin(base + '/', path.lstrip('/'))
    return base


def build_absolute_url(path: str, domain: Optional[str] = None) -> str:
    """
    Build an absolute URL from a relative path.

    Args:
        path: Relative URL path (e.g., '/api/v1/jobs/')
        domain: Optional specific domain to use (defaults to SITE_URL)

    Returns:
        str: Absolute URL (e.g., 'https://zumodra.com/api/v1/jobs/')
    """
    if domain:
        is_dev = domain in _DEV_DOMAINS
        protocol = 'http' if is_dev else 'https'
        if is_dev:
            port = os.environ.get('WEB_PORT', _DEV_PORT)
            base = f"{protocol}://{domain}:{port}"
        else:
            base = f"{protocol}://{domain}"
    else:
        base = get_site_url()

    return urljoin(base + '/', path.lstrip('/'))


def build_api_url(endpoint: str, version: str = 'v1') -> str:
    """
    Build a full API URL for an endpoint.

    Args:
        endpoint: API endpoint path (e.g., 'jobs/', 'jobs/applications/')
        version: API version (default: 'v1')

    Returns:
        str: Full API URL (e.g., 'https://zumodra.com/api/v1/jobs/')
    """
    base = get_api_base_url()
    return f"{base}/{version}/{endpoint.strip('/')}"


# =============================================================================
# EMAIL DOMAIN HELPERS
# =============================================================================

def get_email_domain() -> str:
    """
    Get the domain to use in email addresses.

    Returns:
        str: Email domain (e.g., 'zumodra.com')
    """
    domain = getattr(settings, 'EMAIL_DOMAIN', None)
    if domain:
        return domain
    return get_primary_domain()


def get_noreply_email() -> str:
    """
    Get the no-reply email address.

    Returns:
        str: No-reply email (e.g., 'noreply@zumodra.com')
    """
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None)
    if from_email and '@' in from_email:
        return from_email
    return f"noreply@{get_email_domain()}"


def build_demo_email(username: str, tenant_slug: str = 'demo') -> str:
    """
    Build a demo/test email address.

    Args:
        username: Username part of email
        tenant_slug: Tenant identifier

    Returns:
        str: Demo email (e.g., 'admin@demo.zumodra.com')
    """
    domain = get_primary_domain()
    return f"{username}@{tenant_slug}.{domain}"


def build_anonymized_email(identifier: str) -> str:
    """
    Build an anonymized email address for GDPR compliance.

    Args:
        identifier: Unique identifier (typically UUID hex)

    Returns:
        str: Anonymized email (e.g., 'anonymized-abc123@anonymized.zumodra.com')
    """
    domain = get_anonymized_email_domain()
    return f"anonymized-{identifier}@{domain}"


# =============================================================================
# VALIDATION HELPERS
# =============================================================================

def is_development_domain(domain: str) -> bool:
    """
    Check if a domain is a development-only domain.

    Args:
        domain: Domain to check

    Returns:
        bool: True if this is a dev domain (localhost, 127.0.0.1, etc.)
    """
    # Extract hostname without port
    if ':' in domain:
        domain = domain.split(':')[0]
    return domain.lower() in _DEV_DOMAINS


def is_valid_tenant_domain(domain: str) -> bool:
    """
    Check if a domain is a valid tenant subdomain.

    Args:
        domain: Domain to validate

    Returns:
        bool: True if domain follows tenant subdomain pattern
    """
    base = get_tenant_base_domain()
    return domain.endswith(f'.{base}')


def extract_tenant_slug(domain: str) -> Optional[str]:
    """
    Extract the tenant slug from a tenant domain.

    Args:
        domain: Full tenant domain (e.g., 'acme.zumodra.com')

    Returns:
        str or None: Tenant slug if valid, None otherwise
    """
    base = get_tenant_base_domain()
    suffix = f'.{base}'

    if domain.endswith(suffix):
        slug = domain[:-len(suffix)]
        if slug and '.' not in slug:
            return slug
    return None


# =============================================================================
# CACHE CLEARING
# =============================================================================

def clear_domain_cache():
    """
    Clear all cached domain values.

    Call this if domain configuration changes at runtime (rare).
    """
    get_primary_domain.cache_clear()
    get_site_url.cache_clear()
    get_tenant_base_domain.cache_clear()
    get_api_base_url.cache_clear()
    get_careers_base_domain.cache_clear()
    get_anonymized_email_domain.cache_clear()
    logger.info("Domain configuration cache cleared")
