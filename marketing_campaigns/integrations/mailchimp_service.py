"""
Mailchimp Integration Service for Marketing Campaigns.

This module provides tenant-aware integration with Mailchimp for managing
email marketing contacts and campaigns.

IMPORTANT: This is a TENANT-AWARE version. Each tenant can have their own
Mailchimp API configuration stored in tenant settings.
"""

import logging
import hashlib
from typing import Optional, Dict, Any

from django.conf import settings

from tenants.models import Tenant

logger = logging.getLogger(__name__)


def get_mailchimp_config(tenant: Optional[Tenant] = None) -> Dict[str, str]:
    """
    Get Mailchimp configuration for a specific tenant.

    Args:
        tenant: Tenant instance (if None, uses global settings)

    Returns:
        Dict with 'api_key', 'server_prefix', 'list_id'
    """
    # TODO: Implement tenant-specific config storage
    # For now, use global settings (backward compatible)
    # Future: Store in tenant.settings JSON field or separate TenantSettings model

    if tenant and hasattr(tenant, 'mailchimp_api_key'):
        return {
            'api_key': tenant.mailchimp_api_key or '',
            'server_prefix': tenant.mailchimp_server_prefix or 'us1',
            'list_id': tenant.mailchimp_list_id or ''
        }

    # Fallback to global settings
    return {
        'api_key': getattr(settings, 'MAILCHIMP_API_KEY', ''),
        'server_prefix': getattr(settings, 'MAILCHIMP_SERVER_PREFIX', 'us1'),
        'list_id': getattr(settings, 'MAILCHIMP_LIST_ID', '')
    }


def get_mailchimp_client(tenant: Optional[Tenant] = None):
    """
    Get a configured Mailchimp client for a specific tenant.

    Args:
        tenant: Tenant instance

    Returns:
        mailchimp_marketing.Client or None if not configured
    """
    config = get_mailchimp_config(tenant)
    api_key = config['api_key']
    server_prefix = config['server_prefix']

    if not api_key:
        logger.debug(f"Mailchimp API key not configured for tenant {tenant.name if tenant else 'global'}")
        return None

    try:
        import mailchimp_marketing as MailchimpMarketing
        from mailchimp_marketing.api_client import ApiClientError

        client = MailchimpMarketing.Client()
        client.set_config({
            "api_key": api_key,
            "server": server_prefix
        })

        # Test the connection
        client.ping.get()
        return client

    except ImportError:
        logger.warning("mailchimp-marketing package not installed. Install with: pip install mailchimp-marketing")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize Mailchimp client for tenant {tenant.name if tenant else 'global'}: {e}")
        return None


def get_subscriber_hash(email: str) -> str:
    """
    Get the MD5 hash of a lowercase email address.
    Mailchimp uses this as the subscriber ID.

    Args:
        email: Email address to hash

    Returns:
        MD5 hash of lowercase email
    """
    return hashlib.md5(email.lower().encode()).hexdigest()


def add_subscriber(tenant: Tenant, email: str, first_name: str = '', last_name: str = '',
                   merge_fields: Optional[Dict[str, Any]] = None,
                   tags: Optional[list] = None) -> Dict[str, Any]:
    """
    Add a subscriber to the tenant's Mailchimp list.

    Args:
        tenant: Tenant instance
        email: Subscriber email address
        first_name: Subscriber first name
        last_name: Subscriber last name
        merge_fields: Additional merge fields
        tags: Tags to apply to the subscriber

    Returns:
        Response from Mailchimp or error dict
    """
    client = get_mailchimp_client(tenant)
    config = get_mailchimp_config(tenant)
    list_id = config['list_id']

    if not client:
        return {'success': False, 'error': 'Mailchimp not configured'}

    if not list_id:
        return {'success': False, 'error': 'Mailchimp list ID not configured'}

    try:
        from mailchimp_marketing.api_client import ApiClientError

        # Prepare merge fields
        fields = merge_fields or {}
        if first_name:
            fields['FNAME'] = first_name
        if last_name:
            fields['LNAME'] = last_name

        member_info = {
            "email_address": email,
            "status": "pending",  # Double opt-in
            "merge_fields": fields
        }

        if tags:
            member_info["tags"] = tags

        response = client.lists.add_list_member(list_id, member_info)

        logger.info(f"Successfully added subscriber {email} to Mailchimp for tenant {tenant.name}")
        return {'success': True, 'data': response}

    except ApiClientError as e:
        error_body = e.text if hasattr(e, 'text') else str(e)

        # Check if member already exists
        if 'already a list member' in error_body.lower():
            logger.info(f"Subscriber {email} already exists in Mailchimp for tenant {tenant.name}")
            return {'success': True, 'message': 'Already subscribed'}

        logger.error(f"Mailchimp API error for tenant {tenant.name}: {error_body}")
        return {'success': False, 'error': error_body}

    except Exception as e:
        logger.error(f"Error adding subscriber to Mailchimp for tenant {tenant.name}: {e}")
        return {'success': False, 'error': str(e)}


def update_subscriber(tenant: Tenant, email: str, first_name: str = '', last_name: str = '',
                      merge_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Update an existing subscriber in the tenant's Mailchimp list.

    Args:
        tenant: Tenant instance
        email: Subscriber email address
        first_name: Updated first name
        last_name: Updated last name
        merge_fields: Additional merge fields to update

    Returns:
        Response from Mailchimp or error dict
    """
    client = get_mailchimp_client(tenant)
    config = get_mailchimp_config(tenant)
    list_id = config['list_id']

    if not client:
        return {'success': False, 'error': 'Mailchimp not configured'}

    if not list_id:
        return {'success': False, 'error': 'Mailchimp list ID not configured'}

    try:
        from mailchimp_marketing.api_client import ApiClientError

        subscriber_hash = get_subscriber_hash(email)

        # Prepare update data
        fields = merge_fields or {}
        if first_name:
            fields['FNAME'] = first_name
        if last_name:
            fields['LNAME'] = last_name

        member_info = {}
        if fields:
            member_info["merge_fields"] = fields

        response = client.lists.update_list_member(
            list_id, subscriber_hash, member_info
        )

        logger.info(f"Successfully updated subscriber {email} in Mailchimp for tenant {tenant.name}")
        return {'success': True, 'data': response}

    except ApiClientError as e:
        error_body = e.text if hasattr(e, 'text') else str(e)
        logger.error(f"Mailchimp API error for tenant {tenant.name}: {error_body}")
        return {'success': False, 'error': error_body}

    except Exception as e:
        logger.error(f"Error updating subscriber in Mailchimp for tenant {tenant.name}: {e}")
        return {'success': False, 'error': str(e)}


def unsubscribe(tenant: Tenant, email: str) -> Dict[str, Any]:
    """
    Unsubscribe an email from the tenant's Mailchimp list.

    Args:
        tenant: Tenant instance
        email: Email address to unsubscribe

    Returns:
        Response from Mailchimp or error dict
    """
    client = get_mailchimp_client(tenant)
    config = get_mailchimp_config(tenant)
    list_id = config['list_id']

    if not client:
        return {'success': False, 'error': 'Mailchimp not configured'}

    if not list_id:
        return {'success': False, 'error': 'Mailchimp list ID not configured'}

    try:
        from mailchimp_marketing.api_client import ApiClientError

        subscriber_hash = get_subscriber_hash(email)

        response = client.lists.update_list_member(
            list_id, subscriber_hash, {"status": "unsubscribed"}
        )

        logger.info(f"Successfully unsubscribed {email} from Mailchimp for tenant {tenant.name}")
        return {'success': True, 'data': response}

    except ApiClientError as e:
        error_body = e.text if hasattr(e, 'text') else str(e)
        logger.error(f"Mailchimp API error for tenant {tenant.name}: {error_body}")
        return {'success': False, 'error': error_body}

    except Exception as e:
        logger.error(f"Error unsubscribing from Mailchimp for tenant {tenant.name}: {e}")
        return {'success': False, 'error': str(e)}


def get_subscriber_info(tenant: Tenant, email: str) -> Dict[str, Any]:
    """
    Get subscriber information from the tenant's Mailchimp list.

    Args:
        tenant: Tenant instance
        email: Email address to look up

    Returns:
        Subscriber info or error dict
    """
    client = get_mailchimp_client(tenant)
    config = get_mailchimp_config(tenant)
    list_id = config['list_id']

    if not client:
        return {'success': False, 'error': 'Mailchimp not configured'}

    if not list_id:
        return {'success': False, 'error': 'Mailchimp list ID not configured'}

    try:
        from mailchimp_marketing.api_client import ApiClientError

        subscriber_hash = get_subscriber_hash(email)

        response = client.lists.get_list_member(list_id, subscriber_hash)
        return {'success': True, 'data': response}

    except ApiClientError as e:
        error_body = e.text if hasattr(e, 'text') else str(e)

        if '404' in str(e.status_code) if hasattr(e, 'status_code') else False:
            return {'success': False, 'error': 'Subscriber not found'}

        logger.error(f"Mailchimp API error for tenant {tenant.name}: {error_body}")
        return {'success': False, 'error': error_body}

    except Exception as e:
        logger.error(f"Error getting subscriber info from Mailchimp for tenant {tenant.name}: {e}")
        return {'success': False, 'error': str(e)}


def sync_contact(contact) -> Dict[str, Any]:
    """
    Sync a local Contact with tenant's Mailchimp list.

    Args:
        contact: Contact model instance

    Returns:
        Sync result
    """
    if contact.subscribed:
        return add_subscriber(
            tenant=contact.tenant,
            email=contact.email,
            first_name=contact.first_name,
            last_name=contact.last_name
        )
    else:
        return unsubscribe(tenant=contact.tenant, email=contact.email)


def is_mailchimp_configured(tenant: Optional[Tenant] = None) -> bool:
    """
    Check if Mailchimp is properly configured for a tenant.

    Args:
        tenant: Tenant instance (if None, checks global config)

    Returns:
        True if Mailchimp is configured and accessible
    """
    config = get_mailchimp_config(tenant)
    api_key = config['api_key']
    list_id = config['list_id']

    if not api_key or not list_id:
        return False

    client = get_mailchimp_client(tenant)
    return client is not None
