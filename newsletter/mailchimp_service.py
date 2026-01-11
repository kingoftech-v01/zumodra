"""
Mailchimp Integration Service for Newsletter.

This module provides integration with Mailchimp for managing newsletter subscriptions.
It syncs local newsletter subscriptions with Mailchimp lists/audiences.
"""

import logging
import hashlib
from typing import Optional, Dict, Any

from django.conf import settings

logger = logging.getLogger(__name__)


def get_mailchimp_client():
    """
    Get a configured Mailchimp client.

    Returns:
        mailchimp_marketing.Client or None if not configured
    """
    api_key = getattr(settings, 'MAILCHIMP_API_KEY', '')
    server_prefix = getattr(settings, 'MAILCHIMP_SERVER_PREFIX', 'us1')

    if not api_key:
        logger.debug("Mailchimp API key not configured")
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
        logger.warning("mailchimp-marketing package not installed")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize Mailchimp client: {e}")
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


def add_subscriber(email: str, first_name: str = '', last_name: str = '',
                   merge_fields: Optional[Dict[str, Any]] = None,
                   tags: Optional[list] = None) -> Dict[str, Any]:
    """
    Add a subscriber to the Mailchimp list.

    Args:
        email: Subscriber email address
        first_name: Subscriber first name
        last_name: Subscriber last name
        merge_fields: Additional merge fields
        tags: Tags to apply to the subscriber

    Returns:
        Response from Mailchimp or error dict
    """
    client = get_mailchimp_client()
    list_id = getattr(settings, 'MAILCHIMP_LIST_ID', '')

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

        logger.info(f"Successfully added subscriber {email} to Mailchimp")
        return {'success': True, 'data': response}

    except ApiClientError as e:
        error_body = e.text if hasattr(e, 'text') else str(e)

        # Check if member already exists
        if 'already a list member' in error_body.lower():
            logger.info(f"Subscriber {email} already exists in Mailchimp")
            return {'success': True, 'message': 'Already subscribed'}

        logger.error(f"Mailchimp API error: {error_body}")
        return {'success': False, 'error': error_body}

    except Exception as e:
        logger.error(f"Error adding subscriber to Mailchimp: {e}")
        return {'success': False, 'error': str(e)}


def update_subscriber(email: str, first_name: str = '', last_name: str = '',
                      merge_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Update an existing subscriber in Mailchimp.

    Args:
        email: Subscriber email address
        first_name: Updated first name
        last_name: Updated last name
        merge_fields: Additional merge fields to update

    Returns:
        Response from Mailchimp or error dict
    """
    client = get_mailchimp_client()
    list_id = getattr(settings, 'MAILCHIMP_LIST_ID', '')

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

        logger.info(f"Successfully updated subscriber {email} in Mailchimp")
        return {'success': True, 'data': response}

    except ApiClientError as e:
        error_body = e.text if hasattr(e, 'text') else str(e)
        logger.error(f"Mailchimp API error: {error_body}")
        return {'success': False, 'error': error_body}

    except Exception as e:
        logger.error(f"Error updating subscriber in Mailchimp: {e}")
        return {'success': False, 'error': str(e)}


def unsubscribe(email: str) -> Dict[str, Any]:
    """
    Unsubscribe an email from the Mailchimp list.

    Args:
        email: Email address to unsubscribe

    Returns:
        Response from Mailchimp or error dict
    """
    client = get_mailchimp_client()
    list_id = getattr(settings, 'MAILCHIMP_LIST_ID', '')

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

        logger.info(f"Successfully unsubscribed {email} from Mailchimp")
        return {'success': True, 'data': response}

    except ApiClientError as e:
        error_body = e.text if hasattr(e, 'text') else str(e)
        logger.error(f"Mailchimp API error: {error_body}")
        return {'success': False, 'error': error_body}

    except Exception as e:
        logger.error(f"Error unsubscribing from Mailchimp: {e}")
        return {'success': False, 'error': str(e)}


def get_subscriber_info(email: str) -> Dict[str, Any]:
    """
    Get subscriber information from Mailchimp.

    Args:
        email: Email address to look up

    Returns:
        Subscriber info or error dict
    """
    client = get_mailchimp_client()
    list_id = getattr(settings, 'MAILCHIMP_LIST_ID', '')

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

        logger.error(f"Mailchimp API error: {error_body}")
        return {'success': False, 'error': error_body}

    except Exception as e:
        logger.error(f"Error getting subscriber info from Mailchimp: {e}")
        return {'success': False, 'error': str(e)}


def sync_subscription(subscription) -> Dict[str, Any]:
    """
    Sync a local newsletter subscription with Mailchimp.

    Args:
        subscription: Newsletter Subscription model instance

    Returns:
        Sync result
    """
    if subscription.subscribed:
        return add_subscriber(
            email=subscription.email,
            first_name=subscription.name.split()[0] if subscription.name else '',
            last_name=' '.join(subscription.name.split()[1:]) if subscription.name and len(subscription.name.split()) > 1 else ''
        )
    else:
        return unsubscribe(email=subscription.email)


def is_mailchimp_configured() -> bool:
    """
    Check if Mailchimp is properly configured.

    Returns:
        True if Mailchimp is configured and accessible
    """
    api_key = getattr(settings, 'MAILCHIMP_API_KEY', '')
    list_id = getattr(settings, 'MAILCHIMP_LIST_ID', '')

    if not api_key or not list_id:
        return False

    client = get_mailchimp_client()
    return client is not None
