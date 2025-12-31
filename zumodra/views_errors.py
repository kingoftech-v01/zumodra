"""
Custom Error Handlers for Zumodra

This module provides custom error handlers for HTTP errors (400, 403, 404, 429, 500, 503).
Each handler logs the error appropriately and renders a branded error page with support information.
For API requests, JSON responses are returned instead of HTML templates.
"""

import logging
import uuid
from django.shortcuts import render
from django.http import JsonResponse
from django.utils.translation import gettext as _
from django.conf import settings

# Configure loggers for different error types
logger_client = logging.getLogger('zumodra.errors.client')  # 4xx errors
logger_server = logging.getLogger('zumodra.errors.server')  # 5xx errors

# Support information
SUPPORT_EMAIL = getattr(settings, 'SUPPORT_EMAIL', 'support@rhematek-solutions.com')
STATUS_PAGE_URL = getattr(settings, 'STATUS_PAGE_URL', 'https://status.zumodra.com')


def _get_error_context(request, error_id=None):
    """
    Generate common context for error pages.

    Args:
        request: The HTTP request object
        error_id: Optional error reference ID for tracking

    Returns:
        dict: Common context variables for error templates
    """
    return {
        'support_email': SUPPORT_EMAIL,
        'status_page_url': STATUS_PAGE_URL,
        'error_id': error_id,
        'request_path': request.path,
        'is_authenticated': request.user.is_authenticated if hasattr(request, 'user') else False,
    }


def _is_api_request(request):
    """
    Check if the request is for an API endpoint.

    Args:
        request: The HTTP request object

    Returns:
        bool: True if this is an API request
    """
    return (
        request.path.startswith('/api/') or
        request.content_type == 'application/json' or
        request.META.get('HTTP_ACCEPT', '').startswith('application/json')
    )


def handler400(request, exception=None):
    """
    Handle 400 Bad Request errors.

    This handler is triggered when the request is malformed or invalid.
    Logs the error with request details for debugging.

    Args:
        request: The HTTP request object
        exception: The exception that triggered this error (optional)

    Returns:
        HttpResponse: Rendered 400 error page or JSON response for API
    """
    error_id = str(uuid.uuid4())[:8]

    logger_client.warning(
        'Bad Request (400): %s | Path: %s | Error ID: %s | User: %s | IP: %s',
        str(exception) if exception else 'Unknown',
        request.path,
        error_id,
        getattr(request.user, 'email', 'anonymous') if hasattr(request, 'user') else 'anonymous',
        request.META.get('REMOTE_ADDR', 'unknown'),
    )

    if _is_api_request(request):
        return JsonResponse({
            'error': 'Bad Request',
            'status_code': 400,
            'detail': _('The request was invalid or malformed.'),
            'error_id': error_id,
            'support': SUPPORT_EMAIL,
        }, status=400)

    context = _get_error_context(request, error_id)
    context.update({
        'title': _('Bad Request'),
        'message': _('The request could not be understood by the server.'),
    })

    return render(request, 'errors/400.html', context, status=400)


def handler403(request, exception=None):
    """
    Handle 403 Forbidden errors.

    This handler is triggered when access to a resource is denied.
    Logs the access attempt for security auditing.

    Args:
        request: The HTTP request object
        exception: The exception that triggered this error (optional)

    Returns:
        HttpResponse: Rendered 403 error page or JSON response for API
    """
    error_id = str(uuid.uuid4())[:8]

    logger_client.warning(
        'Forbidden (403): %s | Path: %s | Error ID: %s | User: %s | IP: %s',
        str(exception) if exception else 'Permission denied',
        request.path,
        error_id,
        getattr(request.user, 'email', 'anonymous') if hasattr(request, 'user') else 'anonymous',
        request.META.get('REMOTE_ADDR', 'unknown'),
    )

    if _is_api_request(request):
        return JsonResponse({
            'error': 'Forbidden',
            'status_code': 403,
            'detail': _('You do not have permission to access this resource.'),
            'error_id': error_id,
            'support': SUPPORT_EMAIL,
        }, status=403)

    context = _get_error_context(request, error_id)
    return render(request, 'errors/403.html', context, status=403)


def handler404(request, exception=None):
    """
    Handle 404 Not Found errors.

    This handler is triggered when a requested resource cannot be found.
    Logs the request for analytics and potential broken link detection.

    Args:
        request: The HTTP request object
        exception: The exception that triggered this error (optional)

    Returns:
        HttpResponse: Rendered 404 error page or JSON response for API
    """
    logger_client.info(
        'Not Found (404): %s | Referer: %s | User: %s | IP: %s',
        request.path,
        request.META.get('HTTP_REFERER', 'direct'),
        getattr(request.user, 'email', 'anonymous') if hasattr(request, 'user') else 'anonymous',
        request.META.get('REMOTE_ADDR', 'unknown'),
    )

    if _is_api_request(request):
        return JsonResponse({
            'error': 'Not Found',
            'status_code': 404,
            'detail': _('The requested resource was not found.'),
            'path': request.path,
            'support': SUPPORT_EMAIL,
        }, status=404)

    context = _get_error_context(request)
    return render(request, 'errors/404.html', context, status=404)


def handler429(request, exception=None):
    """
    Handle 429 Too Many Requests errors.

    This handler is triggered when rate limiting kicks in.
    Includes retry information in the response.

    Args:
        request: The HTTP request object
        exception: The exception that triggered this error (optional)

    Returns:
        HttpResponse: Rendered 429 error page or JSON response for API
    """
    # Default retry after 60 seconds
    retry_after = 60

    # Try to get retry_after from exception or headers
    if hasattr(exception, 'wait'):
        retry_after = int(exception.wait)

    logger_client.warning(
        'Rate Limited (429): %s | Path: %s | User: %s | IP: %s | Retry After: %ds',
        str(exception) if exception else 'Rate limit exceeded',
        request.path,
        getattr(request.user, 'email', 'anonymous') if hasattr(request, 'user') else 'anonymous',
        request.META.get('REMOTE_ADDR', 'unknown'),
        retry_after,
    )

    if _is_api_request(request):
        response = JsonResponse({
            'error': 'Too Many Requests',
            'status_code': 429,
            'detail': _('You have exceeded the rate limit. Please wait before making more requests.'),
            'retry_after': retry_after,
            'support': SUPPORT_EMAIL,
        }, status=429)
        response['Retry-After'] = str(retry_after)
        return response

    context = _get_error_context(request)
    context['retry_after'] = retry_after

    response = render(request, 'errors/429.html', context, status=429)
    response['Retry-After'] = str(retry_after)
    return response


def handler500(request):
    """
    Handle 500 Internal Server Error.

    This handler is triggered for unhandled server errors.
    Generates a unique error ID for tracking and logs full error details.

    Args:
        request: The HTTP request object

    Returns:
        HttpResponse: Rendered 500 error page or JSON response for API
    """
    import sys
    import traceback

    error_id = str(uuid.uuid4())[:8]

    # Get exception info
    exc_type, exc_value, exc_tb = sys.exc_info()

    logger_server.error(
        'Internal Server Error (500) | Error ID: %s | Path: %s | User: %s | IP: %s\n%s',
        error_id,
        request.path,
        getattr(request.user, 'email', 'anonymous') if hasattr(request, 'user') else 'anonymous',
        request.META.get('REMOTE_ADDR', 'unknown'),
        ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)) if exc_type else 'No exception info',
    )

    if _is_api_request(request):
        return JsonResponse({
            'error': 'Internal Server Error',
            'status_code': 500,
            'detail': _('An unexpected error occurred. Our team has been notified.'),
            'error_id': error_id,
            'support': SUPPORT_EMAIL,
        }, status=500)

    context = _get_error_context(request, error_id)
    return render(request, 'errors/500.html', context, status=500)


def handler503(request, exception=None, maintenance_info=None):
    """
    Handle 503 Service Unavailable errors.

    This handler is used during maintenance periods or when the service is temporarily unavailable.
    Can include maintenance progress and estimated completion time.

    Args:
        request: The HTTP request object
        exception: The exception that triggered this error (optional)
        maintenance_info: Dict with maintenance details (optional)
            - estimated_completion: String with estimated completion time
            - progress: Integer 0-100 indicating maintenance progress
            - message: Custom maintenance message

    Returns:
        HttpResponse: Rendered 503 error page or JSON response for API
    """
    maintenance_info = maintenance_info or {}

    logger_server.info(
        'Service Unavailable (503): %s | Path: %s | User: %s | IP: %s',
        str(exception) if exception else 'Maintenance mode',
        request.path,
        getattr(request.user, 'email', 'anonymous') if hasattr(request, 'user') else 'anonymous',
        request.META.get('REMOTE_ADDR', 'unknown'),
    )

    if _is_api_request(request):
        response_data = {
            'error': 'Service Unavailable',
            'status_code': 503,
            'detail': maintenance_info.get('message', _('The service is temporarily unavailable. Please try again later.')),
            'status_page': STATUS_PAGE_URL,
            'support': SUPPORT_EMAIL,
        }
        if 'estimated_completion' in maintenance_info:
            response_data['estimated_completion'] = maintenance_info['estimated_completion']

        response = JsonResponse(response_data, status=503)
        response['Retry-After'] = str(maintenance_info.get('retry_after', 300))  # Default 5 minutes
        return response

    context = _get_error_context(request)
    context.update({
        'estimated_completion': maintenance_info.get('estimated_completion'),
        'maintenance_progress': maintenance_info.get('progress', 0),
        'maintenance_message': maintenance_info.get('message'),
        'refresh_interval': maintenance_info.get('refresh_interval', 60),
    })

    response = render(request, 'errors/503.html', context, status=503)
    response['Retry-After'] = str(maintenance_info.get('retry_after', 300))
    return response


# Convenience function to render maintenance page manually
def render_maintenance_page(request, estimated_completion=None, progress=0, message=None):
    """
    Render a maintenance page with custom information.

    This can be called directly from views or middleware to display maintenance mode.

    Args:
        request: The HTTP request object
        estimated_completion: String with estimated completion time
        progress: Integer 0-100 indicating maintenance progress
        message: Custom maintenance message

    Returns:
        HttpResponse: Rendered 503 maintenance page
    """
    return handler503(request, maintenance_info={
        'estimated_completion': estimated_completion,
        'progress': progress,
        'message': message,
    })
