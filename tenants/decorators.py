"""
Tenant-aware decorators for view access control.

This module provides decorators for restricting view access based on tenant type.
"""

from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.utils.translation import gettext_lazy as _
from rest_framework.response import Response
from rest_framework import status


def require_tenant_type(*allowed_types):
    """
    Decorator to restrict view access by tenant type.

    Works for both function-based views and class-based views (via dispatch method).

    Args:
        *allowed_types: One or more tenant type strings ('company', 'freelancer')

    Usage:
        For function-based views:
            @require_tenant_type('company')
            def create_job_view(request):
                ...

        For class-based views:
            @require_tenant_type('company')
            class JobCreateView(CreateView):
                ...

    Example:
        @require_tenant_type('company')  # Only companies can create jobs
        def create_job_posting(request):
            return render(request, 'ats/job_create.html')
    """
    def decorator(view_func_or_class):
        # Check if it's a class-based view
        if isinstance(view_func_or_class, type):
            # It's a class - wrap the dispatch method
            original_dispatch = view_func_or_class.dispatch

            @wraps(original_dispatch)
            def dispatch_wrapper(self, request, *args, **kwargs):
                # Validate tenant type
                if not hasattr(request, 'tenant') or not request.tenant:
                    messages.error(request, _('You must be part of a tenant.'))
                    return redirect('dashboard')

                if request.tenant.tenant_type not in allowed_types:
                    type_names = ', '.join(allowed_types)
                    messages.error(
                        request,
                        _(f'This feature is only available for {type_names} tenants.')
                    )
                    return redirect('dashboard')

                return original_dispatch(self, request, *args, **kwargs)

            view_func_or_class.dispatch = dispatch_wrapper
            return view_func_or_class
        else:
            # It's a function-based view
            @wraps(view_func_or_class)
            def wrapper(request, *args, **kwargs):
                # Validate tenant type
                if not hasattr(request, 'tenant') or not request.tenant:
                    messages.error(request, _('You must be part of a tenant.'))
                    return redirect('dashboard')

                if request.tenant.tenant_type not in allowed_types:
                    type_names = ', '.join(allowed_types)
                    messages.error(
                        request,
                        _(f'This feature is only available for {type_names} tenants.')
                    )
                    return redirect('dashboard')

                return view_func_or_class(request, *args, **kwargs)

            return wrapper

    return decorator


def require_tenant_type_api(*allowed_types):
    """
    Decorator to restrict API view access by tenant type.

    Returns HTTP 403 Forbidden with JSON error instead of redirecting.
    Designed for DRF API views.

    Args:
        *allowed_types: One or more tenant type strings ('company', 'freelancer')

    Usage:
        @require_tenant_type_api('company')
        @api_view(['POST'])
        def create_job_api(request):
            ...

    Example:
        @require_tenant_type_api('company')
        class JobViewSet(viewsets.ModelViewSet):
            ...
    """
    def decorator(view_func_or_class):
        # Check if it's a class-based view (ViewSet)
        if isinstance(view_func_or_class, type):
            # Wrap dispatch or individual action methods
            # For ViewSets, we need to wrap actions
            if hasattr(view_func_or_class, 'action_map'):
                # It's a ViewSet - wrap the dispatch
                original_dispatch = view_func_or_class.dispatch

                @wraps(original_dispatch)
                def dispatch_wrapper(self, request, *args, **kwargs):
                    if not hasattr(request, 'tenant') or not request.tenant:
                        return Response(
                            {'error': 'You must be part of a tenant.'},
                            status=status.HTTP_403_FORBIDDEN
                        )

                    if request.tenant.tenant_type not in allowed_types:
                        type_names = ', '.join(allowed_types)
                        return Response(
                            {'error': f'This feature is only available for {type_names} tenants.'},
                            status=status.HTTP_403_FORBIDDEN
                        )

                    return original_dispatch(self, request, *args, **kwargs)

                view_func_or_class.dispatch = dispatch_wrapper
            return view_func_or_class
        else:
            # It's a function-based API view
            @wraps(view_func_or_class)
            def wrapper(request, *args, **kwargs):
                if not hasattr(request, 'tenant') or not request.tenant:
                    return Response(
                        {'error': 'You must be part of a tenant.'},
                        status=status.HTTP_403_FORBIDDEN
                    )

                if request.tenant.tenant_type not in allowed_types:
                    type_names = ', '.join(allowed_types)
                    return Response(
                        {'error': f'This feature is only available for {type_names} tenants.'},
                        status=status.HTTP_403_FORBIDDEN
                    )

                return view_func_or_class(request, *args, **kwargs)

            return wrapper

    return decorator
