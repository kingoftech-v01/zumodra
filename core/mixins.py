"""
Core View Mixins

Reusable view mixins for Django class-based views.
"""
from django.views.generic.base import ContextMixin


class HTMXMixin:
    """
    Mixin to handle HTMX requests gracefully.

    If request has HX-Request header, returns partial template.
    Sets appropriate HTMX response headers.

    Usage:
        class MyView(HTMXMixin, ListView):
            template_name = 'app/full_page.html'
            partial_template_name = 'app/partials/_list.html'
    """

    partial_template_name = None

    def get_template_names(self):
        """Return partial template for HTMX requests."""
        if self.request.headers.get('HX-Request') and self.partial_template_name:
            return [self.partial_template_name]
        return super().get_template_names()


class TenantContextMixin(ContextMixin):
    """
    Mixin to add tenant context to views.

    Automatically adds tenant object to template context.
    """

    def get_context_data(self, **kwargs):
        """Add tenant to context"""
        context = super().get_context_data(**kwargs)

        if hasattr(self.request, 'tenant'):
            context['tenant'] = self.request.tenant

        return context


class BreadcrumbMixin(ContextMixin):
    """
    Mixin to add breadcrumb navigation to views.

    Set breadcrumbs as a list of tuples: [(title, url), ...]
    """

    breadcrumbs = []

    def get_breadcrumbs(self):
        """Get breadcrumbs for this view"""
        return self.breadcrumbs

    def get_context_data(self, **kwargs):
        """Add breadcrumbs to context"""
        context = super().get_context_data(**kwargs)
        context['breadcrumbs'] = self.get_breadcrumbs()
        return context
