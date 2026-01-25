"""
Views for Zumodra frontend-only project.
All views simply render templates without any backend logic.
"""

from django.shortcuts import render


# Error handlers
def handler404(request, exception):
    """Custom 404 error page"""
    return render(request, 'errors/error-404.html', status=404)


def handler500(request):
    """Custom 500 error page"""
    return render(request, 'errors/error-500.html', status=500)
