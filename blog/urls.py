"""
Blog URLs - Wagtail handles most routing automatically
"""

from django.urls import path
from .views import blog_list_view, blog_search_view

app_name = 'blog'

urlpatterns = [
    # Optional: Auxiliary views (Wagtail handles main routing)
    path('search/', blog_search_view, name='search'),
    # Main blog routing is handled by Wagtail in main urls.py
]
