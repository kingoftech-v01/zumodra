"""
Blog views - Using Wagtail CMS
All blog functionality is handled by Wagtail Page models.
"""

from django.shortcuts import render
from wagtail.models import Page
from .models import BlogPostPage, BlogIndexPage, CategoryPage, Comment

# Wagtail handles routing automatically via Page.serve() method
# These views are backup/auxiliary views if needed

def blog_list_view(request):
    """
    Alternative blog list view (Wagtail BlogIndexPage.get_context handles this normally)
    """
    posts = BlogPostPage.objects.live().public().order_by('-first_published_at')

    context = {
        'posts': posts,
    }
    return render(request, 'blog/blog-list.html', context)


def blog_search_view(request):
    """
    Blog search functionality
    """
    query = request.GET.get('q', '')
    posts = BlogPostPage.objects.live().public()

    if query:
        posts = posts.search(query)

    context = {
        'posts': posts,
        'query': query,
    }
    return render(request, 'blog/blog-search.html', context)
