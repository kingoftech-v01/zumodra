"""
Blog URLs Configuration
========================

URL configuration for the blog application. Most routing is handled
automatically by Wagtail via the page tree, these URLs are complements
for specific features (search, comments).

Namespace: 'blog'

Defined URLs:
-------------
- blog:search - Multi-criteria search (text, category, tag)
- blog:submit_comment - Comment submission (POST only)

Wagtail URLs (Automatic):
--------------------------
These URLs are handled by Wagtail and are NOT in this file:
- /blog/ → BlogIndexPage.serve()
- /blog/<slug>/ → BlogPostPage.serve()
- /blog/category/<slug>/ → CategoryPage.serve()

Template Usage:
---------------
{% url 'blog:search' %} → /blog/search/
{% url 'blog:submit_comment' post.id %} → /blog/comment/123/

Integration:
------------
These URLs are included in the main urls.py file via:
path('blog/', include('blog.urls', namespace='blog'))

Note: The 'blog/' prefix comes from the main file, not here.
"""

from django.urls import path
from .views import blog_list_view, blog_search_view, submit_comment

# Namespace for reverse() and {% url %} tags
app_name = 'blog'

urlpatterns = [
    # Multi-criteria search
    # GET /blog/search/?q=text&category=id&tag=slug&page=num
    path('search/', blog_search_view, name='search'),

    # Comment submission (POST only)
    # POST /blog/comment/123/ with form data
    path('comment/<int:post_id>/', submit_comment, name='submit_comment'),

    # Note: Main routing (/blog/, /blog/post-slug/) is handled by Wagtail
    # via the page tree in the main urls.py file
]
