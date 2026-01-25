"""
Blog Frontend Template Views
==============================

Frontend HTML views for the blog application following URL_AND_VIEW_CONVENTIONS.md.

Most blog routing is handled automatically by Wagtail via Page.serve() methods:
- /blog/ → BlogIndexPage.serve()
- /blog/<slug>/ → BlogPostPage.serve()
- /blog/category/<slug>/ → CategoryPage.serve()

This module provides auxiliary template views:
- blog_search_view: Multi-criteria search (text, category, tag)
- submit_comment: Comment submission with CSRF validation

All views render HTML templates using Django's render().

URL Namespace: frontend:blog:*
"""

from django.shortcuts import render
from wagtail.models import Page
from .models import BlogPostPage, BlogIndexPage, CategoryPage, Comment

# Wagtail handles routing automatically via Page.serve() method
# These views are backup/auxiliary views if needed

def blog_list_view(request):
    """
    Alternative view to display blog post list.

    Note: This view is rarely used because Wagtail handles the main routing
    via BlogIndexPage.serve() and BlogIndexPage.get_context() which includes
    pagination, filters, and sidebar context.

    This view can serve as backup or for special use cases where you
    want to display a list of posts outside the Wagtail tree.

    Args:
        request: HttpRequest object

    Returns:
        HttpResponse with template 'blog/list.html'

    Context:
        posts: QuerySet of all published BlogPostPage, sorted by date

    Example:
        # In urls.py if you want a custom endpoint:
        path('all-posts/', blog_list_view, name='all_posts')
    """
    # Get all live (published) and public posts
    # .live() = Wagtail active status
    # .public() = publicly visible (no page restriction)
    posts = BlogPostPage.objects.live().public().order_by('-first_published_at')

    context = {
        'posts': posts,
    }
    return render(request, 'blog/list.html', context)


def blog_search_view(request):
    """
    Multi-criteria search view for blog posts.

    Allows searching posts by:
    - Free text (search in title and excerpt)
    - Category (CategoryPage ID)
    - Tag (tag slug)

    Criteria can be combined to refine the search.

    Query Parameters:
        q (str, optional): Search text (case-insensitive)
        category (int, optional): CategoryPage ID
        tag (str, optional): Tag slug
        page (int, optional): Page number for pagination (default: 1)

    Returns:
        HttpResponse with template 'blog/search_results.html'

    Context:
        posts: Page object (paginated queryset) of BlogPostPage
        query: Search text (for redisplay in form)
        category_id: Category ID (for redisplay)
        tag_slug: Tag slug (for redisplay)
        total_results: Total number of results
        recent_posts: 5 latest posts (sidebar)
        categories: All CategoryPage (sidebar)
        popular_tags: 10 most popular tags (sidebar)

    Example URLs:
        /blog/search/?q=django
        /blog/search/?category=5
        /blog/search/?tag=python
        /blog/search/?q=tutorial&tag=django&page=2
    """
    from django.db.models import Q
    from django.core.paginator import Paginator

    # Get search parameters from GET
    query = request.GET.get('q', '')  # Free text
    category_id = request.GET.get('category')  # Category ID
    tag_slug = request.GET.get('tag')  # Tag slug

    # Base queryset: all live posts with status='published'
    # Note: .live() filters on Wagtail live=True, we add status='published'
    # to filter on our custom workflow field
    posts = BlogPostPage.objects.live().filter(status='published')

    # FILTER 1: Text search (case-insensitive)
    # Search in title AND excerpt with OR (Q object)
    if query:
        posts = posts.filter(
            Q(title__icontains=query) |
            Q(excerpt__icontains=query)
        )

    # FILTER 2: Filter by category
    # Uses descendant_of() to include posts in child categories
    if category_id:
        try:
            category = CategoryPage.objects.get(pk=category_id)
            # descendant_of() = posts that are descendants of this category
            posts = posts.descendant_of(category)
        except CategoryPage.DoesNotExist:
            # If invalid category, return empty queryset
            posts = posts.none()

    # FILTER 3: Filter by tag
    # tags is a ManyToMany relation via ClusterTaggableManager
    if tag_slug:
        posts = posts.filter(tags__slug=tag_slug)

    # Sort: most recent first
    posts = posts.order_by('-first_published_at')

    # Pagination: 10 posts per page
    paginator = Paginator(posts, 10)
    page_number = request.GET.get('page', 1)
    # get_page() handles invalid numbers automatically (returns page 1 or last)
    page_obj = paginator.get_page(page_number)

    # Prepare template context with sidebar data
    from taggit.models import Tag
    from django.db.models import Count

    context = {
        # Paginated search results
        'posts': page_obj,

        # Search parameters (for redisplay in form and pagination links)
        'query': query,
        'category_id': category_id,
        'tag_slug': tag_slug,
        'total_results': paginator.count,  # Total number (for "Found X results")

        # Sidebar: Recent posts (5 latest, independent of search)
        'recent_posts': BlogPostPage.objects.live().filter(
            status='published'
        ).order_by('-first_published_at')[:5],

        # Sidebar: Category list (all)
        'categories': CategoryPage.objects.live(),

        # Sidebar: Popular tags (top 10 by post count)
        # Note: complex relation via taggit - filter on live+published posts
        # then count and sort
        'popular_tags': Tag.objects.filter(
            blog_blogposttag_items__content_object__live=True,  # Post is live
            blog_blogposttag_items__content_object__status='published'  # AND published
        ).distinct().annotate(
            post_count=Count('blog_blogposttag_items')  # Count posts
        ).order_by('-post_count')[:10],  # Top 10
    }

    return render(request, 'blog/search_results.html', context)


from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages
from .forms import CommentForm


def submit_comment(request, post_id):
    """
    Handle comment submission on a blog post.

    This view only processes POST requests from the comment form
    in the blog-detail1.html template. It validates data,
    sanitizes HTML, and creates the comment in the database.

    Security:
        - CSRF token required (handled by Django middleware)
        - HTML sanitization via CommentForm.clean_content()
        - Author name validation via CommentForm.clean_author_name()

    Args:
        request: HttpRequest object (must be POST)
        post_id: ID of the BlogPostPage to comment on

    Returns:
        HttpResponseRedirect to:
        - The article with anchor #form-review if success
        - The article without anchor if error
        - Homepage if non-POST method

    Messages:
        Uses Django messages framework for user feedback:
        - success: "Your comment has been posted successfully!"
        - error: "There was an error posting your comment..."

    Form Fields:
        - author_name: Commenter name (required, sanitized)
        - content: Comment content (required, sanitized)
        - parent: Parent comment ID (optional, for threading)

    Example Template Form:
        <form method="POST" action="{% url 'blog:submit_comment' page.id %}">
            {% csrf_token %}
            {{ comment_form.author_name }}
            {{ comment_form.content }}
            {{ comment_form.parent }}  {# hidden field #}
            <button type="submit">Post Comment</button>
        </form>

    Threading:
        To create a reply, include the parent comment ID:
        <input type="hidden" name="parent" value="{{ parent_comment.id }}">
    """
    # Security: only accept POST (submitted form)
    # GET requests are redirected to homepage
    if request.method != 'POST':
        return redirect('/')

    # Get post or 404 if non-existent
    # Use BlogPostPage directly (no need for .live() for staff)
    post = get_object_or_404(BlogPostPage, id=post_id)

    # Validate form data
    form = CommentForm(request.POST)

    if form.is_valid():
        # Don't save immediately (commit=False)
        # to manually add post_id
        comment = form.save(commit=False)
        comment.post = post  # Link comment to post
        comment.save()  # Now save

        # Success message (displayed in template via {% if messages %})
        messages.success(request, 'Your comment has been posted successfully!')

        # Redirect with anchor #form-review for automatic scroll
        # to form (visual feedback)
        return redirect(f"{post.url}#form-review")
    else:
        # Validation failed (empty fields, malicious HTML, etc.)
        messages.error(request, 'There was an error posting your comment. Please try again.')

        # Redirect to post (no anchor) to display errors
        # Note: form errors are not persisted here
        # To display errors, would need to pass form via session
        return redirect(post.url)
