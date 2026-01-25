"""
Blog Models - Wagtail CMS Integration
======================================

This module contains all blog application models, integrated with Wagtail CMS.

Models:
-------
- UserProfile: Django User model extension with avatar, bio and followers
- BlogPostPage: Wagtail Page for blog posts with StreamField for rich content
- BlogIndexPage: Wagtail Page for blog post listing with pagination
- CategoryPage: Wagtail Page to organize posts by category
- Comment: Django model for comments with threading support (parent/child)
- BlogPostTag: Linking model for tags via taggit

StreamField Blocks:
-------------------
- RichTextCellBlock: Table cell with rich text
- TableRowBlock: Table row with list of cells
- CustomTableBlock: Complete table with headers and rows
- QuoteBlock: Quote with optional author and source

Features:
---------
- View tracking with thread-safe counter
- Multi-language support via i18n
- SEO optimized with meta_title and meta_description
- Rich content editing via StreamField
- Comments with threading (replies)
- Hierarchical tags and categories
- Audit logging for all modifications

Author: Zumodra Development Team
Date: 2026-01-24
"""

from django.db import models
from wagtail.models import Page
from wagtail.fields import RichTextField
from wagtail.admin.panels import FieldPanel, MultiFieldPanel
from modelcluster.tags import ClusterTaggableManager
from modelcluster.fields import ParentalKey
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _
from wagtail.fields import StreamField
from wagtail import blocks
from wagtail.images.blocks import ImageBlock


# ============================================================================
# USER PROFILE EXTENSION
# ============================================================================

class UserProfile(models.Model):
    """
    Django User model extension to add profile information.

    This model extends Django's standard User model to include:
    - Avatar: Profile image uploaded via Wagtail
    - Bio: User biography/description
    - Followers count: Number of followers (for statistics)

    Relations:
    ----------
    - user: OneToOne with Django User (auto-created via signals)
    - avatar: ForeignKey to Wagtail Image

    Usage:
    ------
    >>> user = User.objects.get(username='john')
    >>> profile = user.profile  # Auto-created via signals
    >>> profile.bio = "Developer and blogger"
    >>> profile.save()

    Signals:
    --------
    UserProfile is automatically created when a User is created
    via the post_save signal in blog.signals.

    Audit:
    ------
    All modifications are tracked via django-auditlog.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    avatar = models.ForeignKey(
        'wagtailimages.Image',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='+',
        help_text="Profile photo"
    )
    bio = models.TextField(blank=True)
    followers_count = models.IntegerField(default=0)

    def __str__(self):
        return f"Profile of {self.user.get_full_name() or self.user.username}"


# ============================================================================
# STREAMFIELD BLOCKS - Reusable content components
# ============================================================================

class RichTextCellBlock(blocks.RichTextBlock):
    """
    Table cell block with RichText support.

    Allows inserting formatted text in table cells,
    including bold, italic, links, etc.
    """
    pass


class TableRowBlock(blocks.StructBlock):
    """
    Block representing a table row.

    Contains a list of RichTextCellBlock cells.
    Used as a component in CustomTableBlock.
    """
    cells = blocks.ListBlock(RichTextCellBlock())


class CustomTableBlock(blocks.StructBlock):
    """
    Custom table block with headers and rows.

    Structure:
    ----------
    - header: List of strings for column headers
    - rows: List of TableRowBlock for data rows

    Template usage:
    ---------------
    {% if block.block_type == 'table' %}
        <table>
            <thead>
                {% for header in block.value.header %}
                <th>{{ header }}</th>
                {% endfor %}
            </thead>
            <tbody>
                {% for row in block.value.rows %}
                <tr>
                    {% for cell in row.cells %}
                    <td>{{ cell|safe }}</td>
                    {% endfor %}
                </tr>
                {% endfor %}
            </tbody>
        </table>
    {% endif %}
    """
    header = blocks.ListBlock(blocks.CharBlock())
    rows = blocks.ListBlock(TableRowBlock())


class QuoteBlock(blocks.StructBlock):
    """
    Quote block with optional author and source.

    Fields:
    -------
    - quote: Quote text (required, BlockQuoteBlock)
    - author: Author name (optional, RichTextBlock)
    - source: Quote source (optional, RichTextBlock)

    Display:
    --------
    The block displays with a left border and special styling
    in the blog-detail1.html template.

    Usage:
    ------
    The Wagtail editor displays an "openquote" icon in the StreamField menu.
    """
    quote = blocks.BlockQuoteBlock(required=True, help_text="Quote text")
    author = blocks.RichTextBlock(required=False, help_text="Quote author")
    source = blocks.RichTextBlock(required=False, help_text="Quote source")

    class Meta:
        icon = "openquote"

# ============================================================================
# BLOG POST PAGE - Main blog article
# ============================================================================

class BlogPostPage(Page):
    """
    Wagtail Page representing a complete blog post.

    This page uses Wagtail CMS to provide a rich editing interface
    with StreamField, tags, categories, and publication status management.

    Fields:
    -------
    - title: Inherited from Page (article title)
    - body: StreamField with support for multiple content types
    - excerpt: Short summary (max 300 characters)
    - featured_image: Main article image
    - status: Publication status (draft, scheduled, finished, published)
    - meta_title: SEO title (optional, overrides title)
    - meta_description: SEO description
    - publishing_date: Scheduled/actual publication date
    - tags: Multiple tags via django-taggit
    - view_count: View counter (auto-incremented, non-editable)

    StreamField Block Types:
    ------------------------
    - heading, heading2-6: Different heading levels
    - paragraph: Rich text paragraph
    - ordered_list: Numbered list
    - unordered_list: Bulleted list
    - image: Image with caption
    - quote: Quote with author
    - table: Table with headers and rows

    Publication Status:
    -------------------
    - draft: Draft (not publicly visible)
    - scheduled: Scheduled for future publication
    - finished: Finished (pending approval)
    - published: Published (publicly visible)

    Relations:
    ----------
    - comments: Associated comments (reverse FK from Comment)
    - tags: Multiple tags (M2M via ClusterTaggableManager)
    - featured_image: Main image (FK to Wagtail Image)

    Methods:
    --------
    - increment_view_count(): Increment view counter (thread-safe)
    - serve(): Override to track views automatically
    - get_context(): Add additional context for template

    Template:
    ---------
    Uses blog/blog-detail1.html with enriched context including:
    - comment_form: Comment submission form
    - comments: Top-level comments with replies
    - recent_posts: 5 recent posts for sidebar
    - related_posts: Similar posts by tags (max 4)
    - previous_post, next_post: Article navigation
    - category: Parent category (if applicable)
    - read_time: Estimated reading time (200 words/min)

    URLs:
    -----
    Frontend: /<lang>/<blog-slug>/<article-slug>/
    API: /api/v1/blog/posts/<id>/

    Audit:
    ------
    All modifications are tracked via django-auditlog.

    Examples:
    ---------
    >>> # Create post via code
    >>> from blog.models import BlogPostPage, BlogIndexPage
    >>> blog_index = BlogIndexPage.objects.first()
    >>> post = BlogPostPage(
    ...     title="My first post",
    ...     excerpt="This is a summary",
    ...     status='published'
    ... )
    >>> blog_index.add_child(instance=post)
    >>> post.save_revision().publish()

    >>> # Access statistics
    >>> post.view_count  # Number of views
    >>> post.comments.count()  # Number of comments
    >>> post.tags.all()  # List of tags
    """
    template = "blog/blog-detail1.html"

    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('scheduled', 'Scheduled'),
        ('finished', 'Finished'),
        ('published', 'Published'),
    ]
    body = StreamField([
        ('heading', blocks.RichTextBlock(form_classname="title")),
        ('heading2', blocks.RichTextBlock(form_classname="title2")),
        ('heading3', blocks.RichTextBlock(form_classname="title3")),
        ('heading4', blocks.RichTextBlock(form_classname="title4")),
        ('heading5', blocks.RichTextBlock(form_classname="title5")),
        ('heading6', blocks.RichTextBlock(form_classname="title6")),
        ('ordered_list', blocks.ListBlock(blocks.RichTextBlock(), icon="list-ol")),
        ('unordered_list', blocks.ListBlock(blocks.RichTextBlock(), icon="list-ul")),
        ('paragraph', blocks.RichTextBlock()),
        ('image', ImageBlock()),
        ('quote', QuoteBlock()),
        ('table', CustomTableBlock()),
    ], null=True, blank=True)
    excerpt = models.TextField(max_length=300, blank=True)
    featured_image = models.ForeignKey(
        'wagtailimages.Image',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='+',
        help_text="Main article image"
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='draft')
    meta_title = models.CharField(max_length=200, blank=True)
    meta_description = models.TextField(blank=True)
    publishing_date = models.DateTimeField(null=True, blank=True)
    tags = ClusterTaggableManager(through='BlogPostTag', blank=True)
    view_count = models.IntegerField(default=0, editable=False)

    content_panels = Page.content_panels + [
        FieldPanel("body"),
        FieldPanel("excerpt"),
        FieldPanel("featured_image"),
        FieldPanel("status"),
        FieldPanel("publishing_date"),
        FieldPanel("tags"),
    ]

    promote_panels = Page.promote_panels + [
        MultiFieldPanel([
            FieldPanel("meta_title"),
            FieldPanel("meta_description"),
        ], heading="SEO"),
    ]

    def increment_view_count(self):
        """
        Increment view counter in a thread-safe manner.

        Uses Django F() expressions to avoid race conditions
        during concurrent counter updates.

        Thread-Safety:
        --------------
        This method is thread-safe because it uses:
        1. UPDATE with F() expression (atomic DB operation)
        2. filter().update() instead of save() (no SELECT before UPDATE)

        Note:
        -----
        After the call, self.view_count will contain F('view_count').
        Use refresh_from_db() to get the actual value.

        Example:
        --------
        >>> post.increment_view_count()
        >>> post.refresh_from_db(fields=['view_count'])
        >>> print(post.view_count)  # Actual value from DB
        """
        from django.db.models import F
        BlogPostPage.objects.filter(pk=self.pk).update(view_count=F('view_count') + 1)
        self.view_count = F('view_count')

    def serve(self, request):
        """
        Override Wagtail's serve() method to track views.

        This method is automatically called by Wagtail on every
        request to this page. The view counter is incremented
        before serving the page.

        Parameters:
        -----------
        request: HttpRequest
            The incoming HTTP request

        Returns:
        --------
        HttpResponse
            The HTTP response generated by the template

        Flow:
        -----
        1. Increment view_count (thread-safe)
        2. Call super().serve() for normal rendering
        3. Return response to client

        Note:
        -----
        This method is called for every page visit, including
        by bots. For more accurate tracking, consider filtering
        user-agents or using Google Analytics.
        """
        self.increment_view_count()
        return super().serve(request)

    def get_context(self, request):
        """
        Add additional context for the detail template.

        This method overrides Wagtail's get_context() to inject
        additional data used in the blog-detail1.html template.

        Parameters:
        -----------
        request: HttpRequest
            The incoming HTTP request

        Returns:
        --------
        dict
            Template context including:
            - page: BlogPostPage instance (inherited)
            - comment_form: CommentForm instance (empty)
            - comments: QuerySet of top-level comments
            - comment_count: Total number of comments
            - recent_posts: 5 recent posts (excludes current)
            - related_posts: Similar posts by tags (max 4)
            - previous_post: Previous article (or None)
            - next_post: Next article (or None)
            - category: Parent CategoryPage (or None)
            - read_time: Reading time in minutes
            - view_count: Number of views (refreshed from DB)

        Logic:
        ------
        1. Get parent context (includes 'page')
        2. Add comment form
        3. Load comments with their replies
        4. Find similar posts by tags
        5. Calculate prev/next navigation
        6. Estimate reading time
        7. Refresh view_count from DB

        Performance:
        ------------
        - Comments: 1 query (filter + order_by)
        - Recent posts: 1 query with exclusion
        - Related posts: 1-2 queries (depends on tags presence)
        - Siblings: 1 query with list conversion
        - Total: ~5-6 DB queries per page load

        Example returned context:
        -------------------------
        {
            'page': <BlogPostPage object>,
            'comment_form': <CommentForm object>,
            'comments': <QuerySet [Comment1, Comment2]>,
            'comment_count': 12,
            'recent_posts': <QuerySet [Post1, Post2, Post3, Post4, Post5]>,
            'related_posts': <QuerySet [Post6, Post7, Post8, Post9]>,
            'previous_post': <BlogPostPage object> or None,
            'next_post': <BlogPostPage object> or None,
            'category': <CategoryPage object> or None,
            'read_time': 5,  # minutes
            'view_count': 1234,
        }
        """
        context = super().get_context(request)

        # Comment form
        from .forms import CommentForm
        context['comment_form'] = CommentForm()

        # Comments (top-level only, replies via template)
        context['comments'] = self.comments.filter(parent=None).order_by('-created_at')
        context['comment_count'] = self.comments.count()

        # Recent posts for sidebar (exclude current article)
        context['recent_posts'] = BlogPostPage.objects.live().filter(
            status='published'
        ).exclude(id=self.id).order_by('-first_published_at')[:5]

        # Similar posts by tags
        if self.tags.exists():
            context['related_posts'] = BlogPostPage.objects.live().filter(
                tags__in=self.tags.all(),
                status='published'
            ).exclude(id=self.id).distinct()[:4]
        else:
            context['related_posts'] = []

        # Previous/next navigation
        siblings = self.get_siblings().live().filter(status='published').order_by('first_published_at')
        try:
            siblings_list = list(siblings)
            current_index = siblings_list.index(self)
            context['previous_post'] = siblings_list[current_index - 1] if current_index > 0 else None
            context['next_post'] = siblings_list[current_index + 1] if current_index < len(siblings_list) - 1 else None
        except (ValueError, IndexError):
            context['previous_post'] = None
            context['next_post'] = None

        # Category (parent page if CategoryPage)
        parent = self.get_parent().specific
        context['category'] = parent if isinstance(parent, CategoryPage) else None

        # Calculate reading time (200 words/min)
        if self.body:
            word_count = sum(len(str(block.value).split()) for block in self.body)
            context['read_time'] = max(1, round(word_count / 200))
        else:
            context['read_time'] = 1

        # Refresh view_count from DB
        self.refresh_from_db(fields=['view_count'])

        return context

class CategoryPage(Page):
    description = models.TextField(blank=True)
    
    content_panels = Page.content_panels + [
        FieldPanel("description"),
    ]

    parent_page_types = ['blog.BlogIndexPage']
    subpage_types = ['blog.CategoryPage', 'blog.BlogPostPage']


class BlogIndexPage(Page):
    intro = RichTextField(blank=True)

    content_panels = Page.content_panels + [
        FieldPanel("intro"),
    ]

    # parent_page_types = ['wagtailcore.Page']

    subpage_types = ['blog.BlogPostPage', 'blog.CategoryPage']

    template = "blog/blog-default.html"

    def get_context(self, request):
        """Add pagination and filters."""
        from django.core.paginator import Paginator
        from taggit.models import Tag
        from django.db.models import Count

        context = super().get_context(request)

        # All published posts
        posts = BlogPostPage.objects.live().filter(
            status='published'
        ).order_by('-first_published_at')

        # Pagination (10 posts per page)
        paginator = Paginator(posts, 10)
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)

        context['posts'] = page_obj

        # Recent posts for sidebar
        context['recent_posts'] = posts[:5]

        # Categories for sidebar
        context['categories'] = CategoryPage.objects.live().child_of(self)

        # Popular tags for sidebar
        context['popular_tags'] = Tag.objects.filter(
            blog_blogposttag_items__content_object__live=True,
            blog_blogposttag_items__content_object__status='published'
        ).distinct().annotate(
            post_count=Count('blog_blogposttag_items')
        ).order_by('-post_count')[:10]

        return context


class Comment(models.Model):
    post = models.ForeignKey(
        'blog.BlogPostPage',
        related_name='comments',
        on_delete=models.CASCADE
    )
    author_name = models.CharField(max_length=120, default='', blank=True)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    parent = models.ForeignKey(
        'self',
        null=True, blank=True,
        related_name='replies',
        on_delete=models.CASCADE
    )

    def __str__(self):
        return f"{self.author_name} - {self.post.title}"


from modelcluster.fields import ParentalKey
from modelcluster.tags import ClusterTaggableManager
from taggit.models import TaggedItemBase

class BlogPostTag(TaggedItemBase):
    content_object = ParentalKey(
        'BlogPostPage',
        related_name='tagged_items',
        on_delete=models.CASCADE
    )

from auditlog.registry import auditlog

auditlog.register(UserProfile)
auditlog.register(BlogPostPage)
auditlog.register(Comment)
auditlog.register(CategoryPage)