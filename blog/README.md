# Blog App

## Overview

The Blog app provides Wagtail CMS-based content management for marketing and company updates on the Zumodra platform. It enables content creators to publish rich blog posts with custom blocks, organize content by categories, and manage a complete publishing workflow from draft to publication.

## Key Features

### Completed Features

- **Rich Content Editing**: Wagtail StreamField with custom blocks (headings, paragraphs, images, quotes, tables, lists)
- **Publishing Workflow**: Four-stage status system (draft, scheduled, finished, published)
- **Category Management**: Hierarchical categories with nested support
- **Tag System**: Tagging with tag-based filtering and popular tags tracking
- **Comment System**: Threaded comments with nested replies and HTML sanitization
- **Image Management**: Featured images with responsive renditions (thumbnail, medium, large)
- **SEO Optimization**: Custom meta titles and descriptions per post
- **Search Functionality**: Full-text search across titles and excerpts with multi-criteria filtering
- **REST API**: Complete API for blog integration with other apps
- **Caching**: Tenant-aware caching for improved performance
- **Audit Logging**: Automatic change tracking for posts, comments, categories, and user profiles
- **User Profiles**: Extended user model with avatars, bios, and follower counts
- **View Tracking**: Thread-safe view counter with automatic increment on page serve
- **Comment Forms**: Django forms with CSRF protection and validation
- **Dynamic Templates**: Fully dynamic templates rendering real data from database
- **Reading Time**: Automatic calculation of reading time based on word count

### Recently Implemented (January 2026)

- ✅ **UserProfile Model**: Extended user profiles with avatars and bios
- ✅ **View Tracking System**: Thread-safe view counter with F() expressions
- ✅ **Dynamic Templates**: Converted all static templates to fully dynamic rendering
- ✅ **Comment Form**: Django form with CSRF protection and HTML sanitization
- ✅ **Search Functionality**: Multi-criteria search (text, category, tag)
- ✅ **Reading Time**: Automatic calculation based on word count (200 words/min)
- ✅ **Navigation**: Previous/next post navigation in detail template
- ✅ **Related Posts**: Tag-based related posts algorithm
- ✅ **Comprehensive Documentation**: Docstrings and comments throughout codebase
- ✅ **Template Pagination**: Django Paginator with proper page range display

### In Development

- Enhanced SEO analytics and optimization
- Advanced category taxonomy (tags + categories)
- Editorial calendar view
- Content scheduling automation
- Social media sharing integration
- Related posts algorithm improvements
- Comment moderation queue

## Architecture

### Models

Located in `blog/models.py`:

| Model | Description | Key Fields |
|-------|-------------|------------|
| **UserProfile** | Extended user profiles | user, avatar (ForeignKey to Image), bio, followers_count |
| **BlogPostPage** | Main blog post content | title, slug, body (StreamField), excerpt, featured_image, status, meta_title, meta_description, publishing_date, tags, view_count |
| **BlogIndexPage** | Blog homepage/listing | title, intro (RichText), contains all blog posts |
| **CategoryPage** | Blog categories | title, description, hierarchical structure |
| **Comment** | Post comments | post, author_name, content, parent (for threading), created_at |
| **BlogPostTag** | Tag association | Links posts to tags via taggit |

### StreamField Block Types

BlogPostPage uses Wagtail's StreamField for flexible content:

| Block Type | Description |
|------------|-------------|
| **heading** - **heading6** | Six levels of headings |
| **paragraph** | Rich text content |
| **ordered_list** | Numbered lists |
| **unordered_list** | Bullet lists |
| **image** | Images with captions |
| **quote** | Blockquotes with author and source |
| **table** | Custom tables with headers and rich text cells |

### Views

#### Frontend Views (`blog/views.py`)

**Blog Views:**
- `blog_list_view` - Alternative list view (Wagtail handles primary routing)
- `blog_search_view` - Search posts by text query, category ID, or tag slug with pagination
- `submit_comment` - Handle comment POST submission with CSRF protection and validation

**Wagtail Page Views** (automatic routing):
- `BlogIndexPage.serve()` - Blog homepage with post listing and pagination
- `BlogPostPage.serve()` - Individual blog post page with automatic view tracking
- `CategoryPage.serve()` - Category landing page

#### API Views (`blog/api/viewsets.py`)

**ViewSets:**
- `BlogPostViewSet` - Blog post CRUD and listing
  - `list()` - List posts with filtering
  - `retrieve()` - Get single post
  - `comments()` - Get post comments
  - `related()` - Get related posts by tags
  - `featured()` - Get featured/recent posts (cached 5 min)
  - `by_tag()` - Get posts filtered by tag

- `CategoryViewSet` - Category management
  - `list()` - List categories (cached 10 min)
  - `retrieve()` - Get single category
  - `posts()` - Get posts in category

- `CommentViewSet` - Comment management
  - `list()` - List comments
  - `create()` - Create new comment
  - `retrieve()` - Get single comment

- `TagViewSet` - Tag management
  - `list()` - List all tags
  - `popular()` - Get popular tags (cached 10 min)

- `BlogStatsView` - Blog analytics (staff only)
  - Total posts, categories, comments, tags
  - Posts by month (last 12 months)
  - Popular tags with counts

### URL Structure

#### Frontend URLs (`blog:*`)

```python
# Search
GET  /blog/search/?q={query}&category={id}&tag={slug}  → blog:search

# Comment submission
POST /blog/comment/{post_id}/                           → blog:submit_comment

# Wagtail automatic routing:
/blog/                    → BlogIndexPage
/blog/post-slug/          → BlogPostPage
/blog/category-slug/      → CategoryPage
```

#### API URLs (`api:v1:blog-api:*`)

```
# Posts
GET    /api/v1/blog/posts/                    # List posts
GET    /api/v1/blog/posts/{id}/                # Get post
GET    /api/v1/blog/posts/{id}/comments/       # Get post comments
GET    /api/v1/blog/posts/{id}/related/        # Get related posts
GET    /api/v1/blog/posts/featured/            # Get featured posts
GET    /api/v1/blog/posts/by_tag/?tag={slug}   # Get posts by tag

# Categories
GET    /api/v1/blog/categories/                # List categories
GET    /api/v1/blog/categories/{id}/           # Get category
GET    /api/v1/blog/categories/{id}/posts/     # Get category posts

# Comments
GET    /api/v1/blog/comments/?post={id}        # List comments
POST   /api/v1/blog/comments/                  # Create comment
GET    /api/v1/blog/comments/{id}/             # Get comment

# Tags
GET    /api/v1/blog/tags/                      # List tags
GET    /api/v1/blog/tags/popular/?limit=10     # Get popular tags

# Stats
GET    /api/v1/blog/stats/                     # Get blog statistics (admin only)
```

### Templates

Located in `blog/templates/blog/`:

**Main Templates:**
- `blog-default.html` - Blog index page (BlogIndexPage template) with pagination and sidebar
- `blog-detail1.html` - Blog post detail page (BlogPostPage template) with StreamField rendering, comments, and navigation
- `search_results.html` - Search results page with multi-criteria filtering

**Template Features:**
- **100% Dynamic Content**: All templates render real data from database (no static placeholders)
- **StreamField Rendering**: Proper block-by-block rendering for all content types (heading, paragraph, list, image, quote, table)
- **Image Renditions**: Wagtail image tags with responsive renditions (fill-800x450, fill-360x240, fill-100x75, etc.)
- **Pagination**: Django Paginator with page range display (10 posts per page)
- **Comment Threading**: Display parent comments with nested replies
- **CSRF Protection**: All POST forms include {% csrf_token %}
- **Conditional Rendering**: Proper {% if %} checks for optional fields (avatars, featured images, tags, etc.)
- **URL Generation**: All links use {% url %} tags with proper namespacing
- **Preserved Styling**: All CSS classes and HTML structure preserved from original static templates

**Note:** Wagtail uses the `template` attribute on Page models to determine rendering. All templates extend `base_public.html`.

### Serializers

Located in `blog/serializers.py`:

- `WagtailImageSerializer` - Handles Wagtail images with multiple renditions
- `TagSerializer` - Tag representation
- `CommentSerializer` - Comment with nested replies
- `CommentCreateSerializer` - Comment creation with HTML sanitization
- `BlogPostListSerializer` - Post listing (id, title, excerpt, tags, comment count)
- `BlogPostDetailSerializer` - Full post (includes body, comments, category, related posts)
- `CategoryListSerializer` - Category listing with post count
- `CategoryDetailSerializer` - Category with child categories
- `BlogIndexSerializer` - Blog index with categories
- `BlogStatsSerializer` - Analytics data

### Forms

Located in `blog/forms.py`:

- `CommentForm` - Django ModelForm for comment submission with:
  - Fields: author_name, content, parent (hidden field for threading)
  - HTML sanitization via `core.validators.sanitize_html`
  - Custom widgets with preserved CSS classes from templates
  - Validation for both content and author name

### Signals

Located in `blog/signals.py`:

- `create_user_profile` - Auto-creates UserProfile when User is created
- `save_user_profile` - Saves UserProfile when User is saved

All signals are registered in `blog/apps.py` via the `ready()` method.

## Integration Points

### With Other Apps

- **Tenants**: Multi-tenant isolation for blog content
- **Accounts**: Staff-only content management, public reading
- **Dashboard**: Blog statistics and recent posts
- **Marketing**: SEO integration, landing pages
- **Notifications**: Comment notifications (planned)
- **Analytics**: Content performance tracking (planned)

### External Services

- **Wagtail CMS**: Core content management system
- **Storage**: S3/local storage for images
- **CDN**: Image delivery optimization (planned)
- **Search**: Wagtail search backend (database or Elasticsearch)

### Wagtail Integration

The blog app leverages Wagtail CMS features:
- **Page Tree**: Hierarchical content organization
- **StreamField**: Flexible content blocks
- **Image Renditions**: Automatic image resizing
- **Search**: Built-in search functionality
- **Admin Panel**: Wagtail admin at `/cms/`
- **Revision History**: Content version control
- **Workflow**: Optional approval workflow

## Security & Permissions

### Role-Based Access

| Role | Permissions |
|------|-------------|
| **Staff/Admin** | Create, edit, delete posts; manage categories; view all statuses |
| **Content Editor** | Create and edit own posts, submit for review (planned) |
| **Public** | View published posts only, create comments |

### Content Security

- **HTML sanitization** for comments via `core.validators.sanitize_html`
  - Applied in `CommentForm.clean_content()` and `CommentForm.clean_author_name()`
  - Prevents XSS attacks in user-generated content
- **CSRF protection** for all POST forms ({% csrf_token %} in templates)
- **Form validation** with Django forms (CommentForm)
- **Thread-safe operations** with F() expressions for view_count
- Rate limiting on comment creation (planned)
- Spam detection for comments (planned)

### Tenant Isolation

- All content scoped to tenant via Wagtail's Site model
- Tenant-aware caching prevents cross-tenant data leakage
- API queries filtered by tenant automatically

## Database Considerations

### Indexes

Key indexes for performance:
- BlogPostPage: `(live, status, first_published_at)`
- Comment: `(post, created_at, parent)`
- Tags: Automatic indexing via taggit

### Relationships

```
BlogIndexPage (1) ←→ (N) BlogPostPage
BlogIndexPage (1) ←→ (N) CategoryPage
CategoryPage (1) ←→ (N) BlogPostPage (via parent)
CategoryPage (1) ←→ (N) CategoryPage (nested categories)
BlogPostPage (1) ←→ (N) Comment
Comment (1) ←→ (N) Comment (nested replies)
BlogPostPage (N) ←→ (N) Tag
```

### Wagtail Page Tree

```
Root
└── BlogIndexPage (/blog/)
    ├── CategoryPage (/blog/category-1/)
    │   ├── BlogPostPage (/blog/category-1/post-1/)
    │   └── BlogPostPage (/blog/category-1/post-2/)
    ├── CategoryPage (/blog/category-2/)
    └── BlogPostPage (/blog/standalone-post/)
```

## Caching Strategy

### Cached Data

- **Featured Posts**: 5 minutes (per staff/public view)
- **Categories List**: 10 minutes
- **Popular Tags**: 10 minutes (per limit parameter)

### Cache Keys

All cache keys are tenant-aware via `TenantCache`:

```python
blog:featured:staff_{bool}
blog:categories:list
blog:tags:popular:limit_{int}
```

### Cache Invalidation

Automatic invalidation via Wagtail signals:
- Post published/unpublished → clear featured posts cache
- Category created/deleted → clear categories cache
- Tag added/removed → clear popular tags cache

## Future Improvements

### High Priority

1. **Enhanced SEO Features**
   - Canonical URLs
   - Open Graph meta tags
   - Twitter Card support
   - XML sitemap generation
   - Structured data (JSON-LD)
   - Automatic internal linking suggestions

2. **Multi-Author Support**
   - Author profiles with bio and photo
   - Author archive pages
   - Multiple authors per post
   - Guest author system
   - Author-specific RSS feeds

3. **Advanced Category System**
   - Multiple taxonomies (categories + tags)
   - Category images
   - Category templates
   - Auto-categorization suggestions
   - Category-specific widgets

4. **Editorial Calendar**
   - Visual calendar view
   - Drag-and-drop scheduling
   - Content pipeline dashboard
   - Publishing reminders
   - Batch scheduling

5. **Content Scheduling Automation**
   - Auto-publish at scheduled time
   - Social media auto-posting
   - Email newsletter integration
   - RSS feed generation
   - Webhook notifications on publish

### Medium Priority

6. **Social Media Integration**
   - Share buttons
   - Social preview cards
   - Auto-posting to LinkedIn, Twitter
   - Social engagement tracking
   - Share count display

7. **Reading Experience**
   - Reading time estimation
   - Progress bar
   - Table of contents
   - Print-friendly view
   - Dark mode support

8. **Related Content**
   - Improved recommendation algorithm
   - Manual related post selection
   - "Read next" suggestions
   - Topic clustering
   - User behavior-based recommendations

9. **Comment Enhancements**
   - Comment moderation queue
   - Spam filtering (Akismet)
   - Email notifications
   - Like/dislike buttons
   - Comment reporting
   - Authenticated user comments

10. **Content Analytics**
    - Page views tracking
    - Engagement metrics
    - Popular posts dashboard
    - Search term tracking
    - Conversion tracking
    - A/B testing

### Low Priority

11. **Advanced Content Blocks**
    - Video embeds (YouTube, Vimeo)
    - Code syntax highlighting
    - Callout boxes
    - Comparison tables
    - FAQ accordions
    - Charts and graphs

12. **Multilingual Support**
    - Wagtail-localize integration
    - Translation management
    - Language switcher
    - Localized URLs
    - RTL language support

13. **Content Import/Export**
    - WordPress import
    - Medium import
    - CSV export
    - Markdown export
    - Backup/restore functionality

14. **Newsletter Integration**
    - Email capture forms
    - Mailchimp/SendGrid sync
    - Newsletter scheduling
    - Subscriber management
    - Newsletter templates

15. **Advanced Search**
    - Elasticsearch integration
    - Faceted search
    - Search suggestions
    - Saved searches
    - Search analytics

## Testing

### Test Coverage

Target: 85%+ coverage for blog functionality

### Test Structure

```
blog/
└── tests.py                    # Current placeholder
    # Planned structure:
    ├── test_models.py          # Model tests
    ├── test_views.py           # View tests
    ├── test_api.py             # API tests
    ├── test_permissions.py     # Permission tests
    ├── test_caching.py         # Cache tests
    └── test_wagtail.py         # Wagtail-specific tests
```

### Key Test Scenarios

- Blog post creation and publishing workflow
- StreamField block rendering
- Category hierarchy and navigation
- Comment creation and threading
- Tag filtering and popular tags
- Search functionality
- Permission enforcement (staff vs public)
- Tenant isolation
- Cache invalidation
- SEO meta tags rendering
- Image rendition generation

### Wagtail Testing Patterns

```python
from wagtail.test.utils import WagtailPageTestCase

class BlogPostPageTest(WagtailPageTestCase):
    def test_can_create_under_blog_index(self):
        # Test page hierarchy
        pass

    def test_streamfield_rendering(self):
        # Test block rendering
        pass
```

## Performance Optimization

### Current Optimizations

- Tenant-aware caching for lists and featured content
- Image renditions cached by Wagtail
- Database indexes on common queries
- `select_related()` for foreign keys
- `prefetch_related()` for tags and comments
- API pagination for large datasets

### Planned Optimizations

- Redis caching for hot content
- Elasticsearch for full-text search
- CDN for image delivery
- Fragment caching for StreamField blocks
- Lazy loading for images
- Database query optimization
- Background tasks for analytics

## Wagtail Admin

### Access

Blog content is managed through the Wagtail admin:
- URL: `/cms/`
- Requires staff permissions
- Modern admin interface
- Inline preview
- Revision history
- Workflow support (optional)

### Content Management

1. **Creating Posts:**
   - Navigate to Pages → Blog → Add child page
   - Select "Blog Post Page"
   - Fill in title, excerpt, body (StreamField)
   - Add featured image
   - Set status and publishing date
   - Add tags
   - Configure SEO settings
   - Save as draft or publish

2. **Managing Categories:**
   - Create CategoryPage under BlogIndexPage
   - Set title and description
   - Nest categories by creating under parent category
   - Assign posts by placing them under category

3. **Comments:**
   - Managed through Django admin (not Wagtail)
   - Moderation features planned

## Migration Notes

When modifying Wagtail models:

```bash
# Create migrations
python manage.py makemigrations blog

# Apply to all tenant schemas
python manage.py migrate_schemas --tenant

# Update Wagtail page structure if needed
python manage.py fixtree
```

**Important:** Wagtail models (Page subclasses) are tenant-specific in django-tenants multi-tenant setup.

## Contributing

When adding features to the blog app:

1. Follow Wagtail best practices for Page models
2. Use StreamField for flexible content
3. Add custom blocks in `models.py` with clear documentation
4. Update serializers for API representation
5. Add caching for performance-critical queries
6. Write tests for new functionality
7. Update this README with changes
8. Test in Wagtail admin interface

### Adding Custom Blocks

```python
from wagtail import blocks

class MyCustomBlock(blocks.StructBlock):
    field1 = blocks.CharBlock()
    field2 = blocks.RichTextBlock()

    class Meta:
        icon = 'placeholder'
        template = 'blog/blocks/my_custom_block.html'

# Add to BlogPostPage body StreamField
body = StreamField([
    # ... existing blocks
    ('my_custom', MyCustomBlock()),
])
```

## Support

For questions or issues related to the blog app:
- Check Wagtail documentation: https://docs.wagtail.org/
- Review `models.py` for available blocks and fields
- Consult Wagtail admin for content management
- Review `api/viewsets.py` for API functionality
- Check the main [CLAUDE.md](../CLAUDE.md) for project guidelines

## Useful Resources

- **Wagtail CMS**: https://wagtail.org/
- **StreamField Guide**: https://docs.wagtail.org/en/stable/topics/streamfield.html
- **Wagtail API**: https://docs.wagtail.org/en/stable/advanced_topics/api/
- **django-tenants with Wagtail**: Ensure proper tenant isolation

---

**Last Updated:** January 2026
**Module Version:** 1.0
**Status:** Production
