"""
Blog Serializers - DRF serializers for Wagtail blog models.
"""

from rest_framework import serializers
from wagtail.images.models import Image

from .models import BlogPostPage, BlogIndexPage, CategoryPage, Comment, BlogPostTag


class WagtailImageSerializer(serializers.Serializer):
    """Serializer for Wagtail images."""
    id = serializers.IntegerField(read_only=True)
    title = serializers.CharField(read_only=True)
    width = serializers.IntegerField(read_only=True)
    height = serializers.IntegerField(read_only=True)

    def to_representation(self, instance):
        if instance is None:
            return None

        data = super().to_representation(instance)
        # Add image URLs for different sizes
        try:
            data['url'] = instance.file.url
            data['thumbnail'] = instance.get_rendition('fill-150x150').url
            data['medium'] = instance.get_rendition('fill-400x300').url
            data['large'] = instance.get_rendition('fill-800x600').url
        except Exception:
            data['url'] = None
            data['thumbnail'] = None
            data['medium'] = None
            data['large'] = None

        return data


class TagSerializer(serializers.Serializer):
    """Serializer for taggit tags."""
    name = serializers.CharField(read_only=True)
    slug = serializers.CharField(read_only=True)


class CommentSerializer(serializers.ModelSerializer):
    """Serializer for blog comments."""
    replies = serializers.SerializerMethodField()
    post_title = serializers.CharField(source='post.title', read_only=True)

    class Meta:
        model = Comment
        fields = [
            'id', 'post', 'post_title', 'author_name', 'content',
            'created_at', 'parent', 'replies'
        ]
        read_only_fields = ['id', 'created_at']

    def get_replies(self, obj):
        """Get nested replies."""
        if obj.replies.exists():
            return CommentSerializer(obj.replies.all(), many=True).data
        return []


class CommentCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating comments."""

    class Meta:
        model = Comment
        fields = ['post', 'author_name', 'content', 'parent']

    def validate_content(self, value):
        """Sanitize comment content."""
        from core.validators import sanitize_html
        return sanitize_html(value)

    def validate_author_name(self, value):
        """Sanitize author name."""
        from core.validators import sanitize_html
        return sanitize_html(value)


class CategoryListSerializer(serializers.Serializer):
    """List serializer for blog categories."""
    id = serializers.IntegerField(read_only=True)
    title = serializers.CharField(read_only=True)
    slug = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    url = serializers.SerializerMethodField()
    post_count = serializers.SerializerMethodField()

    def get_url(self, obj):
        """Get category URL."""
        try:
            return obj.get_url()
        except Exception:
            return None

    def get_post_count(self, obj):
        """Get count of published posts in this category."""
        return BlogPostPage.objects.live().descendant_of(obj).count()


class CategoryDetailSerializer(CategoryListSerializer):
    """Detail serializer for blog categories."""
    child_categories = serializers.SerializerMethodField()

    def get_child_categories(self, obj):
        """Get child categories."""
        children = CategoryPage.objects.live().child_of(obj)
        return CategoryListSerializer(children, many=True).data


class BlogPostListSerializer(serializers.Serializer):
    """List serializer for blog posts."""
    id = serializers.IntegerField(read_only=True)
    title = serializers.CharField(read_only=True)
    slug = serializers.CharField(read_only=True)
    excerpt = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    featured_image = WagtailImageSerializer(read_only=True)
    first_published_at = serializers.DateTimeField(read_only=True)
    last_published_at = serializers.DateTimeField(read_only=True)
    publishing_date = serializers.DateTimeField(read_only=True)
    url = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    comment_count = serializers.SerializerMethodField()

    def get_url(self, obj):
        """Get post URL."""
        try:
            return obj.get_url()
        except Exception:
            return None

    def get_tags(self, obj):
        """Get post tags."""
        return TagSerializer(obj.tags.all(), many=True).data

    def get_comment_count(self, obj):
        """Get comment count."""
        return obj.comments.count()


class BlogPostDetailSerializer(BlogPostListSerializer):
    """Detail serializer for blog posts."""
    body = serializers.SerializerMethodField()
    meta_title = serializers.CharField(read_only=True)
    meta_description = serializers.CharField(read_only=True)
    comments = serializers.SerializerMethodField()
    category = serializers.SerializerMethodField()
    related_posts = serializers.SerializerMethodField()

    def get_body(self, obj):
        """Render StreamField body content as structured data."""
        if obj.body is None:
            return []

        content = []
        for block in obj.body:
            block_data = {
                'type': block.block_type,
                'id': str(block.id),
            }

            # Handle different block types
            if block.block_type == 'image':
                try:
                    block_data['value'] = {
                        'id': block.value.id,
                        'url': block.value.file.url,
                        'title': block.value.title,
                    }
                except Exception:
                    block_data['value'] = None
            elif block.block_type == 'quote':
                block_data['value'] = {
                    'quote': str(block.value.get('quote', '')),
                    'author': str(block.value.get('author', '')),
                    'source': str(block.value.get('source', '')),
                }
            elif block.block_type == 'table':
                block_data['value'] = {
                    'header': list(block.value.get('header', [])),
                    'rows': [
                        {'cells': list(row.get('cells', []))}
                        for row in block.value.get('rows', [])
                    ],
                }
            elif block.block_type in ['ordered_list', 'unordered_list']:
                block_data['value'] = [str(item) for item in block.value]
            else:
                # Heading and paragraph blocks
                block_data['value'] = str(block.value)

            content.append(block_data)

        return content

    def get_comments(self, obj):
        """Get top-level comments."""
        top_level = obj.comments.filter(parent=None).order_by('-created_at')
        return CommentSerializer(top_level, many=True).data

    def get_category(self, obj):
        """Get parent category if any."""
        parent = obj.get_parent()
        if isinstance(parent, CategoryPage):
            return CategoryListSerializer(parent).data
        return None

    def get_related_posts(self, obj):
        """Get related posts by tags."""
        tags = obj.tags.all()
        if not tags:
            return []

        related = BlogPostPage.objects.live().exclude(id=obj.id).filter(
            tags__in=tags
        ).distinct()[:4]

        return BlogPostListSerializer(related, many=True).data


class BlogIndexSerializer(serializers.Serializer):
    """Serializer for blog index page."""
    id = serializers.IntegerField(read_only=True)
    title = serializers.CharField(read_only=True)
    intro = serializers.CharField(read_only=True)
    url = serializers.SerializerMethodField()
    total_posts = serializers.SerializerMethodField()
    categories = serializers.SerializerMethodField()

    def get_url(self, obj):
        """Get index page URL."""
        try:
            return obj.get_url()
        except Exception:
            return None

    def get_total_posts(self, obj):
        """Get total published posts."""
        return BlogPostPage.objects.live().count()

    def get_categories(self, obj):
        """Get all categories."""
        categories = CategoryPage.objects.live().child_of(obj)
        return CategoryListSerializer(categories, many=True).data


class BlogSearchSerializer(serializers.Serializer):
    """Serializer for blog search requests."""
    q = serializers.CharField(required=False, allow_blank=True)
    category = serializers.IntegerField(required=False)
    tag = serializers.CharField(required=False)
    status = serializers.CharField(required=False)
    from_date = serializers.DateField(required=False)
    to_date = serializers.DateField(required=False)


class BlogStatsSerializer(serializers.Serializer):
    """Serializer for blog statistics."""
    total_posts = serializers.IntegerField()
    published_posts = serializers.IntegerField()
    draft_posts = serializers.IntegerField()
    total_categories = serializers.IntegerField()
    total_comments = serializers.IntegerField()
    total_tags = serializers.IntegerField()
    posts_by_month = serializers.ListField()
    popular_tags = serializers.ListField()
