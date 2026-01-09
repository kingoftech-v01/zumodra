"""
Blog API ViewSets - DRF ViewSets for Wagtail blog models.

Caching:
- Blog posts list cached for 5 minutes
- Categories cached for 10 minutes
- Popular tags cached for 10 minutes
- Featured posts cached for 5 minutes
"""

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.views import APIView
import django_filters
from taggit.models import Tag

from core.cache import TenantCache

from ..models import BlogPostPage, BlogIndexPage, CategoryPage, Comment
from ..serializers import (
    BlogPostListSerializer,
    BlogPostDetailSerializer,
    CategoryListSerializer,
    CategoryDetailSerializer,
    CommentSerializer,
    CommentCreateSerializer,
    BlogIndexSerializer,
    BlogStatsSerializer,
    TagSerializer,
)


class BlogPostFilter(django_filters.FilterSet):
    """Filter for blog posts."""
    status = django_filters.CharFilter(field_name='status')
    category = django_filters.NumberFilter(method='filter_category')
    tag = django_filters.CharFilter(method='filter_tag')
    from_date = django_filters.DateFilter(
        field_name='first_published_at__date', lookup_expr='gte'
    )
    to_date = django_filters.DateFilter(
        field_name='first_published_at__date', lookup_expr='lte'
    )
    search = django_filters.CharFilter(method='filter_search')

    def filter_category(self, queryset, name, value):
        """Filter by category (parent page ID)."""
        try:
            category = CategoryPage.objects.get(pk=value)
            return queryset.descendant_of(category)
        except CategoryPage.DoesNotExist:
            return queryset.none()

    def filter_tag(self, queryset, name, value):
        """Filter by tag slug."""
        return queryset.filter(tags__slug=value)

    def filter_search(self, queryset, name, value):
        """Full-text search in title and excerpt."""
        return queryset.filter(
            Q(title__icontains=value) | Q(excerpt__icontains=value)
        )

    class Meta:
        model = BlogPostPage
        fields = ['status', 'category', 'tag', 'from_date', 'to_date', 'search']


class BlogPostViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for blog posts.

    Provides read-only access to published blog posts.
    Staff users can see all posts including drafts.
    """
    permission_classes = [AllowAny]
    filterset_class = BlogPostFilter
    search_fields = ['title', 'excerpt']
    ordering_fields = ['first_published_at', 'title', 'publishing_date']
    ordering = ['-first_published_at']

    def get_queryset(self):
        """Return queryset based on user permissions."""
        base_qs = BlogPostPage.objects.all()

        # Staff can see all posts, public sees only live/published
        if self.request.user.is_authenticated and self.request.user.is_staff:
            return base_qs
        return base_qs.live().filter(status='published')

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return BlogPostDetailSerializer
        return BlogPostListSerializer

    @action(detail=True, methods=['get'])
    def comments(self, request, pk=None):
        """Get comments for a post."""
        post = self.get_object()
        comments = post.comments.filter(parent=None).order_by('-created_at')
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def related(self, request, pk=None):
        """Get related posts."""
        post = self.get_object()
        tags = post.tags.all()

        if not tags:
            return Response([])

        related = BlogPostPage.objects.live().exclude(id=post.id).filter(
            tags__in=tags
        ).distinct()[:4]

        serializer = BlogPostListSerializer(related, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def featured(self, request):
        """Get featured/recent posts with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        is_staff = request.user.is_authenticated and request.user.is_staff
        cache_key = f"blog:featured:staff_{is_staff}"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        posts = self.get_queryset().order_by('-first_published_at')[:5]
        serializer = BlogPostListSerializer(posts, many=True)

        # Cache for 5 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=300)

        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def by_tag(self, request):
        """Get posts grouped by tag."""
        tag_slug = request.query_params.get('tag')
        if not tag_slug:
            return Response(
                {'error': 'Tag parameter required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        posts = self.get_queryset().filter(tags__slug=tag_slug)
        serializer = BlogPostListSerializer(posts, many=True)
        return Response({
            'tag': tag_slug,
            'posts': serializer.data
        })


class CategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for blog categories with caching.

    Provides read-only access to categories.
    """
    permission_classes = [AllowAny]
    ordering = ['title']

    def get_queryset(self):
        """Return live categories."""
        return CategoryPage.objects.live()

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return CategoryDetailSerializer
        return CategoryListSerializer

    def list(self, request, *args, **kwargs):
        """List categories with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        cache_key = "blog:categories:list"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        response = super().list(request, *args, **kwargs)

        # Cache for 10 minutes
        tenant_cache.set(cache_key, response.data, timeout=600)

        return response

    @action(detail=True, methods=['get'])
    def posts(self, request, pk=None):
        """Get posts in this category."""
        category = self.get_object()
        posts = BlogPostPage.objects.live().descendant_of(category)

        # Apply ordering
        ordering = request.query_params.get('ordering', '-first_published_at')
        posts = posts.order_by(ordering)

        serializer = BlogPostListSerializer(posts, many=True)
        return Response(serializer.data)


class CommentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for blog comments.

    Anyone can read comments, authenticated users can create.
    """
    queryset = Comment.objects.all()
    ordering = ['-created_at']

    def get_permissions(self):
        """Set permissions based on action."""
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]
        return [AllowAny()]  # Allow anonymous comments

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'create':
            return CommentCreateSerializer
        return CommentSerializer

    def get_queryset(self):
        """Filter comments by post if specified."""
        queryset = Comment.objects.all()
        post_id = self.request.query_params.get('post')

        if post_id:
            queryset = queryset.filter(post_id=post_id, parent=None)

        return queryset.order_by('-created_at')


class TagViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for blog tags.

    Provides read-only access to tags used in blog posts.
    """
    permission_classes = [AllowAny]
    serializer_class = TagSerializer
    ordering = ['name']

    def get_queryset(self):
        """Return tags used in blog posts."""
        # Get tags that are actually used in published posts
        return Tag.objects.filter(
            blog_blogposttag_items__content_object__live=True
        ).distinct().annotate(
            post_count=Count('blog_blogposttag_items')
        ).order_by('-post_count')

    @action(detail=False, methods=['get'])
    def popular(self, request):
        """Get most popular tags with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        limit = int(request.query_params.get('limit', 10))
        cache_key = f"blog:tags:popular:limit_{limit}"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        tags = self.get_queryset()[:limit]
        serializer = self.get_serializer(tags, many=True)

        # Cache for 10 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=600)

        return Response(serializer.data)


class BlogStatsView(APIView):
    """
    API view for blog statistics.

    Staff-only access to blog analytics.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        """Return blog statistics."""
        all_posts = BlogPostPage.objects.all()
        live_posts = all_posts.live()

        # Posts by status
        published_count = live_posts.filter(status='published').count()
        draft_count = all_posts.filter(status='draft').count()

        # Categories and comments
        categories_count = CategoryPage.objects.live().count()
        comments_count = Comment.objects.count()

        # Tags
        tags_count = Tag.objects.filter(
            blog_blogposttag_items__content_object__live=True
        ).distinct().count()

        # Posts by month (last 12 months)
        from django.db.models.functions import TruncMonth
        posts_by_month = live_posts.annotate(
            month=TruncMonth('first_published_at')
        ).values('month').annotate(
            count=Count('id')
        ).order_by('-month')[:12]

        # Popular tags
        popular_tags = Tag.objects.filter(
            blog_blogposttag_items__content_object__live=True
        ).annotate(
            count=Count('blog_blogposttag_items')
        ).order_by('-count')[:10]

        stats = {
            'total_posts': all_posts.count(),
            'published_posts': published_count,
            'draft_posts': draft_count,
            'total_categories': categories_count,
            'total_comments': comments_count,
            'total_tags': tags_count,
            'posts_by_month': list(posts_by_month),
            'popular_tags': [
                {'name': tag.name, 'count': tag.count}
                for tag in popular_tags
            ],
        }

        serializer = BlogStatsSerializer(stats)
        return Response(serializer.data)
