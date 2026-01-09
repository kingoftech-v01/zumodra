"""
Newsletter API ViewSets - DRF ViewSets for newsletter models.

Caching:
- Newsletter list cached for 10 minutes
- Newsletter stats cached for 5 minutes
"""

from django.db.models import Count, Q
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.views import APIView
import django_filters

from core.cache import TenantCache

from ..models import Newsletter, Subscription, Article, Message, Submission
from ..serializers import (
    NewsletterListSerializer,
    NewsletterDetailSerializer,
    NewsletterCreateSerializer,
    SubscriptionListSerializer,
    SubscriptionDetailSerializer,
    SubscriptionCreateSerializer,
    ArticleSerializer,
    ArticleCreateSerializer,
    MessageListSerializer,
    MessageDetailSerializer,
    MessageCreateSerializer,
    SubmissionListSerializer,
    SubmissionDetailSerializer,
    SubmissionCreateSerializer,
    NewsletterStatsSerializer,
)


class NewsletterFilter(django_filters.FilterSet):
    """Filter for newsletters."""
    visible = django_filters.BooleanFilter(field_name='visible')
    search = django_filters.CharFilter(method='filter_search')

    def filter_search(self, queryset, name, value):
        """Search in title and sender."""
        return queryset.filter(
            Q(title__icontains=value) | Q(sender__icontains=value)
        )

    class Meta:
        model = Newsletter
        fields = ['visible', 'search']


class NewsletterViewSet(viewsets.ModelViewSet):
    """
    ViewSet for newsletters with caching.

    Public can see visible newsletters.
    Admin can manage all newsletters.
    """
    filterset_class = NewsletterFilter
    ordering = ['title']

    def get_queryset(self):
        """Return queryset based on user permissions."""
        if self.request.user.is_authenticated and self.request.user.is_staff:
            return Newsletter.objects.all()
        return Newsletter.objects.filter(visible=True)

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return NewsletterDetailSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return NewsletterCreateSerializer
        return NewsletterListSerializer

    def get_permissions(self):
        """Set permissions based on action."""
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]
        return [IsAdminUser()]

    def list(self, request, *args, **kwargs):
        """List newsletters with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        is_staff = request.user.is_authenticated and request.user.is_staff
        cache_key = f"newsletters:list:staff_{is_staff}"

        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        response = super().list(request, *args, **kwargs)

        # Cache for 10 minutes
        tenant_cache.set(cache_key, response.data, timeout=600)

        return response

    @action(detail=True, methods=['get'])
    def subscribers(self, request, pk=None):
        """Get subscribers for this newsletter."""
        newsletter = self.get_object()
        subscriptions = newsletter.subscription_set.filter(subscribed=True)
        serializer = SubscriptionListSerializer(subscriptions, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def messages(self, request, pk=None):
        """Get messages for this newsletter."""
        newsletter = self.get_object()
        messages = Message.objects.filter(newsletter=newsletter).order_by('-date_create')
        serializer = MessageListSerializer(messages, many=True)
        return Response(serializer.data)


class SubscriptionFilter(django_filters.FilterSet):
    """Filter for subscriptions."""
    newsletter = django_filters.NumberFilter(field_name='newsletter_id')
    subscribed = django_filters.BooleanFilter(field_name='subscribed')
    unsubscribed = django_filters.BooleanFilter(field_name='unsubscribed')
    search = django_filters.CharFilter(method='filter_search')
    from_date = django_filters.DateFilter(
        field_name='create_date__date', lookup_expr='gte'
    )
    to_date = django_filters.DateFilter(
        field_name='create_date__date', lookup_expr='lte'
    )

    def filter_search(self, queryset, name, value):
        """Search in email and name."""
        return queryset.filter(
            Q(email_field__icontains=value) | Q(name_field__icontains=value)
        )

    class Meta:
        model = Subscription
        fields = ['newsletter', 'subscribed', 'unsubscribed', 'search', 'from_date', 'to_date']


class SubscriptionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for subscriptions.

    Public can subscribe (create).
    Admin can manage all subscriptions.
    """
    filterset_class = SubscriptionFilter
    ordering = ['-create_date']

    def get_queryset(self):
        """Return all subscriptions (admin only for list)."""
        return Subscription.objects.all()

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return SubscriptionDetailSerializer
        if self.action == 'create':
            return SubscriptionCreateSerializer
        return SubscriptionListSerializer

    def get_permissions(self):
        """Set permissions based on action."""
        if self.action == 'create':
            return [AllowAny()]  # Public can subscribe
        return [IsAdminUser()]

    @action(detail=True, methods=['post'], permission_classes=[IsAdminUser])
    def confirm(self, request, pk=None):
        """Confirm a subscription."""
        subscription = self.get_object()
        subscription.subscribed = True
        subscription.save()
        serializer = SubscriptionDetailSerializer(subscription)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[IsAdminUser])
    def unsubscribe(self, request, pk=None):
        """Unsubscribe a subscription."""
        subscription = self.get_object()
        subscription.unsubscribed = True
        subscription.save()
        serializer = SubscriptionDetailSerializer(subscription)
        return Response(serializer.data)

    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def public_subscribe(self, request):
        """Public subscription endpoint."""
        serializer = SubscriptionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        subscription = serializer.save()

        # Send confirmation email
        try:
            subscription.send_activation_email('subscribe')
        except Exception:
            pass  # Email sending is non-blocking

        return Response(
            {'message': 'Please check your email to confirm your subscription.'},
            status=status.HTTP_201_CREATED
        )


class ArticleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for newsletter articles.

    Admin-only access.
    """
    queryset = Article.objects.all()
    permission_classes = [IsAdminUser]
    ordering = ['post', 'sortorder']

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action in ['create', 'update', 'partial_update']:
            return ArticleCreateSerializer
        return ArticleSerializer

    def get_queryset(self):
        """Filter by message if specified."""
        queryset = Article.objects.all()
        message_id = self.request.query_params.get('message')

        if message_id:
            queryset = queryset.filter(post_id=message_id)

        return queryset.order_by('post', 'sortorder')


class MessageFilter(django_filters.FilterSet):
    """Filter for messages."""
    newsletter = django_filters.NumberFilter(field_name='newsletter_id')
    search = django_filters.CharFilter(method='filter_search')
    from_date = django_filters.DateFilter(
        field_name='date_create__date', lookup_expr='gte'
    )
    to_date = django_filters.DateFilter(
        field_name='date_create__date', lookup_expr='lte'
    )

    def filter_search(self, queryset, name, value):
        """Search in title."""
        return queryset.filter(title__icontains=value)

    class Meta:
        model = Message
        fields = ['newsletter', 'search', 'from_date', 'to_date']


class MessageViewSet(viewsets.ModelViewSet):
    """
    ViewSet for newsletter messages.

    Admin-only access.
    """
    queryset = Message.objects.all()
    permission_classes = [IsAdminUser]
    filterset_class = MessageFilter
    ordering = ['-date_create']

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return MessageDetailSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return MessageCreateSerializer
        return MessageListSerializer

    @action(detail=True, methods=['get'])
    def articles(self, request, pk=None):
        """Get articles for this message."""
        message = self.get_object()
        articles = message.articles.all()
        serializer = ArticleSerializer(articles, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def create_submission(self, request, pk=None):
        """Create a submission from this message."""
        message = self.get_object()
        submission = Submission.from_message(message)
        serializer = SubmissionDetailSerializer(submission)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class SubmissionFilter(django_filters.FilterSet):
    """Filter for submissions."""
    newsletter = django_filters.NumberFilter(field_name='newsletter_id')
    sent = django_filters.BooleanFilter(field_name='sent')
    prepared = django_filters.BooleanFilter(field_name='prepared')
    from_date = django_filters.DateFilter(
        field_name='publish_date__date', lookup_expr='gte'
    )
    to_date = django_filters.DateFilter(
        field_name='publish_date__date', lookup_expr='lte'
    )

    class Meta:
        model = Submission
        fields = ['newsletter', 'sent', 'prepared', 'from_date', 'to_date']


class SubmissionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for submissions.

    Admin-only access.
    """
    queryset = Submission.objects.all()
    permission_classes = [IsAdminUser]
    filterset_class = SubmissionFilter
    ordering = ['-publish_date']

    def get_serializer_class(self):
        """Return appropriate serializer."""
        if self.action == 'retrieve':
            return SubmissionDetailSerializer
        if self.action in ['create', 'update', 'partial_update']:
            return SubmissionCreateSerializer
        return SubmissionListSerializer

    @action(detail=True, methods=['post'])
    def prepare(self, request, pk=None):
        """Mark submission as prepared for sending."""
        submission = self.get_object()
        submission.prepared = True
        submission.save()
        serializer = SubmissionDetailSerializer(submission)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def send(self, request, pk=None):
        """Send the submission immediately."""
        submission = self.get_object()

        if submission.sent:
            return Response(
                {'error': 'Submission has already been sent.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if submission.sending:
            return Response(
                {'error': 'Submission is currently being sent.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mark as prepared and submit
        submission.prepared = True
        submission.save()

        try:
            submission.submit()
            serializer = SubmissionDetailSerializer(submission)
            return Response(serializer.data)
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'])
    def submit_queue(self, request):
        """Process all pending submissions in the queue."""
        try:
            Submission.submit_queue()
            return Response({'message': 'Queue processing started.'})
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NewsletterStatsView(APIView):
    """
    API view for newsletter statistics with caching.

    Staff-only access to analytics.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        """Return newsletter statistics with caching."""
        tenant_id = getattr(request, 'tenant', None)
        tenant_id = tenant_id.id if tenant_id else None
        tenant_cache = TenantCache(tenant_id)

        cache_key = "newsletter:stats"
        cached_data = tenant_cache.get(cache_key)
        if cached_data is not None:
            return Response(cached_data)

        # Basic counts
        total_newsletters = Newsletter.objects.count()
        total_subscribers = Subscription.objects.count()
        active_subscribers = Subscription.objects.filter(subscribed=True).count()
        total_messages = Message.objects.count()
        total_submissions = Submission.objects.count()
        sent_submissions = Submission.objects.filter(sent=True).count()
        pending_submissions = Submission.objects.filter(
            prepared=True, sent=False, sending=False
        ).count()

        # Subscribers by newsletter
        subscribers_by_newsletter = Newsletter.objects.annotate(
            subscriber_count=Count('subscription', filter=Q(subscription__subscribed=True))
        ).values('id', 'title', 'subscriber_count')

        # Recent submissions
        recent_submissions = Submission.objects.order_by('-publish_date')[:10]

        stats = {
            'total_newsletters': total_newsletters,
            'total_subscribers': total_subscribers,
            'active_subscribers': active_subscribers,
            'total_messages': total_messages,
            'total_submissions': total_submissions,
            'sent_submissions': sent_submissions,
            'pending_submissions': pending_submissions,
            'subscribers_by_newsletter': list(subscribers_by_newsletter),
            'recent_submissions': SubmissionListSerializer(recent_submissions, many=True).data,
        }

        serializer = NewsletterStatsSerializer(stats)

        # Cache for 5 minutes
        tenant_cache.set(cache_key, serializer.data, timeout=300)

        return Response(serializer.data)
