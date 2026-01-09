"""
Newsletter Serializers - DRF serializers for newsletter models.
"""

from rest_framework import serializers

from .models import Newsletter, Subscription, Article, Attachment, Message, Submission


class NewsletterListSerializer(serializers.ModelSerializer):
    """List serializer for newsletters."""
    subscriber_count = serializers.SerializerMethodField()
    subscribe_url = serializers.SerializerMethodField()
    unsubscribe_url = serializers.SerializerMethodField()

    class Meta:
        model = Newsletter
        fields = [
            'id', 'title', 'slug', 'email', 'sender',
            'visible', 'send_html', 'enable_unsubscribe',
            'subscriber_count', 'subscribe_url', 'unsubscribe_url'
        ]

    def get_subscriber_count(self, obj):
        """Get count of active subscribers."""
        return obj.subscription_set.filter(subscribed=True).count()

    def get_subscribe_url(self, obj):
        """Get subscribe URL."""
        try:
            return obj.subscribe_url()
        except Exception:
            return None

    def get_unsubscribe_url(self, obj):
        """Get unsubscribe URL."""
        try:
            return obj.unsubscribe_url()
        except Exception:
            return None


class NewsletterDetailSerializer(NewsletterListSerializer):
    """Detail serializer for newsletters."""
    recent_messages = serializers.SerializerMethodField()
    sites = serializers.SerializerMethodField()

    class Meta(NewsletterListSerializer.Meta):
        fields = NewsletterListSerializer.Meta.fields + [
            'subscription_generator_class', 'recent_messages', 'sites'
        ]

    def get_recent_messages(self, obj):
        """Get recent messages for this newsletter."""
        messages = Message.objects.filter(newsletter=obj).order_by('-date_create')[:5]
        return MessageListSerializer(messages, many=True).data

    def get_sites(self, obj):
        """Get associated sites."""
        return [{'id': site.id, 'domain': site.domain} for site in obj.site.all()]


class NewsletterCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating newsletters."""

    class Meta:
        model = Newsletter
        fields = [
            'title', 'slug', 'email', 'sender',
            'visible', 'send_html', 'enable_unsubscribe',
            'subscription_generator_class'
        ]

    def validate_email(self, value):
        """Validate email format."""
        from django.core.validators import validate_email
        validate_email(value)
        return value


class SubscriptionListSerializer(serializers.ModelSerializer):
    """List serializer for subscriptions."""
    name = serializers.CharField(read_only=True)
    email = serializers.CharField(read_only=True)
    newsletter_title = serializers.CharField(source='newsletter.title', read_only=True)

    class Meta:
        model = Subscription
        fields = [
            'id', 'name', 'email', 'newsletter', 'newsletter_title',
            'subscribed', 'unsubscribed', 'create_date',
            'subscribe_date', 'unsubscribe_date', 'ip'
        ]


class SubscriptionDetailSerializer(SubscriptionListSerializer):
    """Detail serializer for subscriptions."""
    user_info = serializers.SerializerMethodField()

    class Meta(SubscriptionListSerializer.Meta):
        fields = SubscriptionListSerializer.Meta.fields + ['user_info']

    def get_user_info(self, obj):
        """Get associated user info if any."""
        if obj.user:
            return {
                'id': obj.user.id,
                'email': obj.user.email,
                'full_name': obj.user.get_full_name()
            }
        return None


class SubscriptionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating subscriptions (public subscribe)."""
    name = serializers.CharField(required=False, allow_blank=True, source='name_field')
    email = serializers.EmailField(required=True, source='email_field')

    class Meta:
        model = Subscription
        fields = ['newsletter', 'name', 'email']

    def validate_email(self, value):
        """Sanitize and validate email."""
        from core.validators import sanitize_html
        return sanitize_html(value.lower().strip())

    def validate_name(self, value):
        """Sanitize name input."""
        if value:
            from core.validators import sanitize_html
            return sanitize_html(value)
        return value

    def validate(self, data):
        """Check for existing subscription."""
        newsletter = data.get('newsletter')
        email = data.get('email_field')

        # Check if subscription exists
        existing = Subscription.objects.filter(
            newsletter=newsletter,
            email_field__iexact=email
        ).first()

        if existing:
            if existing.subscribed:
                raise serializers.ValidationError(
                    {'email': 'This email is already subscribed to this newsletter.'}
                )
            # If unsubscribed, we'll reactivate
            data['existing_subscription'] = existing

        return data

    def create(self, validated_data):
        """Create or reactivate subscription."""
        existing = validated_data.pop('existing_subscription', None)

        if existing:
            # Reactivate existing subscription
            existing.subscribed = True
            existing.unsubscribed = False
            existing.save()
            return existing

        # Create new subscription
        subscription = Subscription.objects.create(
            newsletter=validated_data['newsletter'],
            name_field=validated_data.get('name_field', ''),
            email_field=validated_data['email_field'],
            subscribed=False,  # Requires confirmation
        )
        return subscription


class ArticleSerializer(serializers.ModelSerializer):
    """Serializer for newsletter articles."""
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Article
        fields = [
            'id', 'title', 'text', 'url', 'sortorder',
            'image', 'image_url', 'image_thumbnail_width', 'image_below_text'
        ]

    def get_image_url(self, obj):
        """Get image URL."""
        if obj.image:
            return obj.image.url
        return None


class ArticleCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating articles."""

    class Meta:
        model = Article
        fields = ['post', 'title', 'text', 'url', 'sortorder', 'image', 'image_below_text']

    def validate_text(self, value):
        """Sanitize article text."""
        from core.validators import sanitize_html
        return sanitize_html(value)


class AttachmentSerializer(serializers.ModelSerializer):
    """Serializer for message attachments."""
    file_name = serializers.CharField(read_only=True)
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = Attachment
        fields = ['id', 'file', 'file_name', 'file_url', 'message']

    def get_file_url(self, obj):
        """Get file URL."""
        if obj.file:
            return obj.file.url
        return None


class MessageListSerializer(serializers.ModelSerializer):
    """List serializer for newsletter messages."""
    newsletter_title = serializers.CharField(source='newsletter.title', read_only=True)
    article_count = serializers.SerializerMethodField()
    attachment_count = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            'id', 'title', 'slug', 'newsletter', 'newsletter_title',
            'date_create', 'date_modify', 'article_count', 'attachment_count'
        ]

    def get_article_count(self, obj):
        """Get article count."""
        return obj.articles.count()

    def get_attachment_count(self, obj):
        """Get attachment count."""
        return obj.attachments.count()


class MessageDetailSerializer(MessageListSerializer):
    """Detail serializer for newsletter messages."""
    articles = ArticleSerializer(many=True, read_only=True)
    attachments = AttachmentSerializer(many=True, read_only=True)

    class Meta(MessageListSerializer.Meta):
        fields = MessageListSerializer.Meta.fields + ['articles', 'attachments']


class MessageCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating messages."""

    class Meta:
        model = Message
        fields = ['title', 'slug', 'newsletter']

    def validate_title(self, value):
        """Sanitize title."""
        from core.validators import sanitize_html
        return sanitize_html(value)


class SubmissionListSerializer(serializers.ModelSerializer):
    """List serializer for submissions."""
    newsletter_title = serializers.CharField(source='newsletter.title', read_only=True)
    message_title = serializers.CharField(source='message.title', read_only=True)
    recipient_count = serializers.SerializerMethodField()

    class Meta:
        model = Submission
        fields = [
            'id', 'newsletter', 'newsletter_title', 'message', 'message_title',
            'publish_date', 'publish', 'prepared', 'sent', 'sending',
            'recipient_count'
        ]

    def get_recipient_count(self, obj):
        """Get recipient count."""
        return obj.subscriptions.count()


class SubmissionDetailSerializer(SubmissionListSerializer):
    """Detail serializer for submissions."""
    message_detail = MessageDetailSerializer(source='message', read_only=True)
    site_info = serializers.SerializerMethodField()

    class Meta(SubmissionListSerializer.Meta):
        fields = SubmissionListSerializer.Meta.fields + [
            'message_detail', 'site_info'
        ]

    def get_site_info(self, obj):
        """Get site info."""
        if obj.site:
            return {'id': obj.site.id, 'domain': obj.site.domain}
        return None


class SubmissionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating submissions."""

    class Meta:
        model = Submission
        fields = ['message', 'publish_date', 'publish']


class NewsletterStatsSerializer(serializers.Serializer):
    """Serializer for newsletter statistics."""
    total_newsletters = serializers.IntegerField()
    total_subscribers = serializers.IntegerField()
    active_subscribers = serializers.IntegerField()
    total_messages = serializers.IntegerField()
    total_submissions = serializers.IntegerField()
    sent_submissions = serializers.IntegerField()
    pending_submissions = serializers.IntegerField()
    subscribers_by_newsletter = serializers.ListField()
    recent_submissions = serializers.ListField()
