"""
Tests for Newsletter API.

This module tests the newsletter API endpoints including:
- Newsletters
- Subscriptions
- Articles
- Messages
- Submissions
"""

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


@pytest.fixture
def api_client():
    """Return API client."""
    return APIClient()


@pytest.fixture
def admin_client(api_client, user_factory):
    """Return admin authenticated API client."""
    user = user_factory(is_staff=True, is_superuser=True)
    api_client.force_authenticate(user=user)
    return api_client, user


class TestNewsletterViewSet:
    """Tests for NewsletterViewSet."""

    @pytest.mark.django_db
    def test_list_newsletters_public(self, api_client):
        """Test listing visible newsletters is public."""
        url = reverse('newsletter-api:newsletter-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_create_newsletter_requires_admin(self, api_client):
        """Test creating newsletter requires admin."""
        url = reverse('newsletter-api:newsletter-list')
        data = {'title': 'Test Newsletter', 'slug': 'test', 'email': 'test@test.com', 'sender': 'Test'}
        response = api_client.post(url, data)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestSubscriptionViewSet:
    """Tests for SubscriptionViewSet."""

    @pytest.mark.django_db
    def test_public_subscribe(self, api_client):
        """Test public subscription endpoint exists."""
        url = reverse('newsletter-api:subscription-public-subscribe')
        response = api_client.post(url, {})

        # Will fail validation but endpoint should exist
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.django_db
    def test_list_subscriptions_requires_admin(self, api_client):
        """Test listing subscriptions requires admin."""
        url = reverse('newsletter-api:subscription-list')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestArticleViewSet:
    """Tests for ArticleViewSet."""

    @pytest.mark.django_db
    def test_list_articles_requires_admin(self, api_client):
        """Test listing articles requires admin."""
        url = reverse('newsletter-api:article-list')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestMessageViewSet:
    """Tests for MessageViewSet."""

    @pytest.mark.django_db
    def test_list_messages_requires_admin(self, api_client):
        """Test listing messages requires admin."""
        url = reverse('newsletter-api:message-list')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestSubmissionViewSet:
    """Tests for SubmissionViewSet."""

    @pytest.mark.django_db
    def test_list_submissions_requires_admin(self, api_client):
        """Test listing submissions requires admin."""
        url = reverse('newsletter-api:submission-list')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestNewsletterStatsView:
    """Tests for NewsletterStatsView."""

    @pytest.mark.django_db
    def test_stats_requires_admin(self, api_client):
        """Test stats requires admin."""
        url = reverse('newsletter-api:stats')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    @pytest.mark.django_db
    def test_stats_with_admin(self, admin_client):
        """Test stats with admin."""
        client, user = admin_client
        url = reverse('newsletter-api:stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
