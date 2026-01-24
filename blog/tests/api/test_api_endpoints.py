"""
Tests for Blog API.

This module tests the blog API endpoints including:
- Blog posts (Wagtail-based)
- Categories
- Comments
- Tags
- Statistics
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
def authenticated_client(api_client, user_factory):
    """Return authenticated API client."""
    user = user_factory()
    api_client.force_authenticate(user=user)
    return api_client, user


@pytest.fixture
def admin_client(api_client, user_factory):
    """Return admin authenticated API client."""
    user = user_factory(is_staff=True, is_superuser=True)
    api_client.force_authenticate(user=user)
    return api_client, user


class TestBlogPostViewSet:
    """Tests for BlogPostViewSet."""

    @pytest.mark.django_db
    def test_list_posts_public(self, api_client):
        """Test listing blog posts is public."""
        url = reverse('blog-api:post-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_featured_posts(self, api_client):
        """Test featured posts endpoint."""
        url = reverse('blog-api:post-featured')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestCategoryViewSet:
    """Tests for CategoryViewSet."""

    @pytest.mark.django_db
    def test_list_categories_public(self, api_client):
        """Test listing categories is public."""
        url = reverse('blog-api:category-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestCommentViewSet:
    """Tests for CommentViewSet."""

    @pytest.mark.django_db
    def test_list_comments_public(self, api_client):
        """Test listing comments is public."""
        url = reverse('blog-api:comment-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestTagViewSet:
    """Tests for TagViewSet."""

    @pytest.mark.django_db
    def test_list_tags_public(self, api_client):
        """Test listing tags is public."""
        url = reverse('blog-api:tag-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_popular_tags(self, api_client):
        """Test popular tags endpoint."""
        url = reverse('blog-api:tag-popular')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestBlogStatsView:
    """Tests for BlogStatsView."""

    @pytest.mark.django_db
    def test_stats_requires_admin(self, api_client):
        """Test stats requires admin authentication."""
        url = reverse('blog-api:stats')
        response = api_client.get(url)

        # Should require admin
        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    @pytest.mark.django_db
    def test_stats_with_admin(self, admin_client):
        """Test stats with admin authentication."""
        client, user = admin_client
        url = reverse('blog-api:stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
