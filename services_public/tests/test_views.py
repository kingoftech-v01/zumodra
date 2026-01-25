"""Tests for views."""
import pytest
from django.urls import reverse

@pytest.mark.django_db
class TestServiceListView:
    def test_list_view_renders(self, client):
        url = reverse('services_public:service_list')
        response = client.get(url)
        assert response.status_code == 200
