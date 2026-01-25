"""Tests for models."""
import pytest
from services_public.models import PublicService

@pytest.mark.django_db
class TestPublicService:
    def test_create_service(self, sample_public_service):
        assert sample_public_service.id is not None
