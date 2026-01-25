"""
API ViewSets for PublicProfile and ProfileFieldSync
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.db import models
from core_identity.models import PublicProfile, ProfileFieldSync
from .serializers import (
    PublicProfileSerializer,
    PublicProfileReadSerializer,
    ProfileFieldSyncSerializer,
    ProfileFieldSyncUpdateSerializer,
)


class PublicProfileViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing PublicProfile.

    Endpoints:
    - GET /api/profile/public/me/ - Get own public profile
    - PATCH /api/profile/public/me/ - Update own public profile
    - GET /api/profile/public/{uuid}/ - View another user's profile (with visibility check)
    """
    queryset = PublicProfile.objects.select_related('user').all()
    serializer_class = PublicProfileSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'uuid'

    def get_queryset(self):
        """
        Filter queryset based on visibility settings.
        Users can always see their own profile.
        """
        user = self.request.user
        queryset = super().get_queryset()

        # If retrieving own profile, return it
        if self.action in ['me', 'update', 'partial_update']:
            return queryset.filter(user=user)

        # For viewing others' profiles, respect visibility settings
        if self.action == 'retrieve':
            # Allow viewing public profiles or profiles of tenants user has joined
            from tenant_profiles.models import TenantUser

            # Get user's tenant UUIDs
            user_tenant_uuids = TenantUser.objects.filter(
                user=user
            ).values_list('tenant__uuid', flat=True)

            queryset = queryset.filter(
                models.Q(profile_visibility=PublicProfile.VISIBILITY_PUBLIC) |
                models.Q(
                    profile_visibility=PublicProfile.VISIBILITY_TENANTS_ONLY,
                    user__tenant_memberships__tenant__uuid__in=user_tenant_uuids
                )
            ).distinct()

        return queryset

    def get_serializer_class(self):
        """
        Use read-only serializer for viewing others' profiles.
        """
        if self.action == 'retrieve' and self.kwargs.get('uuid'):
            return PublicProfileReadSerializer
        return PublicProfileSerializer

    def get_object(self):
        """
        Override to handle 'me' action.
        """
        if self.action == 'me':
            return get_object_or_404(PublicProfile, user=self.request.user)
        return super().get_object()

    @action(detail=False, methods=['get', 'patch'])
    def me(self, request):
        """
        Get or update current user's public profile.

        GET /api/profile/public/me/
        PATCH /api/profile/public/me/
        """
        profile = self.get_object()

        if request.method == 'GET':
            serializer = self.get_serializer(profile)
            return Response(serializer.data)

        elif request.method == 'PATCH':
            serializer = self.get_serializer(profile, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve another user's public profile.
        Respects visibility settings.
        """
        instance = self.get_object()

        # Check if user has permission to view this profile
        if instance.profile_visibility == PublicProfile.VISIBILITY_PRIVATE:
            # Only the owner can view private profiles
            if instance.user != request.user:
                return Response(
                    {'detail': 'This profile is private.'},
                    status=status.HTTP_403_FORBIDDEN
                )

        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def list(self, request, *args, **kwargs):
        """
        Disable listing all profiles (privacy protection).
        """
        return Response(
            {'detail': 'Listing all profiles is not supported. Use search endpoints instead.'},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def create(self, request, *args, **kwargs):
        """
        Disable manual creation (created automatically via signals).
        """
        return Response(
            {'detail': 'Public profiles are created automatically for all users.'},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def destroy(self, request, *args, **kwargs):
        """
        Disable deletion (profiles should persist with user).
        """
        return Response(
            {'detail': 'Public profiles cannot be deleted. Set visibility to private instead.'},
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )


class ProfileFieldSyncViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing ProfileFieldSync settings.

    Endpoints:
    - GET /api/profile/sync-settings/ - List all sync settings
    - GET /api/profile/sync-settings/tenant/{tenant_uuid}/ - Get settings for specific tenant
    - PATCH /api/profile/sync-settings/tenant/{tenant_uuid}/ - Update settings for tenant
    """
    queryset = ProfileFieldSync.objects.select_related('user').all()
    serializer_class = ProfileFieldSyncSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'uuid'

    def get_queryset(self):
        """
        Filter to only show current user's sync settings.
        """
        return super().get_queryset().filter(user=self.request.user)

    def get_serializer_class(self):
        """
        Use update serializer for PATCH requests.
        """
        if self.action in ['update', 'partial_update', 'update_by_tenant']:
            return ProfileFieldSyncUpdateSerializer
        return ProfileFieldSyncSerializer

    @action(detail=False, methods=['get', 'patch'], url_path='tenant/(?P<tenant_uuid>[^/.]+)')
    def by_tenant(self, request, tenant_uuid=None):
        """
        Get or update sync settings for a specific tenant.

        GET /api/profile/sync-settings/tenant/{tenant_uuid}/
        PATCH /api/profile/sync-settings/tenant/{tenant_uuid}/
        """
        # Get or create sync settings for this tenant
        sync_settings, created = ProfileFieldSync.get_or_create_defaults(
            user=request.user,
            tenant_uuid=tenant_uuid
        )

        if request.method == 'GET':
            serializer = ProfileFieldSyncSerializer(sync_settings, context={'request': request})
            return Response(serializer.data)

        elif request.method == 'PATCH':
            serializer = ProfileFieldSyncUpdateSerializer(
                sync_settings,
                data=request.data,
                partial=True,
                context={'request': request}
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()

            # Return full representation
            result_serializer = ProfileFieldSyncSerializer(
                sync_settings,
                context={'request': request}
            )
            return Response(result_serializer.data)

    def create(self, request, *args, **kwargs):
        """
        Disable manual creation (use get_or_create_defaults instead).
        """
        return Response(
            {
                'detail': 'Sync settings are created automatically. '
                          'Use PATCH /api/profile/sync-settings/tenant/{tenant_uuid}/ instead.'
            },
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def destroy(self, request, *args, **kwargs):
        """
        Allow deletion of sync settings (resets to defaults on next access).
        """
        instance = self.get_object()
        tenant_uuid = instance.tenant_uuid
        instance.delete()

        return Response(
            {
                'detail': f'Sync settings for tenant {tenant_uuid} deleted. '
                          'Defaults will be used on next sync.'
            },
            status=status.HTTP_204_NO_CONTENT
        )
