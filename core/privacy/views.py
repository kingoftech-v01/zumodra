"""
GDPR/Privacy Compliance Views for Zumodra ATS/HR Platform

This module provides views and viewsets for privacy management:
- ConsentViewSet: List and create consent records
- DataSubjectRequestViewSet: Create and view DSR status
- PrivacyDashboardView: User privacy settings overview
- DataExportView: Trigger and download data exports

All views are tenant-aware and require authentication.
"""

import logging
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import connection
from django.http import FileResponse, Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView

from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from core.privacy.models import (
    ConsentRecord,
    DataProcessingPurpose,
    DataSubjectRequest,
    DataRetentionPolicy,
    PrivacyPolicy,
    PrivacyAuditLog,
)
from core.privacy.services import (
    ConsentService,
    DataSubjectRequestService,
    AnonymizationService,
)
from core.privacy.exporters import GDPRDataExporter, DataExportRequest
from core.privacy.serializers import (
    ConsentRecordSerializer,
    ConsentCreateSerializer,
    DataSubjectRequestSerializer,
    DataSubjectRequestCreateSerializer,
    PrivacyPolicySerializer,
    DataProcessingPurposeSerializer,
    PrivacyDashboardSerializer,
)

logger = logging.getLogger(__name__)


def get_current_tenant():
    """Get the current tenant from the database connection."""
    return getattr(connection, 'tenant', None)


class ConsentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing user consents.

    Provides endpoints for:
    - Listing user's consent records
    - Creating new consents
    - Withdrawing consents
    - Getting consent history
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ConsentRecordSerializer

    def get_queryset(self):
        """Return consents for the current user and tenant."""
        tenant = get_current_tenant()
        return ConsentRecord.objects.filter(
            tenant=tenant,
            user=self.request.user,
        ).order_by('-created_at')

    def get_serializer_class(self):
        """Use different serializers for different actions."""
        if self.action == 'create':
            return ConsentCreateSerializer
        return ConsentRecordSerializer

    def create(self, request, *args, **kwargs):
        """
        Create a new consent record.

        POST /api/v1/privacy/consents/
        {
            "consent_type": "marketing_email",
            "granted": true,
            "consent_text": "I agree to receive marketing emails..."
        }
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tenant = get_current_tenant()
        consent_service = ConsentService(tenant)

        # Get current privacy policy for versioning
        policy = PrivacyPolicy.objects.filter(
            tenant=tenant,
            is_current=True
        ).first()

        consent = consent_service.record_consent(
            user=request.user,
            consent_type=serializer.validated_data['consent_type'],
            granted=serializer.validated_data['granted'],
            consent_text=serializer.validated_data.get('consent_text', ''),
            consent_text_version=policy.version if policy else '1.0',
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            collection_method='api',
            privacy_policy=policy,
        )

        return Response(
            ConsentRecordSerializer(consent).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['post'])
    def withdraw(self, request, pk=None):
        """
        Withdraw a consent.

        POST /api/v1/privacy/consents/{id}/withdraw/
        """
        consent = self.get_object()

        if consent.user != request.user:
            return Response(
                {'error': 'Not authorized'},
                status=status.HTTP_403_FORBIDDEN
            )

        tenant = get_current_tenant()
        consent_service = ConsentService(tenant)

        consent_service.withdraw_consent(
            user=request.user,
            consent_type=consent.consent_type,
            ip_address=self._get_client_ip(request),
            reason=request.data.get('reason', ''),
        )

        return Response({'status': 'consent_withdrawn'})

    @action(detail=False, methods=['get'])
    def active(self, request):
        """
        Get all active consents for the current user.

        GET /api/v1/privacy/consents/active/
        """
        tenant = get_current_tenant()
        consent_service = ConsentService(tenant)
        active_consents = consent_service.get_active_consents(request.user)

        return Response({
            consent_type: ConsentRecordSerializer(record).data
            for consent_type, record in active_consents.items()
        })

    @action(detail=False, methods=['get'])
    def purposes(self, request):
        """
        Get available data processing purposes.

        GET /api/v1/privacy/consents/purposes/
        """
        tenant = get_current_tenant()
        purposes = DataProcessingPurpose.objects.filter(
            tenant=tenant,
            is_active=True,
        )
        return Response(DataProcessingPurposeSerializer(purposes, many=True).data)

    def _get_client_ip(self, request):
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class DataSubjectRequestViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Data Subject Requests (DSR).

    Provides endpoints for:
    - Listing user's DSR requests
    - Creating access/erasure/rectification/portability requests
    - Checking request status
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = DataSubjectRequestSerializer

    def get_queryset(self):
        """Return DSRs for the current user."""
        tenant = get_current_tenant()
        return DataSubjectRequest.objects.filter(
            tenant=tenant,
            user=self.request.user,
        ).order_by('-submitted_at')

    def get_serializer_class(self):
        """Use different serializers for different actions."""
        if self.action == 'create':
            return DataSubjectRequestCreateSerializer
        return DataSubjectRequestSerializer

    def create(self, request, *args, **kwargs):
        """
        Create a new Data Subject Request.

        POST /api/v1/privacy/requests/
        {
            "request_type": "access",
            "description": "I would like a copy of all my data"
        }
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tenant = get_current_tenant()
        dsr_service = DataSubjectRequestService(tenant)

        request_type = serializer.validated_data['request_type']

        # Route to appropriate creation method
        if request_type == DataSubjectRequest.RequestType.ACCESS:
            dsr = dsr_service.create_access_request(
                user=request.user,
                description=serializer.validated_data.get('description', ''),
                data_categories=serializer.validated_data.get('data_categories', []),
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
        elif request_type == DataSubjectRequest.RequestType.ERASURE:
            dsr = dsr_service.create_erasure_request(
                user=request.user,
                description=serializer.validated_data.get('description', ''),
                data_categories=serializer.validated_data.get('data_categories', []),
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
        elif request_type == DataSubjectRequest.RequestType.RECTIFICATION:
            dsr = dsr_service.create_rectification_request(
                user=request.user,
                rectification_details=serializer.validated_data.get('rectification_details', {}),
                description=serializer.validated_data.get('description', ''),
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
        elif request_type == DataSubjectRequest.RequestType.PORTABILITY:
            dsr = dsr_service.create_portability_request(
                user=request.user,
                description=serializer.validated_data.get('description', ''),
                data_categories=serializer.validated_data.get('data_categories', []),
                export_format=serializer.validated_data.get('export_format', 'json'),
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
            )
        else:
            return Response(
                {'error': 'Invalid request type'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(
            DataSubjectRequestSerializer(dsr).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['get'])
    def status(self, request, pk=None):
        """
        Get the status of a specific DSR.

        GET /api/v1/privacy/requests/{id}/status/
        """
        dsr = self.get_object()
        return Response({
            'request_id': str(dsr.uuid),
            'status': dsr.status,
            'status_display': dsr.get_status_display(),
            'request_type': dsr.request_type,
            'submitted_at': dsr.submitted_at.isoformat(),
            'due_date': dsr.due_date.isoformat() if dsr.due_date else None,
            'days_remaining': dsr.days_remaining,
            'is_overdue': dsr.is_overdue,
            'completed_at': dsr.completed_at.isoformat() if dsr.completed_at else None,
        })

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """
        Download the response file for a completed DSR.

        GET /api/v1/privacy/requests/{id}/download/
        """
        dsr = self.get_object()

        if dsr.status != DataSubjectRequest.RequestStatus.COMPLETED:
            return Response(
                {'error': 'Request not yet completed'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not dsr.response_file:
            return Response(
                {'error': 'No export file available'},
                status=status.HTTP_404_NOT_FOUND
            )

        return FileResponse(
            dsr.response_file,
            as_attachment=True,
            filename=f"gdpr_export_{dsr.uuid.hex[:8]}.zip"
        )

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """
        Cancel a pending DSR.

        POST /api/v1/privacy/requests/{id}/cancel/
        """
        dsr = self.get_object()

        if dsr.status not in [
            DataSubjectRequest.RequestStatus.PENDING,
            DataSubjectRequest.RequestStatus.VERIFIED,
        ]:
            return Response(
                {'error': 'Request cannot be cancelled'},
                status=status.HTTP_400_BAD_REQUEST
            )

        dsr.status = DataSubjectRequest.RequestStatus.CANCELLED
        dsr.completed_at = timezone.now()
        dsr.save(update_fields=['status', 'completed_at'])

        return Response({'status': 'cancelled'})

    def _get_client_ip(self, request):
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class PrivacyDashboardView(LoginRequiredMixin, TemplateView):
    """
    Privacy dashboard view for users.

    Displays:
    - Current consent status
    - Data categories held
    - Active DSR requests
    - Privacy policy acceptance status
    - Data export options
    """

    template_name = 'privacy/privacy_dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = get_current_tenant()
        user = self.request.user

        # Get consent service
        consent_service = ConsentService(tenant)

        # Get active consents
        active_consents = consent_service.get_active_consents(user)

        # Get consent history
        consent_history = consent_service.get_consent_history(
            user,
            include_withdrawn=True
        )[:10]

        # Get pending DSRs
        pending_dsrs = DataSubjectRequest.objects.filter(
            tenant=tenant,
            user=user,
            status__in=[
                DataSubjectRequest.RequestStatus.PENDING,
                DataSubjectRequest.RequestStatus.VERIFIED,
                DataSubjectRequest.RequestStatus.IN_PROGRESS,
            ]
        )

        # Get completed DSRs
        completed_dsrs = DataSubjectRequest.objects.filter(
            tenant=tenant,
            user=user,
            status=DataSubjectRequest.RequestStatus.COMPLETED,
        ).order_by('-completed_at')[:5]

        # Get current privacy policy
        privacy_policy = PrivacyPolicy.objects.filter(
            tenant=tenant,
            is_current=True,
        ).first()

        # Check if user has accepted current policy
        policy_accepted = False
        if privacy_policy:
            policy_accepted = ConsentRecord.objects.filter(
                tenant=tenant,
                user=user,
                consent_type=ConsentRecord.ConsentType.PRIVACY_POLICY,
                privacy_policy=privacy_policy,
                granted=True,
                withdrawn=False,
            ).exists()

        # Get data processing purposes
        purposes = DataProcessingPurpose.objects.filter(
            tenant=tenant,
            is_active=True,
        )

        # Build consent status for each purpose
        purpose_consents = []
        for purpose in purposes:
            has_consent = consent_service.check_consent(
                user,
                ConsentRecord.ConsentType.CUSTOM,
                purpose_code=purpose.code,
            )
            purpose_consents.append({
                'purpose': purpose,
                'has_consent': has_consent,
            })

        context.update({
            'active_consents': active_consents,
            'consent_history': consent_history,
            'pending_dsrs': pending_dsrs,
            'completed_dsrs': completed_dsrs,
            'privacy_policy': privacy_policy,
            'policy_accepted': policy_accepted,
            'purpose_consents': purpose_consents,
            'consent_types': ConsentRecord.ConsentType.choices,
            'dsr_types': DataSubjectRequest.RequestType.choices,
        })

        return context


class DataExportView(LoginRequiredMixin, View):
    """
    View for triggering and downloading data exports.
    """

    def get(self, request):
        """Display the data export page."""
        tenant = get_current_tenant()

        # Check for existing pending export request
        existing_request = DataSubjectRequest.objects.filter(
            tenant=tenant,
            user=request.user,
            request_type=DataSubjectRequest.RequestType.PORTABILITY,
            status__in=[
                DataSubjectRequest.RequestStatus.PENDING,
                DataSubjectRequest.RequestStatus.VERIFIED,
                DataSubjectRequest.RequestStatus.IN_PROGRESS,
            ]
        ).first()

        # Get last completed export
        last_export = DataSubjectRequest.objects.filter(
            tenant=tenant,
            user=request.user,
            request_type__in=[
                DataSubjectRequest.RequestType.ACCESS,
                DataSubjectRequest.RequestType.PORTABILITY,
            ],
            status=DataSubjectRequest.RequestStatus.COMPLETED,
        ).order_by('-completed_at').first()

        return render(request, 'privacy/data_export.html', {
            'existing_request': existing_request,
            'last_export': last_export,
        })

    def post(self, request):
        """Trigger a new data export."""
        tenant = get_current_tenant()

        # Check for existing pending request
        existing = DataSubjectRequest.objects.filter(
            tenant=tenant,
            user=request.user,
            request_type=DataSubjectRequest.RequestType.PORTABILITY,
            status__in=[
                DataSubjectRequest.RequestStatus.PENDING,
                DataSubjectRequest.RequestStatus.VERIFIED,
                DataSubjectRequest.RequestStatus.IN_PROGRESS,
            ]
        ).exists()

        if existing:
            return JsonResponse({
                'error': 'An export request is already in progress'
            }, status=400)

        # Create DSR service
        dsr_service = DataSubjectRequestService(tenant)

        # Create portability request
        export_format = request.POST.get('format', 'json')
        dsr = dsr_service.create_portability_request(
            user=request.user,
            description='User-initiated data export',
            export_format=export_format,
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        # For immediate export, process synchronously (or queue task)
        if request.POST.get('immediate', 'false') == 'true':
            export_request = DataExportRequest(dsr)
            result = export_request.process(
                format=export_format,
                include_formats=['json', 'csv'],
            )

            if result['success']:
                return JsonResponse({
                    'status': 'completed',
                    'download_url': reverse_lazy(
                        'privacy:download_export',
                        kwargs={'pk': dsr.pk}
                    ),
                })

        return JsonResponse({
            'status': 'pending',
            'request_id': str(dsr.uuid),
            'message': 'Your export request has been submitted. '
                      'You will be notified when it is ready.',
        })

    def _get_client_ip(self, request):
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class ConsentFormView(LoginRequiredMixin, TemplateView):
    """
    View for displaying and submitting consent forms.
    """

    template_name = 'privacy/consent_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = get_current_tenant()

        # Get consent type from URL
        consent_type = self.kwargs.get('consent_type')

        # Get current privacy policy
        privacy_policy = PrivacyPolicy.objects.filter(
            tenant=tenant,
            is_current=True,
        ).first()

        # Get associated processing purpose if any
        purpose = None
        if consent_type:
            purpose = DataProcessingPurpose.objects.filter(
                tenant=tenant,
                code=consent_type,
            ).first()

        # Get existing consent if any
        consent_service = ConsentService(tenant)
        existing_consent = None
        if consent_type:
            consents = consent_service.get_consent_history(
                self.request.user,
                consent_type=consent_type,
                include_withdrawn=False,
            )
            existing_consent = consents[0] if consents else None

        context.update({
            'consent_type': consent_type,
            'privacy_policy': privacy_policy,
            'purpose': purpose,
            'existing_consent': existing_consent,
            'consent_types': ConsentRecord.ConsentType.choices,
        })

        return context

    def post(self, request, *args, **kwargs):
        """Process consent form submission."""
        tenant = get_current_tenant()
        consent_service = ConsentService(tenant)

        consent_type = request.POST.get('consent_type')
        granted = request.POST.get('granted') == 'true'
        consent_text = request.POST.get('consent_text', '')

        # Get current privacy policy for versioning
        policy = PrivacyPolicy.objects.filter(
            tenant=tenant,
            is_current=True
        ).first()

        if granted:
            consent_service.record_consent(
                user=request.user,
                consent_type=consent_type,
                granted=True,
                consent_text=consent_text,
                consent_text_version=policy.version if policy else '1.0',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                collection_method='web_form',
                privacy_policy=policy,
            )
        else:
            consent_service.withdraw_consent(
                user=request.user,
                consent_type=consent_type,
                ip_address=self._get_client_ip(request),
            )

        # Redirect back to dashboard
        return redirect('privacy:dashboard')

    def _get_client_ip(self, request):
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class PrivacyPolicyView(TemplateView):
    """
    View for displaying the current privacy policy.
    """

    template_name = 'privacy/privacy_policy.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = get_current_tenant()

        # Get requested version or current
        version = self.kwargs.get('version')

        if version:
            policy = get_object_or_404(
                PrivacyPolicy,
                tenant=tenant,
                version=version,
                is_published=True,
            )
        else:
            policy = PrivacyPolicy.objects.filter(
                tenant=tenant,
                is_current=True,
            ).first()

        # Get all published versions for version selector
        all_versions = PrivacyPolicy.objects.filter(
            tenant=tenant,
            is_published=True,
        ).order_by('-effective_date')

        context.update({
            'policy': policy,
            'all_versions': all_versions,
        })

        return context


# Admin views for managing privacy requests

class AdminDSRListView(LoginRequiredMixin, TemplateView):
    """
    Admin view for listing and managing DSR requests.
    """

    template_name = 'privacy/admin/dsr_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tenant = get_current_tenant()

        # Filter by status if provided
        status_filter = self.request.GET.get('status')

        queryset = DataSubjectRequest.objects.filter(tenant=tenant)

        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Get counts by status
        status_counts = {}
        for status_choice in DataSubjectRequest.RequestStatus.choices:
            status_counts[status_choice[0]] = DataSubjectRequest.objects.filter(
                tenant=tenant,
                status=status_choice[0],
            ).count()

        # Get overdue requests
        overdue_count = DataSubjectRequest.objects.filter(
            tenant=tenant,
            status__in=[
                DataSubjectRequest.RequestStatus.PENDING,
                DataSubjectRequest.RequestStatus.VERIFIED,
                DataSubjectRequest.RequestStatus.IN_PROGRESS,
            ],
            due_date__lt=timezone.now(),
        ).count()

        context.update({
            'dsrs': queryset.order_by('-submitted_at')[:50],
            'status_counts': status_counts,
            'overdue_count': overdue_count,
            'current_filter': status_filter,
            'status_choices': DataSubjectRequest.RequestStatus.choices,
        })

        return context
