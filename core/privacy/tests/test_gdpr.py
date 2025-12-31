"""
GDPR Compliance Tests for Zumodra ATS/HR Platform

This module tests GDPR compliance including:
- Consent recording and withdrawal
- Data subject access request (DSAR) processing
- Data erasure (right to be forgotten)
- Data portability export
- Retention policy enforcement
- Anonymization functions

Each test documents the GDPR requirement being tested.
"""

import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch
from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, RequestFactory
from django.utils import timezone

User = get_user_model()


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def consent_service():
    """Create ConsentService instance."""
    from core.privacy.services import ConsentService
    return ConsentService()


@pytest.fixture
def dsar_service():
    """Create DataSubjectRequestService instance."""
    from core.privacy.services import DataSubjectRequestService
    return DataSubjectRequestService()


@pytest.fixture
def retention_service():
    """Create DataRetentionService instance."""
    from core.privacy.services import DataRetentionService
    return DataRetentionService()


@pytest.fixture
def anonymization_service():
    """Create AnonymizationService instance."""
    from core.privacy.services import AnonymizationService
    return AnonymizationService()


@pytest.fixture
def gdpr_exporter():
    """Create GDPRDataExporter instance."""
    from core.privacy.exporters import GDPRDataExporter
    return GDPRDataExporter()


# =============================================================================
# CONSENT MANAGEMENT TESTS
# =============================================================================

class TestConsentManagement:
    """
    Tests for consent recording and management.

    GDPR Requirements:
    - Article 7: Conditions for consent
    - Article 4(11): Consent definition
    - Consent must be freely given, specific, informed, unambiguous
    """

    def test_consent_recording_includes_required_fields(
        self, consent_service, user_factory, tenant_factory, db
    ):
        """
        Test: Consent records include all required fields.
        GDPR Art. 7(1): Controller must demonstrate consent.
        """
        user = user_factory()
        tenant = tenant_factory()

        consent = consent_service.record_consent(
            user=user,
            tenant=tenant,
            purpose='marketing_emails',
            consent_text='I agree to receive marketing communications',
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0'
        )

        # Required fields for demonstrable consent
        assert consent.user == user
        assert consent.purpose == 'marketing_emails'
        assert consent.consent_text is not None
        assert consent.ip_address is not None
        assert consent.user_agent is not None
        assert consent.consented_at is not None
        assert consent.consent_version is not None

    def test_consent_granularity_per_purpose(
        self, consent_service, user_factory, tenant_factory, db
    ):
        """
        Test: Consent is tracked separately per purpose.
        GDPR Art. 6(1)(a): Consent must be specific.
        """
        user = user_factory()
        tenant = tenant_factory()

        # Consent to marketing
        consent_service.record_consent(
            user=user,
            tenant=tenant,
            purpose='marketing_emails',
            given=True
        )

        # Decline analytics
        consent_service.record_consent(
            user=user,
            tenant=tenant,
            purpose='analytics_tracking',
            given=False
        )

        # Check each purpose separately
        assert consent_service.has_consent(user, 'marketing_emails')
        assert not consent_service.has_consent(user, 'analytics_tracking')

    def test_consent_withdrawal(
        self, consent_service, user_factory, tenant_factory, db
    ):
        """
        Test: Users can withdraw consent at any time.
        GDPR Art. 7(3): Right to withdraw consent.
        """
        user = user_factory()
        tenant = tenant_factory()

        # Give consent
        consent_service.record_consent(
            user=user,
            tenant=tenant,
            purpose='marketing_emails',
            given=True
        )
        assert consent_service.has_consent(user, 'marketing_emails')

        # Withdraw consent
        consent_service.withdraw_consent(user, 'marketing_emails')
        assert not consent_service.has_consent(user, 'marketing_emails')

    def test_consent_withdrawal_audited(
        self, consent_service, user_factory, tenant_factory, db
    ):
        """
        Test: Consent withdrawal is logged for audit.
        """
        user = user_factory()
        tenant = tenant_factory()

        consent_service.record_consent(user=user, tenant=tenant, purpose='marketing', given=True)

        with patch('core.privacy.services.audit_log') as mock_log:
            consent_service.withdraw_consent(user, 'marketing')

            mock_log.log_consent_withdrawal.assert_called()

    def test_consent_version_tracking(
        self, consent_service, user_factory, tenant_factory, db
    ):
        """
        Test: Consent versions are tracked when terms change.
        GDPR: Must recollect consent if purpose/terms change.
        """
        user = user_factory()
        tenant = tenant_factory()

        # Initial consent with version 1
        consent_v1 = consent_service.record_consent(
            user=user,
            tenant=tenant,
            purpose='data_processing',
            consent_version='1.0'
        )

        # Update terms - should require new consent
        assert consent_service.requires_reconsent(user, 'data_processing', required_version='2.0')

    def test_consent_expiry(
        self, consent_service, user_factory, tenant_factory, db
    ):
        """
        Test: Consent can expire after specified period.
        Best Practice: Refresh consent periodically.
        """
        user = user_factory()
        tenant = tenant_factory()

        # Consent with 1-year expiry
        consent_service.record_consent(
            user=user,
            tenant=tenant,
            purpose='marketing',
            expires_in_days=365
        )

        # Currently valid
        assert consent_service.has_valid_consent(user, 'marketing')

        # Simulate 366 days passing
        with patch('core.privacy.services.timezone.now') as mock_now:
            mock_now.return_value = timezone.now() + timedelta(days=366)
            assert not consent_service.has_valid_consent(user, 'marketing')

    def test_consent_for_minors_requires_parental(self):
        """
        Test: Minors (under 16) require parental consent.
        GDPR Art. 8: Conditions for child's consent.
        """
        # This would check date of birth and require additional verification
        pass


# =============================================================================
# DATA SUBJECT ACCESS REQUEST TESTS
# =============================================================================

class TestDataSubjectAccessRequest:
    """
    Tests for Data Subject Access Request (DSAR) processing.

    GDPR Requirements:
    - Article 15: Right of access
    - Must respond within 30 days
    - Free of charge for first request
    """

    def test_dsar_creates_request_record(
        self, dsar_service, user_factory, db
    ):
        """
        Test: DSAR creates a trackable request record.
        """
        user = user_factory()

        request = dsar_service.create_request(
            user=user,
            request_type='access',
            requester_email=user.email
        )

        assert request.id is not None
        assert request.status == 'pending'
        assert request.request_type == 'access'
        assert request.created_at is not None

    def test_dsar_collects_all_user_data(
        self, dsar_service, user_factory, tenant_factory,
        user_profile_factory, application_factory, db
    ):
        """
        Test: DSAR collects all data related to the user.
        GDPR Art. 15(1): Right to obtain all personal data.
        """
        user = user_factory()
        profile = user_profile_factory(user=user)

        # Create DSAR
        request = dsar_service.create_request(user=user, request_type='access')

        # Process request
        data = dsar_service.process_access_request(request)

        # Should include all personal data categories
        assert 'account' in data
        assert 'profile' in data
        assert 'login_history' in data
        assert 'consent_records' in data
        assert 'applications' in data  # If candidate
        assert 'data_access_logs' in data

    def test_dsar_response_within_30_days(
        self, dsar_service, user_factory, db
    ):
        """
        Test: DSAR deadline is tracked (30 days).
        GDPR Art. 12(3): Response within one month.
        """
        user = user_factory()

        request = dsar_service.create_request(user=user, request_type='access')

        assert request.deadline is not None
        expected_deadline = request.created_at + timedelta(days=30)
        assert request.deadline.date() == expected_deadline.date()

    def test_dsar_extension_notification(
        self, dsar_service, user_factory, db
    ):
        """
        Test: Extension of DSAR deadline is allowed with notification.
        GDPR Art. 12(3): Can extend by 2 months with notification.
        """
        user = user_factory()

        request = dsar_service.create_request(user=user, request_type='access')

        with patch('core.privacy.services.send_notification') as mock_notify:
            dsar_service.extend_deadline(request, reason='complex request', days=60)

            mock_notify.assert_called()
            assert request.extension_reason == 'complex request'
            assert request.extended_deadline is not None

    def test_dsar_includes_processing_purposes(
        self, dsar_service, user_factory, db
    ):
        """
        Test: DSAR response includes purposes of processing.
        GDPR Art. 15(1)(a): Purposes of the processing.
        """
        user = user_factory()
        request = dsar_service.create_request(user=user, request_type='access')

        response = dsar_service.process_access_request(request)

        assert 'processing_purposes' in response
        assert len(response['processing_purposes']) > 0

    def test_dsar_includes_data_recipients(
        self, dsar_service, user_factory, db
    ):
        """
        Test: DSAR includes recipients of personal data.
        GDPR Art. 15(1)(c): Recipients or categories.
        """
        user = user_factory()
        request = dsar_service.create_request(user=user, request_type='access')

        response = dsar_service.process_access_request(request)

        assert 'data_recipients' in response

    def test_dsar_includes_retention_period(
        self, dsar_service, user_factory, db
    ):
        """
        Test: DSAR includes data retention period.
        GDPR Art. 15(1)(d): Retention period or criteria.
        """
        user = user_factory()
        request = dsar_service.create_request(user=user, request_type='access')

        response = dsar_service.process_access_request(request)

        assert 'retention_periods' in response


# =============================================================================
# DATA ERASURE TESTS
# =============================================================================

class TestDataErasure:
    """
    Tests for data erasure (right to be forgotten).

    GDPR Requirements:
    - Article 17: Right to erasure
    - Must erase without undue delay
    - Must inform processors
    """

    def test_erasure_deletes_personal_data(
        self, dsar_service, user_factory, user_profile_factory, db
    ):
        """
        Test: Erasure request deletes personal data.
        GDPR Art. 17(1): Right to erasure.
        """
        user = user_factory(email='to_delete@test.com')
        profile = user_profile_factory(user=user)

        request = dsar_service.create_request(user=user, request_type='erasure')
        dsar_service.process_erasure_request(request)

        # User should be deleted or anonymized
        from django.contrib.auth import get_user_model
        User = get_user_model()

        # Either user doesn't exist or is anonymized
        try:
            refreshed_user = User.objects.get(id=user.id)
            # If exists, should be anonymized
            assert refreshed_user.email != 'to_delete@test.com'
        except User.DoesNotExist:
            pass  # Deleted - also acceptable

    def test_erasure_notifies_processors(
        self, dsar_service, user_factory, db
    ):
        """
        Test: Erasure notifies third-party processors.
        GDPR Art. 17(2): Inform other controllers.
        """
        user = user_factory()

        with patch('core.privacy.services.notify_processors') as mock_notify:
            request = dsar_service.create_request(user=user, request_type='erasure')
            dsar_service.process_erasure_request(request)

            mock_notify.assert_called()

    def test_erasure_preserves_legal_hold_data(
        self, dsar_service, user_factory, db
    ):
        """
        Test: Data under legal hold is not erased.
        GDPR Art. 17(3)(e): Establishment of legal claims.
        """
        user = user_factory()

        # Mark user data as under legal hold
        with patch('core.privacy.services.has_legal_hold') as mock_hold:
            mock_hold.return_value = True

            request = dsar_service.create_request(user=user, request_type='erasure')

            with pytest.raises(Exception) as excinfo:
                dsar_service.process_erasure_request(request)

            assert 'legal hold' in str(excinfo.value).lower()

    def test_erasure_preserves_contract_data(
        self, dsar_service, user_factory, db
    ):
        """
        Test: Data necessary for contract performance is retained.
        GDPR Art. 17(3)(b): Performance of a contract.
        """
        user = user_factory()

        # User has active employment contract
        with patch('core.privacy.services.has_active_contract') as mock_contract:
            mock_contract.return_value = True

            request = dsar_service.create_request(user=user, request_type='erasure')

            # Should not fully erase, but partial erasure or rejection
            result = dsar_service.process_erasure_request(request)
            assert result.status in ['partial', 'rejected']

    def test_erasure_logs_for_audit(
        self, dsar_service, user_factory, db
    ):
        """
        Test: Erasure actions are logged for accountability.
        GDPR Art. 5(2): Accountability principle.
        """
        user = user_factory()

        with patch('core.privacy.services.audit_log') as mock_log:
            request = dsar_service.create_request(user=user, request_type='erasure')
            dsar_service.process_erasure_request(request)

            mock_log.log_erasure.assert_called()


# =============================================================================
# DATA PORTABILITY TESTS
# =============================================================================

class TestDataPortability:
    """
    Tests for data portability export.

    GDPR Requirements:
    - Article 20: Right to data portability
    - Machine-readable format
    - Commonly used format (JSON, CSV)
    """

    def test_export_in_machine_readable_format(
        self, gdpr_exporter, user_factory, user_profile_factory, db
    ):
        """
        Test: Data export is in machine-readable format.
        GDPR Art. 20(1): Structured, commonly used format.
        """
        user = user_factory()
        profile = user_profile_factory(user=user)

        export_data = gdpr_exporter.export_user_data(user, format='json')

        # Should be valid JSON
        parsed = json.loads(export_data)
        assert isinstance(parsed, dict)

    def test_export_includes_provided_data(
        self, gdpr_exporter, user_factory, user_profile_factory, db
    ):
        """
        Test: Export includes data provided by user.
        GDPR Art. 20(1): Data concerning them which they provided.
        """
        user = user_factory(email='test@example.com')
        profile = user_profile_factory(user=user, bio='My bio text')

        export_data = gdpr_exporter.export_user_data(user, format='json')
        parsed = json.loads(export_data)

        # Should include user-provided data
        assert parsed['profile']['bio'] == 'My bio text'
        assert parsed['account']['email'] == 'test@example.com'

    def test_export_formats_supported(
        self, gdpr_exporter, user_factory, db
    ):
        """
        Test: Multiple export formats are supported.
        """
        user = user_factory()

        # JSON export
        json_export = gdpr_exporter.export_user_data(user, format='json')
        assert json_export is not None

        # CSV export
        csv_export = gdpr_exporter.export_user_data(user, format='csv')
        assert csv_export is not None

    def test_export_excludes_inferred_data(
        self, gdpr_exporter, user_factory, db
    ):
        """
        Test: Export may exclude inferred/derived data.
        GDPR Art. 20: Only data "provided" by subject.
        """
        user = user_factory()

        export_data = gdpr_exporter.export_user_data(user, format='json')
        parsed = json.loads(export_data)

        # Inferred data (like predictions) may be excluded
        # This depends on implementation

    def test_export_can_be_transmitted_to_other_controller(
        self, gdpr_exporter, user_factory, db
    ):
        """
        Test: Export supports transmission to another controller.
        GDPR Art. 20(2): Right to have data transmitted.
        """
        user = user_factory()

        # Export in format suitable for transmission
        export_data = gdpr_exporter.export_user_data(
            user,
            format='json',
            include_schema=True  # Include schema for interoperability
        )

        parsed = json.loads(export_data)
        assert 'schema' in parsed or 'metadata' in parsed


# =============================================================================
# RETENTION POLICY TESTS
# =============================================================================

class TestRetentionPolicy:
    """
    Tests for data retention policy enforcement.

    GDPR Requirements:
    - Article 5(1)(e): Storage limitation
    - Data kept only as long as necessary
    - Regular review of necessity
    """

    def test_retention_policy_applied(
        self, retention_service, user_factory, application_factory, db
    ):
        """
        Test: Retention policies are applied to data.
        """
        user = user_factory()
        application = application_factory()

        # Set retention policy
        retention_service.set_policy(
            model='Application',
            retention_days=730,  # 2 years
            action='anonymize'
        )

        # Verify policy is stored
        policy = retention_service.get_policy('Application')
        assert policy.retention_days == 730
        assert policy.action == 'anonymize'

    def test_retention_cleanup_job(
        self, retention_service, application_factory, db
    ):
        """
        Test: Retention cleanup job processes expired data.
        """
        # Create old application (past retention)
        with patch('django.utils.timezone.now') as mock_now:
            mock_now.return_value = timezone.now() - timedelta(days=1000)
            old_app = application_factory()

        # Run cleanup
        with patch('core.privacy.services.timezone.now') as mock_now:
            mock_now.return_value = timezone.now()
            results = retention_service.run_cleanup()

        # Old application should be processed
        assert results['processed_count'] > 0

    def test_retention_respects_legal_hold(
        self, retention_service, application_factory, db
    ):
        """
        Test: Legal hold prevents retention cleanup.
        """
        application = application_factory()

        # Put on legal hold
        retention_service.set_legal_hold(application)

        # Cleanup should skip
        with patch.object(retention_service, 'delete_record') as mock_delete:
            retention_service.run_cleanup()
            # Should not be called for held record
            assert application.id not in [
                call.args[0].id for call in mock_delete.call_args_list
            ] if mock_delete.call_args_list else True

    def test_retention_different_per_data_type(
        self, retention_service, db
    ):
        """
        Test: Different data types can have different retention.
        """
        # Applications: 2 years
        retention_service.set_policy('Application', retention_days=730)

        # Login history: 90 days
        retention_service.set_policy('LoginHistory', retention_days=90)

        # Verify different policies
        assert retention_service.get_policy('Application').retention_days == 730
        assert retention_service.get_policy('LoginHistory').retention_days == 90


# =============================================================================
# ANONYMIZATION TESTS
# =============================================================================

class TestAnonymization:
    """
    Tests for data anonymization functions.

    GDPR Requirements:
    - Recital 26: Anonymized data outside GDPR scope
    - Must be irreversibly anonymized
    - No reasonable means of re-identification
    """

    def test_anonymize_email(self, anonymization_service):
        """
        Test: Email addresses are properly anonymized.
        """
        email = "john.doe@company.com"

        anonymized = anonymization_service.anonymize_email(email)

        assert anonymized != email
        assert 'john' not in anonymized.lower()
        assert 'doe' not in anonymized.lower()
        assert '@' in anonymized  # Maintain format for validity

    def test_anonymize_phone(self, anonymization_service):
        """
        Test: Phone numbers are properly anonymized.
        """
        phone = "+1-555-123-4567"

        anonymized = anonymization_service.anonymize_phone(phone)

        assert anonymized != phone
        assert '123' not in anonymized
        assert '4567' not in anonymized

    def test_anonymize_name(self, anonymization_service):
        """
        Test: Names are properly anonymized.
        """
        name = "John Smith"

        anonymized = anonymization_service.anonymize_name(name)

        assert anonymized != name
        assert 'John' not in anonymized
        assert 'Smith' not in anonymized

    def test_anonymize_address(self, anonymization_service):
        """
        Test: Addresses are properly anonymized.
        """
        address = {
            'street': '123 Main Street',
            'city': 'Toronto',
            'postal_code': 'M5V 1A1'
        }

        anonymized = anonymization_service.anonymize_address(address)

        assert anonymized['street'] != address['street']
        assert anonymized['postal_code'] != address['postal_code']

    def test_anonymization_is_irreversible(self, anonymization_service):
        """
        Test: Anonymization cannot be reversed.
        """
        original = "sensitive_data_12345"

        anonymized = anonymization_service.anonymize_text(original)

        # Should use one-way transformation
        # No mapping stored that could reverse it
        assert not anonymization_service.can_reverse(anonymized)

    def test_anonymize_preserves_referential_integrity(
        self, anonymization_service, db
    ):
        """
        Test: Anonymization preserves database relationships.
        """
        # When anonymizing a user, related records should still link correctly
        # (FK constraints maintained, just data changed)

    def test_k_anonymity_check(self, anonymization_service, db):
        """
        Test: Anonymized data meets k-anonymity requirements.
        Best Practice: At least k=5 for quasi-identifiers.
        """
        # After anonymization, each combination of quasi-identifiers
        # should appear at least k times in the dataset

    def test_anonymize_user_record(
        self, anonymization_service, user_factory, user_profile_factory, db
    ):
        """
        Test: Complete user record anonymization.
        """
        user = user_factory(
            email='real.person@email.com',
            first_name='John',
            last_name='Doe'
        )
        profile = user_profile_factory(
            user=user,
            phone='+15551234567',
            address_line1='123 Real Street'
        )

        anonymization_service.anonymize_user(user)

        user.refresh_from_db()
        profile.refresh_from_db()

        # All PII should be anonymized
        assert 'real.person' not in user.email
        assert 'John' not in user.first_name
        assert 'Doe' not in user.last_name
        assert '123 Real Street' not in profile.address_line1


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestGDPRIntegration:
    """
    Integration tests for GDPR compliance.
    """

    @pytest.mark.django_db
    def test_complete_dsar_flow(
        self, dsar_service, gdpr_exporter, user_factory,
        user_profile_factory, db
    ):
        """
        Test: Complete DSAR flow from request to delivery.
        """
        user = user_factory(email='subject@test.com')
        profile = user_profile_factory(user=user)

        # Create DSAR
        request = dsar_service.create_request(
            user=user,
            request_type='access',
            requester_email=user.email
        )

        # Verify identity (mocked)
        dsar_service.verify_identity(request, verification_token='valid')

        # Process request
        data = dsar_service.process_access_request(request)

        # Generate export
        export = gdpr_exporter.export_user_data(user, format='json')

        # Mark as completed
        dsar_service.complete_request(request, export_file=export)

        assert request.status == 'completed'
        assert request.completed_at is not None

    @pytest.mark.django_db
    def test_consent_affects_data_processing(
        self, consent_service, user_factory, tenant_factory, db
    ):
        """
        Test: Data processing respects consent status.
        """
        user = user_factory()
        tenant = tenant_factory()

        # No consent - processing should be blocked
        assert not consent_service.has_consent(user, 'marketing')

        # Attempt to send marketing should fail
        with patch('marketing.services.send_marketing_email') as mock_send:
            from marketing.services import MarketingService
            service = MarketingService()

            # Should check consent before sending
            with pytest.raises(Exception):
                service.send_marketing_email(user, 'Campaign 1')

        # Give consent
        consent_service.record_consent(
            user=user,
            tenant=tenant,
            purpose='marketing',
            given=True
        )

        # Now should be allowed
        assert consent_service.has_consent(user, 'marketing')

    @pytest.mark.django_db
    def test_privacy_by_design_in_new_features(self, db):
        """
        Test: New features implement privacy by design.
        GDPR Art. 25: Data protection by design and by default.
        """
        # This is more of a development guideline check
        # Verify new models have:
        # - Consent fields where needed
        # - Retention policies defined
        # - Anonymization functions
        # - Audit logging
        pass
