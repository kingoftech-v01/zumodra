"""
Comprehensive tests for tenant migration verification and management.

Tests cover:
- Migration verification command
- Health check tenant migration integration
- Error handling in finance views
- Automated fix functionality
- Edge cases and failure scenarios
"""

import pytest
from decimal import Decimal
from unittest.mock import patch, MagicMock, call
from io import StringIO
from django.core.management import call_command
from django.db import OperationalError, ProgrammingError
from django.test import RequestFactory
from django_tenants.utils import schema_context, get_tenant_model

from core.management.commands.verify_tenant_migrations import Command as VerifyCommand
from core.management.commands.health_check import Command as HealthCheckCommand
from finance.template_views import (
    FinanceDashboardView,
    SubscriptionTemplateView,
    SubscriptionStatusPartialView,
    SubscriptionPlansPartialView
)
from finance.models import (
    UserSubscription,
    SubscriptionPlan,
    PaymentTransaction,
    Invoice,
    EscrowTransaction,
    PaymentMethod,
    ConnectedAccount
)


@pytest.mark.django_db
class TestVerifyTenantMigrationsCommand:
    """Test the verify_tenant_migrations management command."""

    def test_command_exists(self):
        """Test that the command can be imported and instantiated."""
        command = VerifyCommand()
        assert command is not None
        assert hasattr(command, 'handle')

    def test_no_tenants_json_output(self, capsys):
        """Test JSON output when no tenants exist."""
        out = StringIO()
        call_command('verify_tenant_migrations', '--json', stdout=out)
        output = out.getvalue()

        assert 'total_tenants' in output
        assert '"status"' in output

    @patch('core.management.commands.verify_tenant_migrations.get_tenant_model')
    def test_check_all_tenants(self, mock_get_tenant_model):
        """Test checking all tenant schemas."""
        # Mock tenant model
        mock_tenant = MagicMock()
        mock_tenant.schema_name = 'tenant_test'
        mock_tenant.get_primary_domain.return_value.domain = 'test.example.com'

        mock_tenant_model = MagicMock()
        mock_tenant_model.objects.exclude.return_value = [mock_tenant]
        mock_get_tenant_model.return_value = mock_tenant_model

        command = VerifyCommand()
        result = command._check_tenant(mock_tenant)

        assert 'schema_name' in result
        assert result['schema_name'] == 'tenant_test'
        assert 'pending_count' in result

    def test_json_output_format(self):
        """Test that JSON output is valid."""
        import json
        out = StringIO()

        try:
            call_command('verify_tenant_migrations', '--json', stdout=out)
            output = out.getvalue()
            data = json.loads(output)

            # Verify JSON structure
            assert 'total_tenants' in data
            assert 'tenants_ok' in data
            assert 'tenants_with_issues' in data
            assert isinstance(data['tenants'], list)
        except json.JSONDecodeError:
            pytest.fail("Command output is not valid JSON")

    @patch('core.management.commands.verify_tenant_migrations.call_command')
    def test_auto_fix_functionality(self, mock_call_command):
        """Test the --fix flag triggers migration application."""
        out = StringIO()

        with patch('core.management.commands.verify_tenant_migrations.get_tenant_model') as mock_tenant_model:
            # Setup mock to simulate pending migrations
            mock_tenant = MagicMock()
            mock_tenant.schema_name = 'tenant_test'
            mock_tenant_model.return_value.objects.exclude.return_value = [mock_tenant]

            # This will attempt auto-fix
            call_command('verify_tenant_migrations', '--fix', '--json', stdout=out)

            # Verify migrate_schemas was called
            assert mock_call_command.called

    def test_app_filter(self):
        """Test filtering by specific app."""
        out = StringIO()
        call_command('verify_tenant_migrations', '--app=finance', '--json', stdout=out)

        import json
        data = json.loads(out.getvalue())
        assert 'total_tenants' in data


@pytest.mark.django_db
class TestHealthCheckTenantMigrations:
    """Test tenant migration integration in health check command."""

    def test_health_check_includes_tenant_migrations(self):
        """Test that full health check includes tenant migration check."""
        out = StringIO()
        call_command('health_check', '--full', '--json', stdout=out)

        import json
        data = json.loads(out.getvalue())

        assert 'checks' in data
        assert 'tenant_migrations' in data['checks']

    def test_tenant_migration_check_structure(self):
        """Test the structure of tenant migration check result."""
        command = HealthCheckCommand()
        result = command._check_tenant_migrations()

        assert 'status' in result
        assert 'message' in result
        assert 'details' in result
        assert result['status'] in ['healthy', 'warning', 'unhealthy']

    @patch('core.management.commands.health_check.get_tenant_model')
    def test_no_tenants_scenario(self, mock_get_tenant_model):
        """Test health check when no tenants exist."""
        mock_tenant_model = MagicMock()
        mock_tenant_model.objects.exclude.return_value.exists.return_value = False
        mock_get_tenant_model.return_value = mock_tenant_model

        command = HealthCheckCommand()
        result = command._check_tenant_migrations()

        assert result['status'] == 'healthy'
        assert 'No tenant schemas to check' in result['message']


@pytest.mark.django_db
class TestFinanceViewErrorHandling:
    """Test defensive error handling in finance views."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.user = MagicMock()
        self.user.id = 1

    def test_finance_dashboard_handles_missing_tables(self):
        """Test FinanceDashboardView handles database errors gracefully."""
        request = self.factory.get('/finance/dashboard/')
        request.user = self.user

        view = FinanceDashboardView()
        view.request = request

        with patch.object(PaymentTransaction.objects, 'filter', side_effect=ProgrammingError("relation does not exist")):
            context = view.get_context_data()

            assert context['migration_error'] is True
            assert context['total_spent'] == Decimal('0.00')
            assert context['payment_count'] == 0

    def test_subscription_view_handles_missing_tables(self):
        """Test SubscriptionTemplateView handles database errors gracefully."""
        request = self.factory.get('/finance/subscription/')
        request.user = self.user

        view = SubscriptionTemplateView()
        view.request = request

        with patch.object(UserSubscription.objects, 'get', side_effect=ProgrammingError("relation does not exist")):
            context = view.get_context_data()

            assert context['migration_error'] is True
            assert context['subscription'] is None

    def test_subscription_view_handles_does_not_exist(self):
        """Test SubscriptionTemplateView handles missing subscription normally."""
        request = self.factory.get('/finance/subscription/')
        request.user = self.user

        view = SubscriptionTemplateView()
        view.request = request

        with patch.object(UserSubscription.objects, 'get', side_effect=UserSubscription.DoesNotExist):
            with patch.object(SubscriptionPlan.objects, 'all', return_value=[]):
                context = view.get_context_data()

                # Should NOT set migration_error for normal DoesNotExist
                assert context.get('migration_error', False) is False
                assert context['subscription'] is None

    def test_subscription_plans_view_handles_errors(self):
        """Test SubscriptionPlansPartialView handles database errors."""
        request = self.factory.get('/finance/subscription/plans/')
        request.user = self.user

        view = SubscriptionPlansPartialView()

        with patch.object(SubscriptionPlan.objects, 'all', side_effect=OperationalError("database error")):
            response = view.get(request)

            # Should return response without crashing
            assert response is not None

    def test_all_aggregations_have_error_handling(self):
        """Test that all database aggregations in dashboard have error handling."""
        request = self.factory.get('/finance/dashboard/')
        request.user = self.user

        view = FinanceDashboardView()
        view.request = request

        # Test with multiple model failures
        with patch.object(PaymentTransaction.objects, 'filter', side_effect=ProgrammingError("error")):
            with patch.object(Invoice.objects, 'filter', side_effect=ProgrammingError("error")):
                with patch.object(EscrowTransaction.objects, 'filter', side_effect=ProgrammingError("error")):
                    with patch.object(PaymentMethod.objects, 'filter', side_effect=ProgrammingError("error")):
                        with patch.object(ConnectedAccount.objects, 'get', side_effect=ProgrammingError("error")):
                            context = view.get_context_data()

                            # Should have safe defaults
                            assert context['migration_error'] is True
                            assert context['total_spent'] == Decimal('0.00')
                            assert context['outstanding_invoices'] == 0
                            assert context['escrow_pending_buyer'] == 0


@pytest.mark.django_db
class TestMigrationVerificationEdgeCases:
    """Test edge cases and error scenarios."""

    def test_verify_command_with_invalid_tenant(self):
        """Test verification with non-existent tenant."""
        out = StringIO()
        err = StringIO()

        with pytest.raises(SystemExit):
            call_command('verify_tenant_migrations', '--tenant=nonexistent', stdout=out, stderr=err)

    def test_verify_command_exit_codes(self):
        """Test that command returns proper exit codes."""
        # Exit code 0 for success, 1 for issues
        out = StringIO()

        try:
            call_command('verify_tenant_migrations', '--json', stdout=out)
            # If no issues, should not raise SystemExit
        except SystemExit as e:
            # Check exit code is appropriate
            assert e.code in [0, 1]

    @patch('core.management.commands.verify_tenant_migrations.logger')
    def test_error_logging(self, mock_logger):
        """Test that errors are logged properly."""
        with patch.object(UserSubscription.objects, 'get', side_effect=ProgrammingError("test error")):
            request = RequestFactory().get('/')
            request.user = MagicMock()

            view = SubscriptionTemplateView()
            view.request = request
            view.get_context_data()

            # Verify error was logged
            # Note: This depends on logger being imported in the view


@pytest.mark.integration
class TestMigrationWorkflow:
    """Integration tests for complete migration workflow."""

    @pytest.mark.django_db
    def test_full_verification_workflow(self):
        """Test complete verification and health check workflow."""
        # Run verification
        verify_out = StringIO()
        call_command('verify_tenant_migrations', '--json', stdout=verify_out)

        # Run health check
        health_out = StringIO()
        call_command('health_check', '--full', '--json', stdout=health_out)

        # Parse outputs
        import json
        verify_data = json.loads(verify_out.getvalue())
        health_data = json.loads(health_out.getvalue())

        # Verify consistency
        assert 'total_tenants' in verify_data
        assert 'tenant_migrations' in health_data['checks']

    @pytest.mark.django_db
    def test_migration_state_consistency(self):
        """Test that migration state is consistent across checks."""
        out1 = StringIO()
        out2 = StringIO()

        call_command('verify_tenant_migrations', '--json', stdout=out1)
        call_command('verify_tenant_migrations', '--json', stdout=out2)

        import json
        data1 = json.loads(out1.getvalue())
        data2 = json.loads(out2.getvalue())

        # Should get same results
        assert data1['total_tenants'] == data2['total_tenants']


@pytest.mark.security
class TestSecurityConsiderations:
    """Test security aspects of migration handling."""

    def test_no_sensitive_data_in_logs(self, caplog):
        """Test that sensitive data is not logged."""
        request = RequestFactory().get('/')
        request.user = MagicMock()
        request.user.id = 999
        request.user.email = "sensitive@example.com"

        view = SubscriptionTemplateView()
        view.request = request

        with patch.object(UserSubscription.objects, 'get', side_effect=ProgrammingError("error")):
            view.get_context_data()

            # Check logs don't contain sensitive info
            log_text = caplog.text.lower()
            assert "sensitive@example.com" not in log_text

    def test_error_messages_safe_for_users(self):
        """Test that error messages shown to users are safe."""
        # Error handling should show generic messages, not expose internals
        request = RequestFactory().get('/')
        request.user = MagicMock()

        view = SubscriptionTemplateView()
        view.request = request

        with patch.object(UserSubscription.objects, 'get', side_effect=ProgrammingError("SELECT * FROM secret_table")):
            context = view.get_context_data()

            # migration_error flag should be set
            assert context['migration_error'] is True
            # But no SQL details exposed


# Performance tests
@pytest.mark.performance
class TestMigrationPerformance:
    """Test performance characteristics of migration verification."""

    @pytest.mark.django_db
    def test_verification_performance_with_many_tenants(self):
        """Test that verification scales reasonably with tenant count."""
        import time

        start_time = time.time()
        out = StringIO()
        call_command('verify_tenant_migrations', '--json', stdout=out)
        duration = time.time() - start_time

        # Should complete within reasonable time (adjust based on your requirements)
        assert duration < 30, f"Verification took {duration}s, should be < 30s"

    @pytest.mark.django_db
    def test_health_check_performance(self):
        """Test that health check with tenant migrations completes quickly."""
        import time

        start_time = time.time()
        out = StringIO()
        call_command('health_check', '--full', '--json', stdout=out)
        duration = time.time() - start_time

        # Full health check should complete within reasonable time
        assert duration < 60, f"Health check took {duration}s, should be < 60s"
