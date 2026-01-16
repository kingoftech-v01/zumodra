"""
Migration metrics collection for observability and monitoring.

This command collects and exports migration-related metrics for dashboards,
alerting, and trending analysis.

Usage:
    python manage.py migration_metrics                 # Display metrics
    python manage.py migration_metrics --json           # JSON format
    python manage.py migration_metrics --prometheus     # Prometheus format
    python manage.py migration_metrics --export         # Export to file
"""

import json
import time
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone
from django_tenants.utils import get_tenant_model, schema_context
from django.db.migrations.executor import MigrationExecutor


class Command(BaseCommand):
    help = 'Collect migration metrics for monitoring and observability'

    def add_arguments(self, parser):
        parser.add_argument(
            '--json',
            action='store_true',
            help='Output in JSON format'
        )
        parser.add_argument(
            '--prometheus',
            action='store_true',
            help='Output in Prometheus format'
        )
        parser.add_argument(
            '--export',
            type=str,
            help='Export to file'
        )
        parser.add_argument(
            '--window',
            type=int,
            default=24,
            help='Time window in hours for historical metrics (default: 24)'
        )

    def handle(self, *args, **options):
        json_output = options.get('json')
        prometheus_output = options.get('prometheus')
        export_file = options.get('export')
        window_hours = options.get('window')

        # Collect metrics
        metrics = self._collect_metrics(window_hours)

        # Output format
        if prometheus_output:
            output = self._format_prometheus(metrics)
        elif json_output:
            output = json.dumps(metrics, indent=2, default=str)
        else:
            output = self._format_human_readable(metrics)

        # Export or display
        if export_file:
            with open(export_file, 'w') as f:
                f.write(output)
            self.stdout.write(self.style.SUCCESS(f"✓ Metrics exported to {export_file}"))
        else:
            self.stdout.write(output)

    def _collect_metrics(self, window_hours):
        """Collect all migration-related metrics."""
        metrics = {
            'timestamp': timezone.now(),
            'collection_duration_seconds': 0,
            'tenant_metrics': {},
            'aggregated_metrics': {},
            'performance_metrics': {},
            'health_metrics': {}
        }

        start_time = time.time()

        # Tenant metrics
        metrics['tenant_metrics'] = self._collect_tenant_metrics()

        # Aggregated metrics
        metrics['aggregated_metrics'] = self._aggregate_tenant_metrics(
            metrics['tenant_metrics']
        )

        # Performance metrics
        metrics['performance_metrics'] = self._collect_performance_metrics()

        # Health metrics
        metrics['health_metrics'] = self._collect_health_metrics()

        metrics['collection_duration_seconds'] = time.time() - start_time

        return metrics

    def _collect_tenant_metrics(self):
        """Collect per-tenant migration metrics."""
        tenant_metrics = {
            'total_tenants': 0,
            'tenants_healthy': 0,
            'tenants_with_pending': 0,
            'tenants_with_errors': 0,
            'details': []
        }

        try:
            Tenant = get_tenant_model()
            tenants = Tenant.objects.exclude(schema_name='public')

            tenant_metrics['total_tenants'] = tenants.count()

            for tenant in tenants:
                tenant_detail = {
                    'schema_name': tenant.schema_name,
                    'pending_migrations': 0,
                    'total_migrations': 0,
                    'last_migration_date': None,
                    'status': 'healthy',
                    'check_duration_seconds': 0
                }

                try:
                    start = time.time()

                    with schema_context(tenant.schema_name):
                        executor = MigrationExecutor(connection)
                        targets = executor.loader.graph.leaf_nodes()
                        pending = executor.migration_plan(targets)

                        tenant_detail['pending_migrations'] = len(pending)
                        tenant_detail['total_migrations'] = len(executor.loader.graph.nodes)

                        # Get last migration timestamp from django_migrations table
                        with connection.cursor() as cursor:
                            cursor.execute(
                                "SELECT MAX(applied) FROM django_migrations"
                            )
                            last_migration = cursor.fetchone()[0]
                            tenant_detail['last_migration_date'] = last_migration

                    tenant_detail['check_duration_seconds'] = time.time() - start

                    if tenant_detail['pending_migrations'] > 0:
                        tenant_detail['status'] = 'pending'
                        tenant_metrics['tenants_with_pending'] += 1
                    else:
                        tenant_metrics['tenants_healthy'] += 1

                except Exception as e:
                    tenant_detail['status'] = 'error'
                    tenant_detail['error'] = str(e)
                    tenant_metrics['tenants_with_errors'] += 1

                tenant_metrics['details'].append(tenant_detail)

        except Exception as e:
            tenant_metrics['error'] = str(e)

        return tenant_metrics

    def _aggregate_tenant_metrics(self, tenant_metrics):
        """Aggregate tenant-level metrics."""
        details = tenant_metrics.get('details', [])

        aggregated = {
            'total_pending_migrations': sum(
                t['pending_migrations'] for t in details
            ),
            'avg_pending_per_tenant': 0,
            'max_pending_migrations': 0,
            'avg_check_duration_seconds': 0,
            'max_check_duration_seconds': 0,
            'oldest_pending_migration': None,
            'newest_migration_date': None
        }

        if details:
            aggregated['avg_pending_per_tenant'] = (
                aggregated['total_pending_migrations'] / len(details)
            )

            aggregated['max_pending_migrations'] = max(
                (t['pending_migrations'] for t in details),
                default=0
            )

            check_durations = [t['check_duration_seconds'] for t in details if 'check_duration_seconds' in t]
            if check_durations:
                aggregated['avg_check_duration_seconds'] = sum(check_durations) / len(check_durations)
                aggregated['max_check_duration_seconds'] = max(check_durations)

            # Find oldest and newest migration dates
            migration_dates = [
                t['last_migration_date'] for t in details
                if t.get('last_migration_date')
            ]
            if migration_dates:
                aggregated['oldest_pending_migration'] = min(migration_dates)
                aggregated['newest_migration_date'] = max(migration_dates)

        return aggregated

    def _collect_performance_metrics(self):
        """Collect performance-related metrics."""
        metrics = {
            'verification_command_available': True,
            'health_check_available': True,
            'automated_monitoring_active': False
        }

        # Check if monitoring is active (cron job exists)
        import os
        if os.path.exists('/etc/cron.d/zumodra'):
            metrics['automated_monitoring_active'] = True

        return metrics

    def _collect_health_metrics(self):
        """Collect health-related metrics."""
        metrics = {
            'overall_health': 'healthy',
            'migration_system_health': 'healthy',
            'issues_detected': []
        }

        # Check for common issues
        try:
            Tenant = get_tenant_model()
            tenants = Tenant.objects.exclude(schema_name='public')

            if not tenants.exists():
                metrics['issues_detected'].append('no_tenants_found')

            # Check if any tenant has many pending migrations
            for tenant in tenants:
                try:
                    with schema_context(tenant.schema_name):
                        executor = MigrationExecutor(connection)
                        pending = executor.migration_plan(executor.loader.graph.leaf_nodes())
                        if len(pending) > 10:
                            metrics['issues_detected'].append(
                                f'{tenant.schema_name}_many_pending_migrations'
                            )
                except Exception:
                    metrics['issues_detected'].append(
                        f'{tenant.schema_name}_migration_check_failed'
                    )

            if metrics['issues_detected']:
                metrics['overall_health'] = 'degraded'
                metrics['migration_system_health'] = 'warning'

        except Exception as e:
            metrics['overall_health'] = 'unhealthy'
            metrics['migration_system_health'] = 'error'
            metrics['issues_detected'].append(f'collection_error: {str(e)}')

        return metrics

    def _format_human_readable(self, metrics):
        """Format metrics for human reading."""
        output = []

        output.append("=" * 60)
        output.append("Migration Metrics Report")
        output.append("=" * 60)
        output.append(f"Timestamp: {metrics['timestamp']}")
        output.append(f"Collection Duration: {metrics['collection_duration_seconds']:.2f}s")
        output.append("")

        # Tenant metrics
        tm = metrics['tenant_metrics']
        output.append("Tenant Metrics:")
        output.append(f"  Total Tenants: {tm['total_tenants']}")
        output.append(f"  Healthy: {tm['tenants_healthy']}")
        output.append(f"  With Pending: {tm['tenants_with_pending']}")
        output.append(f"  With Errors: {tm['tenants_with_errors']}")
        output.append("")

        # Aggregated metrics
        am = metrics['aggregated_metrics']
        output.append("Aggregated Metrics:")
        output.append(f"  Total Pending Migrations: {am['total_pending_migrations']}")
        output.append(f"  Avg Pending per Tenant: {am['avg_pending_per_tenant']:.2f}")
        output.append(f"  Max Pending: {am['max_pending_migrations']}")
        output.append(f"  Avg Check Duration: {am['avg_check_duration_seconds']:.3f}s")
        output.append("")

        # Health metrics
        hm = metrics['health_metrics']
        output.append("Health Status:")
        output.append(f"  Overall: {hm['overall_health']}")
        output.append(f"  Migration System: {hm['migration_system_health']}")
        if hm['issues_detected']:
            output.append(f"  Issues: {', '.join(hm['issues_detected'])}")
        output.append("")

        output.append("=" * 60)

        return "\n".join(output)

    def _format_prometheus(self, metrics):
        """Format metrics for Prometheus."""
        output = []

        timestamp = int(metrics['timestamp'].timestamp() * 1000)

        # Tenant metrics
        tm = metrics['tenant_metrics']
        output.append(f'# HELP zumodra_total_tenants Total number of tenant schemas')
        output.append(f'# TYPE zumodra_total_tenants gauge')
        output.append(f'zumodra_total_tenants {tm["total_tenants"]} {timestamp}')
        output.append('')

        output.append(f'# HELP zumodra_tenants_healthy Number of healthy tenants')
        output.append(f'# TYPE zumodra_tenants_healthy gauge')
        output.append(f'zumodra_tenants_healthy {tm["tenants_healthy"]} {timestamp}')
        output.append('')

        output.append(f'# HELP zumodra_tenants_with_pending Number of tenants with pending migrations')
        output.append(f'# TYPE zumodra_tenants_with_pending gauge')
        output.append(f'zumodra_tenants_with_pending {tm["tenants_with_pending"]} {timestamp}')
        output.append('')

        # Aggregated metrics
        am = metrics['aggregated_metrics']
        output.append(f'# HELP zumodra_total_pending_migrations Total pending migrations across all tenants')
        output.append(f'# TYPE zumodra_total_pending_migrations gauge')
        output.append(f'zumodra_total_pending_migrations {am["total_pending_migrations"]} {timestamp}')
        output.append('')

        output.append(f'# HELP zumodra_max_pending_migrations Maximum pending migrations for any tenant')
        output.append(f'# TYPE zumodra_max_pending_migrations gauge')
        output.append(f'zumodra_max_pending_migrations {am["max_pending_migrations"]} {timestamp}')
        output.append('')

        # Health metrics
        hm = metrics['health_metrics']
        health_value = 1 if hm['overall_health'] == 'healthy' else 0
        output.append(f'# HELP zumodra_migration_health Overall migration system health (1=healthy, 0=unhealthy)')
        output.append(f'# TYPE zumodra_migration_health gauge')
        output.append(f'zumodra_migration_health {health_value} {timestamp}')
        output.append('')

        output.append(f'# HELP zumodra_issues_detected Number of issues detected')
        output.append(f'# TYPE zumodra_issues_detected gauge')
        output.append(f'zumodra_issues_detected {len(hm["issues_detected"])} {timestamp}')
        output.append('')

        return "\n".join(output)
