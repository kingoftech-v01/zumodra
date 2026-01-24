"""
Management command to generate audit reports.

Usage:
    python manage.py generate_audit_report --days 30
    python manage.py generate_audit_report --days 7 --action login --output report.csv
    python manage.py generate_audit_report --start-date 2026-01-01 --end-date 2026-01-31
    python manage.py generate_audit_report --user user@example.com
    python manage.py generate_audit_report --tenant abc123 --format json
"""

import csv
import json
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder
from core.security.audit import AuditLog, AuditAction


class Command(BaseCommand):
    help = 'Generate audit report for specified date range and filters'

    def add_arguments(self, parser):
        # Date range options
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to include in report (default: 30)'
        )
        parser.add_argument(
            '--start-date',
            type=str,
            help='Start date (YYYY-MM-DD format)'
        )
        parser.add_argument(
            '--end-date',
            type=str,
            help='End date (YYYY-MM-DD format)'
        )

        # Filter options
        parser.add_argument(
            '--action',
            type=str,
            help='Filter by action type (e.g., login, create, update)'
        )
        parser.add_argument(
            '--user',
            type=str,
            help='Filter by user email'
        )
        parser.add_argument(
            '--tenant',
            type=str,
            help='Filter by tenant ID'
        )
        parser.add_argument(
            '--resource-type',
            type=str,
            help='Filter by resource type'
        )
        parser.add_argument(
            '--sensitive-only',
            action='store_true',
            help='Only include sensitive data access logs'
        )
        parser.add_argument(
            '--severity',
            type=str,
            choices=['debug', 'info', 'warning', 'error', 'critical'],
            help='Filter by severity level'
        )

        # Output options
        parser.add_argument(
            '--output',
            type=str,
            default='audit_report.csv',
            help='Output file name (default: audit_report.csv)'
        )
        parser.add_argument(
            '--format',
            type=str,
            choices=['csv', 'json'],
            default='csv',
            help='Output format (csv or json)'
        )

        # Statistics options
        parser.add_argument(
            '--stats',
            action='store_true',
            help='Include statistics summary'
        )

    def handle(self, *args, **options):
        # Determine date range
        if options['start_date'] and options['end_date']:
            try:
                start_date = datetime.strptime(options['start_date'], '%Y-%m-%d')
                start_date = timezone.make_aware(start_date)
                end_date = datetime.strptime(options['end_date'], '%Y-%m-%d')
                end_date = timezone.make_aware(end_date)
            except ValueError:
                raise CommandError('Invalid date format. Use YYYY-MM-DD')
        else:
            days = options['days']
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)

        self.stdout.write(f'Generating audit report from {start_date} to {end_date}')

        # Build queryset with filters
        logs = AuditLog.objects.filter(
            timestamp__gte=start_date,
            timestamp__lte=end_date
        )

        # Apply filters
        if options['action']:
            logs = logs.filter(action=options['action'])
            self.stdout.write(f"Filtering by action: {options['action']}")

        if options['user']:
            logs = logs.filter(user_email=options['user'])
            self.stdout.write(f"Filtering by user: {options['user']}")

        if options['tenant']:
            logs = logs.filter(tenant_id=options['tenant'])
            self.stdout.write(f"Filtering by tenant: {options['tenant']}")

        if options['resource_type']:
            logs = logs.filter(resource_type=options['resource_type'])
            self.stdout.write(f"Filtering by resource type: {options['resource_type']}")

        if options['sensitive_only']:
            logs = logs.filter(is_sensitive=True)
            self.stdout.write('Filtering for sensitive data only')

        if options['severity']:
            logs = logs.filter(severity=options['severity'])
            self.stdout.write(f"Filtering by severity: {options['severity']}")

        # Order by timestamp
        logs = logs.order_by('-timestamp')

        total_logs = logs.count()
        self.stdout.write(self.style.SUCCESS(f'Found {total_logs} audit log entries'))

        if total_logs == 0:
            self.stdout.write(self.style.WARNING('No logs found matching criteria'))
            return

        # Generate statistics if requested
        if options['stats']:
            self._print_statistics(logs)

        # Export to file
        output_file = options['output']
        format_type = options['format']

        if format_type == 'csv':
            self._export_csv(logs, output_file)
        else:
            self._export_json(logs, output_file)

        self.stdout.write(self.style.SUCCESS(f'Report generated: {output_file}'))

    def _print_statistics(self, logs):
        """Print statistics summary."""
        from django.db.models import Count

        self.stdout.write('\n' + '='*60)
        self.stdout.write(self.style.SUCCESS('AUDIT LOG STATISTICS'))
        self.stdout.write('='*60 + '\n')

        # Action breakdown
        actions = logs.values('action').annotate(count=Count('id')).order_by('-count')
        self.stdout.write(self.style.WARNING('Top Actions:'))
        for action in actions[:10]:
            self.stdout.write(f"  - {action['action']}: {action['count']}")

        # User breakdown
        users = logs.exclude(user_email='').values('user_email').annotate(
            count=Count('id')
        ).order_by('-count')
        self.stdout.write(self.style.WARNING('\nTop Users:'))
        for user in users[:10]:
            self.stdout.write(f"  - {user['user_email']}: {user['count']}")

        # Resource type breakdown
        resources = logs.values('resource_type').annotate(
            count=Count('id')
        ).order_by('-count')
        self.stdout.write(self.style.WARNING('\nTop Resource Types:'))
        for resource in resources[:10]:
            self.stdout.write(f"  - {resource['resource_type']}: {resource['count']}")

        # Severity breakdown
        severities = logs.values('severity').annotate(count=Count('id')).order_by('-count')
        self.stdout.write(self.style.WARNING('\nSeverity Breakdown:'))
        for severity in severities:
            self.stdout.write(f"  - {severity['severity']}: {severity['count']}")

        # Sensitive data access
        sensitive_count = logs.filter(is_sensitive=True).count()
        self.stdout.write(self.style.WARNING(f'\nSensitive Data Access: {sensitive_count}'))

        self.stdout.write('\n' + '='*60 + '\n')

    def _export_csv(self, logs, output_file):
        """Export logs to CSV format."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Timestamp', 'User', 'Action', 'Resource Type',
                'Resource ID', 'IP Address', 'Severity',
                'Is Sensitive', 'Changes Summary'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for log in logs:
                writer.writerow({
                    'Timestamp': log.timestamp.isoformat(),
                    'User': log.user_email or 'System',
                    'Action': log.action_display or log.action,
                    'Resource Type': log.resource_type,
                    'Resource ID': log.resource_id or '',
                    'IP Address': log.ip_address or '',
                    'Severity': log.severity,
                    'Is Sensitive': 'Yes' if log.is_sensitive else 'No',
                    'Changes Summary': log.changes_summary or '',
                })

    def _export_json(self, logs, output_file):
        """Export logs to JSON format."""
        logs_data = []

        for log in logs:
            logs_data.append({
                'id': str(log.id),
                'timestamp': log.timestamp.isoformat(),
                'user_email': log.user_email,
                'action': log.action,
                'action_display': log.action_display,
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'resource_repr': log.resource_repr,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'severity': log.severity,
                'is_sensitive': log.is_sensitive,
                'request_method': log.request_method,
                'request_path': log.request_path,
                'changes': log.changes,
                'extra_data': log.extra_data,
                'error_message': log.error_message,
            })

        report = {
            'generated_at': timezone.now().isoformat(),
            'total_records': len(logs_data),
            'logs': logs_data
        }

        with open(output_file, 'w', encoding='utf-8') as jsonfile:
            json.dump(report, jsonfile, indent=2, cls=DjangoJSONEncoder)
