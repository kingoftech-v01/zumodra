"""
Management command to check health of all services.
Verifies database, cache, email, and external service connectivity.
"""

import socket
import sys
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.db import connection, connections
from django.core.cache import cache
from django.core.mail import get_connection
from django.conf import settings
from django.utils import timezone


class Command(BaseCommand):
    help = 'Check health of all services and dependencies'

    def add_arguments(self, parser):
        parser.add_argument(
            '--full',
            action='store_true',
            help='Run full health check including external services'
        )
        parser.add_argument(
            '--json',
            action='store_true',
            help='Output results as JSON'
        )
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Only show failed checks'
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=5,
            help='Timeout in seconds for external checks (default: 5)'
        )

    def handle(self, *args, **options):
        full_check = options.get('full', False)
        output_json = options.get('json', False)
        quiet = options.get('quiet', False)
        timeout = options.get('timeout', 5)

        results = {
            'timestamp': timezone.now().isoformat(),
            'status': 'healthy',
            'checks': {}
        }

        # Core checks
        results['checks']['database'] = self._check_database(timeout)
        results['checks']['cache'] = self._check_cache(timeout)
        results['checks']['migrations'] = self._check_migrations()

        # Optional full checks
        if full_check:
            results['checks']['email'] = self._check_email(timeout)
            results['checks']['redis'] = self._check_redis(timeout)
            results['checks']['celery'] = self._check_celery(timeout)
            results['checks']['storage'] = self._check_storage()
            results['checks']['external_services'] = self._check_external_services(timeout)

        # Determine overall status
        failed_checks = [
            name for name, check in results['checks'].items()
            if check['status'] == 'unhealthy'
        ]

        warning_checks = [
            name for name, check in results['checks'].items()
            if check['status'] == 'warning'
        ]

        if failed_checks:
            results['status'] = 'unhealthy'
        elif warning_checks:
            results['status'] = 'degraded'

        # Output results
        if output_json:
            import json
            self.stdout.write(json.dumps(results, indent=2))
        else:
            self._print_results(results, quiet)

        # Exit code
        if results['status'] == 'unhealthy':
            sys.exit(1)
        elif results['status'] == 'degraded':
            sys.exit(2)

    def _check_database(self, timeout):
        """Check database connectivity."""
        result = {'status': 'healthy', 'message': '', 'details': {}}

        try:
            # Check default database
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1')

            result['details']['default'] = 'connected'

            # Check tenant database if different
            if 'tenant' in settings.DATABASES:
                with connections['tenant'].cursor() as cursor:
                    cursor.execute('SELECT 1')
                result['details']['tenant'] = 'connected'

            # Check for pending migrations
            from django.db.migrations.executor import MigrationExecutor
            executor = MigrationExecutor(connection)
            targets = executor.loader.graph.leaf_nodes()
            pending = executor.migration_plan(targets)

            if pending:
                result['status'] = 'warning'
                result['message'] = f'{len(pending)} pending migrations'
                result['details']['pending_migrations'] = len(pending)
            else:
                result['message'] = 'Connected, no pending migrations'

        except Exception as e:
            result['status'] = 'unhealthy'
            result['message'] = f'Database error: {str(e)}'

        return result

    def _check_cache(self, timeout):
        """Check cache connectivity."""
        result = {'status': 'healthy', 'message': '', 'details': {}}

        try:
            # Test set/get
            test_key = 'health_check_test'
            test_value = timezone.now().isoformat()

            cache.set(test_key, test_value, timeout=30)
            retrieved = cache.get(test_key)

            if retrieved == test_value:
                result['message'] = 'Cache working correctly'
                cache.delete(test_key)
            else:
                result['status'] = 'warning'
                result['message'] = 'Cache set/get mismatch'

            result['details']['backend'] = settings.CACHES.get('default', {}).get('BACKEND', 'unknown')

        except Exception as e:
            result['status'] = 'unhealthy'
            result['message'] = f'Cache error: {str(e)}'

        return result

    def _check_migrations(self):
        """Check for pending migrations."""
        result = {'status': 'healthy', 'message': '', 'details': {}}

        try:
            from django.db.migrations.executor import MigrationExecutor
            executor = MigrationExecutor(connection)
            targets = executor.loader.graph.leaf_nodes()
            pending = executor.migration_plan(targets)

            if pending:
                result['status'] = 'warning'
                result['message'] = f'{len(pending)} pending migrations'
                result['details']['pending'] = [str(m) for m in pending[:5]]
            else:
                result['message'] = 'All migrations applied'

        except Exception as e:
            result['status'] = 'unhealthy'
            result['message'] = f'Migration check error: {str(e)}'

        return result

    def _check_email(self, timeout):
        """Check email backend configuration."""
        result = {'status': 'healthy', 'message': '', 'details': {}}

        try:
            backend = settings.EMAIL_BACKEND
            result['details']['backend'] = backend

            if 'console' in backend.lower() or 'filebased' in backend.lower():
                result['message'] = f'Using development backend: {backend}'
                result['status'] = 'warning'
            elif 'smtp' in backend.lower():
                # Try to connect to SMTP
                host = getattr(settings, 'EMAIL_HOST', '')
                port = getattr(settings, 'EMAIL_PORT', 587)

                if host:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    try:
                        sock.connect((host, port))
                        result['message'] = f'SMTP server reachable: {host}:{port}'
                    finally:
                        sock.close()
                else:
                    result['status'] = 'warning'
                    result['message'] = 'EMAIL_HOST not configured'
            else:
                result['message'] = f'Using backend: {backend}'

        except socket.timeout:
            result['status'] = 'unhealthy'
            result['message'] = 'SMTP server connection timeout'
        except Exception as e:
            result['status'] = 'unhealthy'
            result['message'] = f'Email check error: {str(e)}'

        return result

    def _check_redis(self, timeout):
        """Check Redis connectivity."""
        result = {'status': 'healthy', 'message': '', 'details': {}}

        try:
            import redis

            # Try to get Redis URL from settings
            redis_url = getattr(settings, 'REDIS_URL', None)
            if not redis_url:
                # Try to construct from cache settings
                cache_settings = settings.CACHES.get('default', {})
                if 'redis' in cache_settings.get('BACKEND', '').lower():
                    redis_url = cache_settings.get('LOCATION', '')

            if not redis_url:
                result['status'] = 'warning'
                result['message'] = 'Redis not configured'
                return result

            client = redis.from_url(redis_url, socket_timeout=timeout)
            client.ping()
            result['message'] = 'Redis connected'
            result['details']['url'] = redis_url.split('@')[-1] if '@' in redis_url else redis_url

        except ImportError:
            result['status'] = 'warning'
            result['message'] = 'redis-py not installed'
        except Exception as e:
            result['status'] = 'unhealthy'
            result['message'] = f'Redis error: {str(e)}'

        return result

    def _check_celery(self, timeout):
        """Check Celery worker status."""
        result = {'status': 'healthy', 'message': '', 'details': {}}

        try:
            from zumodra.celery import app as celery_app

            # Get active workers
            inspect = celery_app.control.inspect(timeout=timeout)
            active = inspect.active()

            if active:
                worker_count = len(active)
                result['message'] = f'{worker_count} active worker(s)'
                result['details']['workers'] = list(active.keys())
            else:
                result['status'] = 'warning'
                result['message'] = 'No active Celery workers'

        except ImportError:
            result['status'] = 'warning'
            result['message'] = 'Celery not configured'
        except Exception as e:
            result['status'] = 'unhealthy'
            result['message'] = f'Celery check error: {str(e)}'

        return result

    def _check_storage(self):
        """Check storage backend."""
        result = {'status': 'healthy', 'message': '', 'details': {}}

        try:
            from django.core.files.storage import default_storage

            storage_class = default_storage.__class__.__name__
            result['details']['backend'] = storage_class

            # Check if we can list files (basic connectivity test)
            try:
                default_storage.listdir('')
                result['message'] = f'Storage accessible ({storage_class})'
            except NotImplementedError:
                result['message'] = f'Using {storage_class} (listdir not supported)'
            except Exception as e:
                result['status'] = 'warning'
                result['message'] = f'Storage may be inaccessible: {e}'

        except Exception as e:
            result['status'] = 'unhealthy'
            result['message'] = f'Storage check error: {str(e)}'

        return result

    def _check_external_services(self, timeout):
        """Check external service connectivity."""
        result = {'status': 'healthy', 'message': '', 'details': {}}

        services = []

        # Check Stripe if configured
        if getattr(settings, 'STRIPE_SECRET_KEY', None):
            try:
                import stripe
                stripe.api_key = settings.STRIPE_SECRET_KEY
                stripe.Account.retrieve()
                services.append(('Stripe', True))
            except Exception as e:
                services.append(('Stripe', False))
                result['status'] = 'warning'

        # Add more external service checks as needed

        if services:
            healthy = [s[0] for s in services if s[1]]
            unhealthy = [s[0] for s in services if not s[1]]

            result['details']['connected'] = healthy
            result['details']['failed'] = unhealthy

            if unhealthy:
                result['message'] = f'Some services unavailable: {", ".join(unhealthy)}'
                result['status'] = 'warning'
            else:
                result['message'] = f'All external services connected ({len(healthy)})'
        else:
            result['message'] = 'No external services configured'

        return result

    def _print_results(self, results, quiet):
        """Print results in human-readable format."""
        status_colors = {
            'healthy': self.style.SUCCESS,
            'warning': self.style.WARNING,
            'unhealthy': self.style.ERROR,
            'degraded': self.style.WARNING,
        }

        self.stdout.write("\n" + "=" * 60)
        self.stdout.write("ZUMODRA HEALTH CHECK")
        self.stdout.write("=" * 60)
        self.stdout.write(f"Timestamp: {results['timestamp']}")

        color_func = status_colors.get(results['status'], self.style.NOTICE)
        self.stdout.write(f"Overall Status: {color_func(results['status'].upper())}\n")

        for name, check in results['checks'].items():
            if quiet and check['status'] == 'healthy':
                continue

            color_func = status_colors.get(check['status'], self.style.NOTICE)
            status_str = color_func(f"[{check['status'].upper()}]")

            self.stdout.write(f"{name.upper()}: {status_str}")
            self.stdout.write(f"  {check['message']}")

            if check.get('details'):
                for key, value in check['details'].items():
                    self.stdout.write(f"    - {key}: {value}")

            self.stdout.write("")

        self.stdout.write("=" * 60)
