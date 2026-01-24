"""
Background Job Tasks for Zumodra

This module provides Celery tasks for background processing:
- pdf_generation_task: Generate PDF documents
- data_export_task: Export data to various formats
- analytics_aggregation_task: Aggregate analytics data
- cache_warming_task: Pre-warm cache entries

All tasks are designed for low-priority background execution
with proper resource management and progress tracking.
"""

import logging
import os
import json
import tempfile
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta

from celery import shared_task, chain, group
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)


# =============================================================================
# PDF GENERATION TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.background_tasks.pdf_generation_task',
    max_retries=3,
    default_retry_delay=120,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    rate_limit='30/m',
    queue='low_priority',
    soft_time_limit=600,
    time_limit=900,
)
def pdf_generation_task(
    self,
    document_type: str,
    document_id: int,
    template_name: str,
    context: Dict[str, Any],
    output_filename: Optional[str] = None,
    user_id: Optional[int] = None,
    tenant_id: Optional[int] = None,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate a PDF document from a template.

    Args:
        document_type: Type of document (e.g., 'invoice', 'report', 'contract')
        document_id: ID of the source document/record
        template_name: HTML template name for PDF rendering
        context: Template context dictionary
        output_filename: Optional custom filename
        user_id: User who requested the PDF
        tenant_id: Tenant ID for multi-tenant context
        options: PDF generation options (page_size, orientation, etc.)

    Returns:
        dict: Result with file path and metadata
    """
    try:
        logger.info(f"Generating PDF: {document_type} #{document_id}")

        # Update progress
        self.update_state(
            state='PROGRESS',
            meta={'status': 'rendering', 'progress': 10}
        )

        # Render HTML template
        from django.template.loader import render_to_string
        html_content = render_to_string(template_name, context)

        self.update_state(
            state='PROGRESS',
            meta={'status': 'converting', 'progress': 50}
        )

        # Generate PDF
        pdf_options = {
            'page-size': 'A4',
            'orientation': 'Portrait',
            'margin-top': '20mm',
            'margin-right': '15mm',
            'margin-bottom': '20mm',
            'margin-left': '15mm',
            'encoding': 'UTF-8',
            **(options or {})
        }

        pdf_content = _render_pdf(html_content, pdf_options)

        self.update_state(
            state='PROGRESS',
            meta={'status': 'saving', 'progress': 80}
        )

        # Generate filename
        if not output_filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = f"{document_type}_{document_id}_{timestamp}.pdf"

        # Save PDF to storage
        file_path = _save_pdf_file(pdf_content, output_filename, tenant_id)

        # Store metadata in cache for retrieval
        cache_key = f"pdf:{self.request.id}"
        cache.set(cache_key, {
            'file_path': file_path,
            'filename': output_filename,
            'document_type': document_type,
            'document_id': document_id,
            'created_at': datetime.utcnow().isoformat(),
            'user_id': user_id,
        }, timeout=86400)  # 24 hours

        logger.info(f"PDF generated: {file_path}")

        return {
            'status': 'success',
            'file_path': file_path,
            'filename': output_filename,
            'document_type': document_type,
            'document_id': document_id,
            'task_id': self.request.id,
            'cache_key': cache_key,
            'timestamp': datetime.utcnow().isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning(f"PDF generation exceeded time limit: {document_type} #{document_id}")
        raise

    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise self.retry(exc=e)


def _render_pdf(html_content: str, options: Dict[str, Any]) -> bytes:
    """
    Render HTML content to PDF.

    Uses weasyprint or pdfkit depending on availability.
    """
    try:
        # Try weasyprint first (pure Python, more reliable)
        from weasyprint import HTML, CSS

        pdf = HTML(string=html_content).write_pdf(
            stylesheets=[CSS(string='@page { size: A4; margin: 2cm; }')]
        )
        return pdf

    except ImportError:
        pass

    try:
        # Fall back to pdfkit (requires wkhtmltopdf)
        import pdfkit

        pdf = pdfkit.from_string(html_content, False, options=options)
        return pdf

    except ImportError:
        pass

    # Last resort: basic HTML to PDF (limited formatting)
    raise ImportError(
        "No PDF library available. Install weasyprint or pdfkit."
    )


def _save_pdf_file(
    content: bytes,
    filename: str,
    tenant_id: Optional[int] = None
) -> str:
    """
    Save PDF content to file storage.

    Returns:
        str: Path to saved file
    """
    # Determine storage path
    if tenant_id:
        base_path = os.path.join(settings.MEDIA_ROOT, f'tenants/{tenant_id}/pdfs')
    else:
        base_path = os.path.join(settings.MEDIA_ROOT, 'pdfs')

    os.makedirs(base_path, exist_ok=True)

    file_path = os.path.join(base_path, filename)

    with open(file_path, 'wb') as f:
        f.write(content)

    return file_path


# =============================================================================
# DATA EXPORT TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.background_tasks.data_export_task',
    max_retries=2,
    default_retry_delay=180,
    autoretry_for=(Exception,),
    retry_backoff=True,
    rate_limit='10/m',
    queue='low_priority',
    soft_time_limit=1800,
    time_limit=2100,
)
def data_export_task(
    self,
    export_type: str,
    model_name: str,
    filters: Dict[str, Any],
    format: str = 'csv',
    columns: Optional[List[str]] = None,
    user_id: Optional[int] = None,
    tenant_id: Optional[int] = None,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Export data to various formats (CSV, Excel, JSON).

    Args:
        export_type: Type of export (e.g., 'users', 'applications', 'analytics')
        model_name: Django model name (app.Model format)
        filters: QuerySet filter parameters
        format: Output format ('csv', 'xlsx', 'json')
        columns: List of columns to include
        user_id: User who requested the export
        tenant_id: Tenant ID for multi-tenant context
        options: Export options (delimiter, encoding, etc.)

    Returns:
        dict: Result with file path and metadata
    """
    try:
        logger.info(f"Starting data export: {export_type} ({format})")

        self.update_state(
            state='PROGRESS',
            meta={'status': 'querying', 'progress': 10}
        )

        # Get data from database
        data = _fetch_export_data(model_name, filters, columns, tenant_id)

        self.update_state(
            state='PROGRESS',
            meta={'status': 'processing', 'progress': 40, 'records': len(data)}
        )

        # Export to requested format
        if format == 'csv':
            content, content_type = _export_to_csv(data, options)
            extension = 'csv'
        elif format in ('xlsx', 'excel'):
            content, content_type = _export_to_excel(data, options)
            extension = 'xlsx'
        elif format == 'json':
            content, content_type = _export_to_json(data, options)
            extension = 'json'
        else:
            raise ValueError(f"Unsupported export format: {format}")

        self.update_state(
            state='PROGRESS',
            meta={'status': 'saving', 'progress': 80}
        )

        # Generate filename and save
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{export_type}_export_{timestamp}.{extension}"

        file_path = _save_export_file(content, filename, tenant_id)

        # Store metadata in cache
        cache_key = f"export:{self.request.id}"
        cache.set(cache_key, {
            'file_path': file_path,
            'filename': filename,
            'export_type': export_type,
            'format': format,
            'record_count': len(data),
            'created_at': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'content_type': content_type,
        }, timeout=86400)  # 24 hours

        logger.info(f"Data export completed: {filename} ({len(data)} records)")

        return {
            'status': 'success',
            'file_path': file_path,
            'filename': filename,
            'format': format,
            'record_count': len(data),
            'task_id': self.request.id,
            'cache_key': cache_key,
            'timestamp': datetime.utcnow().isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning(f"Data export exceeded time limit: {export_type}")
        raise

    except Exception as e:
        logger.error(f"Data export failed: {e}")
        raise self.retry(exc=e)


def _fetch_export_data(
    model_name: str,
    filters: Dict[str, Any],
    columns: Optional[List[str]],
    tenant_id: Optional[int]
) -> List[Dict[str, Any]]:
    """
    Fetch data for export from database.
    """
    from django.apps import apps

    # Get model class
    app_label, model = model_name.split('.')
    Model = apps.get_model(app_label, model)

    # Build queryset
    queryset = Model.objects.filter(**filters)

    # Select specific columns if provided
    if columns:
        queryset = queryset.values(*columns)
    else:
        queryset = queryset.values()

    # Limit to prevent memory issues
    max_records = 100000
    data = list(queryset[:max_records])

    return data


def _export_to_csv(
    data: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None
) -> tuple:
    """
    Export data to CSV format.
    """
    import csv
    import io

    options = options or {}
    delimiter = options.get('delimiter', ',')
    encoding = options.get('encoding', 'utf-8')

    if not data:
        return b'', 'text/csv'

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=data[0].keys(),
        delimiter=delimiter,
    )

    writer.writeheader()
    writer.writerows(data)

    content = output.getvalue().encode(encoding)
    return content, 'text/csv'


def _export_to_excel(
    data: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None
) -> tuple:
    """
    Export data to Excel format.
    """
    try:
        import openpyxl
        from openpyxl.utils.dataframe import dataframe_to_rows
        import io

        wb = openpyxl.Workbook()
        ws = wb.active

        if data:
            # Write headers
            headers = list(data[0].keys())
            ws.append(headers)

            # Write data rows
            for row in data:
                ws.append([row.get(h) for h in headers])

        output = io.BytesIO()
        wb.save(output)
        content = output.getvalue()

        return content, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

    except ImportError:
        raise ImportError("openpyxl is required for Excel export")


def _export_to_json(
    data: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None
) -> tuple:
    """
    Export data to JSON format.
    """
    from django.core.serializers.json import DjangoJSONEncoder

    options = options or {}
    indent = options.get('indent', 2)

    content = json.dumps(data, cls=DjangoJSONEncoder, indent=indent)
    return content.encode('utf-8'), 'application/json'


def _save_export_file(
    content: bytes,
    filename: str,
    tenant_id: Optional[int] = None
) -> str:
    """
    Save export file to storage.
    """
    if tenant_id:
        base_path = os.path.join(settings.MEDIA_ROOT, f'tenants/{tenant_id}/exports')
    else:
        base_path = os.path.join(settings.MEDIA_ROOT, 'exports')

    os.makedirs(base_path, exist_ok=True)

    file_path = os.path.join(base_path, filename)

    with open(file_path, 'wb') as f:
        f.write(content)

    return file_path


# =============================================================================
# ANALYTICS AGGREGATION TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.background_tasks.analytics_aggregation_task',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
    rate_limit='5/m',
    queue='analytics',
    soft_time_limit=1800,
    time_limit=2100,
)
def analytics_aggregation_task(
    self,
    aggregation_type: str,
    date_range: Optional[Dict[str, str]] = None,
    metrics: Optional[List[str]] = None,
    dimensions: Optional[List[str]] = None,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Aggregate analytics data for reporting.

    Args:
        aggregation_type: Type of aggregation ('daily', 'weekly', 'monthly', 'custom')
        date_range: Start and end dates for aggregation
        metrics: List of metrics to aggregate
        dimensions: Dimensions to group by
        tenant_id: Tenant ID for multi-tenant context

    Returns:
        dict: Aggregation results and metadata
    """
    try:
        logger.info(f"Starting analytics aggregation: {aggregation_type}")

        self.update_state(
            state='PROGRESS',
            meta={'status': 'initializing', 'progress': 5}
        )

        # Determine date range
        if date_range:
            start_date = datetime.fromisoformat(date_range['start'])
            end_date = datetime.fromisoformat(date_range['end'])
        else:
            end_date = timezone.now()
            if aggregation_type == 'daily':
                start_date = end_date - timedelta(days=1)
            elif aggregation_type == 'weekly':
                start_date = end_date - timedelta(weeks=1)
            elif aggregation_type == 'monthly':
                start_date = end_date - timedelta(days=30)
            else:
                start_date = end_date - timedelta(days=1)

        self.update_state(
            state='PROGRESS',
            meta={'status': 'aggregating', 'progress': 20}
        )

        # Default metrics if not specified
        if not metrics:
            metrics = [
                'page_views',
                'unique_visitors',
                'session_duration',
                'bounce_rate',
                'conversion_rate',
            ]

        # Aggregate data
        results = _aggregate_metrics(
            start_date=start_date,
            end_date=end_date,
            metrics=metrics,
            dimensions=dimensions,
            tenant_id=tenant_id,
        )

        self.update_state(
            state='PROGRESS',
            meta={'status': 'storing', 'progress': 80}
        )

        # Store aggregated results
        _store_aggregation_results(
            aggregation_type=aggregation_type,
            start_date=start_date,
            end_date=end_date,
            results=results,
            tenant_id=tenant_id,
        )

        # Update cache with latest aggregations
        cache_key = f"analytics:aggregation:{aggregation_type}"
        if tenant_id:
            cache_key = f"{cache_key}:{tenant_id}"

        cache.set(cache_key, {
            'results': results,
            'updated_at': datetime.utcnow().isoformat(),
        }, timeout=3600)  # 1 hour

        logger.info(f"Analytics aggregation completed: {aggregation_type}")

        return {
            'status': 'success',
            'aggregation_type': aggregation_type,
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
            },
            'metrics': metrics,
            'results': results,
            'task_id': self.request.id,
            'timestamp': datetime.utcnow().isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning(f"Analytics aggregation exceeded time limit: {aggregation_type}")
        raise

    except Exception as e:
        logger.error(f"Analytics aggregation failed: {e}")
        raise self.retry(exc=e)


def _aggregate_metrics(
    start_date: datetime,
    end_date: datetime,
    metrics: List[str],
    dimensions: Optional[List[str]],
    tenant_id: Optional[int],
) -> Dict[str, Any]:
    """
    Aggregate metrics from analytics data.
    """
    from django.db.models import Count, Avg, Sum, F
    from django.db.models.functions import TruncDate

    results = {}

    try:
        from analytics.models import PageView, Session, Event

        # Page views aggregation
        if 'page_views' in metrics:
            queryset = PageView.objects.filter(
                timestamp__gte=start_date,
                timestamp__lt=end_date,
            )

            if dimensions and 'date' in dimensions:
                results['page_views_by_date'] = list(
                    queryset
                    .annotate(date=TruncDate('timestamp'))
                    .values('date')
                    .annotate(count=Count('id'))
                    .order_by('date')
                )
            else:
                results['page_views'] = queryset.count()

        # Unique visitors
        if 'unique_visitors' in metrics:
            results['unique_visitors'] = PageView.objects.filter(
                timestamp__gte=start_date,
                timestamp__lt=end_date,
            ).values('visitor_id').distinct().count()

        # Session duration
        if 'session_duration' in metrics:
            avg_duration = Session.objects.filter(
                created_at__gte=start_date,
                created_at__lt=end_date,
            ).aggregate(avg=Avg('duration'))
            results['avg_session_duration'] = avg_duration.get('avg')

    except Exception as e:
        logger.error(f"Failed to aggregate metrics: {e}")
        results['error'] = str(e)

    return results


def _store_aggregation_results(
    aggregation_type: str,
    start_date: datetime,
    end_date: datetime,
    results: Dict[str, Any],
    tenant_id: Optional[int],
):
    """
    Store aggregation results in database.
    """
    try:
        from analytics.models import AnalyticsAggregation

        AnalyticsAggregation.objects.update_or_create(
            aggregation_type=aggregation_type,
            start_date=start_date.date(),
            end_date=end_date.date(),
            defaults={
                'results': results,
                'updated_at': timezone.now(),
            }
        )

    except Exception as e:
        logger.warning(f"Failed to store aggregation results: {e}")


# =============================================================================
# CACHE WARMING TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.background_tasks.cache_warming_task',
    max_retries=1,
    rate_limit='60/h',
    queue='low_priority',
    soft_time_limit=600,
    time_limit=900,
)
def cache_warming_task(
    self,
    cache_keys: Optional[List[str]] = None,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Pre-warm cache with frequently accessed data.

    Args:
        cache_keys: Specific cache keys to warm (None for all)
        tenant_id: Tenant ID for multi-tenant context

    Returns:
        dict: Cache warming results
    """
    try:
        logger.info("Starting cache warming task")

        warmed_keys = []
        failed_keys = []

        # Default cache warming operations
        warmers = [
            _warm_dashboard_cache,
            _warm_analytics_cache,
            _warm_configuration_cache,
            _warm_user_preferences_cache,
        ]

        total = len(warmers)

        for i, warmer in enumerate(warmers):
            try:
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'status': f'warming_{warmer.__name__}',
                        'progress': int((i / total) * 100)
                    }
                )

                keys = warmer(tenant_id)
                warmed_keys.extend(keys)

            except Exception as e:
                logger.warning(f"Cache warmer {warmer.__name__} failed: {e}")
                failed_keys.append(warmer.__name__)

        logger.info(
            f"Cache warming completed: {len(warmed_keys)} keys warmed, "
            f"{len(failed_keys)} failed"
        )

        return {
            'status': 'success',
            'warmed_keys': len(warmed_keys),
            'failed_warmers': failed_keys,
            'task_id': self.request.id,
            'timestamp': datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Cache warming failed: {e}")
        return {
            'status': 'failed',
            'error': str(e),
            'task_id': self.request.id,
        }


def _warm_dashboard_cache(tenant_id: Optional[int] = None) -> List[str]:
    """
    Warm dashboard-related cache entries.
    """
    keys = []

    try:
        # Dashboard metrics
        from analytics.models import DashboardMetric

        metrics = DashboardMetric.objects.filter(is_active=True)
        for metric in metrics:
            cache_key = f"dashboard:metric:{metric.id}"
            cache.set(cache_key, metric.calculate(), timeout=1800)
            keys.append(cache_key)

    except Exception as e:
        logger.debug(f"Dashboard cache warming skipped: {e}")

    return keys


def _warm_analytics_cache(tenant_id: Optional[int] = None) -> List[str]:
    """
    Warm analytics-related cache entries.
    """
    keys = []

    try:
        # Today's analytics
        today = timezone.now().date()
        cache_key = f"analytics:daily:{today.isoformat()}"

        from analytics.models import PageView

        daily_views = PageView.objects.filter(
            timestamp__date=today
        ).count()

        cache.set(cache_key, {'page_views': daily_views}, timeout=3600)
        keys.append(cache_key)

    except Exception as e:
        logger.debug(f"Analytics cache warming skipped: {e}")

    return keys


def _warm_configuration_cache(tenant_id: Optional[int] = None) -> List[str]:
    """
    Warm configuration-related cache entries.
    """
    keys = []

    try:
        from configurations.models import SystemConfiguration

        configs = SystemConfiguration.objects.filter(is_public=True)
        for config in configs:
            cache_key = f"config:{config.key}"
            cache.set(cache_key, config.value, timeout=3600)
            keys.append(cache_key)

    except Exception as e:
        logger.debug(f"Configuration cache warming skipped: {e}")

    return keys


def _warm_user_preferences_cache(tenant_id: Optional[int] = None) -> List[str]:
    """
    Warm user preferences cache for active users.
    """
    keys = []

    try:
        from django.contrib.auth import get_user_model
        from tenant_profiles.models import UserPreference

        User = get_user_model()

        # Get recently active users
        active_since = timezone.now() - timedelta(hours=24)
        active_users = User.objects.filter(
            last_login__gte=active_since
        ).values_list('id', flat=True)[:1000]

        for user_id in active_users:
            try:
                prefs = UserPreference.objects.get(user_id=user_id)
                cache_key = f"user:preferences:{user_id}"
                cache.set(cache_key, prefs.to_dict(), timeout=7200)
                keys.append(cache_key)
            except Exception:
                pass

    except Exception as e:
        logger.debug(f"User preferences cache warming skipped: {e}")

    return keys
