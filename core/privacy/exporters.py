"""
GDPR Data Export Module for Zumodra ATS/HR Platform

This module provides comprehensive data export functionality for GDPR compliance:
- Exports all user data from all models
- Supports multiple formats (JSON, CSV, XML)
- Includes metadata (collection date, purpose, source)
- Handles related records (applications, time-off, etc.)
- Generates downloadable ZIP archives

All exports are tenant-aware and include audit trails.
"""

import csv
import io
import json
import logging
import os
import uuid
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Type
from xml.etree import ElementTree as ET

from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.files.base import ContentFile
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.utils import timezone

from core.privacy.models import PrivacyAuditLog

logger = logging.getLogger(__name__)


class GDPRDataExporter:
    """
    GDPR-compliant data exporter for user personal data.

    Exports all user data from all models in machine-readable format
    as required by GDPR Article 20 (Right to Data Portability).
    """

    # Models to include in export and their user relationship
    EXPORT_MODELS = [
        # (app_label.model_name, user_field, friendly_name)
        ('custom_account_u.CustomUser', None, 'User Account'),
        ('tenant_profiles.UserProfile', 'user', 'Profile Information'),
        ('tenant_profiles.TenantUser', 'user', 'Tenant Memberships'),
        ('tenant_profiles.KYCVerification', 'user', 'KYC Verifications'),
        ('tenant_profiles.ProgressiveConsent', 'grantor', 'Data Consents Given'),
        ('tenant_profiles.DataAccessLog', 'data_subject', 'Data Access History'),
        ('tenant_profiles.LoginHistory', 'user', 'Login History'),
        ('tenant_profiles.SecurityQuestion', 'user', 'Security Questions'),
        ('jobs.Candidate', 'email', 'Job Applications'),
        ('jobs.Interview', 'candidate__email', 'Interview Records'),
        ('hr_core.Employee', 'user', 'Employment Records'),
        ('hr_core.TimeOffRequest', 'employee__user', 'Time-Off Requests'),
        ('hr_core.Payroll', 'employee__user', 'Payroll Records'),
        ('core.privacy.ConsentRecord', 'user', 'Privacy Consents'),
        ('core.privacy.DataSubjectRequest', 'user', 'Privacy Requests'),
        ('finance.Payment', 'user', 'Payment History'),
        ('finance.Invoice', 'user', 'Invoices'),
        ('messages_sys.Message', 'sender', 'Sent Messages'),
        ('messages_sys.Message', 'recipient', 'Received Messages'),
        ('notifications.Notification', 'recipient', 'Notifications'),
        ('appointment.Appointment', 'client', 'Appointments'),
    ]

    # Fields to exclude from export (sensitive or internal)
    EXCLUDED_FIELDS = [
        'password', 'secret', 'token', 'api_key', 'private_key',
        'encryption_key', 'hash', 'salt', 'answer_hash',
    ]

    # PII fields that need special handling
    PII_FIELDS = [
        'email', 'phone', 'first_name', 'last_name', 'address',
        'city', 'postal_code', 'date_of_birth', 'ssn', 'sin',
        'passport_number', 'driver_license',
    ]

    def __init__(self, tenant, user):
        """
        Initialize the exporter.

        Args:
            tenant: The tenant context.
            user: The user whose data to export.
        """
        self.tenant = tenant
        self.user = user
        self.export_id = uuid.uuid4().hex[:12]
        self.export_timestamp = timezone.now()
        self.errors: List[str] = []

    def export_all_data(
        self,
        format: str = 'json',
        include_metadata: bool = True,
        include_related: bool = True,
    ) -> Dict[str, Any]:
        """
        Export all user data across all models.

        Args:
            format: Export format ('json', 'csv', 'xml').
            include_metadata: Whether to include collection metadata.
            include_related: Whether to include related records.

        Returns:
            Dictionary with export data and metadata.
        """
        export_data = {
            'export_id': self.export_id,
            'export_timestamp': self.export_timestamp.isoformat(),
            'data_subject': {
                'id': str(self.user.id),
                'email': self.user.email,
            },
            'tenant': {
                'id': str(self.tenant.id),
                'name': self.tenant.name,
            },
            'format': format,
            'sections': [],
        }

        # Export data from each model
        for model_path, user_field, friendly_name in self.EXPORT_MODELS:
            try:
                section_data = self._export_model_data(
                    model_path, user_field, friendly_name, include_metadata
                )
                if section_data and section_data.get('records'):
                    export_data['sections'].append(section_data)
            except Exception as e:
                self.errors.append(f"Error exporting {model_path}: {str(e)}")
                logger.warning(f"Error exporting {model_path}: {e}")

        # Add export summary
        export_data['summary'] = {
            'total_sections': len(export_data['sections']),
            'total_records': sum(
                len(s.get('records', []))
                for s in export_data['sections']
            ),
            'errors': self.errors,
        }

        # Log the export
        self._log_export(export_data)

        return export_data

    def _export_model_data(
        self,
        model_path: str,
        user_field: Optional[str],
        friendly_name: str,
        include_metadata: bool,
    ) -> Optional[Dict[str, Any]]:
        """
        Export data from a single model.

        Args:
            model_path: Django model path (app_label.model_name).
            user_field: Field name that references the user.
            friendly_name: Human-readable name for this section.
            include_metadata: Whether to include metadata.

        Returns:
            Dictionary with section data or None.
        """
        try:
            model_class = apps.get_model(model_path)
        except LookupError:
            return None  # Model doesn't exist

        # Build queryset
        if user_field is None:
            # This is the user model itself
            queryset = model_class.objects.filter(pk=self.user.pk)
        elif '__' in user_field:
            # Nested relationship (e.g., employee__user)
            parts = user_field.split('__')
            filter_key = user_field
            if parts[-1] == 'email':
                queryset = model_class.objects.filter(**{filter_key: self.user.email})
            else:
                queryset = model_class.objects.filter(**{filter_key: self.user})
        elif user_field == 'email':
            queryset = model_class.objects.filter(email=self.user.email)
        else:
            queryset = model_class.objects.filter(**{user_field: self.user})

        # Filter by tenant if applicable
        if hasattr(model_class, 'tenant_id'):
            queryset = queryset.filter(tenant=self.tenant)

        if not queryset.exists():
            return None

        # Serialize records
        records = []
        for record in queryset:
            record_data = self._serialize_record(record, include_metadata)
            records.append(record_data)

        return {
            'section_name': friendly_name,
            'model': model_path,
            'record_count': len(records),
            'records': records,
            'exported_at': timezone.now().isoformat(),
        }

    def _serialize_record(
        self,
        record: models.Model,
        include_metadata: bool,
    ) -> Dict[str, Any]:
        """
        Serialize a single record to dictionary.

        Args:
            record: The model instance to serialize.
            include_metadata: Whether to include collection metadata.

        Returns:
            Dictionary representation of the record.
        """
        data = {}

        for field in record._meta.fields:
            field_name = field.name

            # Skip excluded fields
            if any(excl in field_name.lower() for excl in self.EXCLUDED_FIELDS):
                continue

            value = getattr(record, field_name)

            # Handle different field types
            if value is None:
                data[field_name] = None
            elif isinstance(value, datetime):
                data[field_name] = value.isoformat()
            elif isinstance(value, models.Model):
                # Foreign key - include ID and string representation
                data[field_name] = {
                    'id': str(value.pk),
                    'display': str(value),
                }
            elif isinstance(value, uuid.UUID):
                data[field_name] = str(value)
            elif hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
                data[field_name] = list(value)
            else:
                data[field_name] = value

        # Add metadata if requested
        if include_metadata:
            data['_metadata'] = self._get_field_metadata(record)

        return data

    def _get_field_metadata(self, record: models.Model) -> Dict[str, Any]:
        """
        Get metadata for record fields.

        Returns information about when data was collected,
        the purpose, and source.
        """
        metadata = {
            'collection_date': None,
            'last_modified': None,
            'source': 'zumodra_platform',
            'pii_fields': [],
        }

        # Try to get collection/modification dates
        if hasattr(record, 'created_at'):
            metadata['collection_date'] = record.created_at.isoformat()
        if hasattr(record, 'updated_at'):
            metadata['last_modified'] = record.updated_at.isoformat()

        # Identify PII fields present in this record
        for field in record._meta.fields:
            if any(pii in field.name.lower() for pii in self.PII_FIELDS):
                metadata['pii_fields'].append(field.name)

        return metadata

    def generate_zip_archive(
        self,
        export_data: Dict[str, Any],
        include_formats: Optional[List[str]] = None,
    ) -> bytes:
        """
        Generate a ZIP archive containing the exported data.

        Args:
            export_data: The export data dictionary.
            include_formats: List of formats to include ('json', 'csv', 'xml').

        Returns:
            Bytes of the ZIP archive.
        """
        if include_formats is None:
            include_formats = ['json', 'csv']

        buffer = io.BytesIO()

        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add README file
            readme = self._generate_readme(export_data)
            zf.writestr('README.txt', readme)

            # Add JSON export
            if 'json' in include_formats:
                json_content = json.dumps(
                    export_data,
                    indent=2,
                    cls=DjangoJSONEncoder,
                )
                zf.writestr('data_export.json', json_content)

            # Add CSV exports (one per section)
            if 'csv' in include_formats:
                for section in export_data.get('sections', []):
                    csv_content = self._convert_to_csv(section)
                    filename = self._sanitize_filename(section['section_name'])
                    zf.writestr(f'csv/{filename}.csv', csv_content)

            # Add XML export
            if 'xml' in include_formats:
                xml_content = self._convert_to_xml(export_data)
                zf.writestr('data_export.xml', xml_content)

            # Add manifest
            manifest = self._generate_manifest(export_data, include_formats)
            zf.writestr('manifest.json', json.dumps(manifest, indent=2))

        buffer.seek(0)
        return buffer.read()

    def _generate_readme(self, export_data: Dict[str, Any]) -> str:
        """Generate a README file for the export."""
        return f"""GDPR Data Export - Zumodra Platform
====================================

Export ID: {export_data['export_id']}
Export Date: {export_data['export_timestamp']}
Data Subject: {export_data['data_subject']['email']}
Tenant: {export_data['tenant']['name']}

This archive contains all personal data stored by Zumodra for the above user,
as required by GDPR Article 20 (Right to Data Portability).

Contents:
---------
- README.txt: This file
- manifest.json: Export metadata and file listing
- data_export.json: All data in JSON format
- csv/: Individual CSV files for each data category
- data_export.xml: All data in XML format (if included)

Data Categories Included:
-------------------------
{chr(10).join(f"- {s['section_name']}: {s['record_count']} records" for s in export_data.get('sections', []))}

Total Records: {export_data['summary']['total_records']}

For questions about this data export, contact your data protection officer
or email privacy@zumodra.com.

This export was generated in compliance with:
- GDPR Article 15 (Right of Access)
- GDPR Article 20 (Right to Data Portability)
"""

    def _generate_manifest(
        self,
        export_data: Dict[str, Any],
        formats: List[str],
    ) -> Dict[str, Any]:
        """Generate a manifest file for the export."""
        return {
            'export_id': export_data['export_id'],
            'export_timestamp': export_data['export_timestamp'],
            'data_subject_id': export_data['data_subject']['id'],
            'tenant_id': export_data['tenant']['id'],
            'formats_included': formats,
            'sections': [
                {
                    'name': s['section_name'],
                    'model': s['model'],
                    'records': s['record_count'],
                }
                for s in export_data.get('sections', [])
            ],
            'total_records': export_data['summary']['total_records'],
            'gdpr_compliance': {
                'right_of_access': 'Article 15',
                'data_portability': 'Article 20',
                'machine_readable': True,
            },
        }

    def _convert_to_csv(self, section: Dict[str, Any]) -> str:
        """
        Convert a section to CSV format.

        Args:
            section: The section data dictionary.

        Returns:
            CSV string.
        """
        output = io.StringIO()
        records = section.get('records', [])

        if not records:
            return ''

        # Get all field names from records (excluding metadata)
        fieldnames = set()
        for record in records:
            for key in record.keys():
                if key != '_metadata':
                    fieldnames.add(key)
        fieldnames = sorted(fieldnames)

        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()

        for record in records:
            # Flatten complex values for CSV
            row = {}
            for key, value in record.items():
                if key == '_metadata':
                    continue
                if isinstance(value, dict):
                    row[key] = json.dumps(value)
                elif isinstance(value, list):
                    row[key] = json.dumps(value)
                else:
                    row[key] = value
            writer.writerow(row)

        return output.getvalue()

    def _convert_to_xml(self, export_data: Dict[str, Any]) -> str:
        """
        Convert export data to XML format.

        Args:
            export_data: The export data dictionary.

        Returns:
            XML string.
        """
        root = ET.Element('gdpr_export')
        root.set('export_id', export_data['export_id'])
        root.set('timestamp', export_data['export_timestamp'])

        # Data subject info
        subject_elem = ET.SubElement(root, 'data_subject')
        ET.SubElement(subject_elem, 'id').text = export_data['data_subject']['id']
        ET.SubElement(subject_elem, 'email').text = export_data['data_subject']['email']

        # Tenant info
        tenant_elem = ET.SubElement(root, 'tenant')
        ET.SubElement(tenant_elem, 'id').text = export_data['tenant']['id']
        ET.SubElement(tenant_elem, 'name').text = export_data['tenant']['name']

        # Sections
        sections_elem = ET.SubElement(root, 'sections')
        for section in export_data.get('sections', []):
            section_elem = ET.SubElement(sections_elem, 'section')
            section_elem.set('name', section['section_name'])
            section_elem.set('model', section['model'])

            records_elem = ET.SubElement(section_elem, 'records')
            for record in section.get('records', []):
                record_elem = ET.SubElement(records_elem, 'record')
                self._dict_to_xml(record, record_elem)

        return ET.tostring(root, encoding='unicode', method='xml')

    def _dict_to_xml(self, data: Dict[str, Any], parent: ET.Element):
        """Recursively convert a dictionary to XML elements."""
        for key, value in data.items():
            if key == '_metadata':
                continue

            elem = ET.SubElement(parent, self._sanitize_xml_tag(key))

            if value is None:
                elem.set('null', 'true')
            elif isinstance(value, dict):
                self._dict_to_xml(value, elem)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        item_elem = ET.SubElement(elem, 'item')
                        self._dict_to_xml(item, item_elem)
                    else:
                        ET.SubElement(elem, 'item').text = str(item)
            else:
                elem.text = str(value)

    def _sanitize_filename(self, name: str) -> str:
        """Sanitize a string for use as a filename."""
        return "".join(
            c if c.isalnum() or c in '-_' else '_'
            for c in name
        ).lower()

    def _sanitize_xml_tag(self, name: str) -> str:
        """Sanitize a string for use as an XML tag name."""
        # XML tags must start with letter or underscore
        tag = ''.join(c if c.isalnum() or c == '_' else '_' for c in name)
        if tag and tag[0].isdigit():
            tag = '_' + tag
        return tag or 'field'

    def _log_export(self, export_data: Dict[str, Any]):
        """Log the data export action."""
        PrivacyAuditLog.objects.create(
            tenant=self.tenant,
            action=PrivacyAuditLog.ActionType.DATA_EXPORTED,
            description=f"GDPR data export generated for user {self.user.email}",
            actor=self.user,
            data_subject=self.user,
            context={
                'export_id': export_data['export_id'],
                'sections': len(export_data.get('sections', [])),
                'total_records': export_data['summary']['total_records'],
                'format': export_data['format'],
            },
        )

        logger.info(
            f"GDPR data export completed: export_id={export_data['export_id']}, "
            f"user={self.user.id}, records={export_data['summary']['total_records']}"
        )


class DataExportRequest:
    """
    Helper class to manage data export requests.

    Handles the full workflow of:
    - Validating the request
    - Generating the export
    - Storing the result
    - Notifying the user
    """

    def __init__(self, dsr_request):
        """
        Initialize with a DataSubjectRequest.

        Args:
            dsr_request: The DataSubjectRequest instance.
        """
        self.dsr = dsr_request
        self.tenant = dsr_request.tenant
        self.user = dsr_request.user

    def process(
        self,
        format: str = 'json',
        include_formats: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Process the data export request.

        Args:
            format: Primary export format.
            include_formats: List of all formats to include in ZIP.

        Returns:
            Dictionary with export results.
        """
        from core.privacy.models import DataSubjectRequest

        # Update status to in progress
        self.dsr.status = DataSubjectRequest.RequestStatus.IN_PROGRESS
        self.dsr.save(update_fields=['status'])

        try:
            # Create exporter
            exporter = GDPRDataExporter(self.tenant, self.user)

            # Generate export data
            export_data = exporter.export_all_data(
                format=format,
                include_metadata=True,
                include_related=True,
            )

            # Generate ZIP archive
            zip_content = exporter.generate_zip_archive(
                export_data,
                include_formats=include_formats or ['json', 'csv'],
            )

            # Save to DSR response
            filename = f"gdpr_export_{export_data['export_id']}.zip"
            self.dsr.response_file.save(
                filename,
                ContentFile(zip_content),
            )
            self.dsr.response_data = {
                'export_id': export_data['export_id'],
                'sections': len(export_data.get('sections', [])),
                'total_records': export_data['summary']['total_records'],
                'format': format,
                'filename': filename,
            }
            self.dsr.status = DataSubjectRequest.RequestStatus.COMPLETED
            self.dsr.completed_at = timezone.now()
            self.dsr.save()

            return {
                'success': True,
                'export_id': export_data['export_id'],
                'filename': filename,
                'records': export_data['summary']['total_records'],
            }

        except Exception as e:
            logger.exception(f"Error processing data export: {e}")

            self.dsr.status = DataSubjectRequest.RequestStatus.PARTIALLY_COMPLETED
            self.dsr.processing_notes = f"Export error: {str(e)}"
            self.dsr.save(update_fields=['status', 'processing_notes'])

            return {
                'success': False,
                'error': str(e),
            }
