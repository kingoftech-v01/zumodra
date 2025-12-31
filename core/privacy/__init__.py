"""
GDPR/Privacy Compliance Module for Zumodra ATS/HR Platform

This module provides comprehensive GDPR and privacy compliance features:
- Consent management with versioning and audit trails
- Data Subject Request (DSR) handling (access, rectification, erasure, portability)
- Data retention policies and automated cleanup
- Anonymization and pseudonymization services
- GDPR-compliant data export functionality
- Privacy decorators for consent checking and PII logging

All components are tenant-aware and maintain complete audit trails
for regulatory compliance.
"""

from core.privacy.services import (
    ConsentService,
    DataSubjectRequestService,
    DataRetentionService,
    AnonymizationService,
)
from core.privacy.decorators import (
    requires_consent,
    log_data_access,
    anonymize_in_logs,
)
from core.privacy.exporters import GDPRDataExporter

__all__ = [
    # Services
    'ConsentService',
    'DataSubjectRequestService',
    'DataRetentionService',
    'AnonymizationService',
    # Exporters
    'GDPRDataExporter',
    # Decorators
    'requires_consent',
    'log_data_access',
    'anonymize_in_logs',
]
