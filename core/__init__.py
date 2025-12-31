"""
Core - Database & Performance Infrastructure for Zumodra

This module provides foundational database components:
- Base models with UUID, timestamps, soft delete
- Tenant-aware managers for multi-tenancy
- Custom fields for encryption, money, and phone numbers
- Index recommendations for performance optimization
"""

default_app_config = 'core.apps.CoreConfig'
