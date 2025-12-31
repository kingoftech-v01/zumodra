"""
Database Index Recommendations for Zumodra

This module provides:
- Index recommendations for all major models
- Partial indexes for common query patterns
- GIN indexes for JSONB fields
- Full-text search indexes
- Composite indexes for multi-column queries

Apply these indexes via migrations or raw SQL for optimal query performance.
"""

from typing import List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


class IndexType(Enum):
    """Types of PostgreSQL indexes."""
    BTREE = 'btree'        # Default, good for equality and range queries
    HASH = 'hash'          # Fast equality lookups (not crash-safe pre-PG10)
    GIN = 'gin'            # Generalized Inverted Index for arrays/JSONB/full-text
    GIST = 'gist'          # Generalized Search Tree for geometric/full-text
    SPGIST = 'spgist'      # Space-partitioned GiST
    BRIN = 'brin'          # Block Range Index for large sorted tables


@dataclass
class IndexRecommendation:
    """
    Recommendation for a database index.

    Attributes:
        table: Table name
        columns: List of columns to index
        name: Index name (auto-generated if not provided)
        index_type: Type of index (btree, gin, gist, etc.)
        condition: WHERE clause for partial index
        include: Additional columns to include (covering index)
        unique: Whether index enforces uniqueness
        concurrent: Whether to create index concurrently
        description: Why this index is recommended
        priority: Priority level (1=critical, 5=nice-to-have)
    """
    table: str
    columns: List[str]
    name: str = ''
    index_type: IndexType = IndexType.BTREE
    condition: str = ''
    include: List[str] = field(default_factory=list)
    unique: bool = False
    concurrent: bool = True
    description: str = ''
    priority: int = 3

    def __post_init__(self):
        if not self.name:
            cols = '_'.join(self.columns)[:30]
            suffix = '_partial' if self.condition else ''
            self.name = f'idx_{self.table}_{cols}{suffix}'

    def to_sql(self) -> str:
        """Generate CREATE INDEX SQL statement."""
        unique = 'UNIQUE ' if self.unique else ''
        concurrent = 'CONCURRENTLY ' if self.concurrent else ''
        using = f'USING {self.index_type.value} ' if self.index_type != IndexType.BTREE else ''
        columns = ', '.join(self.columns)
        include_clause = f' INCLUDE ({", ".join(self.include)})' if self.include else ''
        where_clause = f' WHERE {self.condition}' if self.condition else ''

        return f'''CREATE {unique}INDEX {concurrent}{self.name}
    ON {self.table} {using}({columns}){include_clause}{where_clause};'''

    def to_django(self) -> str:
        """Generate Django Meta index definition."""
        fields = self.columns
        condition = f'condition=Q({self.condition})' if self.condition else ''

        if self.index_type == IndexType.GIN:
            return f"GinIndex(fields={fields}, name='{self.name}')"
        elif self.index_type == IndexType.GIST:
            return f"GistIndex(fields={fields}, name='{self.name}')"
        elif condition:
            return f"Index(fields={fields}, name='{self.name}', {condition})"
        else:
            return f"Index(fields={fields}, name='{self.name}')"


# =============================================================================
# TENANTS APP INDEXES
# =============================================================================

TENANTS_INDEXES: List[IndexRecommendation] = [
    # Tenant lookups by status (common for active tenant filtering)
    IndexRecommendation(
        table='tenants_tenant',
        columns=['status'],
        condition="status = 'active'",
        description='Partial index for active tenants - used in most queries',
        priority=1
    ),

    # Tenant by slug (URL resolution)
    IndexRecommendation(
        table='tenants_tenant',
        columns=['slug'],
        unique=True,
        description='Unique slug for URL-based tenant resolution',
        priority=1
    ),

    # Tenant by Stripe customer ID (webhook processing)
    IndexRecommendation(
        table='tenants_tenant',
        columns=['stripe_customer_id'],
        condition="stripe_customer_id != ''",
        description='Fast lookup for Stripe webhook processing',
        priority=2
    ),

    # Trial tenants (for expiration checks)
    IndexRecommendation(
        table='tenants_tenant',
        columns=['on_trial', 'trial_ends_at'],
        condition="on_trial = true",
        description='Partial index for trial expiration batch processing',
        priority=2
    ),

    # TenantSettings by tenant (one-to-one lookup)
    IndexRecommendation(
        table='tenants_tenantsettings',
        columns=['tenant_id'],
        unique=True,
        description='Ensures one-to-one relationship integrity',
        priority=1
    ),

    # Domain lookups (request routing)
    IndexRecommendation(
        table='tenants_domain',
        columns=['domain'],
        unique=True,
        description='Fast domain-to-tenant resolution',
        priority=1
    ),

    # TenantInvitation by token (acceptance flow)
    IndexRecommendation(
        table='tenants_tenantinvitation',
        columns=['token'],
        unique=True,
        description='Fast token lookup during invitation acceptance',
        priority=1
    ),

    # Pending invitations (for listing/reminders)
    IndexRecommendation(
        table='tenants_tenantinvitation',
        columns=['tenant_id', 'status', 'expires_at'],
        condition="status = 'pending'",
        description='Filter pending invitations by tenant',
        priority=2
    ),

    # AuditLog by tenant and date (common query pattern)
    IndexRecommendation(
        table='tenants_auditlog',
        columns=['tenant_id', 'created_at'],
        name='idx_auditlog_tenant_date',
        description='Time-series audit log queries per tenant',
        priority=1
    ),

    # AuditLog by resource (finding all changes to an entity)
    IndexRecommendation(
        table='tenants_auditlog',
        columns=['tenant_id', 'resource_type', 'resource_id'],
        name='idx_auditlog_resource',
        description='Find all audit entries for a specific resource',
        priority=2
    ),

    # AuditLog JSONB fields for advanced queries
    IndexRecommendation(
        table='tenants_auditlog',
        columns=['old_values'],
        index_type=IndexType.GIN,
        name='idx_auditlog_old_values_gin',
        description='GIN index for querying historical values',
        priority=3
    ),
]

# =============================================================================
# ACCOUNTS APP INDEXES
# =============================================================================

ACCOUNTS_INDEXES: List[IndexRecommendation] = [
    # TenantUser by user (find all tenants for a user)
    IndexRecommendation(
        table='accounts_tenantuser',
        columns=['user_id'],
        description='Find all tenant memberships for a user',
        priority=1
    ),

    # TenantUser by tenant (list all members)
    IndexRecommendation(
        table='accounts_tenantuser',
        columns=['tenant_id', 'is_active'],
        condition="is_active = true",
        description='List active members of a tenant',
        priority=1
    ),

    # TenantUser by role (permission checks)
    IndexRecommendation(
        table='accounts_tenantuser',
        columns=['tenant_id', 'role'],
        description='Find users by role within a tenant',
        priority=2
    ),

    # UserProfile by user (one-to-one)
    IndexRecommendation(
        table='accounts_userprofile',
        columns=['user_id'],
        unique=True,
        description='One-to-one profile lookup',
        priority=1
    ),

    # KYCVerification by user and type
    IndexRecommendation(
        table='accounts_kycverification',
        columns=['user_id', 'verification_type', 'status'],
        name='idx_kyc_user_type_status',
        description='Check verification status by type',
        priority=1
    ),

    # Valid KYC verifications
    IndexRecommendation(
        table='accounts_kycverification',
        columns=['user_id', 'status', 'expires_at'],
        condition="status = 'verified'",
        name='idx_kyc_valid',
        description='Find valid (non-expired) verifications',
        priority=2
    ),

    # ProgressiveConsent by grantor
    IndexRecommendation(
        table='accounts_progressiveconsent',
        columns=['grantor_id', 'status'],
        description='Find consents granted by a user',
        priority=2
    ),

    # Active consents
    IndexRecommendation(
        table='accounts_progressiveconsent',
        columns=['grantee_tenant_id', 'data_category', 'status'],
        condition="status = 'granted'",
        name='idx_consent_active',
        description='Check active consents for data access',
        priority=1
    ),

    # DataAccessLog for compliance reporting
    IndexRecommendation(
        table='accounts_dataaccesslog',
        columns=['data_subject_id', 'accessed_at'],
        name='idx_dataaccess_subject',
        description='Find all access to a subjects data',
        priority=1
    ),

    # LoginHistory by user (security monitoring)
    IndexRecommendation(
        table='accounts_loginhistory',
        columns=['user_id', 'timestamp'],
        description='User login history timeline',
        priority=2
    ),

    # Failed logins by IP (brute force detection)
    IndexRecommendation(
        table='accounts_loginhistory',
        columns=['ip_address', 'timestamp'],
        condition="result = 'failed'",
        name='idx_login_failed_ip',
        description='Detect brute force attacks by IP',
        priority=1
    ),
]

# =============================================================================
# ATS APP INDEXES
# =============================================================================

ATS_INDEXES: List[IndexRecommendation] = [
    # JobPosting by status (most common filter)
    IndexRecommendation(
        table='ats_jobposting',
        columns=['status', 'created_at'],
        description='Filter jobs by status with date ordering',
        priority=1
    ),

    # Open jobs (career page listings)
    IndexRecommendation(
        table='ats_jobposting',
        columns=['status', 'published_at'],
        condition="status = 'open' AND published_on_career_page = true",
        name='idx_job_open_published',
        description='Career page job listings',
        priority=1
    ),

    # Jobs by category
    IndexRecommendation(
        table='ats_jobposting',
        columns=['category_id', 'status'],
        description='Filter jobs by category',
        priority=2
    ),

    # Jobs by location (geo search)
    IndexRecommendation(
        table='ats_jobposting',
        columns=['location_coordinates'],
        index_type=IndexType.GIST,
        name='idx_job_location_gist',
        description='Geospatial job search',
        priority=2
    ),

    # Full-text search on job postings
    IndexRecommendation(
        table='ats_jobposting',
        columns=['search_vector'],
        index_type=IndexType.GIN,
        name='idx_job_search_vector',
        description='Full-text search on job content',
        priority=1
    ),

    # Jobs by skills (array contains)
    IndexRecommendation(
        table='ats_jobposting',
        columns=['required_skills'],
        index_type=IndexType.GIN,
        name='idx_job_skills_gin',
        description='Filter jobs by required skills',
        priority=2
    ),

    # Candidate by email (duplicate detection)
    IndexRecommendation(
        table='ats_candidate',
        columns=['email'],
        description='Prevent duplicate candidates, fast lookup',
        priority=1
    ),

    # Candidate full-text search
    IndexRecommendation(
        table='ats_candidate',
        columns=['search_vector'],
        index_type=IndexType.GIN,
        name='idx_candidate_search',
        description='Full-text candidate search',
        priority=1
    ),

    # Candidate skills
    IndexRecommendation(
        table='ats_candidate',
        columns=['skills'],
        index_type=IndexType.GIN,
        name='idx_candidate_skills',
        description='Filter candidates by skills',
        priority=2
    ),

    # Application by job and status (pipeline view)
    IndexRecommendation(
        table='ats_application',
        columns=['job_id', 'status', 'current_stage_id'],
        name='idx_application_pipeline',
        description='Pipeline/Kanban board view queries',
        priority=1
    ),

    # Application by candidate (candidate history)
    IndexRecommendation(
        table='ats_application',
        columns=['candidate_id', 'applied_at'],
        description='Candidate application history',
        priority=1
    ),

    # Recent applications (dashboard metrics)
    IndexRecommendation(
        table='ats_application',
        columns=['applied_at', 'status'],
        description='Recent applications for metrics',
        priority=2
    ),

    # Applications by stage (Kanban counts)
    IndexRecommendation(
        table='ats_application',
        columns=['job_id', 'current_stage_id'],
        include=['status'],
        name='idx_application_stage_covering',
        description='Covering index for stage counts',
        priority=2
    ),

    # Interview by date range (calendar view)
    IndexRecommendation(
        table='ats_interview',
        columns=['scheduled_start', 'status'],
        description='Calendar/schedule view queries',
        priority=1
    ),

    # Upcoming interviews by interviewer
    IndexRecommendation(
        table='ats_interview',
        columns=['status', 'scheduled_start'],
        condition="status IN ('scheduled', 'confirmed')",
        name='idx_interview_upcoming',
        description='Upcoming interviews dashboard',
        priority=2
    ),

    # Offer by status (pipeline tracking)
    IndexRecommendation(
        table='ats_offer',
        columns=['status', 'created_at'],
        description='Track offers through approval flow',
        priority=2
    ),

    # SavedSearch by user
    IndexRecommendation(
        table='ats_savedsearch',
        columns=['user_id', 'is_alert_enabled'],
        description='User saved searches with alerts',
        priority=3
    ),

    # SavedSearch filters (JSONB)
    IndexRecommendation(
        table='ats_savedsearch',
        columns=['filters'],
        index_type=IndexType.GIN,
        name='idx_savedsearch_filters',
        description='Query saved search filters',
        priority=3
    ),
]

# =============================================================================
# COMBINED INDEX RECOMMENDATIONS
# =============================================================================

ALL_INDEXES: List[IndexRecommendation] = (
    TENANTS_INDEXES +
    ACCOUNTS_INDEXES +
    ATS_INDEXES
)


def get_indexes_by_priority(max_priority: int = 3) -> List[IndexRecommendation]:
    """
    Get index recommendations filtered by priority.

    Args:
        max_priority: Maximum priority level (1=critical only, 5=all)

    Returns:
        List of IndexRecommendation objects
    """
    return [idx for idx in ALL_INDEXES if idx.priority <= max_priority]


def get_indexes_by_table(table_name: str) -> List[IndexRecommendation]:
    """
    Get index recommendations for a specific table.

    Args:
        table_name: Database table name

    Returns:
        List of IndexRecommendation objects for that table
    """
    return [idx for idx in ALL_INDEXES if idx.table == table_name]


def generate_migration_sql(indexes: List[IndexRecommendation] = None) -> str:
    """
    Generate SQL statements for creating indexes.

    Args:
        indexes: List of indexes to generate (defaults to all)

    Returns:
        SQL script for creating all indexes
    """
    if indexes is None:
        indexes = ALL_INDEXES

    lines = [
        '-- Zumodra Database Index Recommendations',
        '-- Generated for PostgreSQL',
        '-- Run these after initial migration',
        '',
    ]

    current_table = ''
    for idx in sorted(indexes, key=lambda x: (x.table, x.priority)):
        if idx.table != current_table:
            lines.append(f'\n-- {idx.table.upper()}')
            lines.append('-' * 50)
            current_table = idx.table

        lines.append(f'-- Priority: {idx.priority} - {idx.description}')
        lines.append(idx.to_sql())
        lines.append('')

    return '\n'.join(lines)


def generate_django_indexes(app_name: str) -> Dict[str, List[str]]:
    """
    Generate Django Meta class index definitions.

    Args:
        app_name: Django app name (e.g., 'tenants', 'accounts', 'ats')

    Returns:
        Dict mapping model names to list of index definitions
    """
    result: Dict[str, List[str]] = {}
    prefix = f'{app_name}_'

    for idx in ALL_INDEXES:
        if idx.table.startswith(prefix):
            model_name = idx.table[len(prefix):].title()
            if model_name not in result:
                result[model_name] = []
            result[model_name].append(idx.to_django())

    return result


# =============================================================================
# INDEX ANALYSIS UTILITIES
# =============================================================================

def analyze_query_patterns() -> Dict[str, Any]:
    """
    Return common query patterns and their recommended indexes.

    This is documentation for developers to understand index usage.
    """
    return {
        'tenant_isolation': {
            'description': 'All tenant-scoped queries filter by tenant_id first',
            'pattern': "SELECT * FROM table WHERE tenant_id = ? AND ...",
            'recommendation': 'Always include tenant_id as first column in composite indexes',
        },
        'soft_delete': {
            'description': 'Most queries exclude soft-deleted records',
            'pattern': "SELECT * FROM table WHERE is_deleted = false AND ...",
            'recommendation': 'Use partial indexes with condition is_deleted = false',
        },
        'status_filtering': {
            'description': 'Status fields are commonly used for filtering',
            'pattern': "SELECT * FROM table WHERE status = 'active' ORDER BY created_at",
            'recommendation': 'Create partial indexes for common status values',
        },
        'date_range': {
            'description': 'Date range queries for reporting and dashboards',
            'pattern': "SELECT * FROM table WHERE created_at BETWEEN ? AND ?",
            'recommendation': 'Use BRIN indexes for append-only tables with date ordering',
        },
        'full_text_search': {
            'description': 'Text search on job postings and candidates',
            'pattern': "SELECT * FROM table WHERE search_vector @@ to_tsquery(?)",
            'recommendation': 'Use GIN index on SearchVectorField columns',
        },
        'array_contains': {
            'description': 'Queries checking if array contains a value',
            'pattern': "SELECT * FROM table WHERE 'Python' = ANY(skills)",
            'recommendation': 'Use GIN index on ArrayField columns',
        },
        'json_queries': {
            'description': 'Queries on JSONB field contents',
            'pattern': "SELECT * FROM table WHERE metadata->>'key' = 'value'",
            'recommendation': 'Use GIN index with jsonb_path_ops for containment queries',
        },
        'geospatial': {
            'description': 'Location-based queries using PostGIS',
            'pattern': "SELECT * FROM table WHERE ST_DWithin(location, point, radius)",
            'recommendation': 'Use GIST index on geometry/geography columns',
        },
    }


# =============================================================================
# DATABASE EXTENSIONS
# =============================================================================

REQUIRED_EXTENSIONS = [
    {
        'name': 'uuid-ossp',
        'description': 'UUID generation functions (uuid_generate_v4)',
        'sql': "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";",
        'required': True,
    },
    {
        'name': 'pg_trgm',
        'description': 'Trigram matching for fuzzy text search',
        'sql': "CREATE EXTENSION IF NOT EXISTS pg_trgm;",
        'required': True,
    },
    {
        'name': 'postgis',
        'description': 'Geospatial support for location-based queries',
        'sql': "CREATE EXTENSION IF NOT EXISTS postgis;",
        'required': True,
    },
    {
        'name': 'btree_gin',
        'description': 'B-tree support for GIN indexes (multi-type indexes)',
        'sql': "CREATE EXTENSION IF NOT EXISTS btree_gin;",
        'required': False,
    },
    {
        'name': 'pgcrypto',
        'description': 'Cryptographic functions for secure data handling',
        'sql': "CREATE EXTENSION IF NOT EXISTS pgcrypto;",
        'required': False,
    },
]


def generate_extensions_sql() -> str:
    """Generate SQL for creating required PostgreSQL extensions."""
    lines = [
        '-- Required PostgreSQL Extensions for Zumodra',
        '-- Run as superuser or with appropriate privileges',
        '',
    ]

    for ext in REQUIRED_EXTENSIONS:
        required_str = 'REQUIRED' if ext['required'] else 'OPTIONAL'
        lines.append(f"-- {ext['name']} ({required_str}): {ext['description']}")
        lines.append(ext['sql'])
        lines.append('')

    return '\n'.join(lines)
