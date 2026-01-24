"""
ATS Indexes - Database index recommendations and configurations.

This module provides comprehensive index definitions for the ATS module
to optimize query performance. Includes:
- Full-text search indexes (GIN) for job titles and descriptions
- Partial indexes for active jobs, pending applications
- Composite indexes for common filter patterns
- GIN indexes for ArrayField (skills, tags)
- Geospatial indexes for location-based queries

These indexes should be added via Django migrations or raw SQL.
"""

from django.contrib.postgres.indexes import (
    GinIndex,
    GistIndex,
    BTreeIndex,
    HashIndex,
    BrinIndex,
)
from django.db import models


# =============================================================================
# INDEX CONFIGURATIONS FOR EACH MODEL
# =============================================================================

class JobPostingIndexes:
    """
    Index definitions for JobPosting model.

    Key query patterns to optimize:
    - Status filtering (active jobs)
    - Category/department filtering
    - Location-based searches
    - Full-text search on title/description
    - Skills filtering (ArrayField)
    - Date-based queries (created, published, deadline)
    """

    indexes = [
        # Full-text search index on search_vector
        # Crucial for performant job searches
        GinIndex(
            name='ats_job_search_vector_gin',
            fields=['search_vector'],
        ),

        # Partial index for active jobs only
        # Most queries are for open jobs, so this speeds up common case
        BTreeIndex(
            name='ats_job_active_idx',
            fields=['status', 'created_at'],
            condition=models.Q(status='open'),
        ),

        # Partial index for published jobs (public career page)
        BTreeIndex(
            name='ats_job_published_idx',
            fields=['published_at'],
            condition=models.Q(
                status='open',
                published_on_career_page=True
            ),
        ),

        # Composite index for category + status filtering
        BTreeIndex(
            name='ats_job_category_status_idx',
            fields=['category', 'status'],
        ),

        # Composite index for job type + experience level
        BTreeIndex(
            name='ats_job_type_level_idx',
            fields=['job_type', 'experience_level', 'status'],
        ),

        # GIN index for required_skills ArrayField
        # Enables efficient @> (contains) and && (overlap) queries
        GinIndex(
            name='ats_job_required_skills_gin',
            fields=['required_skills'],
        ),

        # GIN index for preferred_skills
        GinIndex(
            name='ats_job_preferred_skills_gin',
            fields=['preferred_skills'],
        ),

        # GIN index for languages_required
        GinIndex(
            name='ats_job_languages_gin',
            fields=['languages_required'],
        ),

        # Location-based index for remote policy filtering
        BTreeIndex(
            name='ats_job_remote_policy_idx',
            fields=['remote_policy', 'status'],
        ),

        # Location composite for city/country searches
        BTreeIndex(
            name='ats_job_location_idx',
            fields=['location_country', 'location_city', 'status'],
        ),

        # Salary range for compensation filtering
        BTreeIndex(
            name='ats_job_salary_idx',
            fields=['salary_currency', 'salary_min', 'salary_max'],
        ),

        # Application deadline for "closing soon" queries
        BTreeIndex(
            name='ats_job_deadline_idx',
            fields=['application_deadline'],
            condition=models.Q(
                status='open',
                application_deadline__isnull=False
            ),
        ),

        # Recruiter assignment for recruiter dashboard
        BTreeIndex(
            name='ats_job_recruiter_idx',
            fields=['recruiter', 'status'],
        ),

        # Hiring manager assignment
        BTreeIndex(
            name='ats_job_hiring_mgr_idx',
            fields=['hiring_manager', 'status'],
        ),

        # Reference code lookup (should be unique but index helps)
        HashIndex(
            name='ats_job_ref_code_hash',
            fields=['reference_code'],
        ),

        # UUID lookup
        HashIndex(
            name='ats_job_uuid_hash',
            fields=['uuid'],
        ),
    ]


class CandidateIndexes:
    """
    Index definitions for Candidate model.

    Key query patterns:
    - Email lookup (unique constraint)
    - Full-text search on name, skills, resume
    - Skills filtering
    - Source tracking analytics
    - Location-based filtering
    """

    indexes = [
        # Full-text search index
        GinIndex(
            name='ats_candidate_search_gin',
            fields=['search_vector'],
        ),

        # Email lookup - frequently used for deduplication
        HashIndex(
            name='ats_candidate_email_hash',
            fields=['email'],
        ),

        # Skills GIN index for array queries
        GinIndex(
            name='ats_candidate_skills_gin',
            fields=['skills'],
        ),

        # Tags GIN index
        GinIndex(
            name='ats_candidate_tags_gin',
            fields=['tags'],
        ),

        # Languages GIN index
        GinIndex(
            name='ats_candidate_languages_gin',
            fields=['languages'],
        ),

        # Source tracking for analytics
        BTreeIndex(
            name='ats_candidate_source_idx',
            fields=['source', 'created_at'],
        ),

        # Location-based filtering
        BTreeIndex(
            name='ats_candidate_location_idx',
            fields=['country', 'city'],
        ),

        # Experience level filtering
        BTreeIndex(
            name='ats_candidate_experience_idx',
            fields=['years_experience'],
        ),

        # Referral tracking
        BTreeIndex(
            name='ats_candidate_referral_idx',
            fields=['referred_by', 'source'],
            condition=models.Q(source='referral'),
        ),

        # GDPR compliance - data retention
        BTreeIndex(
            name='ats_candidate_retention_idx',
            fields=['data_retention_until'],
            condition=models.Q(data_retention_until__isnull=False),
        ),

        # Active candidates (with consent)
        BTreeIndex(
            name='ats_candidate_active_idx',
            fields=['created_at'],
            condition=models.Q(consent_to_store=True),
        ),

        # Last activity for engagement tracking
        BTreeIndex(
            name='ats_candidate_activity_idx',
            fields=['last_activity_at'],
        ),

        # UUID lookup
        HashIndex(
            name='ats_candidate_uuid_hash',
            fields=['uuid'],
        ),
    ]


class ApplicationIndexes:
    """
    Index definitions for Application model.

    Key query patterns:
    - Job + status filtering (pipeline view)
    - Stage-based filtering
    - Assignment tracking
    - Date-based analytics
    """

    indexes = [
        # Primary lookup: job + status (pipeline board view)
        BTreeIndex(
            name='ats_application_job_status_idx',
            fields=['job', 'status'],
        ),

        # Pipeline stage filtering (Kanban view)
        BTreeIndex(
            name='ats_application_stage_idx',
            fields=['job', 'current_stage'],
        ),

        # Partial index for active applications
        BTreeIndex(
            name='ats_application_active_idx',
            fields=['job', 'applied_at'],
            condition=~models.Q(
                status__in=['rejected', 'withdrawn', 'hired']
            ),
        ),

        # Partial index for pending review
        BTreeIndex(
            name='ats_application_pending_idx',
            fields=['applied_at'],
            condition=models.Q(status__in=['new', 'in_review']),
        ),

        # Assignment tracking
        BTreeIndex(
            name='ats_application_assigned_idx',
            fields=['assigned_to', 'status'],
        ),

        # Unassigned applications
        BTreeIndex(
            name='ats_application_unassigned_idx',
            fields=['job', 'applied_at'],
            condition=models.Q(assigned_to__isnull=True),
        ),

        # Candidate lookup
        BTreeIndex(
            name='ats_application_candidate_idx',
            fields=['candidate', 'applied_at'],
        ),

        # Stage change timestamp for staleness detection
        BTreeIndex(
            name='ats_application_stage_change_idx',
            fields=['last_stage_change_at'],
        ),

        # Rating-based queries (high potential)
        BTreeIndex(
            name='ats_application_rating_idx',
            fields=['overall_rating'],
            condition=models.Q(overall_rating__isnull=False),
        ),

        # AI match score
        BTreeIndex(
            name='ats_application_match_score_idx',
            fields=['ai_match_score'],
            condition=models.Q(ai_match_score__isnull=False),
        ),

        # UTM source tracking for analytics
        BTreeIndex(
            name='ats_application_utm_idx',
            fields=['utm_source', 'applied_at'],
        ),

        # Applied date for time-based analytics
        BTreeIndex(
            name='ats_application_date_idx',
            fields=['applied_at'],
        ),

        # Hired date for time-to-hire calculations
        BTreeIndex(
            name='ats_application_hired_idx',
            fields=['hired_at'],
            condition=models.Q(status='hired'),
        ),

        # UUID lookup
        HashIndex(
            name='ats_application_uuid_hash',
            fields=['uuid'],
        ),
    ]


class InterviewIndexes:
    """
    Index definitions for Interview model.

    Key query patterns:
    - Upcoming interviews by date
    - Interviewer assignments
    - Application lookup
    - Status filtering
    """

    indexes = [
        # Primary: scheduled interviews by date
        BTreeIndex(
            name='ats_interview_scheduled_idx',
            fields=['scheduled_start', 'status'],
        ),

        # Partial index for upcoming/active interviews
        BTreeIndex(
            name='ats_interview_upcoming_idx',
            fields=['scheduled_start'],
            condition=models.Q(status__in=['scheduled', 'confirmed']),
        ),

        # Application lookup
        BTreeIndex(
            name='ats_interview_application_idx',
            fields=['application', 'scheduled_start'],
        ),

        # Organizer's interviews
        BTreeIndex(
            name='ats_interview_organizer_idx',
            fields=['organizer', 'scheduled_start'],
        ),

        # Interview type filtering
        BTreeIndex(
            name='ats_interview_type_idx',
            fields=['interview_type', 'status'],
        ),

        # Completed interviews needing feedback
        BTreeIndex(
            name='ats_interview_completed_idx',
            fields=['scheduled_end'],
            condition=models.Q(status='completed'),
        ),

        # Calendar integration lookup
        HashIndex(
            name='ats_interview_calendar_hash',
            fields=['calendar_event_id'],
            condition=models.Q(calendar_event_id__gt=''),
        ),

        # Notification tracking
        BTreeIndex(
            name='ats_interview_notify_idx',
            fields=['scheduled_start'],
            condition=models.Q(
                candidate_notified=False
            ) | models.Q(
                interviewers_notified=False
            ),
        ),

        # UUID lookup
        HashIndex(
            name='ats_interview_uuid_hash',
            fields=['uuid'],
        ),
    ]


class InterviewFeedbackIndexes:
    """
    Index definitions for InterviewFeedback model.
    """

    indexes = [
        # Interview lookup
        BTreeIndex(
            name='ats_feedback_interview_idx',
            fields=['interview', 'created_at'],
        ),

        # Interviewer lookup
        BTreeIndex(
            name='ats_feedback_interviewer_idx',
            fields=['interviewer', 'created_at'],
        ),

        # Recommendation filtering
        BTreeIndex(
            name='ats_feedback_recommendation_idx',
            fields=['recommendation'],
        ),

        # Pending submission
        BTreeIndex(
            name='ats_feedback_pending_idx',
            fields=['created_at'],
            condition=models.Q(submitted_at__isnull=True),
        ),
    ]


class PipelineIndexes:
    """
    Index definitions for Pipeline model.
    """

    indexes = [
        # Active pipelines
        BTreeIndex(
            name='ats_pipeline_active_idx',
            fields=['is_active', 'name'],
        ),

        # Default pipeline lookup
        BTreeIndex(
            name='ats_pipeline_default_idx',
            fields=['is_default'],
            condition=models.Q(is_default=True),
        ),

        # UUID lookup
        HashIndex(
            name='ats_pipeline_uuid_hash',
            fields=['uuid'],
        ),
    ]


class PipelineStageIndexes:
    """
    Index definitions for PipelineStage model.
    """

    indexes = [
        # Pipeline + order (stage ordering)
        BTreeIndex(
            name='ats_stage_pipeline_order_idx',
            fields=['pipeline', 'order'],
        ),

        # Stage type for aggregation
        BTreeIndex(
            name='ats_stage_type_idx',
            fields=['stage_type'],
        ),

        # Active stages
        BTreeIndex(
            name='ats_stage_active_idx',
            fields=['pipeline', 'order'],
            condition=models.Q(is_active=True),
        ),

        # UUID lookup
        HashIndex(
            name='ats_stage_uuid_hash',
            fields=['uuid'],
        ),
    ]


class OfferIndexes:
    """
    Index definitions for Offer model.
    """

    indexes = [
        # Status filtering
        BTreeIndex(
            name='ats_offer_status_idx',
            fields=['status', 'created_at'],
        ),

        # Pending offers (sent, awaiting response)
        BTreeIndex(
            name='ats_offer_pending_idx',
            fields=['expiration_date'],
            condition=models.Q(status='sent'),
        ),

        # Application lookup
        BTreeIndex(
            name='ats_offer_application_idx',
            fields=['application'],
        ),

        # Approval workflow
        BTreeIndex(
            name='ats_offer_approval_idx',
            fields=['created_at'],
            condition=models.Q(status='pending_approval'),
        ),

        # Expiring soon
        BTreeIndex(
            name='ats_offer_expiring_idx',
            fields=['expiration_date', 'status'],
        ),

        # UUID lookup
        HashIndex(
            name='ats_offer_uuid_hash',
            fields=['uuid'],
        ),
    ]


class ApplicationActivityIndexes:
    """
    Index definitions for ApplicationActivity model.
    """

    indexes = [
        # Application timeline
        BTreeIndex(
            name='ats_activity_app_idx',
            fields=['application', 'created_at'],
        ),

        # Activity type filtering
        BTreeIndex(
            name='ats_activity_type_idx',
            fields=['activity_type', 'created_at'],
        ),

        # User activity tracking
        BTreeIndex(
            name='ats_activity_user_idx',
            fields=['performed_by', 'created_at'],
        ),
    ]


class SavedSearchIndexes:
    """
    Index definitions for SavedSearch model.
    """

    indexes = [
        # User's saved searches
        BTreeIndex(
            name='ats_search_user_idx',
            fields=['user', 'updated_at'],
        ),

        # Alert enabled searches
        BTreeIndex(
            name='ats_search_alert_idx',
            fields=['last_run_at'],
            condition=models.Q(is_alert_enabled=True),
        ),

        # UUID lookup
        HashIndex(
            name='ats_search_uuid_hash',
            fields=['uuid'],
        ),
    ]


# =============================================================================
# RAW SQL INDEX DEFINITIONS
# For indexes that need raw SQL (GiST for PostGIS, etc.)
# =============================================================================

RAW_SQL_INDEXES = """
-- PostGIS spatial indexes for location-based queries

-- JobPosting location coordinates (for radius search)
CREATE INDEX IF NOT EXISTS ats_job_location_gist
ON ats_jobposting USING GIST (location_coordinates)
WHERE location_coordinates IS NOT NULL;

-- Candidate location coordinates
CREATE INDEX IF NOT EXISTS ats_candidate_location_gist
ON ats_candidate USING GIST (location_coordinates)
WHERE location_coordinates IS NOT NULL;

-- Full-text search indexes using pg_trgm for fuzzy matching

-- Enable pg_trgm extension (if not already enabled)
-- CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Job title trigram index for fuzzy search
CREATE INDEX IF NOT EXISTS ats_job_title_trgm
ON ats_jobposting USING GIN (title gin_trgm_ops);

-- Candidate name trigram indexes
CREATE INDEX IF NOT EXISTS ats_candidate_first_name_trgm
ON ats_candidate USING GIN (first_name gin_trgm_ops);

CREATE INDEX IF NOT EXISTS ats_candidate_last_name_trgm
ON ats_candidate USING GIN (last_name gin_trgm_ops);

-- Candidate headline trigram
CREATE INDEX IF NOT EXISTS ats_candidate_headline_trgm
ON ats_candidate USING GIN (headline gin_trgm_ops);

-- Job description text search (if search_vector not used)
CREATE INDEX IF NOT EXISTS ats_job_description_trgm
ON ats_jobposting USING GIN (description gin_trgm_ops);

-- BRIN indexes for time-series data (efficient for large tables)

-- Application activity log (append-only, time-ordered)
CREATE INDEX IF NOT EXISTS ats_activity_created_brin
ON ats_applicationactivity USING BRIN (created_at);

-- Applications by applied date (for time-range queries)
CREATE INDEX IF NOT EXISTS ats_application_applied_brin
ON ats_application USING BRIN (applied_at);

-- Interviews by scheduled start (for calendar views)
CREATE INDEX IF NOT EXISTS ats_interview_scheduled_brin
ON ats_interview USING BRIN (scheduled_start);
"""


# =============================================================================
# MIGRATION HELPER
# =============================================================================

def get_all_index_classes():
    """
    Get all index configuration classes.

    Returns:
        dict: Model name -> index class mapping
    """
    return {
        'JobPosting': JobPostingIndexes,
        'Candidate': CandidateIndexes,
        'Application': ApplicationIndexes,
        'Interview': InterviewIndexes,
        'InterviewFeedback': InterviewFeedbackIndexes,
        'Pipeline': PipelineIndexes,
        'PipelineStage': PipelineStageIndexes,
        'Offer': OfferIndexes,
        'ApplicationActivity': ApplicationActivityIndexes,
        'SavedSearch': SavedSearchIndexes,
    }


def get_indexes_for_model(model_name):
    """
    Get index configurations for a specific model.

    Args:
        model_name: Model class name

    Returns:
        list: Index instances for the model
    """
    classes = get_all_index_classes()
    if model_name in classes:
        return classes[model_name].indexes
    return []


def generate_migration_operations():
    """
    Generate Django migration operations for all indexes.

    This can be used to create a migration file programmatically.

    Returns:
        list: Migration operation tuples (model_name, index)
    """
    operations = []
    for model_name, index_class in get_all_index_classes().items():
        for index in index_class.indexes:
            operations.append((model_name, index))
    return operations


# =============================================================================
# INDEX MONITORING QUERIES
# =============================================================================

INDEX_MONITORING_QUERIES = {
    'unused_indexes': """
        SELECT
            schemaname || '.' || relname AS table,
            indexrelname AS index,
            pg_size_pretty(pg_relation_size(i.indexrelid)) AS index_size,
            idx_scan AS index_scans
        FROM pg_stat_user_indexes ui
        JOIN pg_index i ON ui.indexrelid = i.indexrelid
        WHERE NOT indisunique
        AND idx_scan < 50
        AND schemaname = 'public'
        AND relname LIKE 'ats_%'
        ORDER BY pg_relation_size(i.indexrelid) DESC;
    """,

    'missing_indexes': """
        SELECT
            schemaname || '.' || relname AS table,
            seq_scan - idx_scan AS too_much_seq,
            CASE
                WHEN seq_scan - coalesce(idx_scan, 0) > 0
                THEN 'Missing Index?'
                ELSE 'OK'
            END AS status,
            pg_size_pretty(pg_relation_size(relid)) AS table_size,
            seq_scan,
            idx_scan
        FROM pg_stat_user_tables
        WHERE schemaname = 'public'
        AND relname LIKE 'ats_%'
        ORDER BY too_much_seq DESC;
    """,

    'index_sizes': """
        SELECT
            tablename,
            indexname,
            pg_size_pretty(pg_relation_size(indexname::regclass)) AS index_size
        FROM pg_indexes
        WHERE schemaname = 'public'
        AND tablename LIKE 'ats_%'
        ORDER BY pg_relation_size(indexname::regclass) DESC;
    """,

    'index_usage': """
        SELECT
            relname AS table,
            indexrelname AS index,
            idx_scan AS scans,
            idx_tup_read AS tuples_read,
            idx_tup_fetch AS tuples_fetched
        FROM pg_stat_user_indexes
        WHERE schemaname = 'public'
        AND relname LIKE 'ats_%'
        ORDER BY idx_scan DESC;
    """,
}
