"""
Initial migration for core app - Database Extensions and Performance Setup

This migration creates the necessary PostgreSQL extensions for Zumodra:
- uuid-ossp: UUID generation functions
- pg_trgm: Trigram matching for fuzzy search
- postgis: Geospatial support (if not already installed)
- btree_gin: B-tree support for GIN indexes
- pgcrypto: Cryptographic functions

Run this migration before other apps that depend on these features.
"""

from django.db import migrations


class Migration(migrations.Migration):
    """
    Initial migration to set up PostgreSQL extensions.

    These extensions provide:
    - UUID generation (uuid-ossp)
    - Fuzzy text search with trigrams (pg_trgm)
    - Geospatial queries (postgis)
    - Combined B-tree/GIN indexes (btree_gin)
    - Cryptographic functions (pgcrypto)
    """

    initial = True

    dependencies = []

    operations = [
        # UUID-OSSP Extension
        # Provides uuid_generate_v4() and other UUID functions
        # Required for UUID primary keys
        migrations.RunSQL(
            sql='''
                CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
            ''',
            reverse_sql='''
                DROP EXTENSION IF EXISTS "uuid-ossp";
            ''',
            hints={'atomic': False},
        ),

        # PG_TRGM Extension
        # Provides trigram matching for fuzzy text search
        # Enables LIKE queries with index support and similarity matching
        migrations.RunSQL(
            sql='''
                CREATE EXTENSION IF NOT EXISTS pg_trgm;
            ''',
            reverse_sql='''
                DROP EXTENSION IF EXISTS pg_trgm;
            ''',
            hints={'atomic': False},
        ),

        # PostGIS Extension
        # Provides geospatial data types and functions
        # Required for location-based job/candidate matching
        migrations.RunSQL(
            sql='''
                -- Check if PostGIS is available before creating
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM pg_available_extensions WHERE name = 'postgis'
                    ) THEN
                        CREATE EXTENSION IF NOT EXISTS postgis;
                    ELSE
                        RAISE NOTICE 'PostGIS extension not available - skipping';
                    END IF;
                END $$;
            ''',
            reverse_sql='''
                DROP EXTENSION IF EXISTS postgis CASCADE;
            ''',
            hints={'atomic': False},
        ),

        # BTREE_GIN Extension
        # Allows B-tree operators in GIN indexes
        # Useful for combined indexes on different data types
        migrations.RunSQL(
            sql='''
                CREATE EXTENSION IF NOT EXISTS btree_gin;
            ''',
            reverse_sql='''
                DROP EXTENSION IF EXISTS btree_gin;
            ''',
            hints={'atomic': False},
        ),

        # PGCRYPTO Extension
        # Provides cryptographic functions
        # Used for secure hashing and encryption
        migrations.RunSQL(
            sql='''
                CREATE EXTENSION IF NOT EXISTS pgcrypto;
            ''',
            reverse_sql='''
                DROP EXTENSION IF EXISTS pgcrypto;
            ''',
            hints={'atomic': False},
        ),

        # Create database functions for common operations

        # Function to update updated_at timestamp automatically
        migrations.RunSQL(
            sql='''
                CREATE OR REPLACE FUNCTION update_updated_at_column()
                RETURNS TRIGGER AS $$
                BEGIN
                    NEW.updated_at = CURRENT_TIMESTAMP;
                    RETURN NEW;
                END;
                $$ language 'plpgsql';
            ''',
            reverse_sql='''
                DROP FUNCTION IF EXISTS update_updated_at_column();
            ''',
        ),

        # Function to generate short unique IDs (for reference codes)
        migrations.RunSQL(
            sql='''
                CREATE OR REPLACE FUNCTION generate_short_uid(length INTEGER DEFAULT 8)
                RETURNS TEXT AS $$
                DECLARE
                    chars TEXT := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
                    result TEXT := '';
                    i INTEGER;
                BEGIN
                    FOR i IN 1..length LOOP
                        result := result || substr(chars, floor(random() * length(chars) + 1)::integer, 1);
                    END LOOP;
                    RETURN result;
                END;
                $$ LANGUAGE plpgsql;
            ''',
            reverse_sql='''
                DROP FUNCTION IF EXISTS generate_short_uid(INTEGER);
            ''',
        ),

        # Function to calculate similarity between two texts
        migrations.RunSQL(
            sql='''
                CREATE OR REPLACE FUNCTION text_similarity(text1 TEXT, text2 TEXT)
                RETURNS REAL AS $$
                BEGIN
                    IF text1 IS NULL OR text2 IS NULL THEN
                        RETURN 0;
                    END IF;
                    RETURN similarity(lower(text1), lower(text2));
                END;
                $$ LANGUAGE plpgsql IMMUTABLE;
            ''',
            reverse_sql='''
                DROP FUNCTION IF EXISTS text_similarity(TEXT, TEXT);
            ''',
        ),

        # Function to safely parse JSON with fallback
        migrations.RunSQL(
            sql='''
                CREATE OR REPLACE FUNCTION safe_json_extract(
                    json_data JSONB,
                    key_path TEXT,
                    default_value TEXT DEFAULT NULL
                )
                RETURNS TEXT AS $$
                BEGIN
                    RETURN COALESCE(json_data #>> string_to_array(key_path, '.'), default_value);
                EXCEPTION
                    WHEN OTHERS THEN
                        RETURN default_value;
                END;
                $$ LANGUAGE plpgsql IMMUTABLE;
            ''',
            reverse_sql='''
                DROP FUNCTION IF EXISTS safe_json_extract(JSONB, TEXT, TEXT);
            ''',
        ),

        # Create index for fuzzy search if pg_trgm is available
        # This sets up the operator class for trigram indexes
        migrations.RunSQL(
            sql='''
                -- Set up trigram similarity threshold
                -- Values range from 0 to 1, with 1 being exact match
                SET pg_trgm.similarity_threshold = 0.3;
            ''',
            reverse_sql='-- No reverse needed for SET',
            hints={'atomic': False},
        ),

        # Add comment to database for documentation
        migrations.RunSQL(
            sql='''
                COMMENT ON DATABASE CURRENT_DATABASE IS
                'Zumodra Multi-Tenant ATS/HR SaaS Platform -
                Extensions: uuid-ossp, pg_trgm, postgis, btree_gin, pgcrypto';
            ''',
            reverse_sql='-- No reverse needed for COMMENT',
            hints={'atomic': False},
        ),
    ]
