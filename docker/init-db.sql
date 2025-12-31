-- PostgreSQL initialization script for Zumodra
-- Creates extensions required for multi-tenant ATS/HR SaaS

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- For text search
CREATE EXTENSION IF NOT EXISTS unaccent; -- For accent-insensitive search
CREATE EXTENSION IF NOT EXISTS "uuid-ossp"; -- For UUID generation

-- Create the public schema for shared tables
CREATE SCHEMA IF NOT EXISTS public;

-- Grant permissions
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO public;

-- Log completion
DO $$
BEGIN
    RAISE NOTICE 'Zumodra database initialized with extensions: postgis, pg_trgm, unaccent, uuid-ossp';
END $$;
