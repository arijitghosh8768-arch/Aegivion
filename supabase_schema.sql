-- Aegivion Real-Data Supabase Schema
-- Run this in your Supabase SQL Editor

CREATE TABLE IF NOT EXISTS cloud_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id VARCHAR NOT NULL,
    provider VARCHAR NOT NULL, -- 'aws', 'azure', 'gcp'
    provider_account_id VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    status VARCHAR DEFAULT 'CONNECTED',
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_success_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cloud_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id VARCHAR NOT NULL,
    cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider VARCHAR NOT NULL,
    provider_resource_id VARCHAR NOT NULL,
    resource_type VARCHAR NOT NULL, -- e.g., 'aws_ec2_instance'
    name VARCHAR,
    location VARCHAR,
    status VARCHAR,
    configuration JSONB DEFAULT '{}'::jsonb,
    tags JSONB DEFAULT '{}'::jsonb,
    relationships JSONB DEFAULT '[]'::jsonb,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version INTEGER DEFAULT 1,
    provider_metadata JSONB DEFAULT '{}'::jsonb,
    UNIQUE(organization_id, provider_resource_id)
);

CREATE TABLE IF NOT EXISTS asset_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID REFERENCES cloud_assets(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    configuration JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- RLS (Row Level Security) - Enforce organization isolation at the database level
ALTER TABLE cloud_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY isolate_org_accounts ON cloud_accounts
    FOR ALL
    USING (organization_id = current_setting('request.jwt.claims')::json->>'org_id');

ALTER TABLE cloud_assets ENABLE ROW LEVEL SECURITY;
CREATE POLICY isolate_org_assets ON cloud_assets
    FOR ALL
    USING (organization_id = current_setting('request.jwt.claims')::json->>'org_id');
