-- Supabase PostgreSQL Schema for AI Cyber Attack System

-- 1. Sites Table (Tenants)
CREATE TABLE IF NOT EXISTS sites (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    url         TEXT NOT NULL,
    api_key     TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- 2. Attack Log Table
CREATE TABLE IF NOT EXISTS attack_log (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip          TEXT NOT NULL,
    attack      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()),
    site_id     TEXT DEFAULT 'local',
    user_agent  TEXT,
    method      TEXT,
    path        TEXT,
    referer     TEXT,
    country     TEXT,
    city        TEXT,
    asn         TEXT,
    bytes_in    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_log_ip ON attack_log(ip);
CREATE INDEX IF NOT EXISTS idx_log_severity ON attack_log(severity);
CREATE INDEX IF NOT EXISTS idx_log_site ON attack_log(site_id);

-- 3. Blocked IPs Table (Legacy / Global)
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip          TEXT PRIMARY KEY,
    reason      TEXT NOT NULL DEFAULT 'auto',
    block_type  TEXT NOT NULL DEFAULT 'permanent',
    expires_at  DOUBLE PRECISION,
    blocked_at  TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- 4. Site-Specific Blocked IPs
CREATE TABLE IF NOT EXISTS site_blocked_ips (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip          TEXT NOT NULL,
    site_id     TEXT NOT NULL DEFAULT 'local',
    reason      TEXT NOT NULL DEFAULT 'auto',
    block_type  TEXT NOT NULL DEFAULT 'permanent',
    expires_at  DOUBLE PRECISION,
    blocked_at  TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()),
    UNIQUE(ip, site_id)
);
CREATE INDEX IF NOT EXISTS idx_site_block_site ON site_blocked_ips(site_id);
CREATE INDEX IF NOT EXISTS idx_site_block_ip ON site_blocked_ips(ip);

-- 5. Attack History
CREATE TABLE IF NOT EXISTS attack_history (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip          TEXT NOT NULL,
    attack      TEXT NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()),
    site_id     TEXT DEFAULT 'local'
);
CREATE INDEX IF NOT EXISTS idx_history_ip ON attack_history(ip);

-- 6. Failed Attempts
CREATE TABLE IF NOT EXISTS failed_attempts (
    ip          TEXT PRIMARY KEY,
    count       INTEGER NOT NULL DEFAULT 0,
    last_attempt TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- 7. Users Table
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    role          TEXT NOT NULL DEFAULT 'analyst',
    site_id       TEXT REFERENCES sites(id) ON DELETE SET NULL,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Note: We are not enforcing RLS because the backend is used dynamically with service role or secure secrets.
