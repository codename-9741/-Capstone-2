--
-- PostgreSQL database dump
--

\restrict 8ErSWEMpzRPKWidBGIRgI26RlYBh7pKKPaqAlKBRyf4EcY9P39Ghq4kD8wxlFcb

-- Dumped from database version 14.20 (Ubuntu 14.20-0ubuntu0.22.04.1)
-- Dumped by pg_dump version 14.20 (Ubuntu 14.20-0ubuntu0.22.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: btree_gin; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS btree_gin WITH SCHEMA public;


--
-- Name: EXTENSION btree_gin; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION btree_gin IS 'support for indexing common datatypes in GIN';


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: update_updated_at(); Type: FUNCTION; Schema: public; Owner: nightfall
--

CREATE FUNCTION public.update_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_updated_at() OWNER TO nightfall;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: api_calls; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.api_calls (
    id integer NOT NULL,
    api_key_id integer,
    endpoint character varying(255) NOT NULL,
    method character varying(10) NOT NULL,
    status_code integer,
    response_time integer,
    request_body jsonb,
    response_body jsonb,
    ip_address character varying(50),
    user_agent text,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.api_calls OWNER TO nightfall;

--
-- Name: api_calls_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.api_calls_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.api_calls_id_seq OWNER TO nightfall;

--
-- Name: api_calls_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.api_calls_id_seq OWNED BY public.api_calls.id;


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.api_keys (
    id integer NOT NULL,
    user_id integer,
    key_hash character varying(255) NOT NULL,
    name character varying(255),
    permissions jsonb DEFAULT '{}'::jsonb,
    last_used timestamp without time zone,
    expires_at timestamp without time zone,
    is_active boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.api_keys OWNER TO nightfall;

--
-- Name: api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.api_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.api_keys_id_seq OWNER TO nightfall;

--
-- Name: api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.api_keys_id_seq OWNED BY public.api_keys.id;


--
-- Name: asset_history; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.asset_history (
    id integer NOT NULL,
    asset_id integer,
    change_type character varying(50) NOT NULL,
    old_value jsonb,
    new_value jsonb,
    changed_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.asset_history OWNER TO nightfall;

--
-- Name: asset_history_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.asset_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.asset_history_id_seq OWNER TO nightfall;

--
-- Name: asset_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.asset_history_id_seq OWNED BY public.asset_history.id;


--
-- Name: assets; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.assets (
    id integer NOT NULL,
    target_id integer,
    asset_type character varying(50) NOT NULL,
    value text NOT NULL,
    status character varying(50) DEFAULT 'active'::character varying,
    confidence character varying(50) DEFAULT 'high'::character varying,
    source character varying(100),
    metadata jsonb DEFAULT '{}'::jsonb,
    discovered_at timestamp without time zone DEFAULT now(),
    last_seen timestamp without time zone DEFAULT now(),
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.assets OWNER TO nightfall;

--
-- Name: assets_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.assets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.assets_id_seq OWNER TO nightfall;

--
-- Name: assets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.assets_id_seq OWNED BY public.assets.id;


--
-- Name: attack_paths; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.attack_paths (
    id integer NOT NULL,
    target_id integer,
    scan_id integer,
    path_name character varying(255) NOT NULL,
    entry_point text NOT NULL,
    steps jsonb NOT NULL,
    impact text NOT NULL,
    likelihood character varying(50),
    risk_score integer,
    findings_involved integer[] DEFAULT '{}'::integer[],
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.attack_paths OWNER TO nightfall;

--
-- Name: attack_paths_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.attack_paths_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.attack_paths_id_seq OWNER TO nightfall;

--
-- Name: attack_paths_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.attack_paths_id_seq OWNED BY public.attack_paths.id;


--
-- Name: attack_scenarios; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.attack_scenarios (
    id integer NOT NULL,
    target_id integer,
    scenario_name character varying(255) NOT NULL,
    description text,
    attacker_profile character varying(100),
    required_skills character varying(50),
    required_resources character varying(50),
    attack_vector character varying(100),
    impact_confidentiality character varying(50),
    impact_integrity character varying(50),
    impact_availability character varying(50),
    overall_risk character varying(50),
    mitigation_steps text[] DEFAULT '{}'::text[],
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.attack_scenarios OWNER TO nightfall;

--
-- Name: attack_scenarios_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.attack_scenarios_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.attack_scenarios_id_seq OWNER TO nightfall;

--
-- Name: attack_scenarios_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.attack_scenarios_id_seq OWNED BY public.attack_scenarios.id;


--
-- Name: attack_techniques; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.attack_techniques (
    id integer NOT NULL,
    technique_id character varying(20) NOT NULL,
    technique_name character varying(255) NOT NULL,
    description text,
    platforms text[] DEFAULT '{}'::text[],
    required_permissions text[] DEFAULT '{}'::text[],
    data_sources text[] DEFAULT '{}'::text[],
    detection_methods text[] DEFAULT '{}'::text[],
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.attack_techniques OWNER TO nightfall;

--
-- Name: attack_techniques_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.attack_techniques_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.attack_techniques_id_seq OWNER TO nightfall;

--
-- Name: attack_techniques_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.attack_techniques_id_seq OWNED BY public.attack_techniques.id;


--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.audit_logs (
    id integer NOT NULL,
    user_id integer,
    action character varying(100) NOT NULL,
    resource_type character varying(100),
    resource_id integer,
    changes jsonb,
    ip_address character varying(50),
    user_agent text,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.audit_logs OWNER TO nightfall;

--
-- Name: audit_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.audit_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.audit_logs_id_seq OWNER TO nightfall;

--
-- Name: audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.audit_logs_id_seq OWNED BY public.audit_logs.id;


--
-- Name: benchmarks; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.benchmarks (
    id integer NOT NULL,
    industry character varying(100) NOT NULL,
    metric_name character varying(100) NOT NULL,
    average_value numeric(10,2),
    median_value numeric(10,2),
    percentile_75 numeric(10,2),
    percentile_90 numeric(10,2),
    sample_size integer,
    period character varying(50),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.benchmarks OWNER TO nightfall;

--
-- Name: benchmarks_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.benchmarks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.benchmarks_id_seq OWNER TO nightfall;

--
-- Name: benchmarks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.benchmarks_id_seq OWNED BY public.benchmarks.id;


--
-- Name: breaches; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.breaches (
    id integer NOT NULL,
    target_id integer,
    breach_name character varying(255) NOT NULL,
    breach_date timestamp without time zone,
    compromised_accounts integer,
    compromised_data text[] DEFAULT '{}'::text[],
    source character varying(100),
    discovered_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.breaches OWNER TO nightfall;

--
-- Name: breaches_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.breaches_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.breaches_id_seq OWNER TO nightfall;

--
-- Name: breaches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.breaches_id_seq OWNED BY public.breaches.id;


--
-- Name: cis_mappings; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.cis_mappings (
    id integer NOT NULL,
    finding_id integer,
    control_id character varying(20) NOT NULL,
    control_name character varying(255) NOT NULL,
    control_version character varying(20) DEFAULT 'v8'::character varying,
    implementation_group integer,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.cis_mappings OWNER TO nightfall;

--
-- Name: cis_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.cis_mappings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.cis_mappings_id_seq OWNER TO nightfall;

--
-- Name: cis_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.cis_mappings_id_seq OWNED BY public.cis_mappings.id;


--
-- Name: cloud_resources; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.cloud_resources (
    id integer NOT NULL,
    target_id integer,
    provider character varying(50) NOT NULL,
    resource_type character varying(100) NOT NULL,
    resource_name text NOT NULL,
    is_public boolean DEFAULT false,
    url text,
    discovered_at timestamp without time zone DEFAULT now(),
    last_checked timestamp without time zone DEFAULT now(),
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.cloud_resources OWNER TO nightfall;

--
-- Name: cloud_resources_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.cloud_resources_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.cloud_resources_id_seq OWNER TO nightfall;

--
-- Name: cloud_resources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.cloud_resources_id_seq OWNED BY public.cloud_resources.id;


--
-- Name: code_repositories; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.code_repositories (
    id integer NOT NULL,
    target_id integer,
    platform character varying(50) NOT NULL,
    repository_url text NOT NULL,
    repository_name character varying(255),
    is_public boolean DEFAULT true,
    stars integer,
    forks integer,
    last_commit timestamp without time zone,
    discovered_at timestamp without time zone DEFAULT now(),
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.code_repositories OWNER TO nightfall;

--
-- Name: code_repositories_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.code_repositories_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.code_repositories_id_seq OWNER TO nightfall;

--
-- Name: code_repositories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.code_repositories_id_seq OWNED BY public.code_repositories.id;


--
-- Name: dashboards; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.dashboards (
    id integer NOT NULL,
    user_id integer,
    name character varying(255) NOT NULL,
    layout jsonb NOT NULL,
    is_default boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.dashboards OWNER TO nightfall;

--
-- Name: dashboards_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.dashboards_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.dashboards_id_seq OWNER TO nightfall;

--
-- Name: dashboards_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.dashboards_id_seq OWNED BY public.dashboards.id;


--
-- Name: dns_records; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.dns_records (
    id integer NOT NULL,
    target_id integer,
    record_type character varying(20) NOT NULL,
    name character varying(255) NOT NULL,
    value text NOT NULL,
    ttl integer,
    discovered_at timestamp without time zone DEFAULT now(),
    last_seen timestamp without time zone DEFAULT now()
);


ALTER TABLE public.dns_records OWNER TO nightfall;

--
-- Name: dns_records_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.dns_records_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.dns_records_id_seq OWNER TO nightfall;

--
-- Name: dns_records_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.dns_records_id_seq OWNED BY public.dns_records.id;


--
-- Name: false_positives; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.false_positives (
    id integer NOT NULL,
    finding_id integer,
    user_id integer,
    reason text NOT NULL,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.false_positives OWNER TO nightfall;

--
-- Name: false_positives_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.false_positives_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.false_positives_id_seq OWNER TO nightfall;

--
-- Name: false_positives_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.false_positives_id_seq OWNED BY public.false_positives.id;


--
-- Name: finding_comments; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.finding_comments (
    id integer NOT NULL,
    finding_id integer,
    user_id integer,
    comment_text text NOT NULL,
    is_internal boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.finding_comments OWNER TO nightfall;

--
-- Name: finding_comments_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.finding_comments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.finding_comments_id_seq OWNER TO nightfall;

--
-- Name: finding_comments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.finding_comments_id_seq OWNED BY public.finding_comments.id;


--
-- Name: finding_history; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.finding_history (
    id integer NOT NULL,
    finding_id integer,
    user_id integer,
    field_name character varying(100) NOT NULL,
    old_value text,
    new_value text,
    changed_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.finding_history OWNER TO nightfall;

--
-- Name: finding_history_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.finding_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.finding_history_id_seq OWNER TO nightfall;

--
-- Name: finding_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.finding_history_id_seq OWNED BY public.finding_history.id;


--
-- Name: findings; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.findings (
    id integer NOT NULL,
    scan_id integer NOT NULL,
    severity character varying(50) NOT NULL,
    category character varying(100) NOT NULL,
    confidence character varying(50) NOT NULL,
    finding text NOT NULL,
    remediation text,
    evidence text,
    http_method character varying(20),
    outcome character varying(100),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.findings OWNER TO nightfall;

--
-- Name: findings_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.findings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.findings_id_seq OWNER TO nightfall;

--
-- Name: findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.findings_id_seq OWNED BY public.findings.id;


--
-- Name: impact_assessments; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.impact_assessments (
    id integer NOT NULL,
    finding_id integer,
    business_impact text,
    technical_impact text,
    financial_impact text,
    regulatory_impact text,
    reputation_impact text,
    likelihood_score integer,
    impact_score integer,
    overall_risk_score integer,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.impact_assessments OWNER TO nightfall;

--
-- Name: impact_assessments_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.impact_assessments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.impact_assessments_id_seq OWNER TO nightfall;

--
-- Name: impact_assessments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.impact_assessments_id_seq OWNED BY public.impact_assessments.id;


--
-- Name: integrations; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.integrations (
    id integer NOT NULL,
    user_id integer,
    organization_id integer,
    integration_type character varying(50) NOT NULL,
    name character varying(255) NOT NULL,
    config jsonb NOT NULL,
    is_active boolean DEFAULT true,
    last_used timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.integrations OWNER TO nightfall;

--
-- Name: integrations_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.integrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.integrations_id_seq OWNER TO nightfall;

--
-- Name: integrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.integrations_id_seq OWNED BY public.integrations.id;


--
-- Name: iso_mappings; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.iso_mappings (
    id integer NOT NULL,
    finding_id integer,
    control_id character varying(20) NOT NULL,
    control_name character varying(255) NOT NULL,
    standard character varying(50) DEFAULT '27001:2022'::character varying,
    annex character varying(10),
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.iso_mappings OWNER TO nightfall;

--
-- Name: iso_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.iso_mappings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.iso_mappings_id_seq OWNER TO nightfall;

--
-- Name: iso_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.iso_mappings_id_seq OWNED BY public.iso_mappings.id;


--
-- Name: kill_chain_phases; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.kill_chain_phases (
    id integer NOT NULL,
    finding_id integer,
    phase character varying(100) NOT NULL,
    phase_order integer,
    description text,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.kill_chain_phases OWNER TO nightfall;

--
-- Name: kill_chain_phases_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.kill_chain_phases_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.kill_chain_phases_id_seq OWNER TO nightfall;

--
-- Name: kill_chain_phases_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.kill_chain_phases_id_seq OWNED BY public.kill_chain_phases.id;


--
-- Name: metrics; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.metrics (
    id integer NOT NULL,
    metric_name character varying(100) NOT NULL,
    metric_value numeric(10,2) NOT NULL,
    metric_type character varying(50),
    target_id integer,
    scan_id integer,
    "timestamp" timestamp without time zone DEFAULT now(),
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.metrics OWNER TO nightfall;

--
-- Name: metrics_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.metrics_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.metrics_id_seq OWNER TO nightfall;

--
-- Name: metrics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.metrics_id_seq OWNED BY public.metrics.id;


--
-- Name: mitre_mappings; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.mitre_mappings (
    id integer NOT NULL,
    finding_id integer,
    technique_id character varying(20) NOT NULL,
    technique_name character varying(255) NOT NULL,
    tactic character varying(100),
    sub_technique_id character varying(20),
    confidence character varying(50) DEFAULT 'medium'::character varying,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.mitre_mappings OWNER TO nightfall;

--
-- Name: mitre_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.mitre_mappings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.mitre_mappings_id_seq OWNER TO nightfall;

--
-- Name: mitre_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.mitre_mappings_id_seq OWNED BY public.mitre_mappings.id;


--
-- Name: nist_mappings; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.nist_mappings (
    id integer NOT NULL,
    finding_id integer,
    control_family character varying(10) NOT NULL,
    control_id character varying(20) NOT NULL,
    control_name character varying(255) NOT NULL,
    framework character varying(50) DEFAULT '800-53'::character varying,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.nist_mappings OWNER TO nightfall;

--
-- Name: nist_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.nist_mappings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.nist_mappings_id_seq OWNER TO nightfall;

--
-- Name: nist_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.nist_mappings_id_seq OWNED BY public.nist_mappings.id;


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.notifications (
    id integer NOT NULL,
    user_id integer,
    notification_type character varying(50) NOT NULL,
    title character varying(255) NOT NULL,
    message text NOT NULL,
    severity character varying(50) DEFAULT 'info'::character varying,
    is_read boolean DEFAULT false,
    related_resource_type character varying(50),
    related_resource_id integer,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.notifications OWNER TO nightfall;

--
-- Name: notifications_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.notifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.notifications_id_seq OWNER TO nightfall;

--
-- Name: notifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.notifications_id_seq OWNED BY public.notifications.id;


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.organizations (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    domain character varying(255),
    subscription_tier character varying(50) DEFAULT 'free'::character varying,
    max_scans_per_month integer DEFAULT 10,
    max_users integer DEFAULT 5,
    settings jsonb DEFAULT '{}'::jsonb,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.organizations OWNER TO nightfall;

--
-- Name: organizations_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.organizations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.organizations_id_seq OWNER TO nightfall;

--
-- Name: organizations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.organizations_id_seq OWNED BY public.organizations.id;


--
-- Name: owasp_mappings; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.owasp_mappings (
    id integer NOT NULL,
    finding_id integer,
    owasp_id character varying(10) NOT NULL,
    owasp_category character varying(255) NOT NULL,
    owasp_year integer DEFAULT 2021,
    confidence character varying(50) DEFAULT 'high'::character varying,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.owasp_mappings OWNER TO nightfall;

--
-- Name: owasp_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.owasp_mappings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.owasp_mappings_id_seq OWNER TO nightfall;

--
-- Name: owasp_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.owasp_mappings_id_seq OWNED BY public.owasp_mappings.id;


--
-- Name: passive_intelligence; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.passive_intelligence (
    id integer NOT NULL,
    domain character varying(255) NOT NULL,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    duration_seconds double precision,
    modules_executed integer,
    modules_succeeded integer,
    modules_failed integer,
    dns_records jsonb,
    nameservers text[],
    mail_servers text[],
    dns_security jsonb,
    ssl_certificates jsonb,
    ip_addresses jsonb,
    s3_buckets jsonb,
    gcp_resources jsonb,
    azure_resources jsonb,
    tech_stack jsonb,
    social_profiles jsonb,
    raw_data jsonb,
    data_sources text[],
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.passive_intelligence OWNER TO nightfall;

--
-- Name: passive_intelligence_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.passive_intelligence_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.passive_intelligence_id_seq OWNER TO nightfall;

--
-- Name: passive_intelligence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.passive_intelligence_id_seq OWNED BY public.passive_intelligence.id;


--
-- Name: pci_dss_mappings; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.pci_dss_mappings (
    id integer NOT NULL,
    finding_id integer,
    requirement_id character varying(20) NOT NULL,
    requirement_name character varying(255) NOT NULL,
    version character varying(20) DEFAULT '4.0'::character varying,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.pci_dss_mappings OWNER TO nightfall;

--
-- Name: pci_dss_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.pci_dss_mappings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.pci_dss_mappings_id_seq OWNER TO nightfall;

--
-- Name: pci_dss_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.pci_dss_mappings_id_seq OWNED BY public.pci_dss_mappings.id;


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.permissions (
    id integer NOT NULL,
    role_id integer,
    resource character varying(100) NOT NULL,
    action character varying(50) NOT NULL,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.permissions OWNER TO nightfall;

--
-- Name: permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.permissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.permissions_id_seq OWNER TO nightfall;

--
-- Name: permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.permissions_id_seq OWNED BY public.permissions.id;


--
-- Name: report_templates; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.report_templates (
    id integer NOT NULL,
    user_id integer,
    name character varying(255) NOT NULL,
    description text,
    template_type character varying(50) NOT NULL,
    content text NOT NULL,
    variables jsonb DEFAULT '{}'::jsonb,
    is_default boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.report_templates OWNER TO nightfall;

--
-- Name: report_templates_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.report_templates_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.report_templates_id_seq OWNER TO nightfall;

--
-- Name: report_templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.report_templates_id_seq OWNED BY public.report_templates.id;


--
-- Name: reports; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.reports (
    id integer NOT NULL,
    user_id integer,
    scan_id integer,
    report_type character varying(50) NOT NULL,
    format character varying(20) NOT NULL,
    title character varying(255) NOT NULL,
    generated_at timestamp without time zone DEFAULT now(),
    file_path text,
    file_size integer,
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.reports OWNER TO nightfall;

--
-- Name: reports_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.reports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.reports_id_seq OWNER TO nightfall;

--
-- Name: reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.reports_id_seq OWNED BY public.reports.id;


--
-- Name: roles; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.roles (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    permissions jsonb DEFAULT '{}'::jsonb,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.roles OWNER TO nightfall;

--
-- Name: roles_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.roles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.roles_id_seq OWNER TO nightfall;

--
-- Name: roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.roles_id_seq OWNED BY public.roles.id;


--
-- Name: scan_phases; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.scan_phases (
    id integer NOT NULL,
    scan_id integer,
    phase_name character varying(100) NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying,
    progress integer DEFAULT 0,
    module_count integer DEFAULT 0,
    completed_modules integer DEFAULT 0,
    findings_count integer DEFAULT 0,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    duration_seconds integer,
    error_message text,
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.scan_phases OWNER TO nightfall;

--
-- Name: scan_phases_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.scan_phases_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.scan_phases_id_seq OWNER TO nightfall;

--
-- Name: scan_phases_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.scan_phases_id_seq OWNED BY public.scan_phases.id;


--
-- Name: scans; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.scans (
    id integer NOT NULL,
    target_id integer NOT NULL,
    status character varying(50) DEFAULT 'running'::character varying NOT NULL,
    risk_score integer DEFAULT 0,
    risk_grade character varying(50) DEFAULT 'LOW'::character varying,
    started_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp without time zone,
    config jsonb,
    duration_seconds numeric(10,2),
    config_mode character varying(50) DEFAULT 'normal'::character varying,
    config_stealth_enabled boolean DEFAULT true,
    config_respect_robots_txt boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.scans OWNER TO nightfall;

--
-- Name: scans_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.scans_id_seq OWNER TO nightfall;

--
-- Name: scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.scans_id_seq OWNED BY public.scans.id;


--
-- Name: scheduled_scans; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.scheduled_scans (
    id integer NOT NULL,
    user_id integer,
    target_id integer,
    schedule_name character varying(255) NOT NULL,
    cron_expression character varying(100) NOT NULL,
    scan_config jsonb DEFAULT '{}'::jsonb,
    is_active boolean DEFAULT true,
    last_run timestamp without time zone,
    next_run timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.scheduled_scans OWNER TO nightfall;

--
-- Name: scheduled_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.scheduled_scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.scheduled_scans_id_seq OWNER TO nightfall;

--
-- Name: scheduled_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.scheduled_scans_id_seq OWNED BY public.scheduled_scans.id;


--
-- Name: secrets; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.secrets (
    id integer NOT NULL,
    target_id integer,
    secret_type character varying(100) NOT NULL,
    pattern_matched character varying(255),
    location text,
    masked_value text,
    is_verified boolean DEFAULT false,
    severity character varying(50) DEFAULT 'High'::character varying,
    discovered_at timestamp without time zone DEFAULT now(),
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.secrets OWNER TO nightfall;

--
-- Name: secrets_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.secrets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.secrets_id_seq OWNER TO nightfall;

--
-- Name: secrets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.secrets_id_seq OWNED BY public.secrets.id;


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.sessions (
    id integer NOT NULL,
    user_id integer,
    token_hash character varying(255) NOT NULL,
    ip_address character varying(50),
    user_agent text,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.sessions OWNER TO nightfall;

--
-- Name: sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.sessions_id_seq OWNER TO nightfall;

--
-- Name: sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.sessions_id_seq OWNED BY public.sessions.id;


--
-- Name: ssl_certificates; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.ssl_certificates (
    id integer NOT NULL,
    target_id integer,
    common_name character varying(255),
    subject_alt_names text[] DEFAULT '{}'::text[],
    issuer character varying(255),
    serial_number character varying(255),
    not_before timestamp without time zone,
    not_after timestamp without time zone,
    signature_algorithm character varying(100),
    key_size integer,
    is_expired boolean DEFAULT false,
    is_self_signed boolean DEFAULT false,
    certificate_pem text,
    discovered_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.ssl_certificates OWNER TO nightfall;

--
-- Name: ssl_certificates_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.ssl_certificates_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.ssl_certificates_id_seq OWNER TO nightfall;

--
-- Name: ssl_certificates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.ssl_certificates_id_seq OWNED BY public.ssl_certificates.id;


--
-- Name: subdomains; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.subdomains (
    id integer NOT NULL,
    target_id integer,
    subdomain character varying(255) NOT NULL,
    ip_address character varying(50),
    status character varying(50) DEFAULT 'active'::character varying,
    source character varying(100),
    technologies text[] DEFAULT '{}'::text[],
    http_status integer,
    title text,
    discovered_at timestamp without time zone DEFAULT now(),
    last_checked timestamp without time zone DEFAULT now(),
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.subdomains OWNER TO nightfall;

--
-- Name: subdomains_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.subdomains_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.subdomains_id_seq OWNER TO nightfall;

--
-- Name: subdomains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.subdomains_id_seq OWNED BY public.subdomains.id;


--
-- Name: target_groups; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.target_groups (
    id integer NOT NULL,
    user_id integer,
    name character varying(255) NOT NULL,
    description text,
    target_ids integer[] DEFAULT '{}'::integer[],
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.target_groups OWNER TO nightfall;

--
-- Name: target_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.target_groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.target_groups_id_seq OWNER TO nightfall;

--
-- Name: target_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.target_groups_id_seq OWNED BY public.target_groups.id;


--
-- Name: targets; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.targets (
    id integer NOT NULL,
    domain character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.targets OWNER TO nightfall;

--
-- Name: targets_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.targets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.targets_id_seq OWNER TO nightfall;

--
-- Name: targets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.targets_id_seq OWNED BY public.targets.id;


--
-- Name: technologies; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.technologies (
    id integer NOT NULL,
    target_id integer,
    name character varying(255) NOT NULL,
    version character varying(100),
    category character varying(100),
    confidence character varying(50) DEFAULT 'high'::character varying,
    source character varying(100),
    discovered_at timestamp without time zone DEFAULT now(),
    last_seen timestamp without time zone DEFAULT now(),
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.technologies OWNER TO nightfall;

--
-- Name: technologies_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.technologies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.technologies_id_seq OWNER TO nightfall;

--
-- Name: technologies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.technologies_id_seq OWNED BY public.technologies.id;


--
-- Name: threat_indicators; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.threat_indicators (
    id integer NOT NULL,
    target_id integer,
    indicator_type character varying(50) NOT NULL,
    indicator_value text NOT NULL,
    threat_type character varying(100),
    confidence character varying(50) DEFAULT 'medium'::character varying,
    source character varying(100),
    first_seen timestamp without time zone,
    last_seen timestamp without time zone,
    metadata jsonb DEFAULT '{}'::jsonb
);


ALTER TABLE public.threat_indicators OWNER TO nightfall;

--
-- Name: threat_indicators_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.threat_indicators_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.threat_indicators_id_seq OWNER TO nightfall;

--
-- Name: threat_indicators_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.threat_indicators_id_seq OWNED BY public.threat_indicators.id;


--
-- Name: trends; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.trends (
    id integer NOT NULL,
    target_id integer,
    metric_name character varying(100) NOT NULL,
    time_period character varying(50) NOT NULL,
    data_points jsonb NOT NULL,
    calculated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.trends OWNER TO nightfall;

--
-- Name: trends_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.trends_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.trends_id_seq OWNER TO nightfall;

--
-- Name: trends_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.trends_id_seq OWNED BY public.trends.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.users (
    id integer NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    full_name character varying(255) NOT NULL,
    role character varying(50) DEFAULT 'analyst'::character varying NOT NULL,
    organization_id integer,
    is_active boolean DEFAULT true,
    last_login timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.users OWNER TO nightfall;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_id_seq OWNER TO nightfall;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: webhooks; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.webhooks (
    id integer NOT NULL,
    user_id integer,
    url text NOT NULL,
    event_types text[] DEFAULT '{}'::text[],
    secret_key character varying(255),
    is_active boolean DEFAULT true,
    last_triggered timestamp without time zone,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.webhooks OWNER TO nightfall;

--
-- Name: webhooks_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.webhooks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.webhooks_id_seq OWNER TO nightfall;

--
-- Name: webhooks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.webhooks_id_seq OWNED BY public.webhooks.id;


--
-- Name: whois_records; Type: TABLE; Schema: public; Owner: nightfall
--

CREATE TABLE public.whois_records (
    id integer NOT NULL,
    target_id integer,
    registrar character varying(255),
    registered_date timestamp without time zone,
    expiration_date timestamp without time zone,
    updated_date timestamp without time zone,
    name_servers text[] DEFAULT '{}'::text[],
    registrant_name character varying(255),
    registrant_email character varying(255),
    registrant_organization character varying(255),
    admin_email character varying(255),
    tech_email character varying(255),
    status text[] DEFAULT '{}'::text[],
    raw_data text,
    discovered_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.whois_records OWNER TO nightfall;

--
-- Name: whois_records_id_seq; Type: SEQUENCE; Schema: public; Owner: nightfall
--

CREATE SEQUENCE public.whois_records_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.whois_records_id_seq OWNER TO nightfall;

--
-- Name: whois_records_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: nightfall
--

ALTER SEQUENCE public.whois_records_id_seq OWNED BY public.whois_records.id;


--
-- Name: api_calls id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.api_calls ALTER COLUMN id SET DEFAULT nextval('public.api_calls_id_seq'::regclass);


--
-- Name: api_keys id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.api_keys ALTER COLUMN id SET DEFAULT nextval('public.api_keys_id_seq'::regclass);


--
-- Name: asset_history id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.asset_history ALTER COLUMN id SET DEFAULT nextval('public.asset_history_id_seq'::regclass);


--
-- Name: assets id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.assets ALTER COLUMN id SET DEFAULT nextval('public.assets_id_seq'::regclass);


--
-- Name: attack_paths id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_paths ALTER COLUMN id SET DEFAULT nextval('public.attack_paths_id_seq'::regclass);


--
-- Name: attack_scenarios id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_scenarios ALTER COLUMN id SET DEFAULT nextval('public.attack_scenarios_id_seq'::regclass);


--
-- Name: attack_techniques id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_techniques ALTER COLUMN id SET DEFAULT nextval('public.attack_techniques_id_seq'::regclass);


--
-- Name: audit_logs id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.audit_logs ALTER COLUMN id SET DEFAULT nextval('public.audit_logs_id_seq'::regclass);


--
-- Name: benchmarks id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.benchmarks ALTER COLUMN id SET DEFAULT nextval('public.benchmarks_id_seq'::regclass);


--
-- Name: breaches id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.breaches ALTER COLUMN id SET DEFAULT nextval('public.breaches_id_seq'::regclass);


--
-- Name: cis_mappings id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.cis_mappings ALTER COLUMN id SET DEFAULT nextval('public.cis_mappings_id_seq'::regclass);


--
-- Name: cloud_resources id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.cloud_resources ALTER COLUMN id SET DEFAULT nextval('public.cloud_resources_id_seq'::regclass);


--
-- Name: code_repositories id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.code_repositories ALTER COLUMN id SET DEFAULT nextval('public.code_repositories_id_seq'::regclass);


--
-- Name: dashboards id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.dashboards ALTER COLUMN id SET DEFAULT nextval('public.dashboards_id_seq'::regclass);


--
-- Name: dns_records id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.dns_records ALTER COLUMN id SET DEFAULT nextval('public.dns_records_id_seq'::regclass);


--
-- Name: false_positives id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.false_positives ALTER COLUMN id SET DEFAULT nextval('public.false_positives_id_seq'::regclass);


--
-- Name: finding_comments id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.finding_comments ALTER COLUMN id SET DEFAULT nextval('public.finding_comments_id_seq'::regclass);


--
-- Name: finding_history id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.finding_history ALTER COLUMN id SET DEFAULT nextval('public.finding_history_id_seq'::regclass);


--
-- Name: findings id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.findings ALTER COLUMN id SET DEFAULT nextval('public.findings_id_seq'::regclass);


--
-- Name: impact_assessments id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.impact_assessments ALTER COLUMN id SET DEFAULT nextval('public.impact_assessments_id_seq'::regclass);


--
-- Name: integrations id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.integrations ALTER COLUMN id SET DEFAULT nextval('public.integrations_id_seq'::regclass);


--
-- Name: iso_mappings id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.iso_mappings ALTER COLUMN id SET DEFAULT nextval('public.iso_mappings_id_seq'::regclass);


--
-- Name: kill_chain_phases id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.kill_chain_phases ALTER COLUMN id SET DEFAULT nextval('public.kill_chain_phases_id_seq'::regclass);


--
-- Name: metrics id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.metrics ALTER COLUMN id SET DEFAULT nextval('public.metrics_id_seq'::regclass);


--
-- Name: mitre_mappings id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.mitre_mappings ALTER COLUMN id SET DEFAULT nextval('public.mitre_mappings_id_seq'::regclass);


--
-- Name: nist_mappings id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.nist_mappings ALTER COLUMN id SET DEFAULT nextval('public.nist_mappings_id_seq'::regclass);


--
-- Name: notifications id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.notifications ALTER COLUMN id SET DEFAULT nextval('public.notifications_id_seq'::regclass);


--
-- Name: organizations id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.organizations ALTER COLUMN id SET DEFAULT nextval('public.organizations_id_seq'::regclass);


--
-- Name: owasp_mappings id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.owasp_mappings ALTER COLUMN id SET DEFAULT nextval('public.owasp_mappings_id_seq'::regclass);


--
-- Name: passive_intelligence id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.passive_intelligence ALTER COLUMN id SET DEFAULT nextval('public.passive_intelligence_id_seq'::regclass);


--
-- Name: pci_dss_mappings id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.pci_dss_mappings ALTER COLUMN id SET DEFAULT nextval('public.pci_dss_mappings_id_seq'::regclass);


--
-- Name: permissions id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.permissions ALTER COLUMN id SET DEFAULT nextval('public.permissions_id_seq'::regclass);


--
-- Name: report_templates id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.report_templates ALTER COLUMN id SET DEFAULT nextval('public.report_templates_id_seq'::regclass);


--
-- Name: reports id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.reports ALTER COLUMN id SET DEFAULT nextval('public.reports_id_seq'::regclass);


--
-- Name: roles id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.roles ALTER COLUMN id SET DEFAULT nextval('public.roles_id_seq'::regclass);


--
-- Name: scan_phases id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scan_phases ALTER COLUMN id SET DEFAULT nextval('public.scan_phases_id_seq'::regclass);


--
-- Name: scans id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scans ALTER COLUMN id SET DEFAULT nextval('public.scans_id_seq'::regclass);


--
-- Name: scheduled_scans id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scheduled_scans ALTER COLUMN id SET DEFAULT nextval('public.scheduled_scans_id_seq'::regclass);


--
-- Name: secrets id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.secrets ALTER COLUMN id SET DEFAULT nextval('public.secrets_id_seq'::regclass);


--
-- Name: sessions id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.sessions ALTER COLUMN id SET DEFAULT nextval('public.sessions_id_seq'::regclass);


--
-- Name: ssl_certificates id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.ssl_certificates ALTER COLUMN id SET DEFAULT nextval('public.ssl_certificates_id_seq'::regclass);


--
-- Name: subdomains id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.subdomains ALTER COLUMN id SET DEFAULT nextval('public.subdomains_id_seq'::regclass);


--
-- Name: target_groups id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.target_groups ALTER COLUMN id SET DEFAULT nextval('public.target_groups_id_seq'::regclass);


--
-- Name: targets id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.targets ALTER COLUMN id SET DEFAULT nextval('public.targets_id_seq'::regclass);


--
-- Name: technologies id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.technologies ALTER COLUMN id SET DEFAULT nextval('public.technologies_id_seq'::regclass);


--
-- Name: threat_indicators id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.threat_indicators ALTER COLUMN id SET DEFAULT nextval('public.threat_indicators_id_seq'::regclass);


--
-- Name: trends id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.trends ALTER COLUMN id SET DEFAULT nextval('public.trends_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: webhooks id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.webhooks ALTER COLUMN id SET DEFAULT nextval('public.webhooks_id_seq'::regclass);


--
-- Name: whois_records id; Type: DEFAULT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.whois_records ALTER COLUMN id SET DEFAULT nextval('public.whois_records_id_seq'::regclass);


--
-- Data for Name: api_calls; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.api_calls (id, api_key_id, endpoint, method, status_code, response_time, request_body, response_body, ip_address, user_agent, created_at) FROM stdin;
\.


--
-- Data for Name: api_keys; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.api_keys (id, user_id, key_hash, name, permissions, last_used, expires_at, is_active, created_at) FROM stdin;
\.


--
-- Data for Name: asset_history; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.asset_history (id, asset_id, change_type, old_value, new_value, changed_at) FROM stdin;
\.


--
-- Data for Name: assets; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.assets (id, target_id, asset_type, value, status, confidence, source, metadata, discovered_at, last_seen, created_at) FROM stdin;
\.


--
-- Data for Name: attack_paths; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.attack_paths (id, target_id, scan_id, path_name, entry_point, steps, impact, likelihood, risk_score, findings_involved, created_at) FROM stdin;
\.


--
-- Data for Name: attack_scenarios; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.attack_scenarios (id, target_id, scenario_name, description, attacker_profile, required_skills, required_resources, attack_vector, impact_confidentiality, impact_integrity, impact_availability, overall_risk, mitigation_steps, created_at) FROM stdin;
\.


--
-- Data for Name: attack_techniques; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.attack_techniques (id, technique_id, technique_name, description, platforms, required_permissions, data_sources, detection_methods, metadata) FROM stdin;
\.


--
-- Data for Name: audit_logs; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.audit_logs (id, user_id, action, resource_type, resource_id, changes, ip_address, user_agent, created_at) FROM stdin;
\.


--
-- Data for Name: benchmarks; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.benchmarks (id, industry, metric_name, average_value, median_value, percentile_75, percentile_90, sample_size, period, updated_at) FROM stdin;
\.


--
-- Data for Name: breaches; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.breaches (id, target_id, breach_name, breach_date, compromised_accounts, compromised_data, source, discovered_at) FROM stdin;
\.


--
-- Data for Name: cis_mappings; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.cis_mappings (id, finding_id, control_id, control_name, control_version, implementation_group, created_at) FROM stdin;
\.


--
-- Data for Name: cloud_resources; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.cloud_resources (id, target_id, provider, resource_type, resource_name, is_public, url, discovered_at, last_checked, metadata) FROM stdin;
\.


--
-- Data for Name: code_repositories; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.code_repositories (id, target_id, platform, repository_url, repository_name, is_public, stars, forks, last_commit, discovered_at, metadata) FROM stdin;
\.


--
-- Data for Name: dashboards; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.dashboards (id, user_id, name, layout, is_default, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: dns_records; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.dns_records (id, target_id, record_type, name, value, ttl, discovered_at, last_seen) FROM stdin;
\.


--
-- Data for Name: false_positives; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.false_positives (id, finding_id, user_id, reason, created_at) FROM stdin;
\.


--
-- Data for Name: finding_comments; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.finding_comments (id, finding_id, user_id, comment_text, is_internal, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: finding_history; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.finding_history (id, finding_id, user_id, field_name, old_value, new_value, changed_at) FROM stdin;
\.


--
-- Data for Name: findings; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.findings (id, scan_id, severity, category, confidence, finding, remediation, evidence, http_method, outcome, created_at) FROM stdin;
1	1	Low	robots.txt	High	robots.txt accessible. Sensitive paths detected: admin	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-04 17:22:13.415738
2	1	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-04 17:22:13.418043
3	1	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-04 17:22:13.419552
4	1	Info	TLS	High	Certificate subject: *.terralogic.com	Verify certificate matches domain	Subject: *.terralogic.com | Issuer: Sectigo Public Server Authentication CA DV R36 | Valid: 2025-10-30 - 2026-11-30	TLS	Valid	2026-02-04 17:22:13.420565
5	1	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-04 17:22:13.421467
6	1	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-04 17:22:13.422328
7	1	Medium	Admin Panel	High	Admin panels discovered: [/admin /admin/login /admin/index.php /management]	Implement: strong authentication, IP whitelisting, rename default paths, enable rate limiting, use CAPTCHA	/admin, /admin/login, /admin/index.php, /management	GET	Accessible	2026-02-04 17:22:13.423201
8	1	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-04 17:22:13.423934
9	1	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-04 17:22:13.424814
10	1	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-04 17:22:13.425598
11	1	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-04 17:22:13.426329
12	1	Medium	CDN Bypass	Low	Potential origin server disclosure (CDN bypass risk)	Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs	Origin indicators detected	GET	Potential bypass	2026-02-04 17:22:13.427033
13	1	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-04 17:22:13.427867
14	1	Medium	Subresource Integrity	Medium	External resources loaded without Subresource Integrity (SRI)	Add integrity and crossorigin attributes to external scripts/stylesheets; generate SRI hashes	External resources without SRI detected	GET	Missing SRI	2026-02-04 17:22:13.428897
15	1	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-04 17:22:13.429844
16	2	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-04 17:32:28.067473
17	2	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-04 17:32:28.068954
18	2	Info	TLS	High	Certificate subject: example.com	Verify certificate matches domain	Subject: example.com | Issuer: Cloudflare TLS Issuing ECC CA 3 | Valid: 2025-12-16 - 2026-03-16	TLS	Valid	2026-02-04 17:32:28.069823
19	2	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-04 17:32:28.071023
20	2	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-04 17:32:28.071948
21	2	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-04 17:32:28.072721
22	2	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-04 17:32:28.073463
23	2	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-04 17:32:28.074182
24	2	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-04 17:32:28.07488
25	2	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-04 17:32:28.075587
26	2	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-04 17:32:28.076311
27	3	Low	robots.txt	High	robots.txt accessible. Sensitive paths detected: admin	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-04 17:34:00.883702
28	3	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-04 17:34:00.885105
29	3	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-04 17:34:00.886059
30	3	Info	TLS	High	Certificate subject: *.terralogic.com	Verify certificate matches domain	Subject: *.terralogic.com | Issuer: Sectigo Public Server Authentication CA DV R36 | Valid: 2025-10-30 - 2026-11-30	TLS	Valid	2026-02-04 17:34:00.886842
31	3	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-04 17:34:00.887844
32	3	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-04 17:34:00.888733
33	3	Medium	Admin Panel	High	Admin panels discovered: [/admin /admin/login /admin/index.php /management]	Implement: strong authentication, IP whitelisting, rename default paths, enable rate limiting, use CAPTCHA	/admin, /admin/login, /admin/index.php, /management	GET	Accessible	2026-02-04 17:34:00.889543
34	3	Medium	CSRF	Medium	Forms detected without obvious CSRF tokens	Implement CSRF tokens on all state-changing operations; validate Origin/Referer headers; use SameSite cookies	Forms present, no CSRF token patterns found	GET	No CSRF protection detected	2026-02-04 17:34:00.890256
312	10	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-09 17:38:44.465678
35	3	Critical	SSRF	Medium	Potential SSRF in parameter 'url'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-04 17:34:00.890946
36	3	Critical	SSRF	Medium	Potential SSRF in parameter 'link'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-04 17:34:00.892638
37	3	Critical	SSRF	Medium	Potential SSRF in parameter 'redirect'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-04 17:34:00.893478
38	3	Critical	SSRF	Medium	Potential SSRF in parameter 'uri'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-04 17:34:00.894317
39	3	Critical	SSRF	Medium	Potential SSRF in parameter 'path'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-04 17:34:00.895028
40	3	Critical	SSRF	Medium	Potential SSRF in parameter 'dest'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-04 17:34:00.89574
41	3	Critical	SSRF	Medium	Potential SSRF in parameter 'callback'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-04 17:34:00.896447
42	3	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-04 17:34:00.897188
43	3	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-04 17:34:00.897904
44	3	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-04 17:34:00.898601
45	3	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-04 17:34:00.899295
46	3	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-04 17:34:00.900051
47	3	Critical	SSTI	High	Template Injection in parameter 'name'	Never render user input directly in templates; use sandboxed template engines	Math executed: #{7*7} = 49	GET	Template executed	2026-02-04 17:34:00.900768
48	3	Critical	SSTI	High	Template Injection in parameter 'template'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-04 17:34:00.901778
49	3	Critical	SSTI	High	Template Injection in parameter 'view'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-04 17:34:00.902791
50	3	Critical	SSTI	High	Template Injection in parameter 'page'	Never render user input directly in templates; use sandboxed template engines	Math executed: #{7*7} = 49	GET	Template executed	2026-02-04 17:34:00.903833
51	3	Info	Brute Force Protection	Low	Login endpoint detected: /login	Implement: account lockout after 5 failed attempts, exponential backoff, CAPTCHA after 3 attempts, MFA	Endpoint accessible: /login (status: 200)	GET	Login endpoint found	2026-02-04 17:34:00.904815
52	3	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-04 17:34:00.905537
53	3	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-04 17:34:00.906282
54	3	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-04 17:34:00.907002
55	3	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-04 17:34:00.907695
56	3	Medium	File Upload	Low	File upload functionality detected	Validate file types, scan for malware, restrict extensions, use random filenames	File input detected in HTML	GET	Detected	2026-02-04 17:34:00.90845
57	3	High	IDOR	Low	Potential IDOR vulnerability in parameter 'id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: id=1	GET	Sequential access	2026-02-04 17:34:00.909142
58	3	High	IDOR	Low	Potential IDOR vulnerability in parameter 'user_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: user_id=1	GET	Sequential access	2026-02-04 17:34:00.909833
59	3	High	IDOR	Low	Potential IDOR vulnerability in parameter 'account_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: account_id=1	GET	Sequential access	2026-02-04 17:34:00.910581
60	3	High	IDOR	Low	Potential IDOR vulnerability in parameter 'order_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: order_id=1	GET	Sequential access	2026-02-04 17:34:00.911279
61	3	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-04 17:34:00.912167
62	3	High	Privilege Escalation	Low	Admin endpoint accessible: /admin (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-04 17:34:00.913415
63	3	High	Privilege Escalation	Low	Admin endpoint accessible: /api/admin (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-04 17:34:00.914334
64	3	Medium	Account Takeover	Low	Account takeover vectors require authenticated testing (check: session hijacking, CSRF, password reset flaws)	Implement: session timeout, IP binding, device fingerprinting, anomaly detection, MFA	Login endpoint detected	GET	Requires manual testing	2026-02-04 17:34:00.915124
65	3	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-04 17:34:00.915893
66	3	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-04 17:34:00.916715
67	3	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-04 17:34:00.917443
68	3	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-04 17:34:00.918145
69	3	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-04 17:34:00.918836
70	3	Low	DOM Clobbering	Low	Potential DOM Clobbering vectors detected (requires manual verification)	Avoid using document.getElementById with user input; use setAttribute; validate DOM element IDs	DOM manipulation code detected	GET	Requires manual testing	2026-02-04 17:34:00.919995
71	3	High	Prototype Pollution	Low	Application accepts __proto__ in JSON (potential prototype pollution)	Sanitize JSON input; use Object.create(null); implement deep freeze; update dependencies	__proto__ payload accepted	POST	Payload accepted	2026-02-04 17:34:00.920825
72	3	Medium	CDN Bypass	Low	Potential origin server disclosure (CDN bypass risk)	Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs	Origin indicators detected	GET	Potential bypass	2026-02-04 17:34:00.921561
73	3	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-04 17:34:00.922259
74	3	Medium	Subresource Integrity	Medium	External resources loaded without Subresource Integrity (SRI)	Add integrity and crossorigin attributes to external scripts/stylesheets; generate SRI hashes	External resources without SRI detected	GET	Missing SRI	2026-02-04 17:34:00.922959
75	3	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-04 17:34:00.923645
76	4	Info	robots.txt	High	robots.txt accessible. Sensitive paths detected: 	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-05 11:45:03.043662
77	4	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-05 11:45:03.046252
78	4	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-05 11:45:03.047462
79	4	Info	TLS	High	Certificate subject: blazeup.com	Verify certificate matches domain	Subject: blazeup.com | Issuer: Go Daddy Secure Certificate Authority - G2 | Valid: 2025-07-27 - 2026-07-27	TLS	Valid	2026-02-05 11:45:03.048705
80	4	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-05 11:45:03.049884
81	4	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-05 11:45:03.050802
82	4	Critical	SSRF	Medium	Potential SSRF in parameter 'url'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-05 11:45:03.051766
83	4	Critical	SSRF	Medium	Potential SSRF in parameter 'link'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-05 11:45:03.052604
84	4	Critical	SSRF	Medium	Potential SSRF in parameter 'redirect'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-05 11:45:03.053595
85	4	Critical	SSRF	Medium	Potential SSRF in parameter 'uri'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-05 11:45:03.054422
86	4	Critical	SSRF	Medium	Potential SSRF in parameter 'path'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-05 11:45:03.055151
87	4	Critical	SSRF	Medium	Potential SSRF in parameter 'dest'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-05 11:45:03.055869
88	4	Critical	SSRF	Medium	Potential SSRF in parameter 'callback'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-05 11:45:03.056544
89	4	Medium	Rate Limiting	Medium	No rate limiting detected (20 rapid requests succeeded)	Implement rate limiting per IP/user: 100 req/min for general, 5 req/min for login/auth endpoints	All 20 requests succeeded in 3.42423633s	GET	No protection	2026-02-05 11:45:03.057317
90	4	Info	Brute Force Protection	Low	Login endpoint detected: /login	Implement: account lockout after 5 failed attempts, exponential backoff, CAPTCHA after 3 attempts, MFA	Endpoint accessible: /login (status: 200)	GET	Login endpoint found	2026-02-05 11:45:03.058127
91	4	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-05 11:45:03.058867
92	4	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-05 11:45:03.059564
93	4	Medium	Default Credentials	Low	Login endpoint detected: /login (manual testing recommended for default credentials)	Force password change on first login; disable default accounts; implement account lockout	Login form accessible	GET	Login form found	2026-02-05 11:45:03.060521
94	4	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-05 11:45:03.0615
156	6	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-05 16:14:44.345878
95	4	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-05 11:45:03.06228
96	4	High	IDOR	Low	Potential IDOR vulnerability in parameter 'id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: id=1	GET	Sequential access	2026-02-05 11:45:03.063174
97	4	High	IDOR	Low	Potential IDOR vulnerability in parameter 'user_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: user_id=1	GET	Sequential access	2026-02-05 11:45:03.06391
98	4	High	IDOR	Low	Potential IDOR vulnerability in parameter 'account_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: account_id=1	GET	Sequential access	2026-02-05 11:45:03.064692
99	4	High	IDOR	Low	Potential IDOR vulnerability in parameter 'order_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: order_id=1	GET	Sequential access	2026-02-05 11:45:03.065412
100	4	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-05 11:45:03.066089
101	4	High	Privilege Escalation	Low	Admin endpoint accessible: /admin (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-05 11:45:03.066768
102	4	High	Privilege Escalation	Low	Admin endpoint accessible: /administrator (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-05 11:45:03.067479
103	4	High	Privilege Escalation	Low	Admin endpoint accessible: /admin/users (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-05 11:45:03.068288
104	4	High	Privilege Escalation	Low	Admin endpoint accessible: /api/admin (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-05 11:45:03.06952
105	4	Medium	Account Takeover	Low	Account takeover vectors require authenticated testing (check: session hijacking, CSRF, password reset flaws)	Implement: session timeout, IP binding, device fingerprinting, anomaly detection, MFA	Login endpoint detected	GET	Requires manual testing	2026-02-05 11:45:03.071286
106	4	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-05 11:45:03.072682
107	4	Info	App Configuration	High	App configuration file accessible: /app-ads.txt	Review configuration for sensitive data; ensure proper permissions	Config file found	GET	Accessible	2026-02-05 11:45:03.074164
108	4	Info	App Configuration	High	App configuration file accessible: /.well-known/assetlinks.json	Review configuration for sensitive data; ensure proper permissions	Config file found	GET	Accessible	2026-02-05 11:45:03.075583
109	4	Info	App Configuration	High	App configuration file accessible: /.well-known/apple-app-site-association	Review configuration for sensitive data; ensure proper permissions	Config file found	GET	Accessible	2026-02-05 11:45:03.077109
110	4	Info	App Configuration	High	App configuration file accessible: /manifest.json	Review configuration for sensitive data; ensure proper permissions	Config file found	GET	Accessible	2026-02-05 11:45:03.078514
111	4	Info	App Configuration	High	App configuration file accessible: /app.config	Review configuration for sensitive data; ensure proper permissions	Config file found	GET	Accessible	2026-02-05 11:45:03.079798
112	4	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-05 11:45:03.081067
113	4	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-05 11:45:03.082333
114	4	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-05 11:45:03.083501
115	4	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-05 11:45:03.084704
116	4	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-05 11:45:03.085911
117	4	Critical	Cloud Metadata	Medium	Cloud metadata endpoint potentially accessible via SSRF	Block access to cloud metadata endpoints; use IMDSv2 (AWS); implement network segmentation	Metadata endpoint responded	GET	Accessible	2026-02-05 11:45:03.087194
118	4	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-05 11:45:03.08839
119	4	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-05 11:45:03.089757
120	4	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-05 11:45:03.091024
121	4	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-05 11:45:03.092373
122	4	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-05 11:45:03.093596
189	8	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-09 11:25:16.352697
123	4	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-05 11:45:03.094813
124	5	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-05 12:09:14.541397
125	5	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-05 12:09:14.543011
126	5	Info	TLS	High	Certificate subject: tesla.com	Verify certificate matches domain	Subject: tesla.com | Issuer: R12 | Valid: 2025-12-23 - 2026-03-23	TLS	Valid	2026-02-05 12:09:14.544292
127	5	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-05 12:09:14.545419
128	5	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-05 12:09:14.546518
129	5	Info	GraphQL	Medium	GraphQL endpoint detected: /graphql	Disable introspection in production, implement auth, rate limiting	GraphQL indicators found	GET	Detected	2026-02-05 12:09:14.5478
130	5	Info	GraphQL	Medium	GraphQL endpoint detected: /api/graphql	Disable introspection in production, implement auth, rate limiting	GraphQL indicators found	GET	Detected	2026-02-05 12:09:14.548954
131	5	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-05 12:09:14.550101
132	5	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-05 12:09:14.550993
133	5	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-05 12:09:14.55182
134	5	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-05 12:09:14.55264
135	5	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-05 12:09:14.553769
136	5	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-05 12:09:14.554999
137	5	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-05 12:09:14.556287
138	5	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-05 12:09:14.557505
139	5	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-05 12:09:14.558324
140	5	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-05 12:09:14.559091
141	5	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-05 12:09:14.559818
142	5	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-05 12:09:14.560603
143	5	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-05 12:09:14.561458
144	5	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-05 12:09:14.562218
145	5	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-05 12:09:14.563047
146	5	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-05 12:09:14.563771
147	5	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-05 12:09:14.564509
148	6	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-05 16:14:44.322947
149	6	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-05 16:14:44.33828
150	6	Info	TLS	High	Certificate subject: tesla.com	Verify certificate matches domain	Subject: tesla.com | Issuer: R12 | Valid: 2025-12-23 - 2026-03-23	TLS	Valid	2026-02-05 16:14:44.340631
151	6	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-05 16:14:44.341821
152	6	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-05 16:14:44.342735
153	6	Info	GraphQL	Medium	GraphQL endpoint detected: /graphql	Disable introspection in production, implement auth, rate limiting	GraphQL indicators found	GET	Detected	2026-02-05 16:14:44.343891
154	6	Info	GraphQL	Medium	GraphQL endpoint detected: /api/graphql	Disable introspection in production, implement auth, rate limiting	GraphQL indicators found	GET	Detected	2026-02-05 16:14:44.344671
155	6	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-05 16:14:44.345341
157	6	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-05 16:14:44.346685
158	6	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-05 16:14:44.347253
159	6	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-05 16:14:44.347938
160	6	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-05 16:14:44.348659
161	6	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-05 16:14:44.349232
162	6	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-05 16:14:44.34972
163	6	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-05 16:14:44.350168
164	6	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-05 16:14:44.350676
165	6	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-05 16:14:44.351162
166	6	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-05 16:14:44.351629
167	6	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-05 16:14:44.35205
168	6	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-05 16:14:44.352507
169	6	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-05 16:14:44.353016
170	6	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-05 16:14:44.353444
171	6	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-05 16:14:44.353917
172	7	Info	robots.txt	High	robots.txt accessible. Sensitive paths detected: 	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-06 18:53:05.922519
173	7	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-06 18:53:05.936165
174	7	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-06 18:53:05.936964
175	7	Info	TLS	High	Certificate subject: scantest.com	Verify certificate matches domain	Subject: scantest.com | Issuer: E8 | Valid: 2025-12-17 - 2026-03-17	TLS	Valid	2026-02-06 18:53:05.937537
176	7	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-06 18:53:05.938033
177	7	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-06 18:53:05.938594
178	7	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-06 18:53:05.939146
179	7	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-06 18:53:05.939619
180	7	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-06 18:53:05.940491
181	7	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-06 18:53:05.94099
182	7	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-06 18:53:05.941905
183	7	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-06 18:53:05.94242
184	8	Low	robots.txt	High	robots.txt accessible. Sensitive paths detected: admin	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-09 11:25:16.327439
185	8	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-09 11:25:16.34539
186	8	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-09 11:25:16.34751
187	8	Info	TLS	High	Certificate subject: *.terralogic.com	Verify certificate matches domain	Subject: *.terralogic.com | Issuer: Sectigo Public Server Authentication CA DV R36 | Valid: 2025-10-30 - 2026-11-30	TLS	Valid	2026-02-09 11:25:16.349251
188	8	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-09 11:25:16.350972
190	8	Medium	Admin Panel	High	Admin panels discovered: [/admin /admin/login /admin/index.php /management]	Implement: strong authentication, IP whitelisting, rename default paths, enable rate limiting, use CAPTCHA	/admin, /admin/login, /admin/index.php, /management	GET	Accessible	2026-02-09 11:25:16.354361
191	8	Medium	CSRF	Medium	Forms detected without obvious CSRF tokens	Implement CSRF tokens on all state-changing operations; validate Origin/Referer headers; use SameSite cookies	Forms present, no CSRF token patterns found	GET	No CSRF protection detected	2026-02-09 11:25:16.355577
192	8	Critical	SSRF	Medium	Potential SSRF in parameter 'url'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:25:16.356603
193	8	Critical	SSRF	Medium	Potential SSRF in parameter 'link'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:25:16.357524
194	8	Critical	SSRF	Medium	Potential SSRF in parameter 'redirect'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:25:16.358464
195	8	Critical	SSRF	Medium	Potential SSRF in parameter 'uri'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:25:16.359385
196	8	Critical	SSRF	Medium	Potential SSRF in parameter 'path'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:25:16.360191
197	8	Critical	SSRF	Medium	Potential SSRF in parameter 'dest'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:25:16.361007
198	8	Critical	SSRF	Medium	Potential SSRF in parameter 'callback'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:25:16.361823
199	8	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-09 11:25:16.362617
200	8	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-09 11:25:16.363371
201	8	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-09 11:25:16.364147
202	8	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-09 11:25:16.364968
203	8	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-09 11:25:16.365992
204	8	Critical	SSTI	High	Template Injection in parameter 'name'	Never render user input directly in templates; use sandboxed template engines	Math executed: #{7*7} = 49	GET	Template executed	2026-02-09 11:25:16.366896
205	8	Critical	SSTI	High	Template Injection in parameter 'template'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 11:25:16.367934
206	8	Critical	SSTI	High	Template Injection in parameter 'view'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 11:25:16.369019
207	8	Critical	SSTI	High	Template Injection in parameter 'page'	Never render user input directly in templates; use sandboxed template engines	Math executed: #{7*7} = 49	GET	Template executed	2026-02-09 11:25:16.369933
208	8	Info	Brute Force Protection	Low	Login endpoint detected: /login	Implement: account lockout after 5 failed attempts, exponential backoff, CAPTCHA after 3 attempts, MFA	Endpoint accessible: /login (status: 200)	GET	Login endpoint found	2026-02-09 11:25:16.370838
209	8	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-09 11:25:16.371682
210	8	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-09 11:25:16.372475
211	8	Medium	Default Credentials	Low	Login endpoint detected: /login (manual testing recommended for default credentials)	Force password change on first login; disable default accounts; implement account lockout	Login form accessible	GET	Login form found	2026-02-09 11:25:16.373262
212	8	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-09 11:25:16.374055
213	8	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-09 11:25:16.374904
214	8	Medium	File Upload	Low	File upload functionality detected	Validate file types, scan for malware, restrict extensions, use random filenames	File input detected in HTML	GET	Detected	2026-02-09 11:25:16.375731
215	8	Info	File Upload	Low	File upload endpoint requires manual testing	Test with various file extensions, double extensions, content-type bypass	Upload form detected	POST	Requires manual test	2026-02-09 11:25:16.37647
216	8	High	IDOR	Low	Potential IDOR vulnerability in parameter 'id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: id=1	GET	Sequential access	2026-02-09 11:25:16.377223
217	8	High	IDOR	Low	Potential IDOR vulnerability in parameter 'user_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: user_id=1	GET	Sequential access	2026-02-09 11:25:16.377981
218	8	High	IDOR	Low	Potential IDOR vulnerability in parameter 'account_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: account_id=1	GET	Sequential access	2026-02-09 11:25:16.378793
219	8	High	IDOR	Low	Potential IDOR vulnerability in parameter 'order_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: order_id=1	GET	Sequential access	2026-02-09 11:25:16.379572
310	10	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-09 17:38:44.463911
220	8	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-09 11:25:16.380421
221	8	High	Privilege Escalation	Low	Admin endpoint accessible: /admin (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-09 11:25:16.38128
222	8	High	Privilege Escalation	Low	Admin endpoint accessible: /api/admin (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-09 11:25:16.382408
223	8	Medium	Account Takeover	Low	Account takeover vectors require authenticated testing (check: session hijacking, CSRF, password reset flaws)	Implement: session timeout, IP binding, device fingerprinting, anomaly detection, MFA	Login endpoint detected	GET	Requires manual testing	2026-02-09 11:25:16.383818
224	8	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-09 11:25:16.385037
225	8	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-09 11:25:16.386378
226	8	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-09 11:25:16.387463
227	8	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-09 11:25:16.388299
228	8	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-09 11:25:16.389131
229	8	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-09 11:25:16.389899
230	8	Critical	Cloud Metadata	Medium	Cloud metadata endpoint potentially accessible via SSRF	Block access to cloud metadata endpoints; use IMDSv2 (AWS); implement network segmentation	Metadata endpoint responded	GET	Accessible	2026-02-09 11:25:16.390731
231	8	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-09 11:25:16.391532
232	8	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-09 11:25:16.392312
233	8	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-09 11:25:16.39316
234	8	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-09 11:25:16.393909
235	8	Low	DOM Clobbering	Low	Potential DOM Clobbering vectors detected (requires manual verification)	Avoid using document.getElementById with user input; use setAttribute; validate DOM element IDs	DOM manipulation code detected	GET	Requires manual testing	2026-02-09 11:25:16.394646
236	8	High	Prototype Pollution	Low	Application accepts __proto__ in JSON (potential prototype pollution)	Sanitize JSON input; use Object.create(null); implement deep freeze; update dependencies	__proto__ payload accepted	POST	Payload accepted	2026-02-09 11:25:16.395469
237	8	Medium	CDN Bypass	Low	Potential origin server disclosure (CDN bypass risk)	Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs	Origin indicators detected	GET	Potential bypass	2026-02-09 11:25:16.396233
238	8	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-09 11:25:16.396931
239	8	Medium	Subresource Integrity	Medium	External resources loaded without Subresource Integrity (SRI)	Add integrity and crossorigin attributes to external scripts/stylesheets; generate SRI hashes	External resources without SRI detected	GET	Missing SRI	2026-02-09 11:25:16.397659
240	8	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-09 11:25:16.398483
241	9	Low	robots.txt	High	robots.txt accessible. Sensitive paths detected: admin	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-09 11:49:38.390027
242	9	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-09 11:49:38.405084
243	9	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-09 11:49:38.406988
244	9	Info	TLS	High	Certificate subject: *.blazeup.ai	Verify certificate matches domain	Subject: *.blazeup.ai | Issuer: Sectigo Public Server Authentication CA DV R36 | Valid: 2025-09-12 - 2026-09-12	TLS	Valid	2026-02-09 11:49:38.408596
245	9	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-09 11:49:38.409896
246	9	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-09 11:49:38.411089
247	9	High	XXE	Low	Potential XXE vulnerability (XML parsing detected)	Disable external entity processing in XML parsers; use JSON instead of XML where possible	XML payload accepted	POST	XML processed	2026-02-09 11:49:38.412688
248	9	Critical	SSRF	Medium	Potential SSRF in parameter 'url'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:49:38.414721
249	9	Critical	SSRF	Medium	Potential SSRF in parameter 'link'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:49:38.415916
250	9	Critical	SSRF	Medium	Potential SSRF in parameter 'redirect'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:49:38.416953
251	9	Critical	SSRF	Medium	Potential SSRF in parameter 'uri'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:49:38.417692
252	9	Critical	SSRF	Medium	Potential SSRF in parameter 'path'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:49:38.418309
253	9	Critical	SSRF	Medium	Potential SSRF in parameter 'dest'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:49:38.418933
254	9	Critical	SSRF	Medium	Potential SSRF in parameter 'callback'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 11:49:38.41977
255	9	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-09 11:49:38.420525
256	9	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-09 11:49:38.421348
257	9	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-09 11:49:38.422104
258	9	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-09 11:49:38.422825
259	9	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-09 11:49:38.423698
260	9	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-09 11:49:38.424718
261	9	Critical	SSTI	High	Template Injection in parameter 'name'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 11:49:38.425482
262	9	Critical	SSTI	High	Template Injection in parameter 'template'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 11:49:38.426337
263	9	Critical	SSTI	High	Template Injection in parameter 'view'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 11:49:38.427268
264	9	Critical	SSTI	High	Template Injection in parameter 'page'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 11:49:38.428015
265	9	Medium	Rate Limiting	Medium	No rate limiting detected (20 rapid requests succeeded)	Implement rate limiting per IP/user: 100 req/min for general, 5 req/min for login/auth endpoints	All 20 requests succeeded in 2.660200862s	GET	No protection	2026-02-09 11:49:38.428957
266	9	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-09 11:49:38.430723
267	9	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-09 11:49:38.43222
268	9	Medium	Default Credentials	Low	Login endpoint detected: /admin/login (manual testing recommended for default credentials)	Force password change on first login; disable default accounts; implement account lockout	Login form accessible	GET	Login form found	2026-02-09 11:49:38.433659
269	9	Info	MFA	High	Multi-Factor Authentication detected	Ensure MFA is enforced for all users (especially admins); prevent MFA bypass via password reset; log MFA events	MFA indicators present	GET	MFA available	2026-02-09 11:49:38.434679
270	9	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-09 11:49:38.435453
271	9	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-09 11:49:38.436414
272	9	Medium	File Upload	Low	File upload functionality detected	Validate file types, scan for malware, restrict extensions, use random filenames	File input detected in HTML	GET	Detected	2026-02-09 11:49:38.437397
273	9	Info	File Upload	Low	File upload endpoint requires manual testing	Test with various file extensions, double extensions, content-type bypass	Upload form detected	POST	Requires manual test	2026-02-09 11:49:38.438326
274	9	High	IDOR	Low	Potential IDOR vulnerability in parameter 'id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: id=1	GET	Sequential access	2026-02-09 11:49:38.439177
275	9	High	IDOR	Low	Potential IDOR vulnerability in parameter 'user_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: user_id=1	GET	Sequential access	2026-02-09 11:49:38.440397
276	9	High	IDOR	Low	Potential IDOR vulnerability in parameter 'account_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: account_id=1	GET	Sequential access	2026-02-09 11:49:38.441733
277	9	High	IDOR	Low	Potential IDOR vulnerability in parameter 'order_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: order_id=1	GET	Sequential access	2026-02-09 11:49:38.442857
278	9	Medium	Price Manipulation	Low	E-commerce indicators detected (manual testing recommended for price manipulation)	Never trust client-side pricing; validate prices server-side; use signed/encrypted price tokens; log all price changes	Pricing-related fields detected	GET	Requires manual testing	2026-02-09 11:49:38.443945
279	9	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-09 11:49:38.445021
311	10	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-09 17:38:44.464832
280	9	High	Privilege Escalation	Low	Admin endpoint accessible: /admin/users (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-09 11:49:38.446244
281	9	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-09 11:49:38.447284
282	9	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-09 11:49:38.448163
283	9	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-09 11:49:38.449203
284	9	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-09 11:49:38.450204
285	9	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-09 11:49:38.451233
286	9	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-09 11:49:38.452006
287	9	Critical	Cloud Metadata	Medium	Cloud metadata endpoint potentially accessible via SSRF	Block access to cloud metadata endpoints; use IMDSv2 (AWS); implement network segmentation	Metadata endpoint responded	GET	Accessible	2026-02-09 11:49:38.452848
288	9	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-09 11:49:38.453732
289	9	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-09 11:49:38.454439
290	9	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-09 11:49:38.455131
291	9	Info	PCI DSS	Low	Payment processing indicators detected (verify PCI DSS compliance)	PCI DSS requirements: encrypt cardholder data, maintain secure network, implement access controls, monitor networks, test security systems	Payment indicators found	GET	Payment detected	2026-02-09 11:49:38.455803
292	9	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-09 11:49:38.456663
293	9	Medium	CDN Bypass	Low	Potential origin server disclosure (CDN bypass risk)	Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs	Origin indicators detected	GET	Potential bypass	2026-02-09 11:49:38.457415
294	9	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-09 11:49:38.458108
295	9	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-09 11:49:38.458836
296	10	Low	robots.txt	High	robots.txt accessible. Sensitive paths detected: admin	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-09 17:38:44.438284
297	10	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-09 17:38:44.452345
298	10	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-09 17:38:44.453804
299	10	Info	TLS	High	Certificate subject: *.blazeup.ai	Verify certificate matches domain	Subject: *.blazeup.ai | Issuer: Sectigo Public Server Authentication CA DV R36 | Valid: 2025-09-12 - 2026-09-12	TLS	Valid	2026-02-09 17:38:44.454723
300	10	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-09 17:38:44.455649
301	10	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-09 17:38:44.456684
302	10	High	XXE	Low	Potential XXE vulnerability (XML parsing detected)	Disable external entity processing in XML parsers; use JSON instead of XML where possible	XML payload accepted	POST	XML processed	2026-02-09 17:38:44.457632
303	10	Critical	SSRF	Medium	Potential SSRF in parameter 'url'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 17:38:44.458418
304	10	Critical	SSRF	Medium	Potential SSRF in parameter 'link'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 17:38:44.459207
305	10	Critical	SSRF	Medium	Potential SSRF in parameter 'redirect'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 17:38:44.459955
306	10	Critical	SSRF	Medium	Potential SSRF in parameter 'uri'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 17:38:44.460829
307	10	Critical	SSRF	Medium	Potential SSRF in parameter 'path'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 17:38:44.461608
308	10	Critical	SSRF	Medium	Potential SSRF in parameter 'dest'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 17:38:44.462377
309	10	Critical	SSRF	Medium	Potential SSRF in parameter 'callback'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-09 17:38:44.463162
313	10	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-09 17:38:44.466471
314	10	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-09 17:38:44.467742
315	10	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-09 17:38:44.468487
316	10	Critical	SSTI	High	Template Injection in parameter 'name'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 17:38:44.469291
317	10	Critical	SSTI	High	Template Injection in parameter 'template'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 17:38:44.470028
318	10	Critical	SSTI	High	Template Injection in parameter 'view'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 17:38:44.470797
319	10	Critical	SSTI	High	Template Injection in parameter 'page'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-09 17:38:44.471561
320	10	Medium	Rate Limiting	Medium	No rate limiting detected (20 rapid requests succeeded)	Implement rate limiting per IP/user: 100 req/min for general, 5 req/min for login/auth endpoints	All 20 requests succeeded in 2.651736277s	GET	No protection	2026-02-09 17:38:44.472485
321	10	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-09 17:38:44.473729
322	10	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-09 17:38:44.474672
323	10	Medium	Default Credentials	Low	Login endpoint detected: /admin/login (manual testing recommended for default credentials)	Force password change on first login; disable default accounts; implement account lockout	Login form accessible	GET	Login form found	2026-02-09 17:38:44.475594
324	10	Info	MFA	High	Multi-Factor Authentication detected	Ensure MFA is enforced for all users (especially admins); prevent MFA bypass via password reset; log MFA events	MFA indicators present	GET	MFA available	2026-02-09 17:38:44.476411
325	10	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-09 17:38:44.477184
326	10	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-09 17:38:44.477945
327	10	Medium	File Upload	Low	File upload functionality detected	Validate file types, scan for malware, restrict extensions, use random filenames	File input detected in HTML	GET	Detected	2026-02-09 17:38:44.478737
328	10	Info	File Upload	Low	File upload endpoint requires manual testing	Test with various file extensions, double extensions, content-type bypass	Upload form detected	POST	Requires manual test	2026-02-09 17:38:44.47947
329	10	High	IDOR	Low	Potential IDOR vulnerability in parameter 'id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: id=1	GET	Sequential access	2026-02-09 17:38:44.480216
330	10	High	IDOR	Low	Potential IDOR vulnerability in parameter 'user_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: user_id=1	GET	Sequential access	2026-02-09 17:38:44.480997
331	10	High	IDOR	Low	Potential IDOR vulnerability in parameter 'account_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: account_id=1	GET	Sequential access	2026-02-09 17:38:44.481756
332	10	High	IDOR	Low	Potential IDOR vulnerability in parameter 'order_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: order_id=1	GET	Sequential access	2026-02-09 17:38:44.482524
333	10	Medium	Price Manipulation	Low	E-commerce indicators detected (manual testing recommended for price manipulation)	Never trust client-side pricing; validate prices server-side; use signed/encrypted price tokens; log all price changes	Pricing-related fields detected	GET	Requires manual testing	2026-02-09 17:38:44.48339
334	10	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-09 17:38:44.484185
335	10	High	Privilege Escalation	Low	Admin endpoint accessible: /admin/users (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-09 17:38:44.486216
336	10	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-09 17:38:44.48738
337	10	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-09 17:38:44.488321
338	10	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-09 17:38:44.489133
339	10	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-09 17:38:44.489904
340	10	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-09 17:38:44.490737
341	10	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-09 17:38:44.491714
342	10	Critical	Cloud Metadata	Medium	Cloud metadata endpoint potentially accessible via SSRF	Block access to cloud metadata endpoints; use IMDSv2 (AWS); implement network segmentation	Metadata endpoint responded	GET	Accessible	2026-02-09 17:38:44.492712
343	10	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-09 17:38:44.493736
344	10	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-09 17:38:44.494652
345	10	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-09 17:38:44.495514
346	10	Info	PCI DSS	Low	Payment processing indicators detected (verify PCI DSS compliance)	PCI DSS requirements: encrypt cardholder data, maintain secure network, implement access controls, monitor networks, test security systems	Payment indicators found	GET	Payment detected	2026-02-09 17:38:44.496492
347	10	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-09 17:38:44.497344
348	10	Medium	CDN Bypass	Low	Potential origin server disclosure (CDN bypass risk)	Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs	Origin indicators detected	GET	Potential bypass	2026-02-09 17:38:44.498159
349	10	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-09 17:38:44.498944
350	10	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-09 17:38:44.499652
351	11	Low	robots.txt	High	robots.txt accessible. Sensitive paths detected: admin	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-10 15:32:11.981283
352	11	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-10 15:32:11.995416
353	11	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-10 15:32:11.996497
354	11	Info	TLS	High	Certificate subject: *.blazeup.ai	Verify certificate matches domain	Subject: *.blazeup.ai | Issuer: Sectigo Public Server Authentication CA DV R36 | Valid: 2025-09-12 - 2026-09-12	TLS	Valid	2026-02-10 15:32:11.997465
355	11	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-10 15:32:11.998239
356	11	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-10 15:32:11.998896
357	11	High	XXE	Low	Potential XXE vulnerability (XML parsing detected)	Disable external entity processing in XML parsers; use JSON instead of XML where possible	XML payload accepted	POST	XML processed	2026-02-10 15:32:11.999574
358	11	Critical	SSRF	Medium	Potential SSRF in parameter 'url'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:32:12.000143
359	11	Critical	SSRF	Medium	Potential SSRF in parameter 'link'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:32:12.000688
360	11	Critical	SSRF	Medium	Potential SSRF in parameter 'redirect'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:32:12.001237
361	11	Critical	SSRF	Medium	Potential SSRF in parameter 'uri'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:32:12.001812
362	11	Critical	SSRF	Medium	Potential SSRF in parameter 'path'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:32:12.002379
363	11	Critical	SSRF	Medium	Potential SSRF in parameter 'dest'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:32:12.002985
364	11	Critical	SSRF	Medium	Potential SSRF in parameter 'callback'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:32:12.003641
365	11	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 15:32:12.004195
366	11	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 15:32:12.004807
367	11	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 15:32:12.005435
368	11	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 15:32:12.006015
369	11	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 15:32:12.00657
370	11	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 15:32:12.007228
371	11	Critical	SSTI	High	Template Injection in parameter 'name'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 15:32:12.007992
372	11	Critical	SSTI	High	Template Injection in parameter 'template'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 15:32:12.008658
373	11	Critical	SSTI	High	Template Injection in parameter 'view'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 15:32:12.009286
374	11	Critical	SSTI	High	Template Injection in parameter 'page'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 15:32:12.009815
375	11	Medium	Rate Limiting	Medium	No rate limiting detected (20 rapid requests succeeded)	Implement rate limiting per IP/user: 100 req/min for general, 5 req/min for login/auth endpoints	All 20 requests succeeded in 2.666623297s	GET	No protection	2026-02-10 15:32:12.010483
376	11	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-10 15:32:12.011086
377	11	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-10 15:32:12.012046
378	11	Medium	Default Credentials	Low	Login endpoint detected: /admin/login (manual testing recommended for default credentials)	Force password change on first login; disable default accounts; implement account lockout	Login form accessible	GET	Login form found	2026-02-10 15:32:12.012638
379	11	Info	MFA	High	Multi-Factor Authentication detected	Ensure MFA is enforced for all users (especially admins); prevent MFA bypass via password reset; log MFA events	MFA indicators present	GET	MFA available	2026-02-10 15:32:12.013259
380	11	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-10 15:32:12.013805
381	11	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-10 15:32:12.015036
382	11	Medium	File Upload	Low	File upload functionality detected	Validate file types, scan for malware, restrict extensions, use random filenames	File input detected in HTML	GET	Detected	2026-02-10 15:32:12.015967
383	11	Info	File Upload	Low	File upload endpoint requires manual testing	Test with various file extensions, double extensions, content-type bypass	Upload form detected	POST	Requires manual test	2026-02-10 15:32:12.016676
384	11	High	IDOR	Low	Potential IDOR vulnerability in parameter 'id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: id=1	GET	Sequential access	2026-02-10 15:32:12.01736
385	11	High	IDOR	Low	Potential IDOR vulnerability in parameter 'user_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: user_id=1	GET	Sequential access	2026-02-10 15:32:12.018043
386	11	High	IDOR	Low	Potential IDOR vulnerability in parameter 'account_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: account_id=1	GET	Sequential access	2026-02-10 15:32:12.018702
387	11	High	IDOR	Low	Potential IDOR vulnerability in parameter 'order_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: order_id=1	GET	Sequential access	2026-02-10 15:32:12.019498
388	11	Medium	Price Manipulation	Low	E-commerce indicators detected (manual testing recommended for price manipulation)	Never trust client-side pricing; validate prices server-side; use signed/encrypted price tokens; log all price changes	Pricing-related fields detected	GET	Requires manual testing	2026-02-10 15:32:12.020439
389	11	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-10 15:32:12.021273
390	11	High	Privilege Escalation	Low	Admin endpoint accessible: /admin/users (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-10 15:32:12.022059
391	11	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-10 15:32:12.02311
392	11	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-10 15:32:12.024111
393	11	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-10 15:32:12.025225
394	11	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-10 15:32:12.026183
395	11	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-10 15:32:12.026761
396	11	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-10 15:32:12.027381
397	11	Critical	Cloud Metadata	Medium	Cloud metadata endpoint potentially accessible via SSRF	Block access to cloud metadata endpoints; use IMDSv2 (AWS); implement network segmentation	Metadata endpoint responded	GET	Accessible	2026-02-10 15:32:12.027956
398	11	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-10 15:32:12.028475
399	11	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-10 15:32:12.029003
400	11	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-10 15:32:12.029538
401	11	Info	PCI DSS	Low	Payment processing indicators detected (verify PCI DSS compliance)	PCI DSS requirements: encrypt cardholder data, maintain secure network, implement access controls, monitor networks, test security systems	Payment indicators found	GET	Payment detected	2026-02-10 15:32:12.030099
402	11	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-10 15:32:12.030639
403	11	Medium	CDN Bypass	Low	Potential origin server disclosure (CDN bypass risk)	Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs	Origin indicators detected	GET	Potential bypass	2026-02-10 15:32:12.031177
404	11	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-10 15:32:12.03175
405	11	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-10 15:32:12.032356
406	12	Low	robots.txt	High	robots.txt accessible. Sensitive paths detected: admin	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-10 15:59:31.013039
407	12	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-10 15:59:31.015383
408	12	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-10 15:59:31.016517
409	12	Info	TLS	High	Certificate subject: *.blazeup.ai	Verify certificate matches domain	Subject: *.blazeup.ai | Issuer: Sectigo Public Server Authentication CA DV R36 | Valid: 2025-09-12 - 2026-09-12	TLS	Valid	2026-02-10 15:59:31.018296
410	12	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-10 15:59:31.019252
411	12	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-10 15:59:31.02004
412	12	High	XXE	Low	Potential XXE vulnerability (XML parsing detected)	Disable external entity processing in XML parsers; use JSON instead of XML where possible	XML payload accepted	POST	XML processed	2026-02-10 15:59:31.021001
413	12	Critical	SSRF	Medium	Potential SSRF in parameter 'url'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:59:31.022124
414	12	Critical	SSRF	Medium	Potential SSRF in parameter 'link'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:59:31.023021
415	12	Critical	SSRF	Medium	Potential SSRF in parameter 'redirect'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:59:31.02384
416	12	Critical	SSRF	Medium	Potential SSRF in parameter 'uri'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:59:31.024653
417	12	Critical	SSRF	Medium	Potential SSRF in parameter 'path'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:59:31.025398
418	12	Critical	SSRF	Medium	Potential SSRF in parameter 'dest'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:59:31.026137
419	12	Critical	SSRF	Medium	Potential SSRF in parameter 'callback'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 15:59:31.02689
420	12	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 15:59:31.027664
421	12	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 15:59:31.028405
422	12	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 15:59:31.029148
423	12	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 15:59:31.029835
424	12	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 15:59:31.03055
425	12	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 15:59:31.031344
426	12	Critical	SSTI	High	Template Injection in parameter 'name'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 15:59:31.032105
427	12	Critical	SSTI	High	Template Injection in parameter 'template'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 15:59:31.032932
428	12	Critical	SSTI	High	Template Injection in parameter 'view'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 15:59:31.033799
429	12	Critical	SSTI	High	Template Injection in parameter 'page'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 15:59:31.034533
430	12	Medium	Rate Limiting	Medium	No rate limiting detected (20 rapid requests succeeded)	Implement rate limiting per IP/user: 100 req/min for general, 5 req/min for login/auth endpoints	All 20 requests succeeded in 2.708600596s	GET	No protection	2026-02-10 15:59:31.035305
431	12	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-10 15:59:31.036188
432	12	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-10 15:59:31.037009
433	12	Medium	Default Credentials	Low	Login endpoint detected: /admin/login (manual testing recommended for default credentials)	Force password change on first login; disable default accounts; implement account lockout	Login form accessible	GET	Login form found	2026-02-10 15:59:31.037761
434	12	Info	MFA	High	Multi-Factor Authentication detected	Ensure MFA is enforced for all users (especially admins); prevent MFA bypass via password reset; log MFA events	MFA indicators present	GET	MFA available	2026-02-10 15:59:31.03853
435	12	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-10 15:59:31.039282
436	12	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-10 15:59:31.04006
437	12	Medium	File Upload	Low	File upload functionality detected	Validate file types, scan for malware, restrict extensions, use random filenames	File input detected in HTML	GET	Detected	2026-02-10 15:59:31.040849
438	12	Info	File Upload	Low	File upload endpoint requires manual testing	Test with various file extensions, double extensions, content-type bypass	Upload form detected	POST	Requires manual test	2026-02-10 15:59:31.04171
439	12	High	IDOR	Low	Potential IDOR vulnerability in parameter 'id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: id=1	GET	Sequential access	2026-02-10 15:59:31.042462
440	12	High	IDOR	Low	Potential IDOR vulnerability in parameter 'user_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: user_id=1	GET	Sequential access	2026-02-10 15:59:31.043258
441	12	High	IDOR	Low	Potential IDOR vulnerability in parameter 'account_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: account_id=1	GET	Sequential access	2026-02-10 15:59:31.043996
442	12	High	IDOR	Low	Potential IDOR vulnerability in parameter 'order_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: order_id=1	GET	Sequential access	2026-02-10 15:59:31.044762
443	12	Medium	Price Manipulation	Low	E-commerce indicators detected (manual testing recommended for price manipulation)	Never trust client-side pricing; validate prices server-side; use signed/encrypted price tokens; log all price changes	Pricing-related fields detected	GET	Requires manual testing	2026-02-10 15:59:31.045548
444	12	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-10 15:59:31.046328
445	12	High	Privilege Escalation	Low	Admin endpoint accessible: /admin/users (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-10 15:59:31.047311
446	12	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-10 15:59:31.048182
447	12	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-10 15:59:31.049045
448	12	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-10 15:59:31.049827
449	12	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-10 15:59:31.050875
450	12	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-10 15:59:31.05217
451	12	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-10 15:59:31.053678
452	12	Critical	Cloud Metadata	Medium	Cloud metadata endpoint potentially accessible via SSRF	Block access to cloud metadata endpoints; use IMDSv2 (AWS); implement network segmentation	Metadata endpoint responded	GET	Accessible	2026-02-10 15:59:31.055176
453	12	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-10 15:59:31.056173
454	12	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-10 15:59:31.056992
455	12	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-10 15:59:31.057782
456	12	Info	PCI DSS	Low	Payment processing indicators detected (verify PCI DSS compliance)	PCI DSS requirements: encrypt cardholder data, maintain secure network, implement access controls, monitor networks, test security systems	Payment indicators found	GET	Payment detected	2026-02-10 15:59:31.058564
457	12	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-10 15:59:31.059476
458	12	Medium	CDN Bypass	Low	Potential origin server disclosure (CDN bypass risk)	Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs	Origin indicators detected	GET	Potential bypass	2026-02-10 15:59:31.060386
459	12	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-10 15:59:31.061173
460	12	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-10 15:59:31.061945
461	13	Low	robots.txt	High	robots.txt accessible. Sensitive paths detected: admin	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-10 16:38:14.94493
462	13	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-10 16:38:14.948115
463	13	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-10 16:38:14.948827
464	13	Info	TLS	High	Certificate subject: *.blazeup.ai	Verify certificate matches domain	Subject: *.blazeup.ai | Issuer: Sectigo Public Server Authentication CA DV R36 | Valid: 2025-09-12 - 2026-09-12	TLS	Valid	2026-02-10 16:38:14.950252
465	13	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-10 16:38:14.953026
466	13	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-10 16:38:14.954774
467	13	High	XXE	Low	Potential XXE vulnerability (XML parsing detected)	Disable external entity processing in XML parsers; use JSON instead of XML where possible	XML payload accepted	POST	XML processed	2026-02-10 16:38:14.956561
468	13	Critical	SSRF	Medium	Potential SSRF in parameter 'url'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:38:14.958207
469	13	Critical	SSRF	Medium	Potential SSRF in parameter 'link'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:38:14.959233
470	13	Critical	SSRF	Medium	Potential SSRF in parameter 'redirect'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:38:14.960256
471	13	Critical	SSRF	Medium	Potential SSRF in parameter 'uri'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:38:14.961509
472	13	Critical	SSRF	Medium	Potential SSRF in parameter 'path'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:38:14.962618
473	13	Critical	SSRF	Medium	Potential SSRF in parameter 'dest'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:38:14.96355
474	13	Critical	SSRF	Medium	Potential SSRF in parameter 'callback'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:38:14.964364
475	13	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 16:38:14.965224
476	13	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 16:38:14.966028
477	13	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 16:38:14.966787
478	13	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 16:38:14.967558
479	13	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 16:38:14.968282
480	13	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 16:38:14.969001
481	13	Critical	SSTI	High	Template Injection in parameter 'name'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 16:38:14.969737
482	13	Critical	SSTI	High	Template Injection in parameter 'template'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 16:38:14.970578
483	13	Critical	SSTI	High	Template Injection in parameter 'view'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 16:38:14.971358
484	13	Critical	SSTI	High	Template Injection in parameter 'page'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 16:38:14.97212
485	13	Medium	Rate Limiting	Medium	No rate limiting detected (20 rapid requests succeeded)	Implement rate limiting per IP/user: 100 req/min for general, 5 req/min for login/auth endpoints	All 20 requests succeeded in 2.648512698s	GET	No protection	2026-02-10 16:38:14.972851
486	13	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-10 16:38:14.973688
487	13	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-10 16:38:14.974646
488	13	Medium	Default Credentials	Low	Login endpoint detected: /admin/login (manual testing recommended for default credentials)	Force password change on first login; disable default accounts; implement account lockout	Login form accessible	GET	Login form found	2026-02-10 16:38:14.975483
489	13	Info	MFA	High	Multi-Factor Authentication detected	Ensure MFA is enforced for all users (especially admins); prevent MFA bypass via password reset; log MFA events	MFA indicators present	GET	MFA available	2026-02-10 16:38:14.976303
490	13	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-10 16:38:14.978078
491	13	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-10 16:38:14.979883
492	13	Medium	File Upload	Low	File upload functionality detected	Validate file types, scan for malware, restrict extensions, use random filenames	File input detected in HTML	GET	Detected	2026-02-10 16:38:14.981047
493	13	Info	File Upload	Low	File upload endpoint requires manual testing	Test with various file extensions, double extensions, content-type bypass	Upload form detected	POST	Requires manual test	2026-02-10 16:38:14.981993
494	13	High	IDOR	Low	Potential IDOR vulnerability in parameter 'id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: id=1	GET	Sequential access	2026-02-10 16:38:14.982838
495	13	High	IDOR	Low	Potential IDOR vulnerability in parameter 'user_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: user_id=1	GET	Sequential access	2026-02-10 16:38:14.98369
496	13	High	IDOR	Low	Potential IDOR vulnerability in parameter 'account_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: account_id=1	GET	Sequential access	2026-02-10 16:38:14.984513
497	13	High	IDOR	Low	Potential IDOR vulnerability in parameter 'order_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: order_id=1	GET	Sequential access	2026-02-10 16:38:14.985312
498	13	Medium	Price Manipulation	Low	E-commerce indicators detected (manual testing recommended for price manipulation)	Never trust client-side pricing; validate prices server-side; use signed/encrypted price tokens; log all price changes	Pricing-related fields detected	GET	Requires manual testing	2026-02-10 16:38:14.986111
499	13	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-10 16:38:14.98712
500	13	High	Privilege Escalation	Low	Admin endpoint accessible: /admin/users (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-10 16:38:14.988179
501	13	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-10 16:38:14.988987
502	13	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-10 16:38:14.990486
503	13	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-10 16:38:14.992307
504	13	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-10 16:38:14.993637
505	13	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-10 16:38:14.995265
506	13	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-10 16:38:14.996914
507	13	Critical	Cloud Metadata	Medium	Cloud metadata endpoint potentially accessible via SSRF	Block access to cloud metadata endpoints; use IMDSv2 (AWS); implement network segmentation	Metadata endpoint responded	GET	Accessible	2026-02-10 16:38:14.998323
508	13	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-10 16:38:14.999863
509	13	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-10 16:38:15.001342
510	13	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-10 16:38:15.002749
511	13	Info	PCI DSS	Low	Payment processing indicators detected (verify PCI DSS compliance)	PCI DSS requirements: encrypt cardholder data, maintain secure network, implement access controls, monitor networks, test security systems	Payment indicators found	GET	Payment detected	2026-02-10 16:38:15.004084
512	13	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-10 16:38:15.005389
513	13	Medium	CDN Bypass	Low	Potential origin server disclosure (CDN bypass risk)	Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs	Origin indicators detected	GET	Potential bypass	2026-02-10 16:38:15.006798
514	13	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-10 16:38:15.007935
515	13	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-10 16:38:15.009246
516	14	Low	robots.txt	High	robots.txt accessible. Sensitive paths detected: admin	Review robots.txt for sensitive path disclosure	Status 200	GET	Found	2026-02-10 16:41:11.008827
517	14	High	Connectivity	High	Target is not reachable	Check DNS, connectivity, and firewall rules	Get "/": unsupported protocol scheme ""	GET	Failed	2026-02-10 16:41:11.025161
518	14	Info	TLS	High	TLS version: TLS 1.3	Continue using TLS 1.2+	TLS 1.3	TLS	Secure	2026-02-10 16:41:11.027348
519	14	Info	TLS	High	Certificate subject: *.blazeup.ai	Verify certificate matches domain	Subject: *.blazeup.ai | Issuer: Sectigo Public Server Authentication CA DV R36 | Valid: 2025-09-12 - 2026-09-12	TLS	Valid	2026-02-10 16:41:11.029087
520	14	Info	Backup Files	High	No backup files detected	Continue blocking backup file access	No backup files found	GET	Protected	2026-02-10 16:41:11.030794
521	14	Info	Directory Listing	High	No open directory listings detected	Continue blocking directory indexing	All directories protected	GET	Protected	2026-02-10 16:41:11.032384
522	14	High	XXE	Low	Potential XXE vulnerability (XML parsing detected)	Disable external entity processing in XML parsers; use JSON instead of XML where possible	XML payload accepted	POST	XML processed	2026-02-10 16:41:11.034252
523	14	Critical	SSRF	Medium	Potential SSRF in parameter 'url'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:41:11.036075
524	14	Critical	SSRF	Medium	Potential SSRF in parameter 'link'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:41:11.037607
525	14	Critical	SSRF	Medium	Potential SSRF in parameter 'redirect'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:41:11.03918
526	14	Critical	SSRF	Medium	Potential SSRF in parameter 'uri'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:41:11.0404
527	14	Critical	SSRF	Medium	Potential SSRF in parameter 'path'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:41:11.041347
528	14	Critical	SSRF	Medium	Potential SSRF in parameter 'dest'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:41:11.042212
529	14	Critical	SSRF	Medium	Potential SSRF in parameter 'callback'	Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation	Attempted to fetch: http://169.254.169.254/latest/meta-data/ (status: 200)	GET	Request accepted	2026-02-10 16:41:11.04322
530	14	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 16:41:11.044014
531	14	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 16:41:11.04476
532	14	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 16:41:11.045614
533	14	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 16:41:11.046507
534	14	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: *	GET	Suspicious response	2026-02-10 16:41:11.047388
535	14	High	LDAP Injection	Low	Potential LDAP Injection	Escape LDAP special characters; use parameterized LDAP queries	LDAP payload: admin*	GET	Suspicious response	2026-02-10 16:41:11.048201
536	14	Critical	SSTI	High	Template Injection in parameter 'name'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 16:41:11.048941
537	14	Critical	SSTI	High	Template Injection in parameter 'template'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 16:41:11.049818
538	14	Critical	SSTI	High	Template Injection in parameter 'view'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 16:41:11.050785
539	14	Critical	SSTI	High	Template Injection in parameter 'page'	Never render user input directly in templates; use sandboxed template engines	Math executed: {{7*7}} = 49	GET	Template executed	2026-02-10 16:41:11.051701
540	14	Medium	Rate Limiting	Medium	No rate limiting detected (20 rapid requests succeeded)	Implement rate limiting per IP/user: 100 req/min for general, 5 req/min for login/auth endpoints	All 20 requests succeeded in 2.648421473s	GET	No protection	2026-02-10 16:41:11.052728
541	14	Info	Session Management	Low	Session fixation testing requires authenticated session	Regenerate session IDs after authentication	Manual testing required	N/A	Requires auth flow	2026-02-10 16:41:11.053699
542	14	Info	Session Security	Low	Session hijacking vectors require session analysis	Use strong session IDs (128+ bits), HttpOnly, Secure flags	Requires session inspection	N/A	Manual review	2026-02-10 16:41:11.054495
543	14	Medium	Default Credentials	Low	Login endpoint detected: /admin/login (manual testing recommended for default credentials)	Force password change on first login; disable default accounts; implement account lockout	Login form accessible	GET	Login form found	2026-02-10 16:41:11.055392
544	14	Info	MFA	High	Multi-Factor Authentication detected	Ensure MFA is enforced for all users (especially admins); prevent MFA bypass via password reset; log MFA events	MFA indicators present	GET	MFA available	2026-02-10 16:41:11.056373
545	14	Medium	API Rate Limiting	Medium	No rate limiting detected on /api (30 requests succeeded)	Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm	All 30 requests succeeded	GET	No rate limit	2026-02-10 16:41:11.057206
546	14	Info	Mass Assignment	Low	Mass assignment testing requires authenticated testing (manual review recommended)	Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments	Requires manual testing with valid account	POST	Requires auth	2026-02-10 16:41:11.058126
547	14	Medium	File Upload	Low	File upload functionality detected	Validate file types, scan for malware, restrict extensions, use random filenames	File input detected in HTML	GET	Detected	2026-02-10 16:41:11.059001
548	14	Info	File Upload	Low	File upload endpoint requires manual testing	Test with various file extensions, double extensions, content-type bypass	Upload form detected	POST	Requires manual test	2026-02-10 16:41:11.059926
549	14	High	IDOR	Low	Potential IDOR vulnerability in parameter 'id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: id=1	GET	Sequential access	2026-02-10 16:41:11.060724
550	14	High	IDOR	Low	Potential IDOR vulnerability in parameter 'user_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: user_id=1	GET	Sequential access	2026-02-10 16:41:11.061516
551	14	High	IDOR	Low	Potential IDOR vulnerability in parameter 'account_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: account_id=1	GET	Sequential access	2026-02-10 16:41:11.062388
552	14	High	IDOR	Low	Potential IDOR vulnerability in parameter 'order_id' (sequential IDs accessible)	Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership	Sequential ID access: order_id=1	GET	Sequential access	2026-02-10 16:41:11.063212
553	14	Medium	Price Manipulation	Low	E-commerce indicators detected (manual testing recommended for price manipulation)	Never trust client-side pricing; validate prices server-side; use signed/encrypted price tokens; log all price changes	Pricing-related fields detected	GET	Requires manual testing	2026-02-10 16:41:11.064014
554	14	Info	Race Conditions	Low	Race condition testing requires authenticated concurrent requests (manual testing recommended)	Implement database-level locking; use transactions; implement idempotency keys; add request deduplication	Requires authenticated testing	POST	Requires auth	2026-02-10 16:41:11.065152
555	14	High	Privilege Escalation	Low	Admin endpoint accessible: /admin/users (status: 200)	Implement role-based access control; verify privileges on every request; use least privilege principle	Admin path returned 200 without authentication	GET	Accessible	2026-02-10 16:41:11.065961
556	14	Info	Business Logic	Low	Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing	Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations	Requires authenticated user testing	Various	Manual testing required	2026-02-10 16:41:11.066728
557	14	Info	Certificate Pinning	Low	Certificate pinning requires mobile app analysis (static/dynamic)	Implement certificate pinning in mobile apps; use public key pinning; include backup pins	Requires mobile app testing	N/A	Manual testing required	2026-02-10 16:41:11.067534
558	14	Info	Root Detection	Low	Root/jailbreak detection requires mobile app analysis	Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries	Requires mobile app testing	N/A	Manual testing required	2026-02-10 16:41:11.068306
559	14	Info	App Hardening	Low	App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis	Implement: code obfuscation, anti-debugging, tamper detection, string encryption	Requires APK/IPA analysis	N/A	Manual testing required	2026-02-10 16:41:11.069606
560	14	Info	TLS Renegotiation	Low	TLS renegotiation requires specialized tools (testssl.sh, sslyze)	Disable insecure renegotiation; use RFC 5746 secure renegotiation	Requires advanced testing	TLS	Manual testing required	2026-02-10 16:41:11.070756
561	14	Info	Encryption at Rest	Low	Encryption at rest requires backend/database access for verification	Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage	Requires backend access	N/A	Cannot verify remotely	2026-02-10 16:41:11.071879
562	14	Critical	Cloud Metadata	Medium	Cloud metadata endpoint potentially accessible via SSRF	Block access to cloud metadata endpoints; use IMDSv2 (AWS); implement network segmentation	Metadata endpoint responded	GET	Accessible	2026-02-10 16:41:11.073137
563	14	Medium	GDPR	Low	No privacy policy link detected	Implement privacy policy; provide data processing information; enable user data rights (access, deletion)	Privacy policy not found	GET	Missing privacy policy	2026-02-10 16:41:11.074298
564	14	Low	GDPR	Low	No cookie consent banner detected	Implement cookie consent mechanism; allow users to reject non-essential cookies	Cookie consent not found	GET	Missing consent	2026-02-10 16:41:11.075096
565	14	Low	CCPA	Low	No 'Do Not Sell My Info' link detected (required for California users)	Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection	CCPA indicators not found	GET	Missing CCPA link	2026-02-10 16:41:11.075825
566	14	Info	PCI DSS	Low	Payment processing indicators detected (verify PCI DSS compliance)	PCI DSS requirements: encrypt cardholder data, maintain secure network, implement access controls, monitor networks, test security systems	Payment indicators found	GET	Payment detected	2026-02-10 16:41:11.076628
567	14	Info	Data Retention	Low	Data retention requires policy review and backend verification	Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods	Requires policy review	N/A	Manual review required	2026-02-10 16:41:11.077394
568	14	Medium	CDN Bypass	Low	Potential origin server disclosure (CDN bypass risk)	Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs	Origin indicators detected	GET	Potential bypass	2026-02-10 16:41:11.07822
569	14	Info	DNSSEC	Low	DNSSEC validation requires DNS query tools (dig +dnssec)	Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers	Requires DNS testing	N/A	Manual verification required	2026-02-10 16:41:11.078993
570	14	Info	Security Monitoring	Low	Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems	Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring	Requires infrastructure review	N/A	Manual verification required	2026-02-10 16:41:11.079788
\.


--
-- Data for Name: impact_assessments; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.impact_assessments (id, finding_id, business_impact, technical_impact, financial_impact, regulatory_impact, reputation_impact, likelihood_score, impact_score, overall_risk_score, created_at) FROM stdin;
\.


--
-- Data for Name: integrations; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.integrations (id, user_id, organization_id, integration_type, name, config, is_active, last_used, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: iso_mappings; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.iso_mappings (id, finding_id, control_id, control_name, standard, annex, created_at) FROM stdin;
\.


--
-- Data for Name: kill_chain_phases; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.kill_chain_phases (id, finding_id, phase, phase_order, description, created_at) FROM stdin;
\.


--
-- Data for Name: metrics; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.metrics (id, metric_name, metric_value, metric_type, target_id, scan_id, "timestamp", metadata) FROM stdin;
\.


--
-- Data for Name: mitre_mappings; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.mitre_mappings (id, finding_id, technique_id, technique_name, tactic, sub_technique_id, confidence, created_at) FROM stdin;
1	1	T1190	Exploit Public-Facing Application	Initial Access	\N	medium	2026-02-05 15:59:47.00896
\.


--
-- Data for Name: nist_mappings; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.nist_mappings (id, finding_id, control_family, control_id, control_name, framework, created_at) FROM stdin;
\.


--
-- Data for Name: notifications; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.notifications (id, user_id, notification_type, title, message, severity, is_read, related_resource_type, related_resource_id, created_at) FROM stdin;
\.


--
-- Data for Name: organizations; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.organizations (id, name, domain, subscription_tier, max_scans_per_month, max_users, settings, created_at, updated_at) FROM stdin;
1	Default Organization	localhost	pro	10	5	{}	2026-02-05 15:58:39.211057	2026-02-05 15:58:39.211057
\.


--
-- Data for Name: owasp_mappings; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.owasp_mappings (id, finding_id, owasp_id, owasp_category, owasp_year, confidence, created_at) FROM stdin;
1	1	A03	Injection	2021	high	2026-02-05 15:59:47.005325
\.


--
-- Data for Name: passive_intelligence; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.passive_intelligence (id, domain, started_at, completed_at, duration_seconds, modules_executed, modules_succeeded, modules_failed, dns_records, nameservers, mail_servers, dns_security, ssl_certificates, ip_addresses, s3_buckets, gcp_resources, azure_resources, tech_stack, social_profiles, raw_data, data_sources, created_at, updated_at) FROM stdin;
1	example.com	2026-02-10 16:48:27.96963	2026-02-10 16:48:28.786106	0.816476063	60	55	5	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	{"target": "example.com", "patents": null, "asn_info": null, "team_size": {"total": 0, "design": 0, "source": "", "product": 0, "confidence": "", "engineering": 0}, "ip_history": null, "s3_buckets": null, "started_at": "2026-02-10T16:48:27.969630483+05:30", "subdomains": null, "tech_stack": {"tools": null, "devops": null, "databases": null, "languages": null, "confidence": "", "frameworks": null, "cloud_platforms": null}, "trademarks": null, "dns_records": {"A": ["104.18.26.120", "104.18.27.120"], "MX": ["0 ."], "NS": ["hera.ns.cloudflare.com.", "elliott.ns.cloudflare.com."], "TXT": ["v=spf1 -all", "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"], "AAAA": ["2606:4700::6812:1a78", "2606:4700::6812:1b78"]}, "nameservers": ["hera.ns.cloudflare.com.", "elliott.ns.cloudflare.com."], "paste_leaks": null, "tls_history": null, "acquisitions": null, "company_info": {"name": "", "founded": "", "website": "", "industry": "", "description": "", "headquarters": "", "social_links": null, "employee_count": ""}, "completed_at": "2026-02-10T16:48:28.786106511+05:30", "data_sources": ["DNSDumpster", "LinkedIn", "AWS S3", "Azure Blob", "GCP Storage"], "dns_security": {"spf_record": "v=spf1 -all", "caa_records": [], "dmarc_record": "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s", "dkim_selectors": null, "dnssec_enabled": false}, "github_repos": null, "ip_addresses": [{"asn": 0, "isp": "", "type": "IPv4", "ports": null, "address": "104.18.26.120", "geolocation": {"city": "", "region": "", "country": "", "latitude": 0, "longitude": 0}}, {"asn": 0, "isp": "", "type": "IPv4", "ports": null, "address": "104.18.27.120", "geolocation": {"city": "", "region": "", "country": "", "latitude": 0, "longitude": 0}}, {"asn": 0, "isp": "", "type": "IPv6", "ports": null, "address": "2606:4700::6812:1a78", "geolocation": {"city": "", "region": "", "country": "", "latitude": 0, "longitude": 0}}, {"asn": 0, "isp": "", "type": "IPv6", "ports": null, "address": "2606:4700::6812:1b78", "geolocation": {"city": "", "region": "", "country": "", "latitude": 0, "longitude": 0}}], "job_postings": null, "mail_servers": ["."], "revenue_data": {"year": 0, "amount": 0, "source": "", "currency": "", "confidence": ""}, "secret_leaks": null, "threat_feeds": null, "aws_resources": null, "cdn_detection": {"detected": false, "provider": "", "indicators": null}, "code_exposure": null, "data_breaches": null, "docker_images": null, "email_history": null, "gcp_resources": null, "hacker_forums": null, "leaked_emails": null, "news_articles": null, "salary_ranges": null, "whois_history": null, "database_dumps": null, "domain_history": null, "facebook_pages": null, "funding_rounds": null, "glassdoor_data": {"rating": 0, "reviews": 0, "ceo_approval": 0, "recommend_percentage": 0}, "modules_failed": 5, "password_leaks": null, "press_releases": null, "azure_resources": null, "bitbucket_repos": null, "gitlab_projects": null, "reddit_presence": null, "risk_indicators": null, "social_profiles": [{"url": "https://linkedin.com/company/example-com", "platform": "LinkedIn", "username": "example com", "verified": false, "followers": 0, "description": "Company profile"}, {"url": "https://twitter.com/example", "platform": "Twitter", "username": "example", "verified": false, "followers": 0, "description": ""}, {"url": "https://facebook.com/example", "platform": "Facebook", "username": "example", "verified": false, "followers": 0, "description": ""}, {"url": "https://instagram.com/example", "platform": "Instagram", "username": "example", "verified": false, "followers": 0, "description": ""}], "darkweb_mentions": null, "duration_seconds": 0.816476063, "exploit_mentions": null, "malware_analysis": null, "modules_executed": 60, "ssl_certificates": [{"sans": ["example.com", "*.example.com"], "issuer": "CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US", "subject": "CN=example.com", "valid_to": "2026-03-16T18:32:44Z", "valid_from": "2025-12-16T19:39:32Z", "fingerprint": "", "key_algorithm": "ECDSA", "signature_algorithm": "ECDSA-SHA256"}, {"sans": null, "issuer": "CN=SSL.com TLS Transit ECC CA R2,O=SSL Corporation,C=US", "subject": "CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US", "valid_to": "2035-05-27T19:49:44Z", "valid_from": "2025-05-29T19:49:45Z", "fingerprint": "", "key_algorithm": "ECDSA", "signature_algorithm": "ECDSA-SHA384"}, {"sans": null, "issuer": "CN=SSL.com TLS ECC Root CA 2022,O=SSL Corporation,C=US", "subject": "CN=SSL.com TLS Transit ECC CA R2,O=SSL Corporation,C=US", "valid_to": "2037-10-17T17:02:22Z", "valid_from": "2022-10-21T17:02:23Z", "fingerprint": "", "key_algorithm": "ECDSA", "signature_algorithm": "ECDSA-SHA384"}, {"sans": null, "issuer": "CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB", "subject": "CN=SSL.com TLS ECC Root CA 2022,O=SSL Corporation,C=US", "valid_to": "2028-12-31T23:59:59Z", "valid_from": "2025-08-01T00:00:00Z", "fingerprint": "", "key_algorithm": "ECDSA", "signature_algorithm": "SHA256-RSA"}], "twitter_accounts": null, "youtube_channels": null, "linkedin_profiles": null, "modules_succeeded": 55, "wayback_snapshots": null, "instagram_accounts": null, "skill_requirements": null, "certificate_transparency": null, "cloudfront_distributions": null}	\N	2026-02-10 16:48:28.789919	2026-02-10 16:48:28.789919
\.


--
-- Data for Name: pci_dss_mappings; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.pci_dss_mappings (id, finding_id, requirement_id, requirement_name, version, created_at) FROM stdin;
\.


--
-- Data for Name: permissions; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.permissions (id, role_id, resource, action, created_at) FROM stdin;
\.


--
-- Data for Name: report_templates; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.report_templates (id, user_id, name, description, template_type, content, variables, is_default, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: reports; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.reports (id, user_id, scan_id, report_type, format, title, generated_at, file_path, file_size, metadata) FROM stdin;
\.


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.roles (id, name, description, permissions, created_at) FROM stdin;
1	admin	Full system access	{"all": ["*"]}	2026-02-05 15:58:39.209344
2	analyst	Can create scans and manage findings	{"scans": ["create", "read", "update"], "reports": ["create", "read"], "findings": ["create", "read", "update"]}	2026-02-05 15:58:39.209344
3	viewer	Read-only access	{"scans": ["read"], "reports": ["read"], "findings": ["read"]}	2026-02-05 15:58:39.209344
\.


--
-- Data for Name: scan_phases; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.scan_phases (id, scan_id, phase_name, status, progress, module_count, completed_modules, findings_count, started_at, completed_at, duration_seconds, error_message, metadata) FROM stdin;
\.


--
-- Data for Name: scans; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.scans (id, target_id, status, risk_score, risk_grade, started_at, completed_at, config, duration_seconds, config_mode, config_stealth_enabled, config_respect_robots_txt, created_at) FROM stdin;
1	1	completed	63	MEDIUM	2026-02-04 17:19:43.747959	2026-02-04 17:22:13.401007	\N	\N	safe	t	t	2026-02-04 17:19:43.748132
2	2	completed	36	MEDIUM	2026-02-04 17:30:28.883555	2026-02-04 17:32:28.059455	\N	\N	safe	t	t	2026-02-04 17:30:28.883598
3	1	completed	100	HIGH	2026-02-04 17:30:43.809712	2026-02-04 17:34:00.870317	\N	\N	normal	t	t	2026-02-04 17:30:43.809775
4	3	completed	100	HIGH	2026-02-05 11:42:33.462349	2026-02-05 11:45:03.029505	\N	\N	aggressive	t	t	2026-02-05 11:42:33.462508
5	4	completed	56	MEDIUM	2026-02-05 12:03:11.78538	2026-02-05 12:09:14.538545	\N	\N	aggressive	t	t	2026-02-05 12:03:11.785675
6	4	running	0		2026-02-05 16:09:09.393106	\N	\N	\N	aggressive	t	t	2026-02-05 16:09:09.393245
7	6	running	0		2026-02-06 18:50:29.896799	\N	\N	\N	safe	t	t	2026-02-06 18:50:29.896866
8	1	running	0		2026-02-09 11:23:27.959503	\N	\N	\N	aggressive	t	t	2026-02-09 11:23:27.959579
9	5	running	0		2026-02-09 11:49:17.820456	\N	\N	\N	aggressive	t	t	2026-02-09 11:49:17.820661
10	5	running	0		2026-02-09 17:38:22.979335	\N	\N	\N	aggressive	t	t	2026-02-09 17:38:22.979656
11	5	running	0		2026-02-10 15:31:51.068317	\N	\N	\N	aggressive	t	t	2026-02-10 15:31:51.068439
12	5	running	0		2026-02-10 15:59:13.966825	\N	\N	\N	aggressive	t	t	2026-02-10 15:59:13.967249
13	5	running	0		2026-02-10 16:37:56.07648	\N	\N	\N	aggressive	t	t	2026-02-10 16:37:56.076549
14	5	running	0		2026-02-10 16:40:54.052612	\N	\N	\N	aggressive	t	t	2026-02-10 16:40:54.052706
\.


--
-- Data for Name: scheduled_scans; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.scheduled_scans (id, user_id, target_id, schedule_name, cron_expression, scan_config, is_active, last_run, next_run, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: secrets; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.secrets (id, target_id, secret_type, pattern_matched, location, masked_value, is_verified, severity, discovered_at, metadata) FROM stdin;
\.


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at) FROM stdin;
\.


--
-- Data for Name: ssl_certificates; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.ssl_certificates (id, target_id, common_name, subject_alt_names, issuer, serial_number, not_before, not_after, signature_algorithm, key_size, is_expired, is_self_signed, certificate_pem, discovered_at) FROM stdin;
\.


--
-- Data for Name: subdomains; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.subdomains (id, target_id, subdomain, ip_address, status, source, technologies, http_status, title, discovered_at, last_checked, metadata) FROM stdin;
\.


--
-- Data for Name: target_groups; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.target_groups (id, user_id, name, description, target_ids, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: targets; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.targets (id, domain, created_at, updated_at) FROM stdin;
1	terralogic.com	2026-02-04 17:18:09.670521	2026-02-04 17:18:09.670521
2	example.com	2026-02-04 17:30:28.882755	2026-02-04 17:30:28.882755
3	blazeup.com	2026-02-05 11:42:33.447558	2026-02-05 11:42:33.447558
4	tesla.com	2026-02-05 12:03:11.771414	2026-02-05 12:03:11.771414
5	blazeup.ai	2026-02-06 15:39:25.682322	2026-02-06 15:39:25.682322
6	scantest.com	2026-02-06 18:50:01.880503	2026-02-06 18:50:01.880503
7	test123.com	2026-02-09 11:22:11.683313	2026-02-09 11:22:11.683313
\.


--
-- Data for Name: technologies; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.technologies (id, target_id, name, version, category, confidence, source, discovered_at, last_seen, metadata) FROM stdin;
\.


--
-- Data for Name: threat_indicators; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.threat_indicators (id, target_id, indicator_type, indicator_value, threat_type, confidence, source, first_seen, last_seen, metadata) FROM stdin;
\.


--
-- Data for Name: trends; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.trends (id, target_id, metric_name, time_period, data_points, calculated_at) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.users (id, email, password_hash, full_name, role, organization_id, is_active, last_login, created_at, updated_at) FROM stdin;
1	admin@nightfall.local	$2a$10$YourHashedPasswordHere	System Administrator	admin	1	t	\N	2026-02-05 15:59:46.987619	2026-02-05 15:59:46.987619
2	test@nightfall.local	$2a$10$yUsEbL0S2Cp049E9hqDHT.NW1rjtcCzQXOf.MQ9yJSSeHFI2oEOpe	Test User	analyst	\N	t	2026-02-10 16:48:27.950419	2026-02-06 11:02:10.410402	2026-02-10 16:48:27.950468
\.


--
-- Data for Name: webhooks; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.webhooks (id, user_id, url, event_types, secret_key, is_active, last_triggered, created_at) FROM stdin;
\.


--
-- Data for Name: whois_records; Type: TABLE DATA; Schema: public; Owner: nightfall
--

COPY public.whois_records (id, target_id, registrar, registered_date, expiration_date, updated_date, name_servers, registrant_name, registrant_email, registrant_organization, admin_email, tech_email, status, raw_data, discovered_at) FROM stdin;
\.


--
-- Name: api_calls_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.api_calls_id_seq', 1, false);


--
-- Name: api_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.api_keys_id_seq', 1, false);


--
-- Name: asset_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.asset_history_id_seq', 1, false);


--
-- Name: assets_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.assets_id_seq', 1, false);


--
-- Name: attack_paths_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.attack_paths_id_seq', 1, false);


--
-- Name: attack_scenarios_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.attack_scenarios_id_seq', 1, false);


--
-- Name: attack_techniques_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.attack_techniques_id_seq', 1, false);


--
-- Name: audit_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.audit_logs_id_seq', 1, false);


--
-- Name: benchmarks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.benchmarks_id_seq', 1, false);


--
-- Name: breaches_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.breaches_id_seq', 1, false);


--
-- Name: cis_mappings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.cis_mappings_id_seq', 1, false);


--
-- Name: cloud_resources_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.cloud_resources_id_seq', 1, false);


--
-- Name: code_repositories_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.code_repositories_id_seq', 1, false);


--
-- Name: dashboards_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.dashboards_id_seq', 1, false);


--
-- Name: dns_records_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.dns_records_id_seq', 1, false);


--
-- Name: false_positives_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.false_positives_id_seq', 1, false);


--
-- Name: finding_comments_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.finding_comments_id_seq', 1, false);


--
-- Name: finding_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.finding_history_id_seq', 1, false);


--
-- Name: findings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.findings_id_seq', 570, true);


--
-- Name: impact_assessments_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.impact_assessments_id_seq', 1, false);


--
-- Name: integrations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.integrations_id_seq', 1, false);


--
-- Name: iso_mappings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.iso_mappings_id_seq', 1, false);


--
-- Name: kill_chain_phases_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.kill_chain_phases_id_seq', 1, false);


--
-- Name: metrics_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.metrics_id_seq', 1, false);


--
-- Name: mitre_mappings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.mitre_mappings_id_seq', 1, true);


--
-- Name: nist_mappings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.nist_mappings_id_seq', 1, false);


--
-- Name: notifications_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.notifications_id_seq', 1, false);


--
-- Name: organizations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.organizations_id_seq', 1, true);


--
-- Name: owasp_mappings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.owasp_mappings_id_seq', 1, true);


--
-- Name: passive_intelligence_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.passive_intelligence_id_seq', 1, true);


--
-- Name: pci_dss_mappings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.pci_dss_mappings_id_seq', 1, false);


--
-- Name: permissions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.permissions_id_seq', 1, false);


--
-- Name: report_templates_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.report_templates_id_seq', 1, false);


--
-- Name: reports_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.reports_id_seq', 1, false);


--
-- Name: roles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.roles_id_seq', 3, true);


--
-- Name: scan_phases_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.scan_phases_id_seq', 1, false);


--
-- Name: scans_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.scans_id_seq', 14, true);


--
-- Name: scheduled_scans_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.scheduled_scans_id_seq', 1, false);


--
-- Name: secrets_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.secrets_id_seq', 1, false);


--
-- Name: sessions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.sessions_id_seq', 1, false);


--
-- Name: ssl_certificates_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.ssl_certificates_id_seq', 1, false);


--
-- Name: subdomains_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.subdomains_id_seq', 1, false);


--
-- Name: target_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.target_groups_id_seq', 1, false);


--
-- Name: targets_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.targets_id_seq', 7, true);


--
-- Name: technologies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.technologies_id_seq', 1, false);


--
-- Name: threat_indicators_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.threat_indicators_id_seq', 1, false);


--
-- Name: trends_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.trends_id_seq', 1, false);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.users_id_seq', 2, true);


--
-- Name: webhooks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.webhooks_id_seq', 1, false);


--
-- Name: whois_records_id_seq; Type: SEQUENCE SET; Schema: public; Owner: nightfall
--

SELECT pg_catalog.setval('public.whois_records_id_seq', 1, false);


--
-- Name: api_calls api_calls_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.api_calls
    ADD CONSTRAINT api_calls_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_key_hash_key; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: asset_history asset_history_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.asset_history
    ADD CONSTRAINT asset_history_pkey PRIMARY KEY (id);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);


--
-- Name: attack_paths attack_paths_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_pkey PRIMARY KEY (id);


--
-- Name: attack_scenarios attack_scenarios_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_scenarios
    ADD CONSTRAINT attack_scenarios_pkey PRIMARY KEY (id);


--
-- Name: attack_techniques attack_techniques_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_techniques
    ADD CONSTRAINT attack_techniques_pkey PRIMARY KEY (id);


--
-- Name: attack_techniques attack_techniques_technique_id_key; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_techniques
    ADD CONSTRAINT attack_techniques_technique_id_key UNIQUE (technique_id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: benchmarks benchmarks_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.benchmarks
    ADD CONSTRAINT benchmarks_pkey PRIMARY KEY (id);


--
-- Name: breaches breaches_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.breaches
    ADD CONSTRAINT breaches_pkey PRIMARY KEY (id);


--
-- Name: cis_mappings cis_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.cis_mappings
    ADD CONSTRAINT cis_mappings_pkey PRIMARY KEY (id);


--
-- Name: cloud_resources cloud_resources_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.cloud_resources
    ADD CONSTRAINT cloud_resources_pkey PRIMARY KEY (id);


--
-- Name: code_repositories code_repositories_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.code_repositories
    ADD CONSTRAINT code_repositories_pkey PRIMARY KEY (id);


--
-- Name: dashboards dashboards_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.dashboards
    ADD CONSTRAINT dashboards_pkey PRIMARY KEY (id);


--
-- Name: dns_records dns_records_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.dns_records
    ADD CONSTRAINT dns_records_pkey PRIMARY KEY (id);


--
-- Name: false_positives false_positives_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.false_positives
    ADD CONSTRAINT false_positives_pkey PRIMARY KEY (id);


--
-- Name: finding_comments finding_comments_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.finding_comments
    ADD CONSTRAINT finding_comments_pkey PRIMARY KEY (id);


--
-- Name: finding_history finding_history_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.finding_history
    ADD CONSTRAINT finding_history_pkey PRIMARY KEY (id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: impact_assessments impact_assessments_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.impact_assessments
    ADD CONSTRAINT impact_assessments_pkey PRIMARY KEY (id);


--
-- Name: integrations integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_pkey PRIMARY KEY (id);


--
-- Name: iso_mappings iso_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.iso_mappings
    ADD CONSTRAINT iso_mappings_pkey PRIMARY KEY (id);


--
-- Name: kill_chain_phases kill_chain_phases_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.kill_chain_phases
    ADD CONSTRAINT kill_chain_phases_pkey PRIMARY KEY (id);


--
-- Name: metrics metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.metrics
    ADD CONSTRAINT metrics_pkey PRIMARY KEY (id);


--
-- Name: mitre_mappings mitre_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.mitre_mappings
    ADD CONSTRAINT mitre_mappings_pkey PRIMARY KEY (id);


--
-- Name: nist_mappings nist_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.nist_mappings
    ADD CONSTRAINT nist_mappings_pkey PRIMARY KEY (id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: owasp_mappings owasp_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.owasp_mappings
    ADD CONSTRAINT owasp_mappings_pkey PRIMARY KEY (id);


--
-- Name: passive_intelligence passive_intelligence_domain_key; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.passive_intelligence
    ADD CONSTRAINT passive_intelligence_domain_key UNIQUE (domain);


--
-- Name: passive_intelligence passive_intelligence_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.passive_intelligence
    ADD CONSTRAINT passive_intelligence_pkey PRIMARY KEY (id);


--
-- Name: pci_dss_mappings pci_dss_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.pci_dss_mappings
    ADD CONSTRAINT pci_dss_mappings_pkey PRIMARY KEY (id);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);


--
-- Name: permissions permissions_role_id_resource_action_key; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_role_id_resource_action_key UNIQUE (role_id, resource, action);


--
-- Name: report_templates report_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.report_templates
    ADD CONSTRAINT report_templates_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: roles roles_name_key; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: scan_phases scan_phases_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scan_phases
    ADD CONSTRAINT scan_phases_pkey PRIMARY KEY (id);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: scheduled_scans scheduled_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scheduled_scans
    ADD CONSTRAINT scheduled_scans_pkey PRIMARY KEY (id);


--
-- Name: secrets secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);


--
-- Name: ssl_certificates ssl_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.ssl_certificates
    ADD CONSTRAINT ssl_certificates_pkey PRIMARY KEY (id);


--
-- Name: subdomains subdomains_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.subdomains
    ADD CONSTRAINT subdomains_pkey PRIMARY KEY (id);


--
-- Name: target_groups target_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.target_groups
    ADD CONSTRAINT target_groups_pkey PRIMARY KEY (id);


--
-- Name: targets targets_domain_key; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_domain_key UNIQUE (domain);


--
-- Name: targets targets_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_pkey PRIMARY KEY (id);


--
-- Name: technologies technologies_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.technologies
    ADD CONSTRAINT technologies_pkey PRIMARY KEY (id);


--
-- Name: threat_indicators threat_indicators_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.threat_indicators
    ADD CONSTRAINT threat_indicators_pkey PRIMARY KEY (id);


--
-- Name: trends trends_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.trends
    ADD CONSTRAINT trends_pkey PRIMARY KEY (id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: webhooks webhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_pkey PRIMARY KEY (id);


--
-- Name: whois_records whois_records_pkey; Type: CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.whois_records
    ADD CONSTRAINT whois_records_pkey PRIMARY KEY (id);


--
-- Name: idx_api_calls_created; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_api_calls_created ON public.api_calls USING btree (created_at);


--
-- Name: idx_api_calls_key; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_api_calls_key ON public.api_calls USING btree (api_key_id);


--
-- Name: idx_api_keys_hash; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_api_keys_hash ON public.api_keys USING btree (key_hash);


--
-- Name: idx_assets_target; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_assets_target ON public.assets USING btree (target_id);


--
-- Name: idx_assets_type; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_assets_type ON public.assets USING btree (asset_type);


--
-- Name: idx_audit_logs_created; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_audit_logs_created ON public.audit_logs USING btree (created_at);


--
-- Name: idx_audit_logs_user; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_audit_logs_user ON public.audit_logs USING btree (user_id);


--
-- Name: idx_cloud_resources_target; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_cloud_resources_target ON public.cloud_resources USING btree (target_id);


--
-- Name: idx_dns_records_target; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_dns_records_target ON public.dns_records USING btree (target_id);


--
-- Name: idx_finding_comments_finding; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_finding_comments_finding ON public.finding_comments USING btree (finding_id);


--
-- Name: idx_findings_category; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_findings_category ON public.findings USING btree (category);


--
-- Name: idx_findings_created; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_findings_created ON public.findings USING btree (created_at);


--
-- Name: idx_findings_finding_trgm; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_findings_finding_trgm ON public.findings USING gin (finding public.gin_trgm_ops);


--
-- Name: idx_findings_scan; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_findings_scan ON public.findings USING btree (scan_id);


--
-- Name: idx_findings_scan_id; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_findings_scan_id ON public.findings USING btree (scan_id);


--
-- Name: idx_findings_severity; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_findings_severity ON public.findings USING btree (severity);


--
-- Name: idx_integrations_user; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_integrations_user ON public.integrations USING btree (user_id);


--
-- Name: idx_mitre_mappings_finding; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_mitre_mappings_finding ON public.mitre_mappings USING btree (finding_id);


--
-- Name: idx_notifications_read; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_notifications_read ON public.notifications USING btree (is_read);


--
-- Name: idx_notifications_user; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_notifications_user ON public.notifications USING btree (user_id);


--
-- Name: idx_owasp_mappings_finding; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_owasp_mappings_finding ON public.owasp_mappings USING btree (finding_id);


--
-- Name: idx_passive_completed; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_passive_completed ON public.passive_intelligence USING btree (completed_at DESC);


--
-- Name: idx_passive_domain; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_passive_domain ON public.passive_intelligence USING btree (domain);


--
-- Name: idx_scan_phases_scan; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_scan_phases_scan ON public.scan_phases USING btree (scan_id);


--
-- Name: idx_scans_created; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_scans_created ON public.scans USING btree (created_at);


--
-- Name: idx_scans_status; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_scans_status ON public.scans USING btree (status);


--
-- Name: idx_scans_target; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_scans_target ON public.scans USING btree (target_id);


--
-- Name: idx_scans_target_id; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_scans_target_id ON public.scans USING btree (target_id);


--
-- Name: idx_scheduled_scans_next_run; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_scheduled_scans_next_run ON public.scheduled_scans USING btree (next_run);


--
-- Name: idx_scheduled_scans_user; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_scheduled_scans_user ON public.scheduled_scans USING btree (user_id);


--
-- Name: idx_secrets_target; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_secrets_target ON public.secrets USING btree (target_id);


--
-- Name: idx_sessions_token; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_sessions_token ON public.sessions USING btree (token_hash);


--
-- Name: idx_ssl_certificates_target; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_ssl_certificates_target ON public.ssl_certificates USING btree (target_id);


--
-- Name: idx_subdomains_subdomain; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_subdomains_subdomain ON public.subdomains USING btree (subdomain);


--
-- Name: idx_subdomains_target; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_subdomains_target ON public.subdomains USING btree (target_id);


--
-- Name: idx_targets_domain; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_targets_domain ON public.targets USING btree (domain);


--
-- Name: idx_technologies_name; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_technologies_name ON public.technologies USING btree (name);


--
-- Name: idx_technologies_target; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_technologies_target ON public.technologies USING btree (target_id);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: idx_users_organization; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_users_organization ON public.users USING btree (organization_id);


--
-- Name: idx_webhooks_user; Type: INDEX; Schema: public; Owner: nightfall
--

CREATE INDEX idx_webhooks_user ON public.webhooks USING btree (user_id);


--
-- Name: dashboards update_dashboards_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_dashboards_updated_at BEFORE UPDATE ON public.dashboards FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: finding_comments update_finding_comments_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_finding_comments_updated_at BEFORE UPDATE ON public.finding_comments FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: findings update_findings_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON public.findings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: integrations update_integrations_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_integrations_updated_at BEFORE UPDATE ON public.integrations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: organizations update_organizations_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON public.organizations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: report_templates update_report_templates_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_report_templates_updated_at BEFORE UPDATE ON public.report_templates FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: scans update_scans_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON public.scans FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: scheduled_scans update_scheduled_scans_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_scheduled_scans_updated_at BEFORE UPDATE ON public.scheduled_scans FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: target_groups update_target_groups_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_target_groups_updated_at BEFORE UPDATE ON public.target_groups FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: targets update_targets_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_targets_updated_at BEFORE UPDATE ON public.targets FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: users update_users_updated_at; Type: TRIGGER; Schema: public; Owner: nightfall
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();


--
-- Name: api_calls api_calls_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.api_calls
    ADD CONSTRAINT api_calls_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES public.api_keys(id) ON DELETE CASCADE;


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: asset_history asset_history_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.asset_history
    ADD CONSTRAINT asset_history_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: assets assets_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: attack_paths attack_paths_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: attack_paths attack_paths_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: attack_scenarios attack_scenarios_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.attack_scenarios
    ADD CONSTRAINT attack_scenarios_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: audit_logs audit_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: breaches breaches_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.breaches
    ADD CONSTRAINT breaches_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: cis_mappings cis_mappings_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.cis_mappings
    ADD CONSTRAINT cis_mappings_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: cloud_resources cloud_resources_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.cloud_resources
    ADD CONSTRAINT cloud_resources_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: code_repositories code_repositories_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.code_repositories
    ADD CONSTRAINT code_repositories_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: dashboards dashboards_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.dashboards
    ADD CONSTRAINT dashboards_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: dns_records dns_records_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.dns_records
    ADD CONSTRAINT dns_records_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: false_positives false_positives_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.false_positives
    ADD CONSTRAINT false_positives_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: false_positives false_positives_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.false_positives
    ADD CONSTRAINT false_positives_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: finding_comments finding_comments_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.finding_comments
    ADD CONSTRAINT finding_comments_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: finding_comments finding_comments_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.finding_comments
    ADD CONSTRAINT finding_comments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: finding_history finding_history_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.finding_history
    ADD CONSTRAINT finding_history_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: finding_history finding_history_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.finding_history
    ADD CONSTRAINT finding_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: findings findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: impact_assessments impact_assessments_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.impact_assessments
    ADD CONSTRAINT impact_assessments_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: integrations integrations_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: integrations integrations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: iso_mappings iso_mappings_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.iso_mappings
    ADD CONSTRAINT iso_mappings_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: kill_chain_phases kill_chain_phases_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.kill_chain_phases
    ADD CONSTRAINT kill_chain_phases_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: metrics metrics_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.metrics
    ADD CONSTRAINT metrics_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: metrics metrics_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.metrics
    ADD CONSTRAINT metrics_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: mitre_mappings mitre_mappings_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.mitre_mappings
    ADD CONSTRAINT mitre_mappings_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: nist_mappings nist_mappings_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.nist_mappings
    ADD CONSTRAINT nist_mappings_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: notifications notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: owasp_mappings owasp_mappings_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.owasp_mappings
    ADD CONSTRAINT owasp_mappings_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: pci_dss_mappings pci_dss_mappings_finding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.pci_dss_mappings
    ADD CONSTRAINT pci_dss_mappings_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: permissions permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: report_templates report_templates_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.report_templates
    ADD CONSTRAINT report_templates_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: reports reports_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: reports reports_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: scan_phases scan_phases_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scan_phases
    ADD CONSTRAINT scan_phases_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: scans scans_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: scheduled_scans scheduled_scans_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scheduled_scans
    ADD CONSTRAINT scheduled_scans_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: scheduled_scans scheduled_scans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.scheduled_scans
    ADD CONSTRAINT scheduled_scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: secrets secrets_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: ssl_certificates ssl_certificates_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.ssl_certificates
    ADD CONSTRAINT ssl_certificates_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: subdomains subdomains_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.subdomains
    ADD CONSTRAINT subdomains_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: target_groups target_groups_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.target_groups
    ADD CONSTRAINT target_groups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: technologies technologies_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.technologies
    ADD CONSTRAINT technologies_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: threat_indicators threat_indicators_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.threat_indicators
    ADD CONSTRAINT threat_indicators_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: trends trends_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.trends
    ADD CONSTRAINT trends_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: webhooks webhooks_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: whois_records whois_records_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: nightfall
--

ALTER TABLE ONLY public.whois_records
    ADD CONSTRAINT whois_records_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: nightfall
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO nightfall;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

\unrestrict 8ErSWEMpzRPKWidBGIRgI26RlYBh7pKKPaqAlKBRyf4EcY9P39Ghq4kD8wxlFcb

