-- Stage 5: case files with Row-Level Security that mirrors packages/policy.
-- Runs as casefile_migrator (owner). The API connects as casefile_app (not owner, no BYPASSRLS).
-- Vocabulary below must equal packages/policy; tests/api-db/src/drift.test.ts fails the build if it drifts.
-- Forward-only: there is no down migration on purpose (a security schema is never "rolled back" by dropping policies).

CREATE TYPE classification AS ENUM ('OFFICIAL', 'CONFIDENTIAL', 'SECRET');   -- order = clearance rank
CREATE TYPE case_status AS ENUM ('draft', 'submitted', 'approved');

-- RBAC matrix as data. Mirrors ROLE_GRANTS in packages/policy (drift test). Read-only for the app role.
CREATE TABLE role_grants (
  role        text    NOT NULL,
  action      text    NOT NULL,
  cross_unit  boolean NOT NULL DEFAULT false,  -- may perform this write on another unit's file
  own_only    boolean NOT NULL DEFAULT false,  -- limited to files the subject authored
  break_glass boolean NOT NULL DEFAULT false,  -- (role, 'read') only: may request break-glass
  PRIMARY KEY (role, action)
);
INSERT INTO role_grants (role, action, cross_unit, own_only, break_glass) VALUES
  ('analyst',        'create',      false, false, false),
  ('analyst',        'read',        false, false, false),
  ('analyst',        'update',      false, true,  false),
  ('analyst',        'submit',      false, true,  false),
  ('analyst',        'delete',      false, true,  false),
  ('analyst',        'export',      false, false, false),
  ('reviewer',       'read',        false, false, false),
  ('reviewer',       'approve',     true,  false, false),
  ('reviewer',       'export',      false, false, false),
  ('unit-admin',     'create',      false, false, false),
  ('unit-admin',     'read',        false, false, true),
  ('unit-admin',     'update',      false, false, false),
  ('unit-admin',     'submit',      false, false, false),
  ('unit-admin',     'approve',     false, false, false),
  ('unit-admin',     'delete',      false, false, false),
  ('unit-admin',     'export',      false, false, false),
  ('unit-admin',     'manageUsers', false, false, false),
  ('auditor',        'readAudit',   false, false, false),
  ('platform-admin', 'manageUsers', false, false, false);

CREATE FUNCTION compartments_valid(c text[]) RETURNS boolean
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public
  AS $$ SELECT c IS NOT NULL AND cardinality(c) <= 16 AND NOT EXISTS (SELECT 1 FROM unnest(c) AS t(x) WHERE x IS NULL OR x !~ '^[A-Za-z0-9_-]{1,32}$') $$;

CREATE TABLE case_files (
  id              uuid           PRIMARY KEY DEFAULT gen_random_uuid(),
  title           text           NOT NULL CHECK (char_length(title) BETWEEN 1 AND 100),
  body            text           NOT NULL DEFAULT '' CHECK (char_length(body) <= 100000),
  classification  classification NOT NULL,
  unit            text           NOT NULL CHECK (unit ~ '^[A-Za-z0-9_-]{1,32}$'),
  compartments    text[]         NOT NULL DEFAULT '{}' CHECK (compartments_valid(compartments)),
  status          case_status    NOT NULL DEFAULT 'draft',
  author_id       text           NOT NULL CHECK (author_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  submitted_by_id text           CHECK (submitted_by_id IS NULL OR submitted_by_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  version         integer        NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at      timestamptz    NOT NULL DEFAULT now(),
  updated_at      timestamptz    NOT NULL DEFAULT now(),
  CHECK ((status = 'draft') = (submitted_by_id IS NULL))   -- a submitted or approved file always records who submitted it
);
CREATE INDEX case_files_unit_idx ON case_files (unit);
CREATE INDEX case_files_class_idx ON case_files (classification);

-- Request context. The API sets these with set_config(..., is_local => true) inside the transaction that runs the query.
-- Missing, empty or malformed context makes every function below false/empty, so every policy denies (fail closed).
-- Custom settings read back as '' (not NULL) once a transaction that set them has ended, so '' is treated as missing.
CREATE FUNCTION app_ctx_ok() RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT coalesce(current_setting('app.ctx', true), '') = 'v1'
     AND coalesce(current_setting('app.sub', true), '') <> ''
     AND coalesce(current_setting('app.unit', true), '') <> ''
     AND coalesce(current_setting('app.clearance', true), '') IN ('OFFICIAL', 'CONFIDENTIAL', 'SECRET')
$$;
CREATE FUNCTION app_sub() RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$ SELECT coalesce(current_setting('app.sub', true), '') $$;
CREATE FUNCTION app_unit() RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$ SELECT coalesce(current_setting('app.unit', true), '') $$;
CREATE FUNCTION app_clearance() RETURNS classification LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT CASE WHEN app_ctx_ok() THEN current_setting('app.clearance', true)::classification END
$$;
CREATE FUNCTION app_roles() RETURNS text[] LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$ SELECT string_to_array(coalesce(current_setting('app.roles', true), ''), ',') $$;
CREATE FUNCTION app_compartments() RETURNS text[] LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$ SELECT string_to_array(coalesce(current_setting('app.compartments', true), ''), ',') $$;
CREATE FUNCTION app_amr() RETURNS text[] LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$ SELECT string_to_array(coalesce(current_setting('app.amr', true), ''), ',') $$;
-- step-up: acr == mfa AND amr contains otp (packages/policy: abac.step-up)
CREATE FUNCTION app_mfa() RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT coalesce(current_setting('app.acr', true), '') = 'mfa' AND 'otp' = ANY (app_amr())
$$;
-- break-glass: only meaningful for reads. The API sets it after validating the request; a blank justification never counts.
CREATE FUNCTION app_break_glass() RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT coalesce(current_setting('app.break_glass', true), '') = 'on'
     AND char_length(btrim(coalesce(current_setting('app.bg_justification', true), ''))) > 0
$$;

-- Role grants. Unknown roles match no row, so they carry no grants.
CREATE FUNCTION role_allows(a text) RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM role_grants g WHERE g.action = a AND g.role = ANY (app_roles()))
$$;
CREATE FUNCTION role_cross_unit(a text) RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM role_grants g WHERE g.action = a AND g.cross_unit AND g.role = ANY (app_roles()))
$$;
-- ownership binds only if every role that grants the action is own-only for it
CREATE FUNCTION role_own_only(a text) RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT role_allows(a) AND NOT EXISTS (SELECT 1 FROM role_grants g WHERE g.action = a AND NOT g.own_only AND g.role = ANY (app_roles()))
$$;
CREATE FUNCTION role_break_glass() RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM role_grants g WHERE g.action = 'read' AND g.break_glass AND g.role = ANY (app_roles()))
$$;

-- The three subject-vs-resource rules every case-file action shares: clearance floor, need-to-know, step-up for SECRET.
-- Without break-glass. (packages/policy: abac.clearance-floor, abac.need-to-know, abac.step-up)
CREATE FUNCTION app_cleared(c classification, comps text[]) RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT app_ctx_ok() AND c <= app_clearance() AND comps <@ app_compartments() AND (c <> 'SECRET' OR app_mfa())
$$;

-- Row security. FORCE applies it to the owner as well: even the migrator role sees no rows without a context.
ALTER TABLE case_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_files FORCE ROW LEVEL SECURITY;

-- read: floor + need-to-know + step-up, or break-glass over need-to-know only (never the floor, never step-up)
CREATE POLICY case_files_select ON case_files FOR SELECT TO casefile_app USING (
  app_ctx_ok() AND role_allows('read') AND classification <= app_clearance() AND (classification <> 'SECRET' OR app_mfa())
  AND (compartments <@ app_compartments() OR (app_break_glass() AND role_break_glass()))
);

-- create: role, floor, need-to-know, step-up, own unit (or cross-unit role), author is the caller, born as a draft
CREATE POLICY case_files_insert ON case_files FOR INSERT TO casefile_app WITH CHECK (
  app_cleared(classification, compartments) AND role_allows('create')
  AND (unit = app_unit() OR role_cross_unit('create'))
  AND author_id = app_sub() AND status = 'draft' AND submitted_by_id IS NULL AND version = 1
);

-- update, submit, approve: coarse row filter here (role has one of them, cleared, unit scope);
-- the per-action rules need OLD and NEW and live in the case_files_guard trigger below.
CREATE POLICY case_files_update ON case_files FOR UPDATE TO casefile_app USING (
  app_cleared(classification, compartments) AND (role_allows('update') OR role_allows('submit') OR role_allows('approve'))
  AND (unit = app_unit() OR role_cross_unit('update') OR role_cross_unit('submit') OR role_cross_unit('approve'))
) WITH CHECK (
  app_cleared(classification, compartments) AND (role_allows('update') OR role_allows('submit') OR role_allows('approve'))
  AND (unit = app_unit() OR role_cross_unit('update') OR role_cross_unit('submit') OR role_cross_unit('approve'))
);

-- delete: role, cleared, draft only, unit scope, ownership for own-only roles
CREATE POLICY case_files_delete ON case_files FOR DELETE TO casefile_app USING (
  app_cleared(classification, compartments) AND role_allows('delete') AND status = 'draft'
  AND (unit = app_unit() OR role_cross_unit('delete'))
  AND (NOT role_own_only('delete') OR author_id = app_sub())
);

-- Per-action update rules (packages/policy): which action an UPDATE is is derived from the status change.
CREATE FUNCTION case_files_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  act text;
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.author_id IS DISTINCT FROM OLD.author_id
     OR NEW.classification IS DISTINCT FROM OLD.classification OR NEW.unit IS DISTINCT FROM OLD.unit
     OR NEW.compartments IS DISTINCT FROM OLD.compartments OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'policy: IMMUTABLE_COLUMN' USING ERRCODE = '42501';
  END IF;

  IF NEW.status = OLD.status THEN
    act := 'update';
    IF OLD.status <> 'draft' THEN RAISE EXCEPTION 'policy: STATUS_FORBIDS' USING ERRCODE = '42501'; END IF;
    NEW.submitted_by_id := OLD.submitted_by_id;
  ELSIF OLD.status = 'draft' AND NEW.status = 'submitted' THEN
    act := 'submit';
    NEW.submitted_by_id := app_sub();             -- recorded by the database, never taken from the statement
  ELSIF OLD.status = 'submitted' AND NEW.status = 'approved' THEN
    act := 'approve';
    NEW.submitted_by_id := OLD.submitted_by_id;
  ELSE
    RAISE EXCEPTION 'policy: STATUS_FORBIDS' USING ERRCODE = '42501';
  END IF;

  IF NOT role_allows(act) THEN RAISE EXCEPTION 'policy: ROLE_NOT_PERMITTED' USING ERRCODE = '42501'; END IF;
  IF OLD.unit <> app_unit() AND NOT role_cross_unit(act) THEN RAISE EXCEPTION 'policy: UNIT_MISMATCH' USING ERRCODE = '42501'; END IF;
  IF role_own_only(act) AND OLD.author_id <> app_sub() THEN RAISE EXCEPTION 'policy: NOT_OWNER' USING ERRCODE = '42501'; END IF;
  IF act = 'approve' AND (OLD.author_id = app_sub() OR OLD.submitted_by_id = app_sub()) THEN
    RAISE EXCEPTION 'policy: SEPARATION_OF_DUTIES' USING ERRCODE = '42501';
  END IF;

  NEW.version := OLD.version + 1;
  NEW.updated_at := now();
  RETURN NEW;
END $$;
CREATE TRIGGER case_files_guard BEFORE UPDATE ON case_files FOR EACH ROW EXECUTE FUNCTION case_files_guard();

-- Grants: nothing by default, then exactly what the API needs. No TRUNCATE, no REFERENCES, no TRIGGER, no DDL.
REVOKE ALL ON case_files, role_grants FROM PUBLIC;
GRANT SELECT ON role_grants TO casefile_app;
GRANT SELECT, DELETE ON case_files TO casefile_app;
GRANT INSERT (title, body, classification, unit, compartments, author_id, status) ON case_files TO casefile_app;
GRANT UPDATE (title, body, status) ON case_files TO casefile_app;
