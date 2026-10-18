-- Stage 8: attachments of case files. Metadata only; the bytes live on a dedicated volume under a random key (never a user-chosen name).
-- Row security mirrors the parent: whoever may read the case file may see its attachment rows, nobody else, with the same step-up, need-to-know
-- and break-glass rules, because the policy asks case_files itself (its own forced RLS applies inside the subquery).

-- audit details: four more keys for attachment events (keep equal to DETAIL_KEYS in packages/audit; a test compares both)
CREATE OR REPLACE FUNCTION audit_details_ok(d jsonb) RETURNS boolean
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public
  AS $$ SELECT jsonb_typeof(d) = 'object' AND length(d::text) <= 4000 AND NOT EXISTS (
          SELECT 1 FROM jsonb_object_keys(d) AS k(key)
          WHERE k.key NOT IN ('justification', 'alert', 'rule_ids', 'authoritative', 'event', 'count', 'format', 'filters', 'from_id', 'to_id', 'truncated', 'acr', 'detail_code', 'size', 'sha256', 'media', 'scan')) $$;

CREATE TYPE attachment_status AS ENUM ('pending', 'clean', 'quarantined');   -- only 'clean' can be downloaded; anything unscanned or unclear stays pending

CREATE TABLE attachments (
  id             uuid              PRIMARY KEY DEFAULT gen_random_uuid(),
  case_file_id   uuid              NOT NULL REFERENCES case_files (id) ON DELETE RESTRICT,   -- a draft with attachments cannot be deleted: evidence stays
  display_name   text              NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120 AND display_name !~ '[[:cntrl:]/\\]'),
  media_type     text              NOT NULL CHECK (media_type IN ('application/pdf', 'image/png', 'image/jpeg', 'text/plain')),
  size_bytes     integer           NOT NULL CHECK (size_bytes BETWEEN 1 AND 26214400),
  sha256         bytea             NOT NULL CHECK (octet_length(sha256) = 32),
  storage_key    text              NOT NULL UNIQUE CHECK (storage_key ~ '^[0-9a-f]{32}$'),
  status         attachment_status NOT NULL DEFAULT 'pending',
  scan_detail    text              CHECK (scan_detail IS NULL OR scan_detail ~ '^[A-Za-z0-9_.:-]{1,64}$'),
  uploaded_by_id text              NOT NULL CHECK (uploaded_by_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  created_at     timestamptz       NOT NULL DEFAULT now(),
  scanned_at     timestamptz,
  CHECK ((status = 'pending') = (scanned_at IS NULL))
);
CREATE INDEX attachments_case_idx ON attachments (case_file_id, created_at);

ALTER TABLE attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE attachments FORCE ROW LEVEL SECURITY;

-- read: the caller may read the parent (the subquery goes through case_files_select: floor, need-to-know, step-up, break-glass)
CREATE POLICY attachments_select ON attachments FOR SELECT TO casefile_app USING (
  app_ctx_ok() AND role_allows('read')
  AND EXISTS (SELECT 1 FROM case_files c WHERE c.id = case_file_id)
);

-- insert: the caller may update the parent (a draft in the caller's unit, own file for own-only roles, cleared) and is the uploader; born pending
CREATE POLICY attachments_insert ON attachments FOR INSERT TO casefile_app WITH CHECK (
  app_ctx_ok() AND role_allows('update') AND uploaded_by_id = app_sub() AND status = 'pending' AND scanned_at IS NULL
  AND EXISTS (
    SELECT 1 FROM case_files c
    WHERE c.id = case_file_id AND c.status = 'draft' AND app_cleared(c.classification, c.compartments)
      AND (c.unit = app_unit() OR role_cross_unit('update'))
      AND (NOT role_own_only('update') OR c.author_id = app_sub())
  )
);

-- scan verdict: the uploader's request records pending -> clean | quarantined, once (the trigger below pins everything else)
CREATE POLICY attachments_verdict ON attachments FOR UPDATE TO casefile_app USING (
  app_ctx_ok() AND uploaded_by_id = app_sub() AND status = 'pending'
  AND EXISTS (SELECT 1 FROM case_files c WHERE c.id = case_file_id)
) WITH CHECK (app_ctx_ok() AND uploaded_by_id = app_sub());

CREATE FUNCTION attachments_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF OLD.status <> 'pending' OR NEW.status NOT IN ('clean', 'quarantined') OR NEW.scanned_at IS NULL THEN
    RAISE EXCEPTION 'attachment verdicts are final' USING ERRCODE = '42501';
  END IF;
  IF (NEW.id, NEW.case_file_id, NEW.display_name, NEW.media_type, NEW.size_bytes, NEW.sha256, NEW.storage_key, NEW.uploaded_by_id, NEW.created_at)
     IS DISTINCT FROM (OLD.id, OLD.case_file_id, OLD.display_name, OLD.media_type, OLD.size_bytes, OLD.sha256, OLD.storage_key, OLD.uploaded_by_id, OLD.created_at) THEN
    RAISE EXCEPTION 'only the scan verdict of an attachment can change' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER attachments_guard BEFORE UPDATE ON attachments FOR EACH ROW EXECUTE FUNCTION attachments_guard();

-- privileges: no DELETE and no TRUNCATE for the app role; UPDATE only on the verdict columns
GRANT SELECT, INSERT ON attachments TO casefile_app;
GRANT UPDATE (status, scan_detail, scanned_at) ON attachments TO casefile_app;
