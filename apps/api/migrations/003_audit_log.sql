-- Stage 7: append-only, hash-chained audit log. See docs/audit.md for the chain format (acl-audit/v1) so a third party can re-verify it.
--
-- Writers: casefile_app (source 'api') and casefile_web (source 'bff') may INSERT, nothing else. Readers: casefile_app for auditors only (through the
-- request context, like case files) and casefile_audit (the verifier, everything, read-only). Nobody can UPDATE, DELETE or TRUNCATE: no grant, and
-- triggers refuse it for every role including the owner. The only way around the triggers is a superuser or owner disabling them (the documented break
-- procedure); the HMAC chain makes any such edit detectable afterwards.

CREATE FUNCTION audit_details_ok(d jsonb) RETURNS boolean
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public
  AS $$ SELECT jsonb_typeof(d) = 'object' AND length(d::text) <= 4000 AND NOT EXISTS (
          SELECT 1 FROM jsonb_object_keys(d) AS k(key)
          WHERE k.key NOT IN ('justification', 'alert', 'rule_ids', 'authoritative', 'event', 'count', 'format', 'filters', 'from_id', 'to_id', 'truncated', 'acr', 'detail_code')) $$;

CREATE FUNCTION audit_tags_ok(a text[], max_items int) RETURNS boolean
  LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public
  AS $$ SELECT a IS NOT NULL AND cardinality(a) <= max_items AND NOT EXISTS (SELECT 1 FROM unnest(a) AS t(x) WHERE x IS NULL OR x !~ '^[A-Za-z0-9_.:-]{1,64}$') $$;

-- id is assigned by the chain writer (1, 2, 3, ...), not by an identity column: sequences skip values when a transaction rolls back,
-- and a gap-free id is what lets the verifier tell "deleted row" from "rolled back insert".
CREATE TABLE audit_log (
  id            bigint      PRIMARY KEY CHECK (id >= 1),
  ts            timestamptz NOT NULL,
  actor_sub     text        NOT NULL CHECK (actor_sub ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  actor_roles   text[]      NOT NULL CHECK (audit_tags_ok(actor_roles, 16)),
  action        text        NOT NULL CHECK (action ~ '^[A-Za-z][A-Za-z0-9_.-]{0,63}$'),
  resource_type text        NOT NULL CHECK (resource_type ~ '^[a-z_]{1,32}$'),
  resource_id   text        CHECK (resource_id IS NULL OR resource_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  effect        text        NOT NULL CHECK (effect IN ('allow', 'deny')),
  reason_code   text        NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  obligations   text[]      NOT NULL CHECK (audit_tags_ok(obligations, 8)),
  request_id    text        NOT NULL CHECK (request_id ~ '^[A-Za-z0-9-]{8,64}$'),
  source        text        NOT NULL CHECK (source IN ('api', 'bff')),
  details       jsonb       NOT NULL CHECK (audit_details_ok(details)),
  prev_hash     bytea       NOT NULL CHECK (octet_length(prev_hash) = 32),
  key_id        text        NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_.-]{1,32}$'),
  hash          bytea       NOT NULL CHECK (octet_length(hash) = 32)
);
CREATE INDEX audit_log_ts_idx ON audit_log (ts);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_sub, id);
CREATE INDEX audit_log_resource_idx ON audit_log (resource_id, id);

-- The chain head: where the next row must attach. Changed only by the insert trigger below (never by a client).
CREATE TABLE audit_head (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  last_id   bigint  NOT NULL,
  last_hash bytea   NOT NULL CHECK (octet_length(last_hash) = 32)
);
-- genesis: SHA-256 of the ASCII string 'acl-audit/v1 genesis' (packages/audit/src/model.ts GENESIS_HASH_HEX; a test compares both)
INSERT INTO audit_head (last_id, last_hash) VALUES (0, decode('4c28ebab5bc198ff48266a7625eaaeddd4f860656eaa34dd2f89b8579441a465', 'hex'));

-- Signed snapshots of the head. A checkpoint outlives a truncated tail: rows deleted after it was taken are detectable, and an exported copy outside
-- the database makes even deleting the checkpoints detectable.
CREATE TABLE audit_checkpoints (
  id        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts        timestamptz NOT NULL,
  last_id   bigint      NOT NULL CHECK (last_id >= 0),
  last_hash bytea       NOT NULL CHECK (octet_length(last_hash) = 32),
  key_id    text        NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_.-]{1,32}$'),
  mac       bytea       NOT NULL CHECK (octet_length(mac) = 32)
);

-- Immutability: refused for every role, owner and superuser included (triggers fire for them too).
CREATE FUNCTION audit_reject_change() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '42501';
END $$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_reject_change();
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_reject_change();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log FOR EACH STATEMENT EXECUTE FUNCTION audit_reject_change();
CREATE TRIGGER audit_checkpoints_no_update BEFORE UPDATE ON audit_checkpoints FOR EACH ROW EXECUTE FUNCTION audit_reject_change();
CREATE TRIGGER audit_checkpoints_no_delete BEFORE DELETE ON audit_checkpoints FOR EACH ROW EXECUTE FUNCTION audit_reject_change();
CREATE TRIGGER audit_checkpoints_no_truncate BEFORE TRUNCATE ON audit_checkpoints FOR EACH STATEMENT EXECUTE FUNCTION audit_reject_change();
CREATE TRIGGER audit_head_no_delete BEFORE DELETE ON audit_head FOR EACH ROW EXECUTE FUNCTION audit_reject_change();
CREATE TRIGGER audit_head_no_truncate BEFORE TRUNCATE ON audit_head FOR EACH STATEMENT EXECUTE FUNCTION audit_reject_change();

-- The one SECURITY DEFINER function of the schema, and why: writers must NOT hold UPDATE on audit_head (else a compromised writer could rewind the head),
-- yet every insert has to advance it. The function runs as the owner, does exactly two things (check that the new row extends the head, move the head),
-- takes no arguments, is a trigger function (cannot be called directly) and pins search_path. The database cannot verify the HMAC (the key is not in
-- the database), but it does enforce linearity: id = head + 1 and prev_hash = head hash, so a fork or a gap cannot be written by any role.
CREATE FUNCTION audit_chain_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  h audit_head%ROWTYPE;
BEGIN
  SELECT * INTO h FROM audit_head WHERE singleton FOR UPDATE;
  IF NEW.id <> h.last_id + 1 OR NEW.prev_hash <> h.last_hash THEN
    RAISE EXCEPTION 'audit chain: the row does not extend the head' USING ERRCODE = '23514';
  END IF;
  UPDATE audit_head SET last_id = NEW.id, last_hash = NEW.hash WHERE singleton;
  RETURN NEW;
END $$;
CREATE TRIGGER audit_chain BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_chain_guard();

-- The head may change only as a consequence of that trigger (trigger depth 2: insert trigger -> head update), never by a direct statement.
CREATE FUNCTION audit_head_only_via_chain() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION 'audit_head changes only through an audit_log insert' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER audit_head_guard BEFORE UPDATE ON audit_head FOR EACH ROW EXECUTE FUNCTION audit_head_only_via_chain();

-- Row-level security, forced (the owner is bound too).
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoints FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_log_insert_api ON audit_log FOR INSERT TO casefile_app WITH CHECK (source = 'api');
CREATE POLICY audit_log_insert_bff ON audit_log FOR INSERT TO casefile_web WITH CHECK (source = 'bff');
-- auditors read through the request context exactly like case files (role grant readAudit), the verifier reads everything
CREATE POLICY audit_log_select_auditor ON audit_log FOR SELECT TO casefile_app USING (app_ctx_ok() AND role_allows('readAudit'));
CREATE POLICY audit_log_select_verifier ON audit_log FOR SELECT TO casefile_audit USING (true);

CREATE POLICY audit_cp_insert_app ON audit_checkpoints FOR INSERT TO casefile_app WITH CHECK (true);
CREATE POLICY audit_cp_insert_verifier ON audit_checkpoints FOR INSERT TO casefile_audit WITH CHECK (true);
CREATE POLICY audit_cp_select_auditor ON audit_checkpoints FOR SELECT TO casefile_app USING (app_ctx_ok() AND role_allows('readAudit'));
CREATE POLICY audit_cp_select_verifier ON audit_checkpoints FOR SELECT TO casefile_audit USING (true);

-- Grants: INSERT and SELECT only, and only where listed. No UPDATE, DELETE, TRUNCATE, REFERENCES or TRIGGER for anyone but the owner (who is stopped by the triggers).
REVOKE ALL ON audit_log, audit_head, audit_checkpoints FROM PUBLIC;
GRANT INSERT, SELECT ON audit_log TO casefile_app;
GRANT INSERT ON audit_log TO casefile_web;
GRANT SELECT ON audit_log TO casefile_audit;
GRANT SELECT ON audit_head TO casefile_app, casefile_web, casefile_audit;
GRANT INSERT, SELECT ON audit_checkpoints TO casefile_app, casefile_audit;
