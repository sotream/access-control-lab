-- Stage 7: the audit log must record the TRUE reason a hidden file was hidden (clearance, compartment, role), while the client only ever sees 404.
-- Row-level security makes a hidden row invisible to the API, so the API cannot evaluate the policy on it. This function does, in SQL, for the caller's own
-- request context (the same app.* settings the policies use), and returns ONLY a reason code, never a column of the file.
--
-- It is the second SECURITY DEFINER function of the schema (the first is audit_chain_guard). Why it is acceptable:
--  - it runs as casefile_lookup, a NOLOGIN role that can read exactly three columns of case_files (id, classification, compartments) and role_grants;
--  - it returns one of a fixed set of codes: no title, body, unit, author or status leaves the database;
--  - the only extra thing the API role can learn is "does this id exist" (RESOURCE_NOT_FOUND vs another code), which the API logs anyway and never tells the client;
--  - its rules mirror the read rule of packages/policy; tests/api-db/src/audit-db.test.ts checks it against evaluate() on a grid.

GRANT SELECT (id, classification, compartments) ON case_files TO casefile_lookup;
GRANT SELECT ON role_grants TO casefile_lookup;
CREATE POLICY case_files_lookup ON case_files FOR SELECT TO casefile_lookup USING (true);

CREATE FUNCTION audit_read_denial_reason(p_id uuid) RETURNS text
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  r_class classification;
  r_comps text[];
BEGIN
  IF NOT app_ctx_ok() THEN RETURN 'INVALID_INPUT'; END IF;
  SELECT classification, compartments INTO r_class, r_comps FROM case_files WHERE id = p_id;
  IF NOT FOUND THEN RETURN 'RESOURCE_NOT_FOUND'; END IF;
  IF NOT role_allows('read') THEN RETURN 'ROLE_NOT_PERMITTED'; END IF;
  IF r_class > app_clearance() THEN RETURN 'CLEARANCE_TOO_LOW'; END IF;
  IF NOT (r_comps <@ app_compartments()) THEN RETURN 'COMPARTMENT_MISSING'; END IF;
  IF r_class = 'SECRET' AND NOT app_mfa() THEN RETURN 'STEP_UP_REQUIRED'; END IF;
  RETURN 'ALLOWED';
END $$;
-- privileges first, while the migrator still owns the function (a non-owner cannot revoke or grant); ownership moves afterwards and keeps the ACL
REVOKE ALL ON FUNCTION audit_read_denial_reason(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_read_denial_reason(uuid) TO casefile_app;
-- changing a function's owner requires CREATE on the schema for the new owner, for this one statement only
GRANT CREATE ON SCHEMA public TO casefile_lookup;
ALTER FUNCTION audit_read_denial_reason(uuid) OWNER TO casefile_lookup;
REVOKE CREATE ON SCHEMA public FROM casefile_lookup;
