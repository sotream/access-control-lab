-- Stage 6: server-side sessions of the web BFF. Only casefile_web can touch this table; casefile_app cannot see it.
-- The cookie value is never stored (only its SHA-256), tokens are encrypted by the application (AES-256-GCM, key id recorded).

CREATE TABLE bff_sessions (
  sid_hash      bytea       PRIMARY KEY CHECK (octet_length(sid_hash) = 32),
  user_sub      text        NOT NULL CHECK (user_sub ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  csrf_token    text        NOT NULL CHECK (char_length(csrf_token) >= 32),
  tokens_enc    bytea       NOT NULL,
  key_id        text        NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_.-]{1,32}$'),
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,   -- absolute lifetime
  idle_expires_at timestamptz NOT NULL  -- slides with use
);
CREATE INDEX bff_sessions_user_idx ON bff_sessions (user_sub, created_at);
CREATE INDEX bff_sessions_expiry_idx ON bff_sessions (expires_at);

REVOKE ALL ON bff_sessions FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON bff_sessions TO casefile_web;
