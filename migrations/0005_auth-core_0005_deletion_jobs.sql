-- A provider's "delete this person's data" request, recorded before it is
-- carried out (issue #18).
--
-- A row rather than immediate deletion because the callbacks that create
-- one answer synchronously with a confirmation code and a status URL: Meta
-- requires both, and doing the work inside that request would mean either
-- a slow callback or a deletion that silently failed after the answer went
-- out. The scheduled handler drains this table.
--
-- Provider-shaped rather than Meta-shaped: Apple has a comparable
-- obligation, and a second table for the same thing would be a second
-- place to get it wrong.
CREATE TABLE deletion_jobs (
  id                TEXT PRIMARY KEY,
  -- The identities.provider value the request came from.
  provider          TEXT NOT NULL,
  -- The provider's own id for the person, as stored on the identity.
  provider_subject  TEXT NOT NULL,
  -- Shown to the person on the status page and returned to the provider.
  -- Not a secret: it identifies a request, and the status it reveals is
  -- the person's own.
  confirmation_code TEXT NOT NULL,
  -- pending | done
  status            TEXT NOT NULL,
  -- What was actually done, once it has been: unlinked | deleted_user |
  -- nothing_to_do. Recorded because "we deleted your data" and "we had
  -- none" are different answers and a person may ask which.
  outcome           TEXT,
  created_at        TEXT NOT NULL,
  completed_at      TEXT
);

CREATE UNIQUE INDEX deletion_jobs_confirmation_code
  ON deletion_jobs (confirmation_code);

-- The scheduled handler's query: the pending ones, oldest first.
CREATE INDEX deletion_jobs_status_created
  ON deletion_jobs (status, created_at);
