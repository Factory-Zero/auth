-- auth issue #6: client secret rotation with an overlap window. The
-- previous secret's hash stays beside the current one and stops
-- verifying once previous_hash_expires_at has passed, so a rotation
-- is never a hard cutover. Harness portable SQL subset (harness issue
-- #8): plain ALTERs, no dialect functions.

ALTER TABLE clients ADD COLUMN previous_secret_hash TEXT;
ALTER TABLE clients ADD COLUMN previous_hash_expires_at TEXT;
