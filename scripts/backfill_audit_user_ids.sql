-- Normalize historical audit_logs.user_id values that were stored as emails.
-- Run this once on Postgres after deploying code changes.

-- Replace user emails with users.id
UPDATE audit_logs a
SET user_id = u.id::text
FROM users u
WHERE lower(a.user_id) = lower(u.email);

-- Replace admin emails with admins.id
UPDATE audit_logs a
SET user_id = ad.id::text
FROM admins ad
WHERE lower(a.user_id) = lower(ad.email);
