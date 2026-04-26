-- Signup review: pending until admin approves and assigns permissions.

ALTER TABLE app_users ADD COLUMN IF NOT EXISTS review_status VARCHAR(32) NOT NULL DEFAULT 'approved';
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS email VARCHAR(256);
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS registration_note TEXT;
