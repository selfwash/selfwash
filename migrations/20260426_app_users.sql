-- Dashboard users and per-user permissions (JWT auth in API).

CREATE TABLE IF NOT EXISTS app_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_superuser BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_user_permissions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    permission VARCHAR(128) NOT NULL,
    CONSTRAINT uq_app_user_permission UNIQUE (user_id, permission)
);

CREATE INDEX IF NOT EXISTS ix_app_user_permissions_user_id ON app_user_permissions(user_id);
