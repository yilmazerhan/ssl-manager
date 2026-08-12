-- Local username/password login, alongside OIDC. username/password_hash
-- are nullable — OIDC-only accounts never get them — but username stays
-- globally unique (NULLs don't conflict with each other in Postgres) so a
-- login lookup by username is unambiguous. failed_login_attempts/
-- locked_until back a simple lockout against password guessing, and
-- must_change_password lets a seeded or admin-assigned password be forced
-- to change on first use rather than trusted indefinitely.
ALTER TABLE app_user
    ADD COLUMN username text UNIQUE,
    ADD COLUMN password_hash text,
    ADD COLUMN must_change_password boolean NOT NULL DEFAULT false,
    ADD COLUMN failed_login_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN locked_until timestamptz;
