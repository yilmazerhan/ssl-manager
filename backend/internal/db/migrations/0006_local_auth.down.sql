ALTER TABLE app_user
    DROP COLUMN username,
    DROP COLUMN password_hash,
    DROP COLUMN must_change_password,
    DROP COLUMN failed_login_attempts,
    DROP COLUMN locked_until;
