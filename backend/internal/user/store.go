package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("user: not found")

type Store interface {
	GetByID(ctx context.Context, id string) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	GetByUsername(ctx context.Context, username string) (User, error)
	// GetOrCreateByOIDCSubject links (or creates, on first login) the app
	// account for an OIDC identity. New accounts default to RoleViewer —
	// an admin promotes them from there.
	GetOrCreateByOIDCSubject(ctx context.Context, subject, email string) (User, error)
	List(ctx context.Context) ([]User, error)
	SetRoleAndTeam(ctx context.Context, id string, role Role, team string) error

	// CountLocalUsers reports how many accounts have ever had a username
	// set — used at startup to decide whether to seed a default local
	// admin account (only ever done once, against a database that has
	// never had a local account at all).
	CountLocalUsers(ctx context.Context) (int, error)
	// EnsureLocalAdmin creates the seeded admin account. It's safe to call
	// on every startup: the INSERT targets username for its ON CONFLICT,
	// so once "admin" exists this is a no-op even if CountLocalUsers'
	// caller races another instance.
	EnsureLocalAdmin(ctx context.Context, username, email, passwordHash string, role Role) error
	// SetPassword replaces a local account's password hash and resets any
	// lockout state — a successful password change is as good a signal as
	// any that whatever locked the account out no longer applies.
	SetPassword(ctx context.Context, id, passwordHash string, mustChangePassword bool) error
	// RecordFailedLogin persists an updated attempt counter and, once the
	// caller decides the threshold is crossed, a lockout expiry.
	RecordFailedLogin(ctx context.Context, id string, attempts int, lockedUntil *time.Time) error
	ResetFailedLogins(ctx context.Context, id string) error
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

const userColumns = `id, email, coalesce(oidc_subject, ''), coalesce(username, ''), coalesce(password_hash, ''),
	must_change_password, failed_login_attempts, locked_until, role, coalesce(team, ''), created_at`

func (s *PostgresStore) GetByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM app_user WHERE id = $1`, id))
}

func (s *PostgresStore) GetByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM app_user WHERE email = $1`, email))
}

func (s *PostgresStore) GetByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM app_user WHERE username = $1`, username))
}

func (s *PostgresStore) GetOrCreateByOIDCSubject(ctx context.Context, subject, email string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM app_user WHERE oidc_subject = $1`, subject))
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return User{}, err
	}

	return scanUser(s.pool.QueryRow(ctx, `
		INSERT INTO app_user (email, oidc_subject, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (email) DO UPDATE SET oidc_subject = EXCLUDED.oidc_subject
		RETURNING `+userColumns, email, subject, RoleViewer))
}

func (s *PostgresStore) List(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM app_user ORDER BY email ASC`)
	if err != nil {
		return nil, fmt.Errorf("user: list: %w", err)
	}
	defer rows.Close()

	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SetRoleAndTeam(ctx context.Context, id string, role Role, team string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app_user SET role = $2, team = $3 WHERE id = $1`, id, role, team)
	if err != nil {
		return fmt.Errorf("user: set role and team: %w", err)
	}
	return nil
}

func (s *PostgresStore) CountLocalUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM app_user WHERE username IS NOT NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("user: count local users: %w", err)
	}
	return n, nil
}

func (s *PostgresStore) EnsureLocalAdmin(ctx context.Context, username, email, passwordHash string, role Role) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO app_user (username, email, password_hash, role, must_change_password)
		VALUES ($1, $2, $3, $4, true)
		ON CONFLICT (username) DO NOTHING
	`, username, email, passwordHash, role)
	if err != nil {
		return fmt.Errorf("user: ensure local admin: %w", err)
	}
	return nil
}

func (s *PostgresStore) SetPassword(ctx context.Context, id, passwordHash string, mustChangePassword bool) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE app_user
		SET password_hash = $2, must_change_password = $3, failed_login_attempts = 0, locked_until = NULL
		WHERE id = $1
	`, id, passwordHash, mustChangePassword)
	if err != nil {
		return fmt.Errorf("user: set password: %w", err)
	}
	return nil
}

func (s *PostgresStore) RecordFailedLogin(ctx context.Context, id string, attempts int, lockedUntil *time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE app_user SET failed_login_attempts = $2, locked_until = $3 WHERE id = $1`, id, attempts, lockedUntil)
	if err != nil {
		return fmt.Errorf("user: record failed login: %w", err)
	}
	return nil
}

func (s *PostgresStore) ResetFailedLogins(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE app_user SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("user: reset failed logins: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanUser(row rowScanner) (User, error) {
	var u User
	err := row.Scan(
		&u.ID, &u.Email, &u.OIDCSubject, &u.Username, &u.PasswordHash,
		&u.MustChangePassword, &u.FailedLoginAttempts, &u.LockedUntil,
		&u.Role, &u.Team, &u.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("user: scan: %w", err)
	}
	return u, nil
}
