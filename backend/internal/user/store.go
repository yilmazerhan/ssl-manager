package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("user: not found")

type Store interface {
	GetByID(ctx context.Context, id string) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	// GetOrCreateByOIDCSubject links (or creates, on first login) the app
	// account for an OIDC identity. New accounts default to RoleViewer —
	// an admin promotes them from there.
	GetOrCreateByOIDCSubject(ctx context.Context, subject, email string) (User, error)
	List(ctx context.Context) ([]User, error)
	SetRoleAndTeam(ctx context.Context, id string, role Role, team string) error
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) GetByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT id, email, coalesce(oidc_subject, ''), role, coalesce(team, ''), created_at
		FROM app_user WHERE id = $1
	`, id))
}

func (s *PostgresStore) GetByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT id, email, coalesce(oidc_subject, ''), role, coalesce(team, ''), created_at
		FROM app_user WHERE email = $1
	`, email))
}

func (s *PostgresStore) GetOrCreateByOIDCSubject(ctx context.Context, subject, email string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `
		SELECT id, email, coalesce(oidc_subject, ''), role, coalesce(team, ''), created_at
		FROM app_user WHERE oidc_subject = $1
	`, subject))
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
		RETURNING id, email, coalesce(oidc_subject, ''), role, coalesce(team, ''), created_at
	`, email, subject, RoleViewer))
}

func (s *PostgresStore) List(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, coalesce(oidc_subject, ''), role, coalesce(team, ''), created_at
		FROM app_user ORDER BY email ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("user: list: %w", err)
	}
	defer rows.Close()

	var out []User
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

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanUser(row rowScanner) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.OIDCSubject, &u.Role, &u.Team, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("user: scan: %w", err)
	}
	return u, nil
}
