package users

import (
	"context"
	"database/sql"
	"fmt"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user User) (*User, error)
	GetUsers(ctx context.Context) ([]User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id int) (*User, error)
	Update(ctx context.Context, user User) (*User, error)
	Delete(ctx context.Context, id int) error
}

type SQLUserRepository struct {
	db *sql.DB
}

func NewSQLUserRepository(db *sql.DB) UserRepository {
	return &SQLUserRepository{db: db}
}

func (r *SQLUserRepository) CreateUser(ctx context.Context, user User) (*User, error) {
	query := `
        INSERT INTO users (name, email, password)
        VALUES ($1, $2, $3)
        RETURNING id, name, email, created_at, updated_at
    `
	result := &User{}
	err := r.db.QueryRow(query, user.Name, user.Email, user.Password).Scan(
		&result.ID,
		&result.Name,
		&result.Email,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *SQLUserRepository) GetUsers(ctx context.Context) ([]User, error) {
	query := `SELECT id, name, email, created_at FROM users`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User

		err := rows.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.CreatedAt,
			&user.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("could not scan account row: %w", err)
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (r *SQLUserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	query := `
        SELECT id, name, email, password, created_at, updated_at
        FROM users
        WHERE email = $1
    `
	user := &User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *SQLUserRepository) GetByID(ctx context.Context, id int) (*User, error) {
	query := `
        SELECT id, name, email, created_at, updated_at
        FROM users
        WHERE id = $1
    `
	user := &User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *SQLUserRepository) Update(ctx context.Context, user User) (*User, error) {
	query := `
        UPDATE users
        SET name = $1, email = $2
        WHERE id = $3
        RETURNING id, name, email, created_at, updated_at
    `
	result := &User{}
	err := r.db.QueryRow(query, user.Name, user.Email, user.ID).Scan(
		&result.ID,
		&result.Name,
		&result.Email,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *SQLUserRepository) Delete(ctx context.Context, id int) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.Exec(query, id)
	return err
}
