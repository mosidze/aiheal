package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/coolbet/login"
)

type UserRepo struct {
	db *sql.DB
}

// NewRepo returns a new repository backed by the given DB.
func NewRepo(db *sql.DB) *UserRepo {
	return &UserRepo{
		db: db,
	}
}

// Insert satisfies Repository.
func (r *UserRepo) Insert(ctx context.Context, u login.User) error {
	stmt := fmt.Sprintf(`insert into "Users" ("email", "password", "admin", "surname", "name") values ('%s', '%s', '%t', '%s', '%s')`, u.Email, u.Password, u.Admin, u.Surname, u.Name)
	_, err := r.db.Exec(stmt)
	return err
}

// List returns the full contents of the repository.
func (r *UserRepo) List(ctx context.Context) ([]login.User, error) {
	stmt := fmt.Sprintf(`select "id", "email", "name", "surname", "admin" from "Users"`)
	rows, err := r.db.Query(stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	result := []login.User{}
	for rows.Next() {
		var u login.User
		err = rows.Scan(&u.ID, &u.Email, &u.Name, &u.Surname, &u.Admin)
		if err != nil {
			fmt.Println(err)
			continue
		}
		result = append(result, u)
	}
	return result, nil
}

// ByEmail returns a single user by email.
func (r *UserRepo) ByEmail(ctx context.Context, email string) (*login.User, error) {
	q := fmt.Sprintf(`select "id", "email", "name", "surname", "admin" from "Users" where "email"='%s'`, email)
	rows, err := r.db.Query(q)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u login.User
		err = rows.Scan(&u.ID, &u.Email, &u.Name, &u.Surname, &u.Admin)
		if err == nil {
			return &u, nil
		}
	}
	return nil, nil
}

// Login returns a given user if the email/password combination matches an existing user
func (r *UserRepo) Login(ctx context.Context, email string, password string) (*login.User, error) {
	q := fmt.Sprintf(`select "id", "email", "name", "surname", "admin" from "Users" where "email"='%s' AND "password"='%s'`, email, password)
	rows, err := r.db.Query(q)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u login.User
		err = rows.Scan(&u.ID, &u.Email, &u.Name, &u.Surname, &u.Admin)
		if err == nil {
			return &u, nil
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}
