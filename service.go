package login

import (
	"context"
	jwt "github.com/dgrijalva/jwt-go"
)

type ErrorString string

// Error satisfies error.
func (e ErrorString) Error() string {
	return string(e)
}

// ErrInvalidUser is returned if the user is invalid.
const ErrInvalidUser ErrorString = "Invalid user"

// ErrNotFound is used to indicate that a resource has not been found.
// N.B. it is _not_ used when the collection is empty.
const ErrNotFound ErrorString = "Not found"

// ErrDatabase indicates a problem communicating with the database.
const ErrDatabase ErrorString = "Database error"

// ErrUnauthorized indicates that the requested action doesn't match the
// user's permissions set out in the JWT claims
const ErrUnauthorized ErrorString = "Unauthorised"

// ErrUserExists indicates that the user which is attempted to register
// already exists
const ErrUserExists ErrorString = "User already exists"

// ErrBadLogin indicates bad login credentials
const ErrBadLogin ErrorString = "Bad login"

// Repository represents a collection of users in the database.
type Repository interface {
	Insert(ctx context.Context, in User) error
	List(ctx context.Context) ([]User, error)
	ByEmail(ctx context.Context, email string) (*User, error)
	Login(ctx context.Context, email string, password string) (*User, error)
}

// Service provides operations on Users.
type Service interface {
	CreateUser(ctx context.Context, u User) (*User, error)
	ListUsers(ctx context.Context, j *JWTUser) (users *Users, err error)
	Me(ctx context.Context, j *JWTUser) (u *User, err error)
	Login(ctx context.Context, d LoginData) (l *LoginResponse, err error)
}

// NewUserService returns a pointer to a new user service instance.
func NewUserService(r Repository) *UserService {
	return &UserService{
		r: r,
	}
}

type UserService struct {
	r Repository
}

type JWTUser struct {
	Email string
	Admin bool
}

// ListUsers gets all users from the database.
func (svc *UserService) ListUsers(ctx context.Context, j *JWTUser) (*Users, error) {
	if j == nil || !j.Admin {
		return nil, ErrUnauthorized
	}
	list, err := svc.r.List(ctx)
	if err != nil {
		return nil, err
	}

	return &Users{
		Data: list,
	}, nil
}

// Me gets a specific user - by email - from the database.
func (svc *UserService) Me(ctx context.Context, j *JWTUser) (*User, error) {
	u, err := svc.r.ByEmail(ctx, j.Email)
	if err != nil {
		return nil, err
	}

	return u, nil
}

// CreateUser adds a User to the database.
func (svc *UserService) CreateUser(ctx context.Context, u User) (*User, error) {
	test, err := svc.r.ByEmail(ctx, u.Email)
	if test != nil {
		return nil, ErrUserExists
	}
	err = svc.r.Insert(ctx, u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// Login performs a check in the database if a user/pass combination exists
func (svc *UserService) Login(ctx context.Context, d LoginData) (*LoginResponse, error) {
	u, err := svc.r.Login(ctx, d.Email, d.Password)
	if err != nil {
		return nil, err
	}
	if u != nil {
		claims := jwt.MapClaims{
			"email": u.Email,
			"admin": u.Admin,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("SuperSecret"))
		if err != nil {
			panic(err)
		}
		return &LoginResponse{
			Token: tokenString,
		}, nil
	} else {
		return nil, ErrBadLogin
	}
}

// convertDBError converts a repository error to a domain one.
func convertDBError(err error) error {
	switch err {
	case nil:
		return nil
	case ErrNotFound:
		return ErrNotFound
	default:
		return ErrDatabase
	}
}
