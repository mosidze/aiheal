package login

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	stdjwt "github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

var (
	// ErrBadRouting is returned when an expected path variable is missing.
	// It always indicates programmer error.
	ErrBadRouting = errors.New("inconsistent mapping between route and handler (programmer error)")
	// ErrBadRequest is returned in response to JSON decode errors.
	ErrBadRequest = errors.New("JSON could not be decoded")
)

// MakeHTTPHandler mounts all of the service endpoints into an http.Handler.
// Useful in a profilesvc server.
func MakeHTTPHandler(e Endpoints, logger log.Logger) http.Handler {
	r := mux.NewRouter()
	options := []httptransport.ServerOption{
		httptransport.ServerErrorLogger(logger),
		httptransport.ServerErrorEncoder(encodeError),
		httptransport.ServerBefore(jwt.HTTPToContext()),
	}

	// GET		/users					retrieves the list of users (admin only)
	// GET		/me					    retrieves own user's data
	// POST		/register				registers to the system with a new user
	// POST		/login					performs a login (and get a token)

	r.Methods("GET").Path("/users").Handler(httptransport.NewServer(
		e.ListUsers,
		httptransport.NopRequestDecoder,
		encodeResponse,
		options...,
	))
	r.Methods("GET").Path("/me").Handler(httptransport.NewServer(
		e.Me,
		httptransport.NopRequestDecoder,
		encodeResponse,
		options...,
	))
	r.Methods("POST").Path("/register").Handler(httptransport.NewServer(
		e.CreateUser,
		decodeCreateUserRequest,
		encodeResponseWithStatus(http.StatusCreated),
		options...,
	))
	r.Methods("POST").Path("/login").Handler(httptransport.NewServer(
		e.Login,
		decodeLoginRequest,
		encodeResponseWithStatus(http.StatusCreated),
		options...,
	))
	return r
}

func decodeCreateUserRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var p User
	if e := json.NewDecoder(r.Body).Decode(&p); e != nil {
		return nil, ErrBadRequest
	}
	return p, nil
}

func decodeLoginRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var l LoginData
	if e := json.NewDecoder(r.Body).Decode(&l); e != nil {
		return nil, ErrBadRequest
	}
	return l, nil
}

// Returns an EncodeResponseFunc that will set the given status code before
// encode the JSON response with encodeResponse.
func encodeResponseWithStatus(code int) httptransport.EncodeResponseFunc {
	return func(ctx context.Context, w http.ResponseWriter, response interface{}) error {
		w.WriteHeader(code)
		return encodeResponse(ctx, w, response)
	}
}

// encodeResponse is the common method to encode all response types to the
// client.
func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	code := codeFrom(err)
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": http.StatusText(code),
	})
}

func codeFrom(err error) int {
	switch err {
	case ErrNotFound:
		return http.StatusNotFound
	case ErrBadRequest:
		return http.StatusBadRequest
	case ErrInvalidUser:
		return http.StatusBadRequest
	case ErrUnauthorized:
		return http.StatusUnauthorized
	case ErrBadLogin:
		return http.StatusUnauthorized
	case ErrUserExists:
		return http.StatusUnauthorized
	case jwt.ErrTokenContextMissing:
		return http.StatusUnauthorized
	case jwt.ErrTokenInvalid:
		return http.StatusUnauthorized
	case jwt.ErrTokenExpired:
		return http.StatusUnauthorized
	case jwt.ErrTokenMalformed:
		return http.StatusUnauthorized
	case jwt.ErrTokenNotActive:
		return http.StatusUnauthorized
	case jwt.ErrUnexpectedSigningMethod:
		return http.StatusUnauthorized
	case jwt.ErrTokenMalformed:
		return http.StatusUnauthorized
	case jwt.ErrTokenExpired:
		return http.StatusUnauthorized
	case jwt.ErrTokenNotActive:
		return http.StatusUnauthorized
	case jwt.ErrTokenInvalid:
		return http.StatusUnauthorized
	case stdjwt.ErrSignatureInvalid:
		return http.StatusUnauthorized
	}
	return http.StatusInternalServerError
}
