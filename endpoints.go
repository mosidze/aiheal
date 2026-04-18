package login

import (
	"context"
	"errors"

	"github.com/go-kit/kit/endpoint"
)

const UserContextKey = "email"

// Endpoints collects all of the service's endpoints.
type Endpoints struct {
	ListUsers  endpoint.Endpoint
	CreateUser endpoint.Endpoint
	Login      endpoint.Endpoint
	Me         endpoint.Endpoint
}

func contextToJWTUser(ctx context.Context) *JWTUser {
	u, ok := ctx.Value(UserContextKey).(*JWTUser)
	if !ok {
		return nil
	}
	return u
}

// MakeServerEndpoints returns an Endpoints struct where each endpoint invokes
// the corresponding method on the provided service.
func MakeServerEndpoints(s Service, jwtmw endpoint.Middleware) Endpoints {

	return Endpoints{
		ListUsers:  jwtmw(MakeListUsersEndpoint(s)),
		CreateUser: MakeCreateUserEndpoint(s),
		Login:      MakeLoginEndpoint(s),
		Me:         jwtmw(MakeMeEndpoint(s)),
	}
}

// MakeListUsersEndpoint returns an endpoint wrapping the given server.
func MakeListUsersEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, _ interface{}) (response interface{}, err error) {
		j := contextToJWTUser(ctx)
		return s.ListUsers(ctx, j)
	}
}

// MakeMeEndpoint returns an endpoint wrapping the given server.
func MakeMeEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, _ interface{}) (response interface{}, err error) {
		j := contextToJWTUser(ctx)
		return s.Me(ctx, j)
	}
}

// MakeCreateUserEndpoint returns an endpoint wrapping the given server.
func MakeCreateUserEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		u, ok := request.(User)
		if !ok {
			return nil, errors.New("invalid request type, likely bad wiring")
		}
		return s.CreateUser(ctx, u)
	}
}

// MakeLoginEndpoint returns an endpoint wrapping the given server.
func MakeLoginEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		d, ok := request.(LoginData)
		if !ok {
			return nil, errors.New("invalid request type, likely bad wiring")
		}
		return s.Login(ctx, d)
	}
}
