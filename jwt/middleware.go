package jwtauth

import (
	"context"

	"github.com/coolbet/login"
	stdjwt "github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/endpoint"
)

func NewMiddleware(signingString string) endpoint.Middleware {
	newClaims := jwt.MapClaimsFactory
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			tokenString, ok := ctx.Value(jwt.JWTContextKey).(string)
			if !ok {
				return nil, jwt.ErrTokenContextMissing
			}

			token, _, err := new(stdjwt.Parser).ParseUnverified(tokenString, newClaims())
			if err != nil {
				return nil, jwt.ErrTokenInvalid
			}

			ctx = context.WithValue(ctx, jwt.JWTClaimsContextKey, token.Claims)
			mc := token.Claims.(stdjwt.MapClaims)

			u := login.JWTUser{
				Email: mc["email"].(string),
				Admin: mc["admin"].(bool),
			}
			ctx = context.WithValue(ctx, login.UserContextKey, &u)

			return next(ctx, request)
		}
	}
}
