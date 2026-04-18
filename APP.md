# Demo App API

The demo app exposes four endpoints:

1. `GET /users`
2. `GET /me`
3. `POST /register`
4. `POST /login`

`/register` and `/login` are unauthenticated. `/me` requires a bearer token for the current user. `/users` requires an authenticated admin token.

## JWT helper

Authorization uses JSON Web Tokens signed with `SuperSecret` by default. Running `make` builds `bin/login` and `bin/token`, and `bin/token -admin` creates an admin token for manual testing.

## Example requests

Register a user:

```bash
curl localhost:8080/register \
  -d '{"email":"coolbet@cool.bet","password":"pass","name":"Jon","surname":"Doe"}'
```

Log in and receive a token:

```bash
curl localhost:8080/login \
  -d '{"email":"coolbet@cool.bet","password":"pass"}'
```

Read your own profile:

```bash
curl localhost:8080/me \
  -H 'Authorization: Bearer <jwt-token>'
```

Read all users as an admin:

```bash
curl localhost:8080/users \
  -H 'Authorization: Bearer <admin-jwt-token>'
```
