// IGNORE THE CONTENT OF THIS FILE
package main

import (
	"flag"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

func main() {
	var admin = flag.Bool("admin", false, "Token has admin privileges: true/false")
	var key = flag.String("key", "SuperSecret", "Signing key. Defaults to match docker-compose")

	flag.Parse()

	claims := jwt.MapClaims{
		"email": "coolbet@idontexist.nope",
		"admin": admin,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(*key))
	if err != nil {
		panic(err)
	}
	fmt.Print(tokenString)
}
