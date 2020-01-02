# Json Web Token (RFC7519) Library

This library has two goals.
* Make generating and validating _JWTs_ as intuitive and easy as possible, with the ability to add complexity if the developer chooses
* Follow RFC7519 and implement the recommended cryptographic algorithms for both JWS and JWE

### Example
Chances are you are a developer that just wants to generate and validate a token.
Generating a HS256 token (which is commonly used to authenticate clients).

```go
package main

import (
    "fmt"
    . "github.com/bmwadforth/jwt"
    "log"
    "time"
)

func generateJwt(key []byte) (string, error) {
    claims := NewClaimSet()
    err := claims.Add(string(Audience), "your_audience")
    if err != nil {
        //Handle error
        log.Fatal(err)
    }
 
    claims.Add(string(Subject), "your_subject")
    claims.Add(string(IssuedAt), time.Now())
    claims.Add("my_claim", "some_value")
    
    //Use HS256 if you're just looking to generate a JWT to authenticate a client
    token, err := New(HS256, claims, key)
    if err != nil {
        log.Fatal(err)
    }

    tokenBytes, err := token.Encode()
    return string(tokenBytes), nil
    //https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ5b3VyX2F1ZGllbmNlIiwiaWF0IjoiMjAyMC0wMS0wMlQxOToyNDoxOS4wMTYzOTUrMTE6MDAiLCJteV9jbGFpbSI6InNvbWVfdmFsdWUiLCJzdWIiOiJ5b3VyX3N1YmplY3QifQ.vjNqqbMxyh86m9vB7XiCqVRq8Xmxi9858WwrIFoagzo
}

func validateToken(tokenString string, key []byte) (bool, error) {
    _, err := Parse(tokenString)
	if err != nil {
		log.Fatal(err)
	}
    
    //TODO: token.Validate()
    return true, nil
}


func main(){
    key := []byte("HMAC ALLOWS AN ARBITRARY KEY SIZE, BUT 64 BYTES IS RECOMMENDED")
    tokenString, _ := generateJwt(key)
    tokenValid, _ := validateToken(tokenString, key)
    
    if tokenValid {
        //Do something
    }
}
```
