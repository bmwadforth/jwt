# Json Web Token (RFC7519) Library

This library has two goals.
* Make generating and validating "JWTs" as intuitive and easy as possible, with the ability to add complexity if the developer chooses
* Follow RFC7519 and implement the recommended cryptographic algorithms for both JWS and JWE

### Example
Chances are you are a developer that just wants to generate and validate a token

Generating a HS256 token - (if you just want to generate a JWT, this is 99% of the time what you want to do)

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
   
    /*
      You don't need to check for an error 
      as long as you don't add a claim 
      that is valid JSON grammar
    */
    claims.Add(string(Subject), "your_subject")
    claims.Add(string(IssuedAt), time.Now())
    claims.Add("my_claim", "some_value")
    
    //Chances are you want to use HS256 if you just want a 'jwt'
    token, err := New(HS256, claims, key)
    if err != nil {
        //Unable to create JWT for some reason, handle error here
        log.Fatal(err)
    }

    tokenBytes, err := token.Encode()
    return string(tokenBytes), nil
    //https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ5b3VyX2F1ZGllbmNlIiwiaWF0IjoiMjAyMC0wMS0wMlQxOToyNDoxOS4wMTYzOTUrMTE6MDAiLCJteV9jbGFpbSI6InNvbWVfdmFsdWUiLCJzdWIiOiJ5b3VyX3N1YmplY3QifQ.vjNqqbMxyh86m9vB7XiCqVRq8Xmxi9858WwrIFoagzo
}

func verifyToken(tokenString string, key []byte) (bool, error) {
    _, err := Parse(tokenString)
	if err != nil {
		log.Fatal(err)
	}
    
    //TODO: token.Verify()
    return true, nil
}


func main(){
    key := []byte("HMAC ALLOWS AN ARBITRARY KEY SIZE, BUT 64 BYTES IS RECOMMENDED")
    tokenString, _ := generateJwt(key)
    tokenValid, _ := verifyToken(tokenString, key)
    
    if tokenValid {
        //Do something
    }
}
```
