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
    token, err := Parse(tokenString)
	if err != nil {
		log.Fatal(err)
	}
    
    isValid, _ := token.Validate(key)
    
    if !isValid {
        //Not Valid
    }
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


### Supported Algorithms
This library currently supports JWS only - implementing HS256 and insecure JWTs.


#### JWS
| "alg" Param        | Digital Signature/MAC Algorithm           | Implementation Requirement  | Implemented  |
| ------------- |:-------------:| -----:| -----:|
| HS256        | HMAC using SHA-256            | Required           | ✅ |
   | HS384        | HMAC using SHA-384            | Optional           |❌ |
   | HS512        | HMAC using SHA-512            | Optional           |❌ |
   | RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        | ❌|
   |              | SHA-256                       |                    | ❌|
   | RS384        | RSASSA-PKCS1-v1_5 using       | Optional           | ❌|
   |              | SHA-384                       |                    | ❌|
   | RS512        | RSASSA-PKCS1-v1_5 using       | Optional           | ❌|
   |              | SHA-512                       |                    | ❌|
   | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       | ❌|
   | ES384        | ECDSA using P-384 and SHA-384 | Optional           | ❌|
   | ES512        | ECDSA using P-521 and SHA-512 | Optional           | ❌|
   | PS256        | RSASSA-PSS using SHA-256 and  | Optional           | ❌|
   |              | MGF1 with SHA-256             |                    | ❌|
   | PS384        | RSASSA-PSS using SHA-384 and  | Optional           | ❌|
   |              | MGF1 with SHA-384             |                    | ❌|
   | PS512        | RSASSA-PSS using SHA-512 and  | Optional           | ❌|
   |              | MGF1 with SHA-512             |                    | ❌|
   | none         | No digital signature or MAC   | Optional           | ✅|
   |              | performed                     |
   
   
#### JWE
_Implementation coming_